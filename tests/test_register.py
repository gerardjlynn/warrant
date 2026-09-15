"""Register tests.

Each of these catches an implementation that passes the others. The two veto
tests bracket the exception: one fails if the evaluator forgets to look back
past the current revision, the other if it looks back without checking
withdrawal.
"""

import pytest

from server import register
from server.register import (BLOCKED, CLOSED, EFFECTIVE, PENDING, Register,
                             RegisterRejected)

ALICE, BOB, CAROL = "rep-alice", "rep-bob", "rep-carol"


class FakeTuples:
    """Stands in for OpenFGA. Records the order of operations so the tests can
    assert the tuple moved before the log said it had."""

    def __init__(self):
        self.active = set()
        self.graph = set()
        self.calls = []
        self.proposers = {(ALICE, "acme"), (BOB, "acme")}

    def may_propose(self, user, account):
        return (user, account) in self.proposers

    def _key(self, grant_id, request):
        return (grant_id, request["account"])

    def write_graph(self, grant_id, request):
        self.graph |= {(grant_id, t["relation"], t["user"])
                       for t in register._graph_tuples(grant_id, request)}

    def delete_graph(self, grant_id, request):
        self.graph -= {(grant_id, t["relation"], t["user"])
                       for t in register._graph_tuples(grant_id, request)}

    def present(self, grant_id, request):
        return self._key(grant_id, request) in self.active

    def write_active(self, grant_id, request):
        self.active.add(self._key(grant_id, request))
        self.calls.append(("write", grant_id))
        return 0.4

    def delete_active(self, grant_id, request):
        self.active.discard(self._key(grant_id, request))
        self.calls.append(("delete", grant_id))
        return 0.3


@pytest.fixture
def reg(tmp_path):
    return Register(log_path=tmp_path / "register.log.jsonl", tuples=FakeTuples())


def propose(reg, condition, *, grantors=(ALICE, BOB), principal=(ALICE, BOB),
            veto=(), grant_id="dlg-124", by=ALICE, **kw):
    reg.propose(grant_id, by=by, principal=list(principal), grantors=list(grantors),
                actor="warrant-agent", account="acme",
                action_scope=["orders:read", "refunds:issue"],
                call_time_conditions={"max_refund_cents": 50000},
                condition=condition, veto=list(veto), **kw)
    return reg.grant(grant_id)["revision"]


def approve(reg, who, rev, gid="dlg-124"):
    return reg.act(gid, who, "approve", rev)


# ---------------- the v2.1 case still works ----------------

def test_named_grant_becomes_effective_on_the_approval(reg):
    rev = propose(reg, {"op": "named", "grantor": ALICE},
                  grantors=(ALICE,), principal=(ALICE,))
    assert reg.state("dlg-124") == PENDING
    assert not reg.tuples.active
    assert approve(reg, ALICE, rev) == EFFECTIVE
    assert reg.tuples.active


def test_withdrawal_under_named_ends_it(reg):
    rev = propose(reg, {"op": "named", "grantor": ALICE},
                  grantors=(ALICE,), principal=(ALICE,))
    approve(reg, ALICE, rev)
    assert reg.act("dlg-124", ALICE, "withdraw", rev) == PENDING
    assert not reg.tuples.active


# ---------------- pending is a real state ----------------

def test_all_of_is_pending_until_the_last_approval(reg):
    rev = propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]})
    assert approve(reg, ALICE, rev) == PENDING
    assert not reg.tuples.active
    assert approve(reg, BOB, rev) == EFFECTIVE
    assert reg.tuples.active


def test_nothing_counts_as_agreement_except_an_approval(reg):
    propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]})
    assert reg.state("dlg-124") == PENDING  # silence is not assent


# ---------------- every act recomputes; the tuple follows ----------------

def test_withdrawal_that_leaves_the_condition_satisfied_changes_nothing(reg):
    rev = propose(reg, {"op": "any_of", "grantors": [ALICE, BOB]})
    approve(reg, ALICE, rev)
    approve(reg, BOB, rev)
    assert reg.act("dlg-124", ALICE, "withdraw", rev) == EFFECTIVE
    assert reg.tuples.active


def test_withdrawal_that_unsatisfies_it_deletes_the_tuple(reg):
    rev = propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]})
    approve(reg, ALICE, rev)
    approve(reg, BOB, rev)
    assert reg.act("dlg-124", BOB, "withdraw", rev) == PENDING
    assert not reg.tuples.active


# ---------------- the condition form means what it says ----------------

def test_threshold_is_satisfied_despite_a_refusal(reg):
    rev = propose(reg, {"op": "threshold", "n": 2, "grantors": [ALICE, BOB, CAROL]},
                  grantors=(ALICE, BOB, CAROL))
    approve(reg, ALICE, rev)
    reg.act("dlg-124", CAROL, "refuse", rev)
    assert approve(reg, BOB, rev) == EFFECTIVE


def test_one_refusal_under_threshold_is_pending_and_two_is_blocked(reg):
    rev = propose(reg, {"op": "threshold", "n": 2, "grantors": [ALICE, BOB, CAROL]},
                  grantors=(ALICE, BOB, CAROL))
    assert reg.act("dlg-124", ALICE, "refuse", rev) == PENDING
    assert reg.act("dlg-124", BOB, "refuse", rev) == BLOCKED


def test_any_refusal_blocks_under_all_of(reg):
    rev = propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]})
    assert reg.act("dlg-124", ALICE, "refuse", rev) == BLOCKED


# ---------------- the veto exception, bracketed ----------------

def test_veto_refusal_recorded_on_n_still_blocks_on_n_plus_one(reg):
    """Fails for an evaluator that filters acts to the current revision."""
    rev = propose(reg, {"op": "threshold", "n": 2, "grantors": [ALICE, BOB, CAROL]},
                  grantors=(ALICE, BOB, CAROL), veto=(ALICE,))
    assert reg.act("dlg-124", ALICE, "refuse", rev) == BLOCKED
    reg.revise("dlg-124", by=BOB, call_time_conditions={"max_refund_cents": 20000})
    rev2 = reg.grant("dlg-124")["revision"]
    assert rev2 != rev
    assert reg.state("dlg-124") == BLOCKED
    approve(reg, BOB, rev2)
    approve(reg, CAROL, rev2)
    assert reg.state("dlg-124") == BLOCKED  # satisfied but for the veto
    assert not reg.tuples.active


def test_the_same_refusal_withdrawn_no_longer_blocks(reg):
    """Fails for an evaluator that scans every revision for a veto refusal:
    acts are never deleted, so the withdrawn one is still in the log."""
    rev = propose(reg, {"op": "threshold", "n": 2, "grantors": [ALICE, BOB, CAROL]},
                  grantors=(ALICE, BOB, CAROL), veto=(ALICE,))
    reg.act("dlg-124", ALICE, "refuse", rev)
    reg.revise("dlg-124", by=BOB, call_time_conditions={"max_refund_cents": 20000})
    rev2 = reg.grant("dlg-124")["revision"]
    assert reg.act("dlg-124", ALICE, "withdraw", rev2) == PENDING
    approve(reg, BOB, rev2)
    assert approve(reg, CAROL, rev2) == EFFECTIVE
    assert reg.tuples.active


def test_a_non_veto_refusal_does_not_survive_revision(reg):
    rev = propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]})
    assert reg.act("dlg-124", ALICE, "refuse", rev) == BLOCKED
    reg.revise("dlg-124", by=ALICE, call_time_conditions={"max_refund_cents": 100})
    assert reg.state("dlg-124") == PENDING


# ---------------- standing, not present ----------------

def test_a_later_act_supersedes_its_author_s_earlier_one(reg):
    rev = propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]})
    approve(reg, ALICE, rev)
    assert reg.act("dlg-124", ALICE, "refuse", rev) == BLOCKED  # no withdraw needed
    assert approve(reg, ALICE, rev) == PENDING
    assert approve(reg, BOB, rev) == EFFECTIVE


def test_approvals_do_not_survive_revision(reg):
    rev = propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]})
    approve(reg, ALICE, rev)
    approve(reg, BOB, rev)
    assert reg.state("dlg-124") == EFFECTIVE
    reg.revise("dlg-124", by=ALICE, call_time_conditions={"max_refund_cents": 100})
    assert reg.state("dlg-124") == PENDING
    assert not reg.tuples.active


# ---------------- rules ----------------

def test_only_a_declared_reviser_may_revise(reg):
    propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]},
            grantors=(ALICE, BOB), principal=(ALICE,), revisers=[ALICE])
    with pytest.raises(RegisterRejected) as e:
        reg.revise("dlg-124", by=BOB, call_time_conditions={"max_refund_cents": 1})
    assert e.value.reason == "not_a_reviser"
    assert any(x["type"] == "revision_rejected" for x in reg.entries())


def test_a_revision_may_not_remove_a_refusing_veto_member(reg):
    rev = propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]}, veto=(ALICE,))
    reg.act("dlg-124", ALICE, "refuse", rev)
    with pytest.raises(RegisterRejected) as e:
        reg.revise("dlg-124", by=BOB, veto=[])
    assert e.value.reason == "veto_removal_while_refusing"
    assert reg.state("dlg-124") == BLOCKED


def test_the_guard_is_reachable_through_grantors(reg):
    """Dropping the refuser from grantors would otherwise erase the block."""
    rev = propose(reg, {"op": "any_of", "grantors": [ALICE, BOB]}, veto=(ALICE,))
    reg.act("dlg-124", ALICE, "refuse", rev)
    with pytest.raises(RegisterRejected) as e:
        reg.revise("dlg-124", by=BOB, grantors=[BOB],
                   condition={"op": "any_of", "grantors": [BOB]}, veto=[ALICE])
    assert e.value.reason == "veto_outside_grantors"


def test_an_act_against_a_stale_revision_is_rejected(reg):
    rev = propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]})
    reg.revise("dlg-124", by=ALICE, call_time_conditions={"max_refund_cents": 100})
    with pytest.raises(RegisterRejected) as e:
        approve(reg, ALICE, rev)
    assert e.value.reason == "stale_revision"
    assert e.value.detail["current_revision"] == reg.grant("dlg-124")["revision"]


def test_a_condition_may_only_name_grantors(reg):
    with pytest.raises(RegisterRejected) as e:
        propose(reg, {"op": "all_of", "grantors": [ALICE, CAROL]})
    assert e.value.reason == "condition_names_non_grantor"


def test_an_approval_no_clause_names_counts_toward_nothing(reg):
    rev = propose(reg, {"op": "named", "grantor": ALICE}, grantors=(ALICE, BOB))
    assert approve(reg, BOB, rev) == PENDING
    assert any(x["type"] == "act_recorded" and x["grantor"] == BOB
               for x in reg.entries())


# ---------------- who sets the grant up ----------------

def test_only_a_declared_proposer_may_propose(reg):
    with pytest.raises(RegisterRejected) as e:
        propose(reg, {"op": "named", "grantor": ALICE},
                grantors=(ALICE,), principal=(ALICE,), by=CAROL)
    assert e.value.reason == "not_a_grant_proposer"
    assert any(x["type"] == "proposal_rejected" for x in reg.entries())
    assert "dlg-124" not in reg.grants()


def test_the_log_names_who_set_the_grant_up(reg):
    propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]}, by=BOB)
    assert reg.grant("dlg-124")["request"]["proposed_by"] == BOB


def test_revising_does_not_make_you_the_author(reg):
    propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]}, by=BOB)
    reg.revise("dlg-124", by=ALICE, call_time_conditions={"max_refund_cents": 100})
    assert reg.grant("dlg-124")["request"]["proposed_by"] == BOB


# ---------------- graph tuples are inert, not absent ----------------

def test_a_pending_grant_has_its_graph_tuples_but_no_active_delegation(reg):
    """Check 2 precedes check 4 and the first failed check is decisive, so a
    pending grant with no principal tuple would deny with
    delegation_binding_mismatch instead of delegation_revoked/pending."""
    propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]})
    assert not reg.tuples.active
    assert ("dlg-124", "principal", f"user:{ALICE}") in reg.tuples.graph
    assert ("dlg-124", "grantor", f"user:{BOB}") in reg.tuples.graph
    assert ("dlg-124", "actor", "agent:warrant-agent") in reg.tuples.graph


def test_graph_tuples_survive_the_grant_ceasing_to_be_effective(reg):
    """audit_report.py answers 'who established this' for delegations that have
    already been taken apart."""
    rev = propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]})
    approve(reg, ALICE, rev)
    approve(reg, BOB, rev)
    reg.act("dlg-124", BOB, "withdraw", rev)
    assert not reg.tuples.active
    assert ("dlg-124", "grantor", f"user:{ALICE}") in reg.tuples.graph


# ---------------- ordering and reconciliation ----------------

def test_the_log_never_says_authority_ended_before_the_tuple_went(reg):
    rev = propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]})
    approve(reg, ALICE, rev)
    approve(reg, BOB, rev)
    reg.act("dlg-124", BOB, "withdraw", rev)
    types = [e["type"] for e in reg.entries()]
    act = len(types) - 1 - types[::-1].index("act_recorded")
    assert act < types.index("tuple_deleted") < types.index("grant_ceased_to_be_effective")


def test_reconciliation_deletes_a_tuple_whose_grant_is_not_effective(reg):
    propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]})
    reg.tuples.active.add(("dlg-124", "acme"))  # crash during revocation
    assert reg.reconcile()["tuples_deleted"] == 1
    assert not reg.tuples.active


def test_reconciliation_writes_a_tuple_an_effective_grant_is_missing(reg):
    rev = propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]})
    approve(reg, ALICE, rev)
    approve(reg, BOB, rev)
    reg.tuples.active.clear()  # crash between the act landing and the write
    assert reg.reconcile()["tuples_written"] == 1
    assert reg.tuples.active


def test_state_is_recomputed_from_the_log_not_read_from_a_cache(reg):
    rev = propose(reg, {"op": "named", "grantor": ALICE},
                  grantors=(ALICE,), principal=(ALICE,))
    approve(reg, ALICE, rev)
    fresh = Register(log_path=reg.log_path, tuples=reg.tuples)
    assert fresh.state("dlg-124") == EFFECTIVE


# ---------------- closing retires the request ----------------

def refuse(reg, who, rev, gid="dlg-124"):
    return reg.act(gid, who, "refuse", rev)


def test_closing_an_effective_grant_takes_the_tuple_with_it(reg):
    """Closing is also a revocation, or a grant could be retired on paper while
    the agent kept acting under it."""
    rev = propose(reg, {"op": "named", "grantor": ALICE},
                  grantors=(ALICE,), principal=(ALICE,))
    approve(reg, ALICE, rev)
    assert reg.tuples.active
    assert reg.close("dlg-124", by=ALICE, reason="superseded") == CLOSED
    assert not reg.tuples.active
    assert reg.state("dlg-124") == CLOSED


def test_a_closed_grant_stops_competing_in_resolution(reg):
    """The collision closing exists for, in the shape it was found in.

    A grant whose veto holder refused and then left is permanently blocked, and
    the ordinary answer is to cancel it and raise a new one. Without a way to
    retire the first, both apply to the same call, nothing chooses between them,
    and every call on the account dies of ambiguous_delegation -- so the redo
    does not merely fail to help, it bricks the account.
    """
    stale = propose(reg, {"op": "any_of", "grantors": [ALICE, BOB]},
                    veto=(BOB,), grant_id="dlg-124")
    refuse(reg, BOB, stale)                      # ... and then Bob leaves
    assert reg.state("dlg-124") == BLOCKED

    redo = propose(reg, {"op": "named", "grantor": ALICE}, grantors=(ALICE,),
                   principal=(ALICE, BOB), grant_id="dlg-125")
    approve(reg, ALICE, redo, gid="dlg-125")
    assert reg.state("dlg-125") == EFFECTIVE

    args = (ALICE, "warrant-agent", "acme", "refunds:issue")
    assert reg.applicable(*args) == ["dlg-124", "dlg-125"]
    reg.close("dlg-124", by=ALICE, reason="veto holder departed")
    assert reg.applicable(*args) == ["dlg-125"]


def test_only_the_proposer_or_a_reviser_may_close(reg):
    """Held by the people who could already change what the grant says, not by
    the grantors -- otherwise a grant nobody can act on could never be got rid
    of, which is the deadlock closing exists to avoid."""
    propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]},
            principal=(ALICE,), revisers=(ALICE,), by=ALICE)
    with pytest.raises(RegisterRejected) as e:
        reg.close("dlg-124", by=BOB)
    assert e.value.reason == "not_a_closer"
    assert reg.state("dlg-124") == PENDING
    rejected = [e for e in reg.entries() if e["type"] == "close_rejected"]
    assert rejected[-1]["grantor"] == BOB


def test_nothing_happens_to_a_closed_grant(reg):
    rev = propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]})
    approve(reg, ALICE, rev)
    reg.close("dlg-124", by=ALICE)
    for call in (lambda: reg.act("dlg-124", BOB, "approve", rev),
                 lambda: reg.act("dlg-124", ALICE, "withdraw", rev),
                 lambda: reg.revise("dlg-124", ALICE, action_scope=["orders:read"]),
                 lambda: reg.close("dlg-124", by=ALICE)):
        with pytest.raises(RegisterRejected) as e:
            call()
        assert e.value.reason == "grant_closed"
    assert reg.state("dlg-124") == CLOSED
    assert not reg.tuples.active


def test_a_closed_grant_is_not_resurrected_by_reconciliation(reg):
    """Closing outranks the condition: the approvals still stand in the log, so
    a reconciliation that recomputed from them alone would write the tuple back
    and the grant would return from the dead on the next restart."""
    rev = propose(reg, {"op": "named", "grantor": ALICE},
                  grantors=(ALICE,), principal=(ALICE,))
    approve(reg, ALICE, rev)
    reg.close("dlg-124", by=ALICE)
    assert reg.reconcile()["tuples_written"] == 0
    assert not reg.tuples.active
    assert reg.state("dlg-124") == CLOSED


# ---------------- writing tuples is idempotent per tuple, not per batch ----------------

class FakeHTTP:
    """Stands in for OpenFGA's write endpoint, with its transactional shape:
    a request either applies wholly or not at all."""

    def __init__(self, already=()):
        self.already = set(already)
        self.requests = []
        self.applied = []

    def post(self, url, json=None, **kw):
        keys = json["writes"]["tuple_keys"] if "writes" in json \
            else json["deletes"]["tuple_keys"]
        self.requests.append(keys)
        clash = [k for k in keys if k["user"] in self.already]
        if clash:
            return type("R", (), {"status_code": 400,
                                  "text": "write a tuple which already exists",
                                  "raise_for_status": lambda self: None})()
        self.applied.extend(keys)
        return type("R", (), {"status_code": 200, "text": "",
                              "raise_for_status": lambda self: None})()


def test_one_tuple_already_present_does_not_suppress_the_others(monkeypatch):
    """The bug a revision hit. An OpenFGA write is transactional, so a batch
    containing one tuple that already exists fails whole -- and the "already
    there, that is fine" check then swallows the failure of every other tuple
    with it. A grant that gains a grantor would lose its whole delegation graph:
    the four surviving tuples trip the batch and nothing is written at all.
    """
    http = FakeHTTP(already={"user:rep-alice"})
    monkeypatch.setattr(register, "requests", http)
    request = register.build_request(
        proposed_by=ALICE, principal=[ALICE], grantors=[ALICE, BOB],
        actor="warrant-agent", account="acme", action_scope=["orders:read"],
        call_time_conditions={"max_refund_cents": 50000},
        condition={"op": "all_of", "grantors": [ALICE, BOB]})

    register.OpenFGATuples().write_graph("dlg-9", request)

    # one request per tuple, so the clash is contained to its own
    assert all(len(keys) == 1 for keys in http.requests)
    written = {(k["user"], k["relation"]) for k in http.applied}
    assert ("user:rep-bob", "grantor") in written
    assert ("agent:warrant-agent", "actor") in written
    assert ("delegation:dlg-9", "refund_grant") in written
    # and the one that was already there is the only one not re-applied
    assert ("user:rep-alice", "principal") not in written
