"""The invariant: no state-changing tool path reaches the order store without a
BatchCheck and an audit event.

Trivially true with three tools. It is the classic way these systems rot at
fifteen -- a new tool, a fast path for a "safe" case, an early return that skips
the audit write -- so it is asserted rather than assumed, and asserted over
every way a call can end rather than over the happy one.

Nothing here talks to Keycloak, OpenFGA or the register. The point is the shape
of the pipeline, not the answers the dependencies give, so the dependencies are
stubbed and every outcome is reachable on demand.
"""

import pytest

from server import core

CLAIMS = {
    "preferred_username": "rep-alice",
    "azp": "warrant-agent",
    "scope": "orders:read refunds:issue",
    "exp": 9_999_999_999,
    "jti": "jti-1",
    "act": {"sub": "warrant-agent"},
}

ALL_PASS = {"rep_assigned": True, "principal_bound": True, "actor_bound": True,
            "delegation_active": True, "refund_within_cap": True}


class Recorder:
    """Stands in for the three things a tool call must not skip."""

    def __init__(self, monkeypatch, checks=None, claims=CLAIMS, applicable=None):
        self.batch_checks, self.events, self.store_writes = [], [], []
        self.checks = dict(checks or ALL_PASS)

        def batch_check(**kwargs):
            self.batch_checks.append(kwargs)
            return {k: v for k, v in self.checks.items()
                    if k != "refund_within_cap"
                    or kwargs.get("amount_cents") is not None}, 1.0

        def audit(**event):
            self.events.append(event)
            return event

        def issue_refund(order_id, amount_cents):
            self.store_writes.append((order_id, amount_cents))
            return {"refund_id": "rf_test", "order_id": order_id,
                    "amount_cents": amount_cents}

        def validate(token):
            if claims is None:
                raise core.auth.AuthError("invalid_token", {}, token_valid=False)
            return dict(claims)

        monkeypatch.setattr(core.pdp, "batch_check",
                            lambda **kw: batch_check(**kw))
        monkeypatch.setattr(core, "audit", audit)
        monkeypatch.setattr(core.orders, "issue_refund", issue_refund)
        monkeypatch.setattr(core.auth, "validate", validate)
        monkeypatch.setattr(core, "REGISTER", FakeRegister(applicable))

    def assert_invariant(self):
        """Whatever happened, it is not possible to have moved money without
        a policy decision and a record of it."""
        if self.store_writes:
            assert self.batch_checks, "store written without a BatchCheck"
            allowed = [e for e in self.events if e.get("decision") == "allow"]
            assert allowed, "store written without an allow audit event"
        assert self.events, "no audit event for a completed tool call"


class FakeRegister:
    def __init__(self, applicable=None):
        self._applicable = ["dlg-1"] if applicable is None else applicable

    def applicable(self, subject, actor, account, scope):
        return list(self._applicable)

    def state(self, grant_id):
        return "effective"


def refund(rec, amount_cents=1000, order_id="1042"):
    try:
        return core.issue_refund("Bearer t", order_id=order_id,
                                 amount_cents=amount_cents)
    except core.ToolDenied as e:
        return e
    finally:
        rec.assert_invariant()


# ---------------- every way a refund can end ----------------

def test_the_allowed_path_checks_audits_and_only_then_writes(monkeypatch):
    rec = Recorder(monkeypatch)
    out = refund(rec)
    assert out["refund_id"] == "rf_test"
    assert len(rec.batch_checks) == 1
    assert rec.store_writes == [("1042", 1000)]


@pytest.mark.parametrize("failing,reason", [
    ("rep_assigned", "rep_not_assigned"),
    ("principal_bound", "delegation_binding_mismatch"),
    ("delegation_active", "delegation_revoked"),
    ("refund_within_cap", "over_refund_cap"),
])
def test_no_policy_denial_reaches_the_store(monkeypatch, failing, reason):
    rec = Recorder(monkeypatch, checks={**ALL_PASS, failing: False})
    out = refund(rec)
    assert isinstance(out, core.ToolDenied) and out.reason == reason
    assert rec.store_writes == []


def test_an_unresolved_delegation_reaches_neither_the_store_nor_an_allow(monkeypatch):
    """Resolution is a reason-override, not a gate: the BatchCheck still runs so
    check 1 can speak first, and the call still fails closed."""
    rec = Recorder(monkeypatch, applicable=[])
    out = refund(rec)
    assert isinstance(out, core.ToolDenied)
    assert out.reason == "no_applicable_delegation"
    assert len(rec.batch_checks) == 1
    assert rec.store_writes == []


def test_two_applicable_delegations_fail_closed(monkeypatch):
    rec = Recorder(monkeypatch, applicable=["dlg-1", "dlg-2"])
    out = refund(rec)
    assert isinstance(out, core.ToolDenied)
    assert out.reason == "ambiguous_delegation"
    assert rec.store_writes == []


def test_pre_pdp_failures_never_reach_the_store(monkeypatch):
    """A bad token, a missing scope, a bad amount and an unknown order all end
    before the PDP. Each still writes an audit event, and none writes money."""
    for kwargs, expected in [
        (dict(claims=None), "invalid_token"),
        (dict(claims={**CLAIMS, "scope": "orders:read"}), "missing_scope"),
    ]:
        rec = Recorder(monkeypatch, **kwargs)
        out = refund(rec)
        assert isinstance(out, core.ToolDenied) and out.reason == expected
        assert rec.store_writes == [] and rec.batch_checks == []

    rec = Recorder(monkeypatch)
    out = refund(rec, amount_cents=0)
    assert isinstance(out, core.ToolDenied) and out.reason == "invalid_amount"
    assert rec.store_writes == []

    rec = Recorder(monkeypatch)
    out = refund(rec, order_id="does-not-exist")
    assert isinstance(out, core.ToolDenied) and out.reason == "order_not_found"
    assert rec.store_writes == []


def test_the_read_paths_are_checked_and_audited_too(monkeypatch):
    rec = Recorder(monkeypatch)
    core.get_order("Bearer t", order_id="1042")
    rec.assert_invariant()
    assert len(rec.batch_checks) == 1
    # A read carries no amount, so the cap check is not in the set at all.
    assert "refund_within_cap" not in rec.events[-1]["policy_checks"]
