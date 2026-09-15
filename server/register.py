"""The grant register: multi-grantor logic, kept outside the policy decision point.

Holds grant requests and the append-only record of who said what about them,
evaluates the declared condition, and writes or deletes the single
active_delegation tuple in OpenFGA as a result. It is a function over that
record -- no model, no inference, no interpretation of what a term means. The
same record returns the same answer whether it ran a moment ago or a week ago.

The log is the source of truth; the tuple is a materialization of it. State is
recomputed from the log on every read. The entries recording a state change are
a record of what happened, never the answer to what is true now.

**Two doors.** The methods below take a grantor as a string and verify nothing;
that is the operator door, used by bootstrap to seed a grant the way it writes
account tuples directly, and every entry it writes is stamped `via: operator`.
The `*_with_token` methods are the authenticated door: they derive the author
from a Keycloak token and stamp `via: token`. The evaluator is the same either
way -- this is entirely about how an act gets in, and about the log saying which
door it came through rather than presenting both as the same kind of fact.

What the authenticated door does not do: it authenticates an act *as* a
grantor, it does not make the act provably *from* them. Anyone who can
administer the realm can reset a password and cast that grantor's vote
legitimately. Closing that needs the grantor to sign the act with a key the IdP
does not hold, which is future work rather than built here.
"""

import hashlib
import json
import os
import time
import uuid
from pathlib import Path

import requests

from .auth import validate_grantor
from .config import FGA_MODEL_ID, FGA_STORE_ID, FGA_URL, REGISTER_LOG

PENDING, EFFECTIVE, BLOCKED = "pending", "effective", "blocked"
# Terminal, and not a state the condition can produce: it says the request was
# retired, not that the answer was no.
CLOSED = "closed"
ACT_TYPES = ("approve", "refuse", "withdraw")


class RegisterRejected(Exception):
    """A rule refused the operation. Rejections are recorded, not silent."""

    def __init__(self, reason: str, **detail):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


# ---------------- the grant request ----------------

SET_FIELDS = ("principal", "grantors", "revisers", "veto")


def build_request(*, proposed_by, principal, grantors, actor, account,
                  action_scope, condition, call_time_conditions=None,
                  revisers=None, veto=None) -> dict:
    """Normalize a grant request. Sets are sorted so the revision hash is stable."""
    request = {
        # Who authored the terms. Hashed like every other field, because who set
        # a grant up is material to whether you would approve it. Carried
        # unchanged across revisions: revising does not make you the author.
        "proposed_by": proposed_by,
        "principal": sorted(set(principal)),
        "grantors": sorted(set(grantors)),
        # Defaults to the union of principal and grantors; principal has no default.
        "revisers": sorted(set(revisers) if revisers is not None
                           else set(principal) | set(grantors)),
        "veto": sorted(set(veto or ())),
        "actor": actor,
        "account": account,
        "action_scope": sorted(set(action_scope)),
        "call_time_conditions": call_time_conditions or {},
        "condition": condition,
    }
    validate_request(request)
    return request


def validate_request(request: dict) -> None:
    if not request.get("proposed_by"):
        raise RegisterRejected("no_proposer")
    grantors = set(request["grantors"])
    if not grantors:
        raise RegisterRejected("no_grantors")
    if not request["principal"]:
        raise RegisterRejected("no_principal")
    # veto is a subset of grantors, and that is load-bearing rather than
    # descriptive: it is what keeps the veto guard in revise() from being walked
    # around through grantors. Without it a reviser drops a refusing veto member
    # from grantors instead of from veto and the absolute block evaporates.
    outside = set(request["veto"]) - grantors
    if outside:
        raise RegisterRejected("veto_outside_grantors", grantors=sorted(outside))
    named = condition_grantors(request["condition"])
    outside = named - grantors
    if outside:
        raise RegisterRejected("condition_names_non_grantor", grantors=sorted(outside))


def revision_hash(request: dict) -> str:
    """A content hash over every field of the request, including veto and revisers."""
    canonical = json.dumps(request, sort_keys=True, separators=(",", ":"))
    return "rev_" + hashlib.sha256(canonical.encode()).hexdigest()[:12]


# ---------------- the condition evaluator ----------------

def condition_grantors(condition: dict) -> set[str]:
    op = condition.get("op")
    if op == "named":
        return {condition["grantor"]}
    if op in ("all_of", "any_of", "threshold"):
        return set(condition["grantors"])
    raise RegisterRejected("unknown_condition_op", op=op)


def evaluate(condition: dict, approvers: set[str]) -> bool:
    """Does this set of approvals satisfy the condition? The form means what it
    says: a refusal is not an approval, and that is the whole of its effect here.
    Absolute veto is applied by compute_state, from the declared veto list."""
    op = condition["op"]
    if op == "named":
        return condition["grantor"] in approvers
    named = set(condition["grantors"])
    if op == "all_of":
        return named <= approvers
    if op == "any_of":
        return bool(named & approvers)
    if op == "threshold":
        return len(named & approvers) >= condition["n"]
    raise RegisterRejected("unknown_condition_op", op=op)


# ---------------- standing acts, and the three cases ----------------

def standing_acts(grant: dict) -> dict[str, dict]:
    """Each author's latest act, minus withdrawals.

    Standing is not the same as present. Acts are never deleted, so the log
    holds every act its author has since taken back; an act stands only if it
    has been neither withdrawn nor superseded by a later act of the same author.
    """
    latest: dict[str, dict] = {}
    for act in grant["acts"]:
        latest[act["grantor"]] = act
    return {g: a for g, a in latest.items() if a["type"] != "withdraw"}


def counted_acts(grant: dict) -> tuple[set[str], set[str]]:
    """(approvals, refusals) that bear on the current revision.

    Evaluating a grant is not a filter to the current revision. Three cases:
      1. an act on the current revision counts normally;
      2. a standing refuse from a current veto member counts whatever revision
         it was recorded on;
      3. a refuse its author has withdrawn counts for nothing, on any revision,
         while remaining in the log.
    """
    revision = grant["revision"]
    veto = set(grant["request"]["veto"])
    approvals, refusals = set(), set()
    for grantor, act in standing_acts(grant).items():
        on_current = act["grant_revision"] == revision
        if act["type"] == "approve" and on_current:
            approvals.add(grantor)
        elif act["type"] == "refuse" and (on_current or grantor in veto):
            refusals.add(grantor)
    return approvals, refusals


def compute_state(grant: dict) -> str:
    """pending / effective / blocked, computed from the condition rather than
    read off the veto list, so the state means something under every form --
    or closed, which is not computed from anything and outranks all three.
    """
    if grant.get("closed"):
        return CLOSED
    request = grant["request"]
    condition = request["condition"]
    approvals, refusals = counted_acts(grant)
    if set(request["veto"]) & refusals:
        return BLOCKED
    if evaluate(condition, approvals):
        return EFFECTIVE
    # Blocked means no further approval can satisfy it: evaluate with every
    # refuser treated as incapable of approving.
    if not evaluate(condition, set(request["grantors"]) - refusals):
        return BLOCKED
    return PENDING


# ---------------- OpenFGA tuples ----------------

def _graph_tuples(grant_id: str, request: dict) -> list[dict]:
    """The delegation-graph tuples for a grant: who may drive it, who
    established it, which agent acts, and the call-time cap. These are not
    active_delegation -- they may exist while the grant is pending, because
    check 4 is what gates everything."""
    delegation = f"delegation:{grant_id}"
    tuples = [{"user": f"user:{p}", "relation": "principal", "object": delegation}
              for p in request["principal"]]
    tuples += [{"user": f"user:{g}", "relation": "grantor", "object": delegation}
               for g in request["grantors"]]
    tuples.append({"user": f"agent:{request['actor']}", "relation": "actor",
                   "object": delegation})
    cap = request["call_time_conditions"].get("max_refund_cents")
    if cap is not None:
        tuples.append({"user": delegation, "relation": "refund_grant",
                       "object": f"account:{request['account']}",
                       "condition": {"name": "refund_within_cap",
                                     "context": {"max_refund_cents": cap}}})
    return tuples


def _active_tuple(grant_id: str, request: dict) -> dict:
    return {"user": f"delegation:{grant_id}", "relation": "active_delegation",
            "object": f"account:{request['account']}"}


class OpenFGATuples:
    """The register's only side effect outside its own log."""

    def _write(self, key: str, tuples: list[dict]) -> None:
        """One request per tuple, deliberately.

        An OpenFGA write is transactional, so a batch containing one tuple that
        already exists (or one delete for a tuple that does not) fails whole --
        and the "that is fine, it is already in the state we wanted" check below
        would then swallow the failure of every *other* tuple in the batch along
        with it. That is how a revision loses the delegation graph: the request
        gains one grantor, the write trips on the four tuples that were already
        there, and nothing is written at all. Found by watching a walkthrough
        deny a refund it should have allowed.

        Idempotence has to be per tuple or it is a lie. `bootstrap.py` writes
        its account tuples one at a time for exactly this reason; the register
        does the same. These are not on the per-call path -- a handful of
        requests when a grant changes, never when the agent acts.
        """
        for tuple_key in tuples:
            r = requests.post(
                f"{FGA_URL}/stores/{FGA_STORE_ID}/write",
                json={key: {"tuple_keys": [tuple_key]},
                      "authorization_model_id": FGA_MODEL_ID},
            )
            if r.status_code == 400 and ("already exists" in r.text
                                         or "cannot delete" in r.text):
                continue
            r.raise_for_status()

    def write_graph(self, grant_id, request):
        self._write("writes", _graph_tuples(grant_id, request))

    def delete_graph(self, grant_id, request):
        self._write("deletes", [dict(t, condition=None) if "condition" in t else t
                                for t in _graph_tuples(grant_id, request)])

    def may_propose(self, user: str, account: str) -> bool:
        """Propose-time only, never on the per-call path: the check set does not
        change. Who may author a grant over an account is set up outside the
        register, the same way assigned_rep is."""
        r = requests.post(
            f"{FGA_URL}/stores/{FGA_STORE_ID}/check",
            json={"tuple_key": {"user": f"user:{user}",
                                "relation": "grant_proposer",
                                "object": f"account:{account}"},
                  "authorization_model_id": FGA_MODEL_ID},
        )
        r.raise_for_status()
        return bool(r.json().get("allowed"))

    def present(self, grant_id, request) -> bool:
        key = _active_tuple(grant_id, request)
        r = requests.post(
            f"{FGA_URL}/stores/{FGA_STORE_ID}/read",
            json={"tuple_key": {"user": key["user"], "relation": key["relation"],
                                "object": key["object"]}},
        )
        r.raise_for_status()
        return bool(r.json().get("tuples"))

    def write_active(self, grant_id, request) -> float:
        t0 = time.perf_counter()
        self._write("writes", [_active_tuple(grant_id, request)])
        return round((time.perf_counter() - t0) * 1000, 1)

    def delete_active(self, grant_id, request) -> float:
        t0 = time.perf_counter()
        self._write("deletes", [_active_tuple(grant_id, request)])
        return round((time.perf_counter() - t0) * 1000, 1)


# ---------------- the register ----------------

class Register:
    def __init__(self, log_path=REGISTER_LOG, tuples=None):
        self.log_path = Path(log_path)
        self.tuples = tuples if tuples is not None else OpenFGATuples()

    # -- log --

    def _append(self, via: str = "operator", **entry) -> dict:
        entry = {"entry_id": f"reg_{uuid.uuid4().hex[:12]}",
                 "ts": round(time.time(), 3), "via": via, **entry}
        with self.log_path.open("a") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())
        return entry

    def entries(self) -> list[dict]:
        if not self.log_path.exists():
            return []
        return [json.loads(line) for line in self.log_path.read_text().splitlines()
                if line.strip()]

    def grants(self) -> dict[str, dict]:
        """Replay the log. Acts survive revision: they stop satisfying anything,
        they do not stop existing."""
        grants: dict[str, dict] = {}
        for e in self.entries():
            t = e["type"]
            if t == "grant_proposed":
                grants[e["grant_id"]] = {"grant_id": e["grant_id"],
                                         "request": e["request"],
                                         "revision": e["grant_revision"],
                                         "acts": [], "closed": None}
            elif t == "revision_superseded":
                g = grants[e["grant_id"]]
                g["request"], g["revision"] = e["request"], e["grant_revision"]
            elif t == "grant_closed":
                grants[e["grant_id"]]["closed"] = {
                    "by": e["grantor"], "ts": e["ts"],
                    "reason": e.get("close_reason")}
            elif t == "act_recorded":
                grants[e["grant_id"]]["acts"].append(
                    {"grantor": e["grantor"], "type": e["act_type"],
                     "grant_revision": e["grant_revision"], "ts": e["ts"],
                     "reason": e.get("act_reason"),
                     # Entries written before the authenticated door existed
                     # came through the only door there was.
                     "via": e.get("via", "operator")})
        return grants

    def grant(self, grant_id: str) -> dict:
        grant = self.grants().get(grant_id)
        if grant is None:
            raise RegisterRejected("unknown_grant", grant_id=grant_id)
        return grant

    def applicable(self, subject: str, actor: str, account: str,
                   scope: str) -> list[str]:
        """The resource server derives which delegation applies from
        the authenticated subject, the bound actor, the account and the action,
        instead of trusting a static claim.

        Returns every grant that applies, in whatever state *except* closed.
        State is otherwise reported separately and deliberately: a pending grant
        still *applies*, and saying so is what lets a denial read "not effective
        yet" instead of "you are not bound to this delegation".

        Closed is the exception because it is not a state the request is in, it
        is the request no longer being one. Without it an abandoned grant
        competes here forever: cancel-and-redo -- the ordinary answer to a
        grantor leaving -- leaves two applicable grants and nothing to choose
        between them, which is `ambiguous_delegation` on every call to that
        account. The redo would not merely fail to help, it would brick the
        account.
        """
        out = []
        for grant_id, grant in sorted(self.grants().items()):
            r = grant["request"]
            if (subject in r["principal"] and r["actor"] == actor
                    and r["account"] == account and scope in r["action_scope"]
                    and compute_state(grant) != CLOSED):
                out.append(grant_id)
        return out

    def for_party(self, username: str) -> list[str]:
        """Every grant this person has any standing in, whatever its state.

        Distinct from `applicable`, which answers the resource server's question
        -- which delegation covers this call. This answers the surface's
        question: what am I being asked about, or what did I set up. A closed
        grant is included, because "the request I approved was retired" is
        something a person should be able to see; the state says which.
        """
        out = []
        for grant_id, grant in sorted(self.grants().items()):
            r = grant["request"]
            if username in (set(r["principal"]) | set(r["grantors"])
                            | set(r["revisers"]) | {r["proposed_by"]}):
                out.append(grant_id)
        return out

    def roles(self, grant_id: str, username: str) -> list[str]:
        """What this person is to this grant, in the order the surface should
        say it. Drives what the page offers: a grantor may act, a proposer or
        reviser may close, and someone who is only a principal may do neither
        while still having every right to read it."""
        r = self.grant(grant_id)["request"]
        held = []
        if r["proposed_by"] == username:
            held.append("proposer")
        if username in r["grantors"]:
            held.append("grantor")
        if username in r["veto"]:
            held.append("veto")
        if username in r["revisers"]:
            held.append("reviser")
        if username in r["principal"]:
            held.append("principal")
        return held

    def state(self, grant_id: str) -> str:
        """Always recomputed. The derived state in the log is a cache and never
        an answer -- between a tuple delete and the entry recording it, a cached
        read would report effective for a grant whose authority has ended."""
        return compute_state(self.grant(grant_id))

    def _reject(self, reason, grant_id, via="operator", **detail):
        self._append(via=via, type=detail.pop("entry_type", "act_rejected"),
                     grant_id=grant_id, reason=reason, **detail)
        raise RegisterRejected(reason, grant_id=grant_id, **detail)

    # -- operations --

    def propose(self, grant_id: str, by: str, via: str = "operator",
                **fields) -> str:
        if grant_id in self.grants():
            raise RegisterRejected("duplicate_grant", grant_id=grant_id)
        request = build_request(proposed_by=by, **fields)
        revision = revision_hash(request)
        # Propose is the third way a grant's terms change, after revise and
        # withdraw, and the last one to get an owner. A proposal authorizes
        # nothing by itself -- it is pending until grantors approve -- but the
        # proposer picks the shape: the grantor set, the condition, the principal,
        # and whether there is a veto list at all.
        if not self.tuples.may_propose(by, request["account"]):
            self._reject("not_a_grant_proposer", grant_id, via=via,
                         entry_type="proposal_rejected", grant_revision=revision,
                         grantor=by)
        self._append(via=via, type="grant_proposed", grant_id=grant_id,
                     grant_revision=revision, request=request, grantor=by,
                     state=PENDING)
        self.tuples.write_graph(grant_id, request)
        return self._settle(grant_id, via=via)

    def revise(self, grant_id: str, by: str, via: str = "operator",
               **changes) -> str:
        grant = self.grant(grant_id)
        self._require_open(grant, via=via, grantor=by,
                           entry_type="revision_rejected")
        old = grant["request"]
        if by not in old["revisers"]:
            self._reject("not_a_reviser", grant_id, via=via,
                         entry_type="revision_rejected",
                         grant_revision=grant["revision"], grantor=by)
        new = build_request(**{**{k: old[k] for k in old if k != "revision"},
                               **changes})
        if revision_hash(new) == grant["revision"]:
            raise RegisterRejected("no_change", grant_id=grant_id)
        # A revision may not remove a grantor from veto while that
        # grantor has a standing refuse -- otherwise an absolute block is erased
        # by dropping its holder from the list rather than by altering terms.
        refusing = {g for g, a in standing_acts(grant).items() if a["type"] == "refuse"}
        escaping = (set(old["veto"]) - set(new["veto"])) & refusing
        if escaping:
            self._reject("veto_removal_while_refusing", grant_id, via=via,
                         entry_type="revision_rejected",
                         grant_revision=grant["revision"], grantor=by,
                         grantors=sorted(escaping))
        revision = revision_hash(new)
        self._append(via=via, type="revision_superseded", grant_id=grant_id,
                     grant_revision=revision, from_revision=grant["revision"],
                     request=new, grantor=by)
        self.tuples.delete_graph(grant_id, old)
        self.tuples.write_graph(grant_id, new)
        return self._settle(grant_id, by=by, via=via)

    def act(self, grant_id: str, grantor: str, act_type: str,
            grant_revision: str, reason: str | None = None,
            via: str = "operator") -> str:
        grant = self.grant(grant_id)
        if act_type not in ACT_TYPES:
            raise RegisterRejected("unknown_act_type", act_type=act_type)
        self._require_open(grant, via=via, grantor=grantor, act_type=act_type)
        if grantor not in grant["request"]["grantors"]:
            self._reject("not_a_grantor", grant_id, via=via,
                         grant_revision=grant_revision,
                         grantor=grantor, act_type=act_type)
        if grant_revision != grant["revision"]:
            # The surface renders the terms as of the hash an act binds to; an
            # act against anything else is refused, with the current revision
            # returned so it can re-render and ask again.
            self._reject("stale_revision", grant_id, via=via,
                         grant_revision=grant_revision,
                         grantor=grantor, act_type=act_type,
                         current_revision=grant["revision"])
        self._append(via=via, type="act_recorded", grant_id=grant_id,
                     grant_revision=grant_revision, grantor=grantor,
                     act_type=act_type, act_reason=reason)
        return self._settle(grant_id, by=grantor, via=via)

    def _require_open(self, grant: dict, *, via: str, **detail) -> None:
        """Nothing happens to a closed grant. Closing retires the request; the
        answer to wanting different terms afterwards is a new request, which is
        what makes closing safe to be terminal."""
        if grant.get("closed"):
            self._reject("grant_closed", grant["grant_id"], via=via,
                         grant_revision=grant["revision"],
                         closed_by=grant["closed"]["by"], **detail)

    def close(self, grant_id: str, by: str, reason: str | None = None,
              via: str = "operator") -> str:
        """Retire the request. Distinct from `withdraw`, which retracts your own
        act: this retracts the thing acts were about.

        Held by the proposer or a declared reviser -- the people who could
        already change what the grant says -- rather than by the grantors, so
        that a grant nobody can act on any more (its veto holder has left with a
        refusal standing) can still be got rid of. That is the whole point:
        departure is an ordinary staleness problem, and the ordinary answer is
        to cancel the request and raise a new one.

        An effective grant loses its tuple on the way out, before anything else
        happens, so closing is also a revocation.
        """
        grant = self.grant(grant_id)
        self._require_open(grant, via=via, grantor=by,
                           entry_type="close_rejected")
        request = grant["request"]
        if by != request["proposed_by"] and by not in request["revisers"]:
            self._reject("not_a_closer", grant_id, via=via,
                         entry_type="close_rejected",
                         grant_revision=grant["revision"], grantor=by)
        self._append(via=via, type="grant_closed", grant_id=grant_id,
                     grant_revision=grant["revision"], grantor=by,
                     close_reason=reason, state=CLOSED)
        state = self._settle(grant_id, by=by, via=via)
        # Only once the authority is gone: the graph tuples materialize a
        # request that no longer exists, and nothing checks them for a grant
        # that can no longer resolve.
        self.tuples.delete_graph(grant_id, request)
        return state

    # -- the authenticated door --

    # The grantor is never a parameter here. It is read off a validated token
    # and passed on, so the only way to record an act as someone else is to
    # hold a token Keycloak issued to them.

    def propose_with_token(self, grant_id: str, token: str, **fields) -> str:
        return self.propose(grant_id, validate_grantor(token), via="token",
                            **fields)

    def revise_with_token(self, grant_id: str, token: str, **changes) -> str:
        return self.revise(grant_id, validate_grantor(token), via="token",
                           **changes)

    def act_with_token(self, grant_id: str, token: str, act_type: str,
                       grant_revision: str, reason: str | None = None) -> str:
        return self.act(grant_id, validate_grantor(token), act_type,
                        grant_revision, reason=reason, via="token")

    def close_with_token(self, grant_id: str, token: str,
                         reason: str | None = None) -> str:
        return self.close(grant_id, validate_grantor(token), reason=reason,
                          via="token")

    # -- the tuple follows the recomputation --

    def _settle(self, grant_id: str, by: str | None = None,
                via: str = "operator") -> str:
        """Every act recomputes the condition and the tuple follows.

        Ordering: the act is already logged and fsynced. Only then is the tuple
        touched, and only then does the log record the state change -- so it can
        never claim authority ended before it did.
        """
        grant = self.grant(grant_id)
        request, state = grant["request"], compute_state(grant)
        present = self.tuples.present(grant_id, request)
        if state == EFFECTIVE and not present:
            ms = self.tuples.write_active(grant_id, request)
            self._append(via=via, type="tuple_written", grant_id=grant_id,
                         grant_revision=grant["revision"], grantor=by,
                         tuple_write_latency_ms=ms, state=state)
            self._append(via=via, type="grant_became_effective",
                         grant_id=grant_id, grant_revision=grant["revision"],
                         grantor=by, state=state)
        elif state != EFFECTIVE and present:
            ms = self.tuples.delete_active(grant_id, request)
            self._append(via=via, type="tuple_deleted", grant_id=grant_id,
                         grant_revision=grant["revision"], grantor=by,
                         tuple_write_latency_ms=ms, state=state)
            self._append(via=via, type="grant_ceased_to_be_effective",
                         grant_id=grant_id, grant_revision=grant["revision"],
                         grantor=by, state=state)
        return state

    def reconcile(self) -> dict:
        """Startup reconciliation, both ways. The delete direction covers a crash
        during revocation; the write direction covers a crash between the act
        landing and the tuple write, which would otherwise leave a grant
        permanently effective in the log and dead in OpenFGA, safe but
        unrepairable by any future act."""
        written = deleted = 0
        for grant_id, grant in self.grants().items():
            request, state = grant["request"], compute_state(grant)
            # The graph tuples materialize the request, so reconciliation
            # restores those too: after a store is wiped and rebuilt they are
            # gone, and checks 2 and 3 would fail for a grant the log says is
            # effective. Idempotent when they are already there -- and skipped
            # for a closed grant, whose request is no longer one.
            if state != CLOSED:
                self.tuples.write_graph(grant_id, request)
            present = self.tuples.present(grant_id, request)
            if state == EFFECTIVE and not present:
                self.tuples.write_active(grant_id, request)
                written += 1
            elif state != EFFECTIVE and present:
                self.tuples.delete_active(grant_id, request)
                deleted += 1
        summary = {"grants": len(self.grants()), "tuples_written": written,
                   "tuples_deleted": deleted}
        self._append(type="startup_reconciliation", **summary)
        return summary
