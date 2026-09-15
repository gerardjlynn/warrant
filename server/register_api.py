"""The register's HTTP surface: the door people use.

Identity is derived from the caller's own Keycloak token and never from the
request body, so `grantor`, `proposed_by` and the reviser are the authenticated
subject in every case. The evaluator underneath is untouched -- this is entirely
about how an act gets in.

Mounted on the orders-api service because the register already lives inside
it. It is a separate audience from the tool endpoints all the same: a
delegated token is good for `/tools/*` and refused here, and a grantor token
is good here and refused by `auth.validate`.
"""

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from .auth import GrantorAuthError, bearer, validate_grantor
from .register import (Register, RegisterRejected, compute_state,
                       counted_acts, standing_acts)

router = APIRouter(prefix="/register", tags=["register"])
REGISTER = Register()

# Which rejections are refusals of authority, which are conflicts with the
# record, and which are malformed requests. Anything unlisted is malformed.
STATUS = {
    "unknown_grant": 404,
    "duplicate_grant": 409,
    "stale_revision": 409,
    "no_change": 409,
    "not_a_grantor": 403,
    "not_a_reviser": 403,
    "not_a_grant_proposer": 403,
    "not_a_closer": 403,
    "grant_closed": 409,
    "already_closed": 409,
    "veto_removal_while_refusing": 403,
}


class ProposeIn(BaseModel):
    grant_id: str
    principal: list[str]
    grantors: list[str]
    actor: str
    account: str
    action_scope: list[str]
    condition: dict
    call_time_conditions: dict | None = None
    revisers: list[str] | None = None
    veto: list[str] | None = None


class ReviseIn(BaseModel):
    """Partial: only the fields present are changed, the rest carry over."""
    principal: list[str] | None = None
    grantors: list[str] | None = None
    actor: str | None = None
    account: str | None = None
    action_scope: list[str] | None = None
    condition: dict | None = None
    call_time_conditions: dict | None = None
    revisers: list[str] | None = None
    veto: list[str] | None = None


class ActIn(BaseModel):
    act_type: str
    grant_revision: str
    reason: str | None = None


def _token(authorization: str | None) -> str:
    token = bearer(authorization)
    if not token:
        raise HTTPException(401, {"reason": "missing_token"})
    return token


def _run(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except GrantorAuthError as e:
        raise HTTPException(401, {"reason": e.reason})
    except RegisterRejected as e:
        # `stale_revision` carries the current revision, which is what lets the
        # surface re-render the terms and ask again.
        raise HTTPException(STATUS.get(e.reason, 400),
                            {"reason": e.reason, **e.detail})


def _view(grant_id: str) -> dict:
    grant = REGISTER.grant(grant_id)
    standing = standing_acts(grant)
    return {
        "grant_id": grant_id,
        "revision": grant["revision"],
        "request": grant["request"],
        "state": compute_state(grant),
        "standing_acts": {g: {"type": a["type"], "grant_revision":
                              a["grant_revision"], "via": a["via"]}
                          for g, a in sorted(standing.items())},
        # Who has not answered *these* terms. Not "who has no act in the log":
        # an approval bound to a superseded revision no longer counts, so its
        # author is still being waited on, and saying otherwise would name the
        # wrong person as the one holding a grant up. Computed from the same
        # function the evaluator uses, so the page and the decision cannot
        # disagree.
        "awaiting": ([] if grant.get("closed")
                     else sorted(set(grant["request"]["grantors"])
                                 - set().union(*counted_acts(grant)))),
        "closed": grant.get("closed"),
    }


@router.post("/grants")
def propose(body: ProposeIn, authorization: str | None = Header(None)):
    fields = body.model_dump()
    grant_id = fields.pop("grant_id")
    state = _run(REGISTER.propose_with_token, grant_id, _token(authorization),
                 **fields)
    return {"state": state, **_view(grant_id)}


@router.post("/grants/{grant_id}/revisions")
def revise(grant_id: str, body: ReviseIn,
           authorization: str | None = Header(None)):
    changes = body.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(400, {"reason": "no_change", "grant_id": grant_id})
    state = _run(REGISTER.revise_with_token, grant_id, _token(authorization),
                 **changes)
    return {"state": state, **_view(grant_id)}


@router.post("/grants/{grant_id}/acts")
def act(grant_id: str, body: ActIn, authorization: str | None = Header(None)):
    state = _run(REGISTER.act_with_token, grant_id, _token(authorization),
                 body.act_type, body.grant_revision, reason=body.reason)
    return {"state": state, **_view(grant_id)}


class CloseIn(BaseModel):
    reason: str | None = None


@router.post("/grants/{grant_id}/close")
def close(grant_id: str, body: CloseIn,
          authorization: str | None = Header(None)):
    """Retire the request. Not an act: it is held by the proposer or a declared
    reviser rather than by the grantors, which is what lets a grant nobody can
    act on any more be got rid of."""
    state = _run(REGISTER.close_with_token, grant_id, _token(authorization),
                 reason=body.reason)
    return {"state": state, **_view(grant_id)}


@router.get("/grants/{grant_id}")
def read(grant_id: str, authorization: str | None = Header(None)):
    """Read behind the same door. The terms a person approves are rendered from
    here, so the read is as much part of the act as the write is."""
    _run(validate_grantor, _token(authorization))
    return _run(_view, grant_id)
