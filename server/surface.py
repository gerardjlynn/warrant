"""The authoring surface: where a person reads a grant and answers it.

The register has always been reachable over HTTP; what was missing was anything
a human would use. This is that, and it is deliberately small, because most of
what it must get right is a matter of what it shows rather than what it does.

**The load-bearing rule.** Every act carries the revision hash, and the page
renders the terms *as of that hash*. Server-side binding alone is not enough:
if a person can approve while looking at terms other than the ones their act
will bind to, the apparatus is ceremony. So the hash the page rendered rides in
the form, the register refuses anything else, and a refusal re-renders the new
terms and asks again rather than quietly re-binding the answer.

**No prose reaches the register.** Terms are rendered from the structured
fields; nothing typed here becomes part of a grant. The one free-text field is
the reason on an act, which the register stores against the act and never
interprets.

Identity comes from the person's own token, obtained through the authorization
code flow with PKCE -- a public client must not be handed a password, and a
surface that collected one would be pretending. The token is held server-side
against a session cookie and never reaches the page.
"""

import base64
import hashlib
import html
import json
import os
import secrets
import time
import urllib.parse
from pathlib import Path

import requests
from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from .auth import GrantorAuthError, validate_grantor
from .config import AUDIT_LOG, GRANTOR_CLIENT_ID, ISSUER
from .register import (EFFECTIVE, RegisterRejected, compute_state,
                       counted_acts, standing_acts)
from .register_api import REGISTER

router = APIRouter(prefix="/surface", tags=["surface"])
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

SURFACE_URL = "http://localhost:8090"
REDIRECT_URI = f"{SURFACE_URL}/surface/callback"
AUTHORIZE = f"{ISSUER}/protocol/openid-connect/auth"
TOKEN = f"{ISSUER}/protocol/openid-connect/token"

# Sessions live in memory, like the order store: this is one process serving a
# demonstration. The access token stays here and never goes into a cookie, so
# the browser holds an opaque id and nothing else.
SESSIONS: dict[str, dict] = {}
PENDING_LOGINS: dict[str, str] = {}


def _session(request: Request) -> dict | None:
    s = SESSIONS.get(request.cookies.get("sid", ""))
    if s and s["expires"] < time.time():
        SESSIONS.pop(request.cookies.get("sid", ""), None)
        return None
    return s


# ---------------- login ----------------

@router.get("/login")
def login():
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    state = secrets.token_urlsafe(16)
    PENDING_LOGINS[state] = verifier
    query = urllib.parse.urlencode({
        "client_id": GRANTOR_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    return RedirectResponse(f"{AUTHORIZE}?{query}", status_code=303)


@router.get("/callback")
def callback(code: str = "", state: str = ""):
    verifier = PENDING_LOGINS.pop(state, None)
    if not code or verifier is None:
        return _page("Sign-in did not complete",
                     "<p>Start again from <a href='/surface'>the grant list</a>.</p>")
    r = requests.post(TOKEN, data={
        "grant_type": "authorization_code", "code": code,
        "client_id": GRANTOR_CLIENT_ID, "redirect_uri": REDIRECT_URI,
        "code_verifier": verifier})
    if r.status_code != 200:
        return _page("Sign-in was refused",
                     f"<pre>{html.escape(r.text[:400])}</pre>")
    token = r.json()["access_token"]
    try:
        username = validate_grantor(token)
    except GrantorAuthError as e:
        # The same validation the register applies. A token this surface cannot
        # attribute is one the register would refuse anyway, and finding that
        # out here rather than on the first act is the kinder failure.
        return _page("That sign-in cannot act on a grant",
                     f"<p class=deny>{html.escape(e.reason)}</p>")
    sid = secrets.token_urlsafe(24)
    SESSIONS[sid] = {"token": token, "username": username,
                     "expires": time.time() + 600}
    response = RedirectResponse("/surface", status_code=303)
    response.set_cookie("sid", sid, httponly=True, samesite="lax")
    return response


@router.get("/logout")
def logout(request: Request):
    SESSIONS.pop(request.cookies.get("sid", ""), None)
    response = RedirectResponse("/surface", status_code=303)
    response.delete_cookie("sid")
    return response


# ---------------- rendering the terms ----------------

def condition_text(condition: dict) -> str:
    """The declared condition in ordinary language.

    One direction only. Structured fields are primary and this renders them for
    a person to read; nothing a person types is ever parsed back into a
    condition. The register never sees a word of it.
    """
    op = condition["op"]
    if op == "named":
        return f"{condition['grantor']} must approve"
    people = list(condition["grantors"])
    if op == "all_of":
        return " and ".join(people) + " must all approve"
    if op == "any_of":
        return "any one of " + ", ".join(people) + " must approve"
    if op == "threshold":
        return f"at least {condition['n']} of " + ", ".join(people) + " must approve"
    return op


def _money(cents: int) -> str:
    return f"${cents / 100:,.2f}"


def _agreement(grant, revision: str) -> list[dict]:
    """Every grantor and where they stand on *these* terms.

    Read off counted_acts, so the page agrees with the evaluator by
    construction. An act bound to a superseded revision shows as not having
    answered, which is what it is -- with the act still named, because "I did
    answer" is the first thing that person will think.
    """
    approvals, refusals = counted_acts(grant)
    standing = standing_acts(grant)
    rows = []
    for who in sorted(grant["request"]["grantors"]):
        act = standing.get(who)
        if who in approvals:
            status, mark = "approved", "yes"
        elif who in refusals:
            status, mark = "refused", "no"
        else:
            status, mark = "not yet answered", "waiting"
        rows.append({
            "who": who, "status": status, "mark": mark,
            "veto": who in grant["request"]["veto"],
            "reason": act["reason"] if act else None,
            # Named so nobody reads "not yet answered" as "said nothing ever".
            "superseded": bool(act and mark == "waiting"),
        })
    return rows


def _recent_decisions(grant_id: str, limit: int = 4) -> list[dict]:
    """What the agent's calls against this grant actually got.

    Read-only, out of the call log. The surface deliberately cannot *make* such
    a call: it holds a person's token, never the agent's, and a page that could
    act as the agent would undo the separation the whole design rests on.
    """
    if not AUDIT_LOG.exists():
        return []
    rows = []
    for line in AUDIT_LOG.read_text().splitlines():
        if not line.strip():
            continue
        e = json.loads(line)
        if e.get("delegation_id") == grant_id and e.get("policy_checks"):
            rows.append({"action": e["action"], "decision": e["decision"],
                         "reason": e["reason"],
                         "state": e.get("grant_state_at_decision"),
                         "ts": e["ts"]})
    return rows[-limit:][::-1]


def _grant_view(grant_id: str, username: str) -> dict:
    grant = REGISTER.grant(grant_id)
    request = grant["request"]
    standing = standing_acts(grant)
    revision = grant["revision"]
    roles = REGISTER.roles(grant_id, username)
    cap = request["call_time_conditions"].get("max_refund_cents")
    return {
        "grant_id": grant_id,
        "request": request,
        "revision": revision,
        "state": compute_state(grant),
        "closed": grant.get("closed"),
        "roles": roles,
        "cap": _money(cap) if cap is not None else None,
        "condition_text": condition_text(request["condition"]),
        "standing": [
            # `stale` is the veto exception made visible: a refusal recorded on
            # an earlier revision still counts if its author holds the veto, and
            # a page that showed it without saying so would be confusing.
            {**act, "grantor": who,
             "stale": act["grant_revision"] != revision}
            for who, act in sorted(standing.items())
        ],
        # Who has not answered these terms -- see register_api._view. An act
        # bound to a superseded revision leaves its author still awaited. Empty
        # once the request is retired: nobody is being waited on for an answer
        # that can no longer be given, and a page saying otherwise asks someone
        # for something they cannot do.
        "awaiting": ([] if grant.get("closed")
                     else sorted(set(request["grantors"])
                                 - set().union(*counted_acts(grant)))),
        "can_act": "grantor" in roles and not grant.get("closed"),
        "has_standing": username in standing,
        "can_close": (("proposer" in roles or "reviser" in roles)
                      and not grant.get("closed")),
        "agreement": _agreement(grant, revision),
        "decisions": _recent_decisions(grant_id),
        # The consequence, in the terms an onlooker cares about. Everything else
        # on the page is machinery for deciding this one sentence.
        "authority": compute_state(grant) == EFFECTIVE,
        "authority_scope": ", ".join(request["action_scope"]),
    }


def _page(heading: str, body: str, request: Request = None, deny: bool = False):
    return templates.TemplateResponse(
        request, "message.html",
        {"heading": heading, "body": body, "deny": deny, "username": None})


# ---------------- the pages ----------------

@router.get("")
@router.get("/")
def index(request: Request):
    session = _session(request)
    if session is None:
        return templates.TemplateResponse(
            request, "message.html",
            {"heading": "warrant", "username": None, "deny": False,
             "body": "Sign in to read and answer the grants that name you."})
    username = session["username"]
    rows = []
    for grant_id in REGISTER.for_party(username):
        view = _grant_view(grant_id, username)
        rows.append({"grant_id": grant_id, "state": view["state"],
                     "account": view["request"]["account"],
                     "condition_text": view["condition_text"],
                     "awaiting": view["awaiting"], "roles": view["roles"],
                     "authority": view["authority"],
                     # Not "may you act" but "is anything waiting on you" --
                     # the only reason to open a grant before anyone asks.
                     "needs_you": view["can_act"] and username in view["awaiting"]})
    return templates.TemplateResponse(
        request, "grants.html", {"grants": rows, "username": username})


@router.get("/grants/{grant_id}")
def grant(grant_id: str, request: Request, notice: str = "", deny: str = ""):
    session = _session(request)
    if session is None:
        return RedirectResponse("/surface", status_code=303)
    try:
        view = _grant_view(grant_id, session["username"])
    except RegisterRejected as e:
        return _page("No such grant", e.reason, request, deny=True)
    return templates.TemplateResponse(
        request, "grant.html",
        {**view, "username": session["username"],
         "notice": notice, "notice_deny": bool(deny)})


# ---------------- acting ----------------

def _back(grant_id: str, notice: str = "", deny: bool = False):
    query = urllib.parse.urlencode(
        {k: v for k, v in {"notice": notice, "deny": "1" if deny else ""}.items() if v})
    return RedirectResponse(f"/surface/grants/{grant_id}?{query}", status_code=303)


@router.post("/grants/{grant_id}/acts")
def act(grant_id: str, request: Request, act_type: str = Form(...),
        grant_revision: str = Form(...), reason: str = Form("")):
    """The act carries the revision the page rendered, not the current one.

    That is the whole point of the field. Reading it off the register here would
    make the form self-consistent and meaningless -- it would bind the answer to
    whatever the terms had become, which is the thing the hash exists to stop.
    """
    session = _session(request)
    if session is None:
        return RedirectResponse("/surface", status_code=303)
    try:
        state = REGISTER.act_with_token(grant_id, session["token"], act_type,
                                        grant_revision, reason=reason or None)
    except RegisterRejected as e:
        if e.reason == "stale_revision":
            return _back(grant_id, deny=True, notice=(
                "The terms changed while you were reading them, so your answer "
                "was not recorded. These are the new terms — please read them "
                "and answer again."))
        return _back(grant_id, e.reason, deny=True)
    except GrantorAuthError as e:
        return _page("Your sign-in expired", e.reason, request, deny=True)
    return _back(grant_id, f"Recorded. The grant is now {state}.")


@router.post("/grants/{grant_id}/close")
def close(grant_id: str, request: Request, reason: str = Form("")):
    session = _session(request)
    if session is None:
        return RedirectResponse("/surface", status_code=303)
    try:
        REGISTER.close_with_token(grant_id, session["token"],
                                  reason=reason or None)
    except RegisterRejected as e:
        return _back(grant_id, e.reason, deny=True)
    except GrantorAuthError as e:
        return _page("Your sign-in expired", e.reason, request, deny=True)
    return _back(grant_id, "The request is retired.")
