"""The authoring surface.

Most of what a surface must get right is what it shows, so most of these assert
about the page rather than about the register. The one that matters more than
the rest is the stale-revision pair: a person must not be able to answer terms
they were not shown, and finding that out must re-ask rather than quietly bind
their answer to whatever the terms became.
"""

import re
import time

import pytest
from fastapi.testclient import TestClient

from server import register, register_api, surface
from server.register import BLOCKED, EFFECTIVE, PENDING, Register

from .test_register import ALICE, BOB, FakeTuples, propose

CAROL = "rep-carol"


@pytest.fixture
def app(tmp_path, monkeypatch):
    reg = Register(log_path=tmp_path / "register.log.jsonl", tuples=FakeTuples())
    monkeypatch.setattr(register_api, "REGISTER", reg)
    monkeypatch.setattr(surface, "REGISTER", reg)
    # A token is just a name here; the register's own auth is covered by
    # tests/test_register_auth.py against real signed tokens.
    monkeypatch.setattr(register, "validate_grantor", lambda t: t.removeprefix("tok-"))
    surface.SESSIONS.clear()
    from server.app import app as fastapi_app
    return TestClient(fastapi_app, raise_server_exceptions=False), reg


def sign_in(client, who):
    sid = f"sid-{who}"
    surface.SESSIONS[sid] = {"token": f"tok-{who}", "username": who,
                             "expires": time.time() + 600}
    client.cookies.set("sid", sid)
    return client


def revision_in(page: str) -> str:
    m = re.search(r'name="grant_revision" value="(rev_[0-9a-f]+)"', page)
    return m.group(1) if m else ""


# ---------------- what you can see ----------------

def test_signed_out_is_asked_to_sign_in(app):
    client, _ = app
    page = client.get("/surface").text
    assert "Sign in" in page
    assert "/surface/login" not in page or "sign" in page.lower()


def test_you_see_the_grants_that_name_you_and_not_the_others(app):
    client, reg = app
    propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]}, grant_id="dlg-1")
    propose(reg, {"op": "named", "grantor": ALICE}, grantors=(ALICE,),
            principal=(ALICE,), grant_id="dlg-2")
    page = sign_in(client, BOB).get("/surface").text
    assert "dlg-1" in page and "dlg-2" not in page


def test_the_list_says_who_is_still_being_waited_on(app):
    client, reg = app
    rev = propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]}, grant_id="dlg-1")
    reg.act("dlg-1", ALICE, "approve", rev)
    page = sign_in(client, BOB).get("/surface").text
    assert "waiting on rep-bob" in page
    assert "your answer" in page          # flagged as needing him, in the list


# ---------------- the terms, as of the hash ----------------

def test_the_page_renders_the_terms_and_binds_the_form_to_the_revision(app):
    client, reg = app
    rev = propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]}, grant_id="dlg-1")
    page = sign_in(client, BOB).get("/surface/grants/dlg-1").text
    assert revision_in(page) == rev
    assert rev in page                       # shown, not only submitted
    assert "must all approve" in page        # the condition, in words
    assert "refunds:issue" in page and "account:acme" in page


def test_a_veto_is_spelled_out_rather_than_left_in_a_field(app):
    client, reg = app
    propose(reg, {"op": "any_of", "grantors": [ALICE, BOB]}, veto=(ALICE,),
            grant_id="dlg-1")
    page = sign_in(client, ALICE).get("/surface/grants/dlg-1").text
    assert "survives a revision" in page


# ---------------- the rule the surface exists for ----------------

def test_answering_the_terms_you_were_shown_is_recorded(app):
    client, reg = app
    rev = propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]}, grant_id="dlg-1")
    sign_in(client, ALICE).post("/surface/grants/dlg-1/acts",
                                data={"act_type": "approve",
                                      "grant_revision": rev, "reason": "ok"},
                                follow_redirects=True)
    sign_in(client, BOB).post("/surface/grants/dlg-1/acts",
                              data={"act_type": "approve",
                                    "grant_revision": rev, "reason": ""},
                              follow_redirects=True)
    assert reg.state("dlg-1") == EFFECTIVE


def test_answering_terms_that_changed_under_you_is_refused_and_re_asked(app):
    """The load-bearing one. Bob opens the page, Alice revises, Bob answers the
    terms he was shown. His answer must not land, and he must be shown the new
    terms rather than told a hash did not match."""
    client, reg = app
    rev = propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]}, grant_id="dlg-1")
    bob = sign_in(client, BOB)
    page = bob.get("/surface/grants/dlg-1").text
    shown = revision_in(page)

    reg.revise("dlg-1", ALICE, call_time_conditions={"max_refund_cents": 100})
    assert reg.grant("dlg-1")["revision"] != shown

    after = bob.post("/surface/grants/dlg-1/acts",
                     data={"act_type": "approve", "grant_revision": shown,
                           "reason": ""}, follow_redirects=True).text
    assert "The terms changed while you were reading them" in after
    assert reg.state("dlg-1") == PENDING
    assert not [e for e in reg.entries() if e["type"] == "act_recorded"]
    # and the page now offers the new terms, bound to the new hash
    assert revision_in(after) == reg.grant("dlg-1")["revision"]


def test_the_form_does_not_quietly_rebind_to_the_current_revision(app):
    """An implementation that read the revision off the register at submit time
    would make the hash self-consistent and meaningless. Posting a hash that was
    never current must fail even though the grant exists and Bob may act."""
    client, reg = app
    propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]}, grant_id="dlg-1")
    after = sign_in(client, BOB).post(
        "/surface/grants/dlg-1/acts",
        data={"act_type": "approve", "grant_revision": "rev_000000000000",
              "reason": ""}, follow_redirects=True).text
    assert "terms changed" in after
    assert reg.state("dlg-1") == PENDING


# ---------------- who is offered what ----------------

def test_someone_who_is_only_a_principal_is_not_asked_to_answer(app):
    client, reg = app
    propose(reg, {"op": "named", "grantor": ALICE}, grantors=(ALICE,),
            principal=(ALICE, CAROL), revisers=(ALICE,), grant_id="dlg-1")
    page = sign_in(client, CAROL).get("/surface/grants/dlg-1").text
    assert "Your answer" not in page
    assert "not asked to answer" in page


def test_close_is_offered_to_the_proposer_and_retires_the_request(app):
    client, reg = app
    rev = propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]}, grant_id="dlg-1")
    reg.act("dlg-1", ALICE, "approve", rev)
    reg.act("dlg-1", BOB, "approve", rev)
    assert reg.state("dlg-1") == EFFECTIVE

    alice = sign_in(client, ALICE)
    assert "Retire the request" in alice.get("/surface/grants/dlg-1").text
    after = alice.post("/surface/grants/dlg-1/close",
                       data={"reason": "superseded"},
                       follow_redirects=True).text
    assert reg.state("dlg-1") == "closed"
    assert not reg.tuples.active          # closing an effective grant revokes it
    assert "Retired by rep-alice" in after
    assert "Your answer" not in after     # nothing further can happen to it


def test_close_is_not_offered_to_a_grantor_who_is_neither_proposer_nor_reviser(app):
    client, reg = app
    propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]}, principal=(ALICE,),
            revisers=(ALICE,), by=ALICE, grant_id="dlg-1")
    page = sign_in(client, BOB).get("/surface/grants/dlg-1").text
    assert "Your answer" in page and "Retire the request" not in page


def test_acting_without_a_session_does_not_reach_the_register(app):
    client, reg = app
    rev = propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]}, grant_id="dlg-1")
    client.cookies.clear()
    client.post("/surface/grants/dlg-1/acts",
                data={"act_type": "approve", "grant_revision": rev},
                follow_redirects=False)
    assert not [e for e in reg.entries() if e["type"] == "act_recorded"]


def test_a_revision_puts_everyone_back_in_the_awaited_list(app):
    """Alice approves, then the terms change. Her approval was bound to the
    superseded revision and no longer counts, so she is being waited on again
    just as Bob is. A page that listed only Bob would name the wrong person as
    the one holding it up -- and it is the person reading it who would act on
    that."""
    client, reg = app
    rev = propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]}, grant_id="dlg-1")
    reg.act("dlg-1", ALICE, "approve", rev)

    page = sign_in(client, BOB).get("/surface/grants/dlg-1").text
    assert "rep-alice" not in page.split("Not yet heard from")[1][:80]

    reg.revise("dlg-1", ALICE, call_time_conditions={"max_refund_cents": 100})
    page = client.get("/surface/grants/dlg-1").text
    awaited = page.split("Not yet heard from")[1][:120]
    assert "rep-alice" in awaited and "rep-bob" in awaited
    # her act is still in the log, shown against the revision it bound to
    assert "earlier revision" in page


def test_a_standing_veto_refusal_counts_as_having_answered(app):
    """The mirror of the above: a veto member's refusal travels across
    revisions, so revising does not put them back in the awaited list."""
    client, reg = app
    rev = propose(reg, {"op": "any_of", "grantors": [ALICE, BOB]}, veto=(ALICE,),
                  grant_id="dlg-1")
    reg.act("dlg-1", ALICE, "refuse", rev)
    reg.revise("dlg-1", ALICE, call_time_conditions={"max_refund_cents": 100})
    page = sign_in(client, BOB).get("/surface/grants/dlg-1").text
    assert reg.state("dlg-1") == BLOCKED
    awaited = page.split("Not yet heard from")[1][:120]
    assert "rep-alice" not in awaited and "rep-bob" in awaited


def test_a_retired_request_asks_nobody_for_anything(app):
    """A closed grant is not waiting on its grantors: the answer it wanted can
    no longer be given. Both the list and the page must stop asking."""
    client, reg = app
    propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]}, grant_id="dlg-1")
    reg.close("dlg-1", by=ALICE, reason="abandoned")

    listing = sign_in(client, BOB).get("/surface").text
    assert "waiting on" not in listing
    assert "your answer" not in listing

    page = client.get("/surface/grants/dlg-1").text
    assert "Not yet heard from" not in page
    assert "Silence is not assent" not in page
    assert "Retired by rep-alice" in page


# ---------------- the consequence, said plainly ----------------

def test_the_page_says_whether_the_agent_can_act_right_now(app):
    """The one sentence an onlooker cares about. Everything else on the page is
    machinery for deciding it, and a demo that needs a terminal to answer it has
    buried the point."""
    client, reg = app
    rev = propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]}, grant_id="dlg-1")
    bob = sign_in(client, BOB)

    page = bob.get("/surface/grants/dlg-1").text
    assert "The agent cannot act under this grant." in page
    assert "Not everyone the condition names has agreed yet" in page

    reg.act("dlg-1", ALICE, "approve", rev)
    reg.act("dlg-1", BOB, "approve", rev)
    page = bob.get("/surface/grants/dlg-1").text
    assert "The agent can act under this grant right now." in page
    assert "refunds:issue" in page and "account:acme" in page


def test_blocked_and_retired_say_which_they_are(app):
    client, reg = app
    rev = propose(reg, {"op": "any_of", "grantors": [ALICE, BOB]}, veto=(ALICE,),
                  grant_id="dlg-1")
    reg.act("dlg-1", ALICE, "refuse", rev)
    page = sign_in(client, BOB).get("/surface/grants/dlg-1").text
    assert reg.state("dlg-1") == BLOCKED
    assert "Someone answered, and the answer was no" in page

    reg.close("dlg-1", by=ALICE)
    page = client.get("/surface/grants/dlg-1").text
    assert "The request was retired" in page


def test_where_it_stands_marks_each_person_on_the_current_terms(app):
    client, reg = app
    rev = propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]}, grant_id="dlg-1")
    reg.act("dlg-1", ALICE, "approve", rev, reason="fine by me")
    page = sign_in(client, BOB).get("/surface/grants/dlg-1").text
    stands = page.split("Where it stands")[1].split("The terms")[0]
    assert "rep-alice" in stands and "approved" in stands and "fine by me" in stands
    assert "not yet answered" in stands

    reg.revise("dlg-1", ALICE, call_time_conditions={"max_refund_cents": 100})
    stands = client.get("/surface/grants/dlg-1").text.split("Where it stands")[1]
    # Alice did answer, and it no longer counts. Both halves have to be said, or
    # the page is either lying or accusing her of silence.
    assert "answered an earlier revision, which no longer counts" in stands


def test_the_surface_cannot_act_as_the_agent(app):
    """It holds a person's token and never the agent's. The call history is read
    off the log; there is no route here that issues a refund."""
    client, _ = app
    routes = [r.path for r in client.app.routes if hasattr(r, "path")]
    assert not [r for r in routes if r.startswith("/surface") and "tool" in r]
