"""The register's authenticated door.

`Register.act` takes a grantor as a string and verifies nothing, so a register
reachable without a door would let anyone record any act as anyone. These
tests cover the door that closes it, and each one catches a
plausible wrong implementation:

- taking the grantor from the request body when a token is also present;
- accepting any Keycloak token, which lets the agent replay the rep login it
  already holds for token exchange and approve its own authority;
- accepting a delegated token, same hole by the other route;
- not recording which door an act came through, which makes a seeded operator
  act and an authenticated one indistinguishable in the log.
"""

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from server import auth, register_api
from server.auth import GrantorAuthError, validate_grantor
from server.config import GRANTOR_CLIENT_ID, ISSUER, REGISTER_AUDIENCE
from server.register import EFFECTIVE, PENDING, Register, RegisterRejected

from .test_register import ALICE, BOB, FakeTuples, approve, propose

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeJWKS:
    """The realm's signing key, without the realm."""

    def get_signing_key_from_jwt(self, token):
        return type("K", (), {"key": KEY.public_key()})()


@pytest.fixture(autouse=True)
def jwks(monkeypatch):
    monkeypatch.setattr(auth, "_jwks", FakeJWKS())


def token(username=ALICE, *, aud=REGISTER_AUDIENCE, azp=GRANTOR_CLIENT_ID,
          act=None, exp=None, iss=ISSUER, **claims):
    payload = {"sub": f"uuid-{username}", "preferred_username": username,
               "aud": aud, "azp": azp, "iss": iss,
               "exp": exp if exp is not None else int(time.time()) + 300,
               "iat": int(time.time()), **claims}
    if act is not None:
        payload["act"] = act
    return jwt.encode(payload, KEY, algorithm="RS256")


# ---------------- validate_grantor ----------------

def test_returns_the_username_from_the_token():
    assert validate_grantor(token(BOB)) == BOB


def test_the_rep_login_that_feeds_token_exchange_is_refused():
    """The agent holds this token for the length of the exchange. If the
    register accepted it, the agent could cast the approval that authorizes
    the agent -- so it is refused on audience and again on client."""
    rep_login = token(ALICE, aud="warrant-agent", azp="rep-cli")
    with pytest.raises(GrantorAuthError) as e:
        validate_grantor(rep_login)
    assert e.value.reason == "wrong_audience"


def test_a_token_for_the_right_audience_but_the_wrong_client_is_refused():
    with pytest.raises(GrantorAuthError) as e:
        validate_grantor(token(ALICE, azp="rep-cli"))
    assert e.value.reason == "wrong_client"


def test_a_delegated_token_is_refused():
    """An act is a person acting for themselves. Delegating the casting of an
    approval to the agent it authorizes is the whole confused deputy."""
    delegated = token(ALICE, act={"sub": "warrant-agent"})
    with pytest.raises(GrantorAuthError) as e:
        validate_grantor(delegated)
    assert e.value.reason == "delegated_token_not_accepted"


def test_an_expired_token_is_refused():
    with pytest.raises(GrantorAuthError) as e:
        validate_grantor(token(ALICE, exp=int(time.time()) - 10))
    assert e.value.reason == "token_expired"


def test_a_token_from_another_issuer_is_refused():
    with pytest.raises(GrantorAuthError) as e:
        validate_grantor(token(ALICE, iss="http://evil/realms/warrant"))
    assert e.value.reason == "invalid_token"


def test_a_token_without_a_username_cannot_name_a_grantor():
    """sub is an opaque UUID; the register's grantor sets are usernames."""
    t = token(ALICE)
    payload = jwt.decode(t, options={"verify_signature": False})
    del payload["preferred_username"]
    with pytest.raises(GrantorAuthError) as e:
        validate_grantor(jwt.encode(payload, KEY, algorithm="RS256"))
    assert e.value.reason == "missing_grantor_username"


def test_missing_and_malformed_tokens():
    for bad, reason in [("", "missing_token"), ("not-a-jwt", "invalid_token")]:
        with pytest.raises(GrantorAuthError) as e:
            validate_grantor(bad)
        assert e.value.reason == reason


# ---------------- the register ----------------

@pytest.fixture
def reg(tmp_path):
    return Register(log_path=tmp_path / "register.log.jsonl", tuples=FakeTuples())


def entries_of(reg, type_):
    return [e for e in reg.entries() if e["type"] == type_]


def test_the_act_is_attributed_to_the_token_not_to_the_caller(reg):
    rev = propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]})
    reg.act_with_token("dlg-124", token(ALICE), "approve", rev)
    reg.act_with_token("dlg-124", token(BOB), "approve", rev)
    assert reg.state("dlg-124") == EFFECTIVE
    assert [e["grantor"] for e in entries_of(reg, "act_recorded")] == [ALICE, BOB]


def test_bob_cannot_record_an_act_as_alice(reg):
    """There is no parameter to try: `act_with_token` has no grantor argument,
    so the only way to act as Alice is to hold a token Keycloak issued to her.
    Bob's token on a grant Bob is not a grantor of is rejected as Bob."""
    rev = propose(reg, {"op": "named", "grantor": ALICE}, grantors=(ALICE,),
                  principal=(ALICE,))
    with pytest.raises(RegisterRejected) as e:
        reg.act_with_token("dlg-124", token(BOB), "approve", rev)
    assert e.value.reason == "not_a_grantor"
    rejected = entries_of(reg, "act_rejected")[-1]
    assert rejected["grantor"] == BOB and rejected["via"] == "token"
    assert reg.state("dlg-124") == PENDING


def test_the_log_says_which_door_each_act_came_through(reg):
    """A seeded operator act and an authenticated one are different kinds of
    fact, and the log that is the product has to distinguish them."""
    rev = propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]})
    approve(reg, ALICE, rev)                                  # operator door
    reg.act_with_token("dlg-124", token(BOB), "approve", rev)  # authenticated
    assert [(e["grantor"], e["via"]) for e in entries_of(reg, "act_recorded")] \
        == [(ALICE, "operator"), (BOB, "token")]
    # And it survives the replay, so a surface can show it.
    standing = {a["grantor"]: a["via"] for a in reg.grant("dlg-124")["acts"]}
    assert standing == {ALICE: "operator", BOB: "token"}


def test_proposing_and_revising_go_through_the_same_door(reg):
    reg.propose_with_token(
        "dlg-125", token(ALICE), principal=[ALICE], grantors=[ALICE, BOB],
        actor="warrant-agent", account="acme", action_scope=["orders:read"],
        condition={"op": "all_of", "grantors": [ALICE, BOB]})
    proposed = entries_of(reg, "grant_proposed")[-1]
    assert proposed["request"]["proposed_by"] == ALICE
    assert proposed["via"] == "token"

    reg.revise_with_token("dlg-125", token(BOB), action_scope=["orders:read",
                                                               "refunds:issue"])
    revised = entries_of(reg, "revision_superseded")[-1]
    assert revised["grantor"] == BOB and revised["via"] == "token"


# ---------------- the HTTP surface ----------------

@pytest.fixture
def client(tmp_path, monkeypatch):
    reg = Register(log_path=tmp_path / "register.log.jsonl", tuples=FakeTuples())
    monkeypatch.setattr(register_api, "REGISTER", reg)
    from server.app import app
    return TestClient(app, raise_server_exceptions=False), reg


def test_http_act_takes_its_grantor_from_the_bearer_token(client):
    api, reg = client
    rev = propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]})
    for who in (ALICE, BOB):
        r = api.post("/register/grants/dlg-124/acts",
                     json={"act_type": "approve", "grant_revision": rev},
                     headers={"Authorization": f"Bearer {token(who)}"})
        assert r.status_code == 200, r.text
    body = r.json()
    assert body["state"] == EFFECTIVE
    assert body["awaiting"] == []
    assert set(body["standing_acts"]) == {ALICE, BOB}


def test_http_reports_who_has_not_been_heard_from(client):
    """The demo needs the register to name Bob, not just say pending."""
    api, reg = client
    rev = propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]})
    r = api.post("/register/grants/dlg-124/acts",
                 json={"act_type": "approve", "grant_revision": rev},
                 headers={"Authorization": f"Bearer {token(ALICE)}"})
    assert r.json()["state"] == PENDING
    assert r.json()["awaiting"] == [BOB]


def test_http_without_a_token_records_nothing(client):
    api, reg = client
    rev = propose(reg, {"op": "named", "grantor": ALICE}, grantors=(ALICE,),
                  principal=(ALICE,))
    before = len(reg.entries())
    r = api.post("/register/grants/dlg-124/acts",
                 json={"act_type": "approve", "grant_revision": rev})
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "missing_token"
    assert len(reg.entries()) == before
    assert reg.state("dlg-124") == PENDING


def test_http_stale_revision_returns_the_current_one(client):
    """The surface has to be able to re-render the terms and ask again."""
    api, reg = client
    propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]})
    r = api.post("/register/grants/dlg-124/acts",
                 json={"act_type": "approve", "grant_revision": "rev_stale"},
                 headers={"Authorization": f"Bearer {token(ALICE)}"})
    assert r.status_code == 409
    assert r.json()["detail"]["reason"] == "stale_revision"
    assert r.json()["detail"]["current_revision"] == reg.grant("dlg-124")["revision"]


def test_http_read_renders_the_terms_as_of_the_current_hash(client):
    api, reg = client
    rev = propose(reg, {"op": "all_of", "grantors": [ALICE, BOB]})
    r = api.get("/register/grants/dlg-124",
                headers={"Authorization": f"Bearer {token(ALICE)}"})
    assert r.status_code == 200
    assert r.json()["revision"] == rev
    assert r.json()["request"]["grantors"] == [ALICE, BOB]
