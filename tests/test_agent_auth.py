"""The agent's own door: the delegated token the resource server validates.

`validate_grantor` had tests from the day it existed, because the register's
door was built to stop acts being recorded under a claimed name. `validate`
did not -- the tool pipeline stubs it -- so the binding the whole demo rests
on was asserted nowhere.

The case these exist for is the nested `act`. RFC 8693 4.1 expresses a
delegation chain by nesting `act` inside `act`, current actor outermost. The
design forbids agent-to-agent delegation, and a rule with no enforcement point is
a sentence in a document: without the refusal, a chained token does not fail,
it *succeeds quietly*. The outer `act.sub` satisfies the binding, the PDP is
asked about one agent, and the audit event records `actor: azp` -- one name for
a call that arrived through two. Denial would be safe; passing and logging
short is the failure worth a test.
"""

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from server import auth
from server.auth import AuthError, validate
from server.config import AGENT_CLIENT_ID, AUDIENCE, ISSUER

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeJWKS:
    def get_signing_key_from_jwt(self, token):
        return type("K", (), {"key": KEY.public_key()})()


@pytest.fixture(autouse=True)
def jwks(monkeypatch):
    monkeypatch.setattr(auth, "_jwks", FakeJWKS())


def token(*, sub="rep-alice", azp=AGENT_CLIENT_ID, act=..., aud=AUDIENCE,
          scope="orders:read refunds:issue", **claims):
    if act is ...:
        act = {"sub": AGENT_CLIENT_ID}
    payload = {"sub": f"uuid-{sub}", "preferred_username": sub,
               "aud": aud, "azp": azp, "iss": ISSUER, "scope": scope,
               "exp": int(time.time()) + 300, "iat": int(time.time()),
               **claims}
    if act is not None:
        payload["act"] = act
    return jwt.encode(payload, KEY, algorithm="RS256")


def reason(tok):
    with pytest.raises(AuthError) as e:
        validate(tok)
    return e.value.reason


def test_ordinary_delegated_token_passes():
    claims = validate(token())
    assert claims["preferred_username"] == "rep-alice"
    assert claims["act"]["sub"] == claims["azp"] == AGENT_CLIENT_ID


def test_act_chain_is_refused():
    assert reason(token(act={"sub": AGENT_CLIENT_ID,
                             "act": {"sub": "other-agent"}})) \
        == "act_chain_not_accepted"


def test_the_chain_would_otherwise_have_passed():
    """Why the check has to be its own refusal rather than a consequence.

    Strip the nested `act` from the same token and it validates. So the
    implementation that reads `act["sub"]` and stops does not deny a chained
    token -- it authorizes one and records a single actor.
    """
    chained = {"sub": AGENT_CLIENT_ID, "act": {"sub": "other-agent"}}
    assert reason(token(act=chained)) == "act_chain_not_accepted"
    claims = validate(token(act={"sub": chained["sub"]}))
    assert claims["azp"] == AGENT_CLIENT_ID


def test_deeply_nested_chain_is_refused():
    assert reason(token(act={"sub": AGENT_CLIENT_ID,
                             "act": {"sub": "b", "act": {"sub": "c"}}})) \
        == "act_chain_not_accepted"


def test_binding_and_missing_act_still_answer_first():
    """The new refusal must not reorder the two that were already there."""
    assert reason(token(act=None)) == "missing_act_claim"
    assert reason(token(act={"sub": "other-agent",
                             "act": {"sub": "third"}})) \
        == "actor_binding_mismatch"


def test_a_sibling_claim_inside_act_is_not_a_chain():
    """Only a nested `act` is a chain. Refusing anything else would reject
    ordinary tokens the moment a mapper adds a field."""
    claims = validate(token(act={"sub": AGENT_CLIENT_ID, "iss": ISSUER}))
    assert claims["act"]["iss"] == ISSUER
