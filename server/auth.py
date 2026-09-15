"""JWT validation, for two different kinds of caller.

`validate` is the per-call path: the agent's delegated token, checked for
signature, iss, exp, aud, sub, and act.sub == azp.

`validate_grantor` is the register's authenticated door: a person's own login,
which carries no `act` claim and no `delegation_id` and so cannot go through
`validate` at all. It returns a username and nothing else, because that is the
only thing the register takes from it.

Failures raise AuthError with an audit reason and whatever claims could be
read without trusting them (for the audit event only, never for authorization).
"""

import jwt
from jwt import PyJWKClient

from .config import (AGENT_CLIENT_ID, AUDIENCE, GRANTOR_CLIENT_ID, ISSUER,
                     JWKS_URL, REGISTER_AUDIENCE)

_jwks = PyJWKClient(JWKS_URL)


class AuthError(Exception):
    def __init__(self, reason: str, claims: dict, token_valid: bool):
        super().__init__(reason)
        self.reason = reason
        self.claims = claims  # unverified; audit use only
        self.token_valid = token_valid


def _unverified(token: str) -> dict:
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except jwt.InvalidTokenError:
        return {}


def validate(token: str) -> dict:
    if not token:
        raise AuthError("missing_token", {}, token_valid=False)
    try:
        key = _jwks.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=ISSUER,
            options={"require": ["exp", "sub", "aud", "iss"]},
        )
    except jwt.ExpiredSignatureError:
        raise AuthError("token_expired", _unverified(token), token_valid=False)
    except jwt.InvalidAudienceError:
        raise AuthError("invalid_audience", _unverified(token), token_valid=True)
    except (jwt.InvalidTokenError, jwt.PyJWKClientError, ValueError):
        raise AuthError("invalid_token", _unverified(token), token_valid=False)

    # Actor attribution must be tied to the authenticated OAuth client,
    # not just a mapper-generated string: act.sub == azp == warrant-agent.
    act = claims.get("act") or {}
    act_sub = act.get("sub")
    if not act_sub:
        raise AuthError("missing_act_claim", claims, token_valid=True)
    if act_sub != claims.get("azp") or act_sub != AGENT_CLIENT_ID:
        raise AuthError("actor_binding_mismatch", claims, token_valid=True)
    # RFC 8693 4.1 nests `act` inside `act` to express a delegation chain: the
    # current actor outermost, the one it acts for beneath. Refuse it. There is
    # no agent-to-agent delegation here -- every agent that acts is an `actor`
    # on a grant people approved -- and the refusal has to be in code, because
    # the alternative is not that the chain is rejected but that it is ignored:
    # the outer act.sub satisfies the binding above, and the audit event records
    # `actor: azp`, one name. A chain would authorize normally and log short.
    if act.get("act"):
        raise AuthError("act_chain_not_accepted", claims, token_valid=True)
    # No delegation_id requirement. The resource server resolves the applicable
    # delegation per call by reading the register, and a static claim can only
    # ever be right for one grant -- it was the thing hiding collisions between
    # grants that apply to the same call. A token that does carry one is still
    # honoured: resolution uses it when it applies and denies on a mismatch.
    if not claims.get("preferred_username"):
        raise AuthError("missing_subject_username", claims, token_valid=True)
    return claims


class GrantorAuthError(Exception):
    """The act could not be attributed to an authenticated person."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def bearer(header: str | None) -> str:
    """The token out of an Authorization header, or "" if there isn't one."""
    if not header:
        return ""
    scheme, _, token = header.partition(" ")
    return token.strip() if scheme.lower() == "bearer" else ""


def validate_grantor(token: str) -> str:
    """Authenticate the author of a register act. Returns their username.

    The register never takes a grantor from a request body, so this is the only
    way an act acquires an author on the authenticated door. Three refusals
    beyond the ordinary ones, each closing a way to cast someone else's vote:

    - a token carrying `act` is a delegated token, and an act is a person
      acting for themselves. Accepting one would let the agent cast the
      approval that authorizes the agent.
    - a token whose `azp` is not the grantor client was minted for something
      else. The rep login that feeds token exchange is `azp: rep-cli` and is
      held by the agent for the length of the exchange; the audience check
      already refuses it, and this refuses it again for a different reason.
    - a token without `preferred_username` cannot name a grantor. `sub` is an
      opaque UUID and the register's grantor sets are usernames.
    """
    if not token:
        raise GrantorAuthError("missing_token")
    try:
        key = _jwks.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=REGISTER_AUDIENCE,
            issuer=ISSUER,
            options={"require": ["exp", "sub", "aud", "iss"]},
        )
    except jwt.ExpiredSignatureError:
        raise GrantorAuthError("token_expired")
    except jwt.InvalidAudienceError:
        raise GrantorAuthError("wrong_audience")
    except (jwt.InvalidTokenError, jwt.PyJWKClientError, ValueError):
        raise GrantorAuthError("invalid_token")

    if claims.get("act"):
        raise GrantorAuthError("delegated_token_not_accepted")
    if claims.get("azp") != GRANTOR_CLIENT_ID:
        raise GrantorAuthError("wrong_client")
    username = claims.get("preferred_username")
    if not username:
        raise GrantorAuthError("missing_grantor_username")
    return username
