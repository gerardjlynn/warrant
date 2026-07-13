"""JWT validation: signature, iss, exp, aud, sub, and act.sub == azp.

Failures raise AuthError with an audit reason and whatever claims could be
read without trusting them (for the audit event only, never for authorization).
"""

import jwt
from jwt import PyJWKClient

from .config import AGENT_CLIENT_ID, AUDIENCE, ISSUER, JWKS_URL

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
    act_sub = (claims.get("act") or {}).get("sub")
    if not act_sub:
        raise AuthError("missing_act_claim", claims, token_valid=True)
    if act_sub != claims.get("azp") or act_sub != AGENT_CLIENT_ID:
        raise AuthError("actor_binding_mismatch", claims, token_valid=True)
    if not claims.get("delegation_id"):
        raise AuthError("missing_delegation_id", claims, token_valid=True)
    if not claims.get("preferred_username"):
        raise AuthError("missing_subject_username", claims, token_valid=True)
    return claims
