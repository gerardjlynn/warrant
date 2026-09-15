"""Load the bootstrap-generated environment."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load() -> dict:
    env = {}
    for line in (ROOT / ".env.generated").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            env[k] = v
    return env


ENV = _load()

KC_URL = ENV["KC_URL"]
KC_REALM = ENV["KC_REALM"]
FGA_URL = ENV["FGA_URL"]
FGA_STORE_ID = ENV["FGA_STORE_ID"]
FGA_MODEL_ID = ENV["FGA_MODEL_ID"]

ISSUER = f"{KC_URL}/realms/{KC_REALM}"
JWKS_URL = f"{ISSUER}/protocol/openid-connect/certs"
AUDIENCE = "orders-api"
AGENT_CLIENT_ID = ENV["KC_AGENT_CLIENT_ID"]

# The register's authenticated door. A grantor's act is authenticated against a
# token minted for the register alone: a separate audience from orders-api, and
# a separate client from the one the agent holds a rep token for, so neither the
# delegated token nor the rep login used in token exchange can be replayed to
# cast that rep's approval.
REGISTER_AUDIENCE = "grant-register"
GRANTOR_CLIENT_ID = "grantor-cli"

AUDIT_LOG = ROOT / "audit.log.jsonl"
REGISTER_LOG = ROOT / "register.log.jsonl"
