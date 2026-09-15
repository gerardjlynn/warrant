#!/usr/bin/env bash
# Token check: obtain the rep token, exchange it, and decode the result.
# Success = the decoded payload shows sub=rep-alice, azp=warrant-agent,
# act.sub=warrant-agent, aud=orders-api and restricted scopes -- and *no*
# delegation_id, because the resource server resolves which
# delegation applies per call by reading the register. The last check does that
# resolution and asserts exactly one grant applies, which is what the token
# claim used to assert statically and could only ever get right for one grant.
set -euo pipefail
cd "$(dirname "$0")/.."
source .env.generated

echo "== 1. rep-alice authenticates via rep-cli (aud includes warrant-agent) =="
REP_TOKEN=$(curl -sf "$KC_URL/realms/$KC_REALM/protocol/openid-connect/token" \
  -d grant_type=password \
  -d client_id=rep-cli \
  -d username=rep-alice \
  -d password=alice | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
echo "   got rep token"

echo "== 2. warrant-agent exchanges it (RFC 8693, audience=orders-api) =="
API_TOKEN=$(curl -sf "$KC_URL/realms/$KC_REALM/protocol/openid-connect/token" \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d client_id="$KC_AGENT_CLIENT_ID" \
  -d client_secret="$KC_AGENT_CLIENT_SECRET" \
  -d subject_token="$REP_TOKEN" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d audience=orders-api | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
echo "   got exchanged token"

echo "== 3. decoded payload =="
.venv/bin/python - "$API_TOKEN" <<'EOF'
import base64, json, sys
from server.register import Register
payload = sys.argv[1].split(".")[1]
payload += "=" * (-len(payload) % 4)
claims = json.loads(base64.urlsafe_b64decode(payload))
print(json.dumps(claims, indent=2))

applicable = Register().applicable(
    claims.get("preferred_username"), claims.get("azp"), "acme", "refunds:issue")
print(f"\n== delegations the register resolves for this token on account:acme ==\n"
      f"   {applicable}")
checks = {
    "sub is a user (rep)": "sub" in claims,
    "azp == warrant-agent": claims.get("azp") == "warrant-agent",
    "act.sub == warrant-agent": claims.get("act", {}).get("sub") == "warrant-agent",
    "act.sub == azp": claims.get("act", {}).get("sub") == claims.get("azp"),
    "aud includes orders-api": "orders-api" in (claims.get("aud") if isinstance(claims.get("aud"), list) else [claims.get("aud")]),
    "no static delegation_id claim": "delegation_id" not in claims,
    "exactly one delegation resolves": len(applicable) == 1,
    "scope has orders:read": "orders:read" in claims.get("scope", ""),
    "scope has refunds:issue": "refunds:issue" in claims.get("scope", ""),
}
print("\n== token checks ==")
ok = True
for name, passed in checks.items():
    print(("  PASS  " if passed else "  FAIL  ") + name)
    ok = ok and passed
sys.exit(0 if ok else 1)
EOF
