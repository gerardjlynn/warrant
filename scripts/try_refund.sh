#!/usr/bin/env bash
# One refund, as the agent, with the decision that governed it. For watching a
# grant's state change land on a real call.
set -euo pipefail
cd "$(dirname "$0")/.."
source .env.generated

REP=$(curl -sf "$KC_URL/realms/$KC_REALM/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=rep-cli -d username=rep-alice \
  -d password=alice | .venv/bin/python -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
TOKEN=$(curl -sf "$KC_URL/realms/$KC_REALM/protocol/openid-connect/token" \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d client_id="$KC_AGENT_CLIENT_ID" -d client_secret="$KC_AGENT_CLIENT_SECRET" \
  -d subject_token="$REP" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d audience=orders-api | .venv/bin/python -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

echo "agent attempts: issue_refund order 1042, \$20"
curl -s "http://localhost:8090/tools/issue_refund" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"order_id":"1042","amount_cents":2000}' | sed 's/^/  /'
echo
.venv/bin/python - <<'EOF'
import json
from pathlib import Path
e = [json.loads(l) for l in
     Path("audit.log.jsonl").read_text().splitlines() if l.strip()][-1]
print("the decision that governed it:")
for k in ("decision", "reason", "grant_state_at_decision", "delegation_id",
          "decisive_check", "token_valid_at_decision"):
    if e.get(k) is not None:
        print(f"  {k:26} {e[k]}")
EOF
