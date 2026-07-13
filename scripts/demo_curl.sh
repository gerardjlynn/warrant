#!/usr/bin/env bash
# Saturday PM curl test: the four demo outcomes plus a pre-PDP failure,
# no agent involved. Server must be running (make server).
set -euo pipefail
cd "$(dirname "$0")/.."
source .env.generated
API=http://localhost:8090

get_api_token() {
  local rep_token
  rep_token=$(curl -sf "$KC_URL/realms/$KC_REALM/protocol/openid-connect/token" \
    -d grant_type=password -d client_id=rep-cli \
    -d username=rep-alice -d password=alice \
    | .venv/bin/python -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
  curl -sf "$KC_URL/realms/$KC_REALM/protocol/openid-connect/token" \
    -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
    -d client_id="$KC_AGENT_CLIENT_ID" -d client_secret="$KC_AGENT_CLIENT_SECRET" \
    -d subject_token="$rep_token" \
    -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
    -d audience=orders-api \
    | .venv/bin/python -c 'import sys,json; print(json.load(sys.stdin)["access_token"])'
}

call() { # call <label> <path> <json-body> <token>
  echo
  echo "== $1 =="
  curl -s -w "\n   HTTP %{http_code}\n" "$API/tools/$2" \
    -H "Authorization: Bearer $4" -H "Content-Type: application/json" -d "$3"
}

TOKEN=$(get_api_token)
echo "got delegated token"

call "1. get_order 1042 (expect allow)"                 get_order    '{"order_id":"1042"}' "$TOKEN"
call "2. refund 1042 for \$40 (expect allow)"           issue_refund '{"order_id":"1042","amount_cents":4000}' "$TOKEN"
call "3. refund 2077 for \$900 (expect over_refund_cap)" issue_refund '{"order_id":"2077","amount_cents":90000}' "$TOKEN"
call "4. list_orders globex (expect rep_not_assigned)"  list_orders  '{"account_id":"globex"}' "$TOKEN"
call "5. garbage token (expect pre-PDP invalid_token)"  get_order    '{"order_id":"1042"}' "not-a-jwt"

echo
echo "== 6. kill switch: revoke dlg-123 mid-session =="
.venv/bin/python scripts/revoke_delegation.py

call "7. refund 1042 for \$10, same token (expect delegation_revoked)" \
  issue_refund '{"order_id":"1042","amount_cents":1000}' "$TOKEN"

echo
echo "== last audit event (token_valid_at_decision should be true) =="
tail -1 audit.log.jsonl | .venv/bin/python -m json.tool
