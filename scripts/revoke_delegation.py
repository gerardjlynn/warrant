#!/usr/bin/env python3
"""Kill switch: rep-alice withdraws her approval, through the register's
authenticated door.

The agent's client stays registered and its JWT stays cryptographically valid;
only the delegation grant dies. The next tool call is denied (delegation_revoked)
because check 4 gates everything. Rerun `make bootstrap` to restore the grant.

The tuple is not deleted directly. The register is the only writer of it,
and a delete behind the register's back would leave its log saying the
grant is effective while the authority was already gone -- which turns the log
from a record into a claim.

Nor is the grantor a string this script chooses. It logs in as rep-alice against
`grantor-cli` and hands the register the token; the register reads the name off
it. What the log records is therefore an act by someone who could authenticate
as Alice, not an act by whoever could run this file. The limit is worth stating:
that is authentication *as* Alice, not proof the act came *from* her -- anyone
who can administer the realm can reset her password and withdraw on her behalf.
"""

import os
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from server.config import ENV, GRANTOR_CLIENT_ID  # noqa: E402
from server.register import EFFECTIVE, Register  # noqa: E402

GRANTOR = "rep-alice"
PASSWORD = os.environ.get("WARRANT_GRANTOR_PASSWORD", "alice")


def grantor_token(username: str, password: str) -> str:
    r = requests.post(
        f"{ENV['KC_URL']}/realms/{ENV['KC_REALM']}/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": GRANTOR_CLIENT_ID,
              "username": username, "password": password},
    )
    r.raise_for_status()
    return r.json()["access_token"]


reg = Register()

# Which grant, resolved the way the resource server resolves it:
# from the subject, the actor, the account and the action, rather than from a
# name this script carries. A retired grant is not a candidate, so a rerun
# after cancel-and-redo finds the live one.
applicable = reg.applicable("rep-alice", ENV["KC_AGENT_CLIENT_ID"], "acme",
                            "refunds:issue")
if len(applicable) != 1:
    sys.exit(f"expected exactly one applicable delegation, got {applicable}")
grant_id = applicable[0]

if reg.state(grant_id) != EFFECTIVE:
    print(f"{grant_id} was already revoked (state: {reg.state(grant_id)})")
    sys.exit(0)

revision = reg.grant(grant_id)["revision"]
token = grantor_token(GRANTOR, PASSWORD)
state = reg.act_with_token(grant_id, token, "withdraw", revision,
                           reason="kill switch")

entries = reg.entries()
act = next(e for e in reversed(entries) if e["type"] == "act_recorded")
latency = next((e["tuple_write_latency_ms"] for e in reversed(entries)
                if e["type"] == "tuple_deleted"), None)
print(f"revoked {grant_id}: {act['grantor']} withdrew their approval on "
      f"{revision} (via={act['via']}, authenticated by {GRANTOR_CLIENT_ID}); "
      f"grant is now {state}, active_delegation tuple deleted in {latency}ms")
