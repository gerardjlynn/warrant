#!/usr/bin/env python3
"""Put the system into the state worth looking at, then get out of the way.

Not a test -- the two-person flow is covered in tests/test_surface.py and was
run end to end headlessly. This exists because the interesting state is fiddly
to reach by hand: bootstrap seeds a grant one person can satisfy, and the point
of v3.2 only shows when a grant needs two.

So this revises the seeded grant to require both reps and leaves it pending,
which is the moment before the thing you want to watch. Everything a person
does from here happens in a browser, through the authenticated door.
"""

import socket
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from server.config import ENV, GRANTOR_CLIENT_ID  # noqa: E402
from server.register import PENDING, Register  # noqa: E402

ALICE, BOB = "rep-alice", "rep-bob"


def token(username: str, password: str) -> str:
    r = requests.post(
        f"{ENV['KC_URL']}/realms/{ENV['KC_REALM']}/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": GRANTOR_CLIENT_ID,
              "username": username, "password": password})
    r.raise_for_status()
    return r.json()["access_token"]


def port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.4)
        return s.connect_ex(("127.0.0.1", port)) == 0


reg = Register()
applicable = reg.applicable(ALICE, ENV["KC_AGENT_CLIENT_ID"], "acme",
                            "refunds:issue")
if len(applicable) != 1:
    sys.exit(f"expected one applicable delegation on acme, got {applicable}. "
             "Run `make bootstrap` first.")
grant_id = applicable[0]

grant = reg.grant(grant_id)
if grant["request"]["condition"] != {"op": "all_of", "grantors": [ALICE, BOB]}:
    # Alice's own act, through the authenticated door, so the log attributes the
    # change to her rather than to whoever ran this file.
    reg.revise_with_token(
        grant_id, token(ALICE, "alice"),
        grantors=[ALICE, BOB],
        condition={"op": "all_of", "grantors": [ALICE, BOB]})
    print(f"  {ALICE} revised {grant_id}: it now needs both reps")

state = reg.state(grant_id)
revision = reg.grant(grant_id)["revision"]
awaiting = sorted(set(reg.grant(grant_id)["request"]["grantors"]))

print(f"""
{grant_id} is {state} on {revision}.

Alice's earlier approval was bound to the revision before this one, so it has
stopped counting: both of them are being waited on. Nothing expires, nothing
times out, and nothing happens until they answer.

Walk it through:

  1. {'The surface is up.' if port_open(8090) else 'Run `make surface` in another terminal.'}
     Open http://localhost:8090/surface
  2. Sign in as rep-bob / bob. Read {grant_id}: the terms, the condition in
     words, and the revision the answer will bind to. Approve it.
     -> still pending. One of two is not agreement.
  3. Run `make try-refund`. Denied, delegation_revoked,
     grant_state_at_decision=pending.
  4. Sign out, sign in as rep-alice / alice, approve.
     -> effective. The register writes the tuple on her act.
  5. `make try-refund` again. Allowed.
  6. Back in the surface as either of them, withdraw.
     -> pending again, and `make try-refund` is denied while the agent's JWT is
     still perfectly valid. Two people made it; one unmade it.

Worth trying at step 2: open the grant as Bob, and before approving, have Alice
revise it in another browser. Bob's answer is refused and he is shown the new
terms -- he cannot approve something he was not looking at.
""")
