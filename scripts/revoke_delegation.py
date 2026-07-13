#!/usr/bin/env python3
"""Kill switch: delete the active_delegation tuple in OpenFGA.

The agent's client stays registered and its JWT stays cryptographically valid;
only the delegation grant dies. The next tool call is denied (delegation_revoked)
because check 4 gates everything. Rerun `make bootstrap` to restore the grant.
"""

import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
ENV = dict(line.split("=", 1)
           for line in (ROOT / ".env.generated").read_text().splitlines()
           if "=" in line)

tuple_key = {
    "user": f"delegation:{ENV['DELEGATION_ID']}",
    "relation": "active_delegation",
    "object": "account:acme",
}

r = requests.post(
    f"{ENV['FGA_URL']}/stores/{ENV['FGA_STORE_ID']}/write",
    json={"deletes": {"tuple_keys": [tuple_key]},
          "authorization_model_id": ENV["FGA_MODEL_ID"]},
)
if r.status_code == 400 and "cannot delete" in r.text:
    print(f"{ENV['DELEGATION_ID']} was already revoked")
    sys.exit(0)
r.raise_for_status()
print(f"revoked {ENV['DELEGATION_ID']}: deleted "
      f"[{tuple_key['user']} {tuple_key['relation']} {tuple_key['object']}]")
