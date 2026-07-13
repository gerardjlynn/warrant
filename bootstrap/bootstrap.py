#!/usr/bin/env python3
"""warrant bootstrap: phases A-D from the build spec, plus OpenFGA model + tuples.

A. Obtain a one-use initial access token (only if the agent client doesn't exist).
B. Register the agent client via Keycloak's client registration service.
C. Apply Keycloak-specific config via Admin REST: protocol mappers (act,
   delegation_id, audience), scopes, and enable Standard Token Exchange V2 on
   the confidential warrant-agent requester client.
D. Persist credentials to .env.generated. Idempotent on rerun.

Then: create the OpenFGA store, write the delegation-graph authorization model,
and write the dlg-123 tuples.
"""

import json
import sys
import time
from pathlib import Path

import requests

KC = "http://localhost:8080"
REALM = "warrant"
FGA = "http://localhost:8081"

AGENT_CLIENT_ID = "warrant-agent"
DELEGATION_ID = "dlg-123"
MAX_REFUND_CENTS = 50000

ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT / ".env.generated"


def wait_for(url: str, name: str, timeout: int = 120) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=2)
            if r.status_code < 500:
                print(f"  {name} is up")
                return
        except requests.ConnectionError:
            pass
        time.sleep(2)
    sys.exit(f"FATAL: {name} not reachable at {url} after {timeout}s")


def admin_token() -> str:
    r = requests.post(
        f"{KC}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": "admin",
            "password": "admin",
        },
    )
    r.raise_for_status()
    return r.json()["access_token"]


def admin(method: str, path: str, token: str, **kwargs) -> requests.Response:
    r = requests.request(
        method,
        f"{KC}/admin/realms/{REALM}{path}",
        headers={"Authorization": f"Bearer {token}"},
        **kwargs,
    )
    r.raise_for_status()
    return r


def find_client(token: str, client_id: str):
    r = admin("GET", f"/clients?clientId={client_id}", token)
    clients = r.json()
    return clients[0] if clients else None


def phase_ab_register(token: str) -> dict:
    """Phases A+B. Idempotent: look up by clientId first; only obtain and
    consume a new initial access token when the client does not already exist."""
    existing = find_client(token, AGENT_CLIENT_ID)
    if existing:
        print(f"  {AGENT_CLIENT_ID} already registered (id={existing['id']})")
        return existing

    # Phase A: one-use initial access token
    r = admin("POST", "/clients-initial-access", token,
              json={"count": 1, "expiration": 300})
    iat = r.json()["token"]
    print("  obtained one-use initial access token")

    # Phase B: register via the client registration service.
    # (Keycloak's default endpoint accepts a full representation so the
    # clientId is stable; the pure OIDC DCR endpoint would generate one.)
    r = requests.post(
        f"{KC}/realms/{REALM}/clients-registrations/default",
        headers={"Authorization": f"Bearer {iat}",
                 "Content-Type": "application/json"},
        json={
            "clientId": AGENT_CLIENT_ID,
            "name": "Warrant Agent",
            "publicClient": False,
            "standardFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": True,
        },
    )
    r.raise_for_status()
    print(f"  registered {AGENT_CLIENT_ID} via client registration service")
    return find_client(token, AGENT_CLIENT_ID)


def phase_c_configure(token: str, client: dict) -> str:
    """Phase C: mappers, scopes, Standard Token Exchange V2. Returns secret."""
    uuid = client["id"]

    # Enable Standard Token Exchange V2 on the confidential requester client
    # (NOT the legacy fine-grained token-exchange permission model).
    rep = admin("GET", f"/clients/{uuid}", token).json()
    attrs = rep.get("attributes", {})
    attrs["standard.token.exchange.enabled"] = "true"
    rep["attributes"] = attrs
    admin("PUT", f"/clients/{uuid}", token, json=rep)
    print("  enabled Standard Token Exchange V2 on warrant-agent")

    # Protocol mappers: the requester client's mappers shape the exchanged token.
    existing = {m["name"] for m in
                admin("GET", f"/clients/{uuid}/protocol-mappers/models", token).json()}
    mappers = [
        {
            "name": "act-claim",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-hardcoded-claim-mapper",
            "config": {
                "claim.name": "act",
                "claim.value": json.dumps({"sub": AGENT_CLIENT_ID}),
                "jsonType.label": "JSON",
                "access.token.claim": "true",
                "id.token.claim": "false",
                "userinfo.token.claim": "false",
            },
        },
        {
            "name": "delegation-id",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-hardcoded-claim-mapper",
            "config": {
                "claim.name": "delegation_id",
                "claim.value": DELEGATION_ID,
                "jsonType.label": "String",
                "access.token.claim": "true",
                "id.token.claim": "false",
                "userinfo.token.claim": "false",
            },
        },
        {
            "name": "aud-orders-api",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {
                "included.custom.audience": "orders-api",
                "access.token.claim": "true",
                "id.token.claim": "false",
            },
        },
        {
            # The PDP checks user:<username>; sub alone is an opaque UUID.
            "name": "rep-username",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-attribute-mapper",
            "config": {
                "user.attribute": "username",
                "claim.name": "preferred_username",
                "jsonType.label": "String",
                "access.token.claim": "true",
                "id.token.claim": "false",
                "userinfo.token.claim": "false",
            },
        },
    ]
    for m in mappers:
        if m["name"] not in existing:
            admin("POST", f"/clients/{uuid}/protocol-mappers/models", token, json=m)
            print(f"  added mapper {m['name']}")

    # Restricted scopes: assign orders:read + refunds:issue as default scopes.
    all_scopes = {s["name"]: s["id"]
                  for s in admin("GET", "/client-scopes", token).json()}
    for scope in ("orders:read", "refunds:issue"):
        admin("PUT", f"/clients/{uuid}/default-client-scopes/{all_scopes[scope]}",
              token)
    print("  assigned scopes orders:read, refunds:issue")

    secret = admin("GET", f"/clients/{uuid}/client-secret", token).json()["value"]
    return secret


# ---------------- OpenFGA ----------------

FGA_MODEL = {
    "schema_version": "1.1",
    "type_definitions": [
        {"type": "user"},
        {"type": "agent"},
        {
            "type": "delegation",
            "relations": {"principal": {"this": {}}, "actor": {"this": {}}},
            "metadata": {"relations": {
                "principal": {"directly_related_user_types": [{"type": "user"}]},
                "actor": {"directly_related_user_types": [{"type": "agent"}]},
            }},
        },
        {
            "type": "account",
            "relations": {
                "assigned_rep": {"this": {}},
                "active_delegation": {"this": {}},
                "refund_grant": {"this": {}},
            },
            "metadata": {"relations": {
                "assigned_rep": {"directly_related_user_types": [{"type": "user"}]},
                "active_delegation": {"directly_related_user_types": [{"type": "delegation"}]},
                "refund_grant": {"directly_related_user_types": [
                    {"type": "delegation", "condition": "refund_within_cap"}]},
            }},
        },
    ],
    "conditions": {
        "refund_within_cap": {
            "name": "refund_within_cap",
            "expression": "amount_cents <= max_refund_cents",
            "parameters": {
                "amount_cents": {"type_name": "TYPE_NAME_INT"},
                "max_refund_cents": {"type_name": "TYPE_NAME_INT"},
            },
        }
    },
}

FGA_TUPLES = [
    {"user": "user:rep-alice", "relation": "assigned_rep", "object": "account:acme"},
    {"user": "user:rep-alice", "relation": "principal",
     "object": f"delegation:{DELEGATION_ID}"},
    {"user": f"agent:{AGENT_CLIENT_ID}", "relation": "actor",
     "object": f"delegation:{DELEGATION_ID}"},
    {"user": f"delegation:{DELEGATION_ID}", "relation": "active_delegation",
     "object": "account:acme"},
    {"user": f"delegation:{DELEGATION_ID}", "relation": "refund_grant",
     "object": "account:acme",
     "condition": {"name": "refund_within_cap",
                   "context": {"max_refund_cents": MAX_REFUND_CENTS}}},
]


def setup_openfga() -> tuple[str, str]:
    stores = requests.get(f"{FGA}/stores").json().get("stores", [])
    store = next((s for s in stores if s["name"] == "warrant"), None)
    if store:
        store_id = store["id"]
        print(f"  store exists (id={store_id})")
    else:
        r = requests.post(f"{FGA}/stores", json={"name": "warrant"})
        r.raise_for_status()
        store_id = r.json()["id"]
        print(f"  created store (id={store_id})")

    r = requests.post(f"{FGA}/stores/{store_id}/authorization-models",
                      json=FGA_MODEL)
    r.raise_for_status()
    model_id = r.json()["authorization_model_id"]
    print(f"  wrote authorization model (id={model_id})")

    # One at a time so a rerun restores any tuple deleted by revoke_delegation.py
    # (a batch write is transactional and would fail on the surviving duplicates).
    written = 0
    for t in FGA_TUPLES:
        r = requests.post(
            f"{FGA}/stores/{store_id}/write",
            json={"writes": {"tuple_keys": [t]},
                  "authorization_model_id": model_id},
        )
        if r.status_code == 400 and "already exists" in r.text:
            continue
        r.raise_for_status()
        written += 1
    print(f"  wrote {written} tuples, {len(FGA_TUPLES) - written} already present "
          f"(delegation {DELEGATION_ID})")
    return store_id, model_id


def phase_d_persist(secret: str, store_id: str, model_id: str) -> None:
    ENV_FILE.write_text(
        f"KC_URL={KC}\n"
        f"KC_REALM={REALM}\n"
        f"KC_AGENT_CLIENT_ID={AGENT_CLIENT_ID}\n"
        f"KC_AGENT_CLIENT_SECRET={secret}\n"
        f"FGA_URL={FGA}\n"
        f"FGA_STORE_ID={store_id}\n"
        f"FGA_MODEL_ID={model_id}\n"
        f"DELEGATION_ID={DELEGATION_ID}\n"
    )
    print(f"  wrote {ENV_FILE.name}")


def main() -> None:
    print("waiting for services...")
    wait_for(f"{KC}/realms/{REALM}/.well-known/openid-configuration", "keycloak")
    wait_for(f"{FGA}/healthz", "openfga")

    print("phases A+B: agent registration")
    token = admin_token()
    client = phase_ab_register(token)

    print("phase C: keycloak configuration")
    secret = phase_c_configure(token, client)

    print("openfga: model + delegation tuples")
    store_id, model_id = setup_openfga()

    print("phase D: persist credentials")
    phase_d_persist(secret, store_id, model_id)
    print("bootstrap complete")


if __name__ == "__main__":
    main()
