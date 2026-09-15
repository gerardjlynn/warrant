#!/usr/bin/env python3
"""warrant bootstrap: Keycloak in phases A-D, OpenFGA, then the seed grant in E.

A. Obtain a one-use initial access token (only if the agent client doesn't exist).
B. Register the agent client via Keycloak's client registration service.
C. Apply Keycloak-specific config via Admin REST: protocol mappers (act,
   audience, username), scopes, and enable Standard Token Exchange V2 on the
   confidential warrant-agent requester client. No delegation_id mapper: the
   resource server resolves the applicable delegation per call.
D. Persist credentials to .env.generated. Idempotent on rerun.

Then: create the OpenFGA store, write the delegation-graph authorization model,
and write the account-level tuples.

Also: the two clients behind the register's authenticated door, so an approval
act is attributed to a token Keycloak issued rather than to a claimed name.

E. Seed the dlg-123 grant through the register. The register is the only writer
   of any tuple naming a delegation it owns, so the v2.1 grant is proposed
   and approved rather than written directly. The v2.1 outcomes still pass,
   but they now run through a seeded named() grant --
   that is a real cost, not a free one.
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
# The register's authenticated door: an audience to bind grantor tokens to, and
# the public client grantors log in through. Kept apart from rep-cli on purpose
# -- see ensure_register_clients.
REGISTER_AUDIENCE = "grant-register"
GRANTOR_CLIENT_ID = "grantor-cli"
SURFACE_URL = "http://localhost:8090"
DELEGATION_ID = "dlg-123"
MAX_REFUND_CENTS = 50000

ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT / ".env.generated"
# Run as `python bootstrap/bootstrap.py`, so the repo root is not on the path;
# phase E imports the register from it.
sys.path.insert(0, str(ROOT))


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

    # v2.1 stamped every token with delegation_id=dlg-123 from a hardcoded
    # mapper. Multi-grantor makes each grant its own delegation, so a static
    # claim can only ever be right for one of them -- and while it was there it
    # disambiguated resolution and hid collisions between grants. Removed
    # rather than left in place, and removed from a realm that already has it.
    for m in admin("GET", f"/clients/{uuid}/protocol-mappers/models", token).json():
        if m["name"] == "delegation-id":
            admin("DELETE", f"/clients/{uuid}/protocol-mappers/models/{m['id']}",
                  token)
            print("  removed mapper delegation-id (resolution reads the register)")

    # Restricted scopes: assign orders:read + refunds:issue as default scopes.
    all_scopes = {s["name"]: s["id"]
                  for s in admin("GET", "/client-scopes", token).json()}
    for scope in ("orders:read", "refunds:issue"):
        admin("PUT", f"/clients/{uuid}/default-client-scopes/{all_scopes[scope]}",
              token)
    print("  assigned scopes orders:read, refunds:issue")

    secret = admin("GET", f"/clients/{uuid}/client-secret", token).json()["value"]
    return secret


GRANTORS = {"rep-alice": "alice", "rep-bob": "bob"}


def ensure_grantors(token: str) -> None:
    """The people who can authenticate an act. rep-alice comes from the realm
    file; rep-bob is the second grantor the multi-grantor outcomes need, and is
    ensured here so an existing stack picks him up without a realm reimport.
    He is a grantor and not a principal: the agent never acts on his behalf, it
    acts on Alice's under a grant Bob had to agree to."""
    for username, password in GRANTORS.items():
        if admin("GET", f"/users?username={username}&exact=true", token).json():
            continue
        admin("POST", "/users", token, json={
            "username": username, "enabled": True,
            "emailVerified": True,
            "credentials": [{"type": "password", "value": password,
                             "temporary": False}],
        })
        print(f"  created user {username}")


def ensure_register_clients(token: str) -> None:
    """Two clients v2.1 had no need of, both idempotent.

    `grant-register` exists only to be an audience. `grantor-cli` is how a
    person authenticates an act, and it is deliberately not `rep-cli`: a
    rep-cli token is handed to the agent as the subject token for exchange, so
    if it also carried the register's audience the agent could replay it and
    cast the very approval that authorizes the agent. Separate client, separate
    audience, and the register refuses anything carrying an `act` claim as
    well -- an act is a person acting for themselves.
    """
    if not find_client(token, REGISTER_AUDIENCE):
        admin("POST", "/clients", token, json={
            "clientId": REGISTER_AUDIENCE,
            "name": "Grant register (resource server)",
            "publicClient": False,
            "standardFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": False,
        })
        print(f"  created {REGISTER_AUDIENCE} (audience only)")

    client = find_client(token, GRANTOR_CLIENT_ID)
    if not client:
        admin("POST", "/clients", token, json={"clientId": GRANTOR_CLIENT_ID,
                                               "name": "Grantor CLI"})
        client = find_client(token, GRANTOR_CLIENT_ID)
        print(f"  created {GRANTOR_CLIENT_ID}")

    # Both flows, for the two ways a person reaches the register. Direct access
    # grants are how a script authenticates (the kill switch, the demo). The
    # authorization code flow with PKCE is how a person does, in a browser, on
    # the authoring surface -- a public client must not be trusted with a
    # password form, and a surface that collected one would be exactly the
    # pretending this project is otherwise careful to avoid.
    rep = admin("GET", f"/clients/{client['id']}", token).json()
    rep.update(publicClient=True, directAccessGrantsEnabled=True,
               standardFlowEnabled=True,
               redirectUris=[f"{SURFACE_URL}/surface/callback"],
               webOrigins=[SURFACE_URL],
               attributes={**rep.get("attributes", {}),
                           "pkce.code.challenge.method": "S256"})
    admin("PUT", f"/clients/{client['id']}", token, json=rep)

    uuid = client["id"]
    existing = {m["name"] for m in
                admin("GET", f"/clients/{uuid}/protocol-mappers/models", token).json()}
    # Everything explicit, the way warrant-agent's mappers are. Declaring
    # `clientScopes` in the realm file replaces Keycloak's built-in set rather
    # than adding to it, so this realm has no `basic` and no `profile` and no
    # client in it carries a claim nothing put there on purpose. Without `sub`
    # the token is not a well-formed access token; without `preferred_username`
    # it cannot name a grantor, because the register's grantor sets are
    # usernames and `sub` is an opaque UUID.
    mappers = [
        {
            "name": "aud-grant-register",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {
                "included.custom.audience": REGISTER_AUDIENCE,
                "access.token.claim": "true",
                "id.token.claim": "false",
            },
        },
        {
            "name": "grantor-sub",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-sub-mapper",
            "config": {
                "access.token.claim": "true",
                "introspection.token.claim": "true",
            },
        },
        {
            "name": "grantor-username",
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
            admin("POST", f"/clients/{uuid}/protocol-mappers/models", token,
                  json=m)
            print(f"  added mapper {m['name']} to {GRANTOR_CLIENT_ID}")


# ---------------- OpenFGA ----------------

FGA_MODEL = {
    "schema_version": "1.1",
    "type_definitions": [
        {"type": "user"},
        {"type": "agent"},
        {
            "type": "delegation",
            "relations": {"principal": {"this": {}}, "grantor": {"this": {}},
                          "actor": {"this": {}}},
            "metadata": {"relations": {
                "principal": {"directly_related_user_types": [{"type": "user"}]},
                # Records who established the authority. Not on the per-call
                # path; it is how the graph answers "who granted this".
                "grantor": {"directly_related_user_types": [{"type": "user"}]},
                "actor": {"directly_related_user_types": [{"type": "agent"}]},
            }},
        },
        {
            "type": "account",
            "relations": {
                "assigned_rep": {"this": {}},
                "grant_proposer": {"this": {}},
                "active_delegation": {"this": {}},
                "refund_grant": {"this": {}},
            },
            "metadata": {"relations": {
                "assigned_rep": {"directly_related_user_types": [{"type": "user"}]},
                "grant_proposer": {"directly_related_user_types": [{"type": "user"}]},
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

# Account-level facts only. Everything naming a delegation -- principal,
# grantor, actor, refund_grant, active_delegation -- is written by the register
# in phase E, because those tuples materialize a grant request and this file is
# not where grant requests live.
FGA_TUPLES = [
    {"user": "user:rep-alice", "relation": "assigned_rep", "object": "account:acme"},
    # Who may author a grant over this account. Set up here, outside the
    # register, the same way assigned_rep is -- the register enforces that the
    # declared people agreed, not that the right people were asked.
    {"user": "user:rep-alice", "relation": "grant_proposer",
     "object": "account:acme"},
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

    # One at a time so a rerun tolerates tuples that already exist (a batch
    # write is transactional and would fail on the surviving duplicates).
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
    print(f"  wrote {written} account tuples, "
          f"{len(FGA_TUPLES) - written} already present")
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


def _seed_grant_id(grants: dict) -> str:
    """The seed grant, or the next one along if the last was retired.

    A closed grant is not revivable and must not be revived: closing retires the
    request, and the answer to wanting it back is a new request. So bootstrap
    does what an organisation does -- cancel and redo -- rather than
    trying to reopen something that was deliberately ended. This is what keeps
    `make bootstrap && make demo` repeatable after a run that closes the seed.
    """
    from server.register import CLOSED, compute_state

    n = 1
    while True:
        grant_id = DELEGATION_ID if n == 1 else f"{DELEGATION_ID}-{n}"
        if grant_id not in grants or compute_state(grants[grant_id]) != CLOSED:
            return grant_id
        n += 1


def phase_e_seed_grant() -> None:
    """Seed the v2.1 grant through the register: a named(rep-alice) request and
    Alice's approval, on the operator door. Imported here rather than at module
    scope because server.config reads .env.generated, which phase D has only
    just written."""
    from server.register import EFFECTIVE, Register

    reg = Register()
    grant_id = _seed_grant_id(reg.grants())

    # Retire anything a previous run left applicable on the account. Bootstrap's
    # job is to restore the starting state, and once grants can be retired the
    # starting state is "exactly one grant applies" -- a demo that stopped half
    # way through leaves a second one open, and every call on acme would then
    # die of ambiguous_delegation. Closing is the only way back: acts are never
    # deleted, and a request that has been abandoned is closed, not withdrawn.
    for other in reg.applicable("rep-alice", AGENT_CLIENT_ID, "acme",
                                "refunds:issue"):
        if other != grant_id:
            reg.close(other, by=reg.grant(other)["request"]["proposed_by"],
                      reason="left open by a previous run")
            print(f"  closed {other}, left open by a previous run")
    if grant_id not in reg.grants():
        reg.propose(
            grant_id, by="rep-alice",
            principal=["rep-alice"], grantors=["rep-alice"],
            actor=AGENT_CLIENT_ID, account="acme",
            action_scope=["orders:read", "refunds:issue"],
            call_time_conditions={"max_refund_cents": MAX_REFUND_CENTS},
            condition={"op": "named", "grantor": "rep-alice"},
        )
        print(f"  proposed {grant_id}: named(rep-alice)")
    # Restores the graph tuples and the active_delegation tuple if the store was
    # wiped since the last run; a no-op otherwise.
    reg.reconcile()
    if reg.state(grant_id) != EFFECTIVE:
        revision = reg.grant(grant_id)["revision"]
        reg.act(grant_id, "rep-alice", "approve", revision,
                reason="bootstrap seed")
        print(f"  rep-alice approved {grant_id} ({revision})")
    print(f"  {grant_id} is {reg.state(grant_id)}")

    # Phase D wrote the placeholder; the seed id is only known here.
    text = ENV_FILE.read_text().replace(f"DELEGATION_ID={DELEGATION_ID}\n",
                                        f"DELEGATION_ID={grant_id}\n")
    ENV_FILE.write_text(text)


def main() -> None:
    print("waiting for services...")
    wait_for(f"{KC}/realms/{REALM}/.well-known/openid-configuration", "keycloak")
    wait_for(f"{FGA}/healthz", "openfga")

    print("phases A+B: agent registration")
    token = admin_token()
    client = phase_ab_register(token)

    print("phase C: keycloak configuration")
    secret = phase_c_configure(token, client)

    print("register door: grantor-cli + grant-register audience")
    ensure_register_clients(token)
    ensure_grantors(token)

    print("openfga: model + account tuples")
    store_id, model_id = setup_openfga()

    print("phase D: persist credentials")
    phase_d_persist(secret, store_id, model_id)

    print("phase E: seed the grant through the register")
    phase_e_seed_grant()
    print("bootstrap complete")


if __name__ == "__main__":
    main()
