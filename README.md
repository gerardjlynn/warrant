# warrant

**An agent acts under a warrant, not a vibe.**

A customer-service agent that can check orders and issue refunds on behalf of
a human rep, where every action runs through real identity infrastructure:
the agent has a stable registered identity, acts under an RFC 8693-shaped
delegated token with an `act` claim, is authorized per-call by a single
policy engine that also holds the delegation grant, writes an audit log, and
can be killed mid-session — with the audit log proving the JWT was still
valid when authorization died.

## The demo, verbatim

Claude drives three MCP tools under a delegated token. Four outcomes in one
session (unedited output of `make demo`):

```text
obtained delegated token: sub=rep-alice, act.sub=warrant-agent, delegation_id=dlg-123, scopes=[orders:read refunds:issue]
connected to MCP server; tools: ['get_order', 'list_orders', 'issue_refund']

rep> Please refund order 1042 for $40.

agent> I'll process that refund for you right away.
  [tool call]   issue_refund {"order_id": "1042", "amount_cents": 4000}
  [tool result] {"refund_id": "rf_0001", "order_id": "1042", "amount_cents": 4000}

agent> Done — I've refunded $40.00 on order 1042. The refund ID is rf_0001.

rep> Now refund order 2077 for $900.

agent> I'll process that refund now.
  [tool call]   issue_refund {"order_id": "2077", "amount_cents": 90000}
  [tool result] {"denied": true, "reason": "over_refund_cap"}

agent> That refund was denied. The reason given: over_refund_cap — the $900.00
amount exceeds the allowed refund cap.

rep> List the orders for account globex.
  [tool call]   list_orders {"account_id": "globex"}
  [tool result] {"denied": true, "reason": "rep_not_assigned"}

agent> That request was denied. The reason given: rep_not_assigned — the rep
isn't assigned to account globex, so I can't list its orders.

=== KILL SWITCH: operator revokes dlg-123 mid-session (the agent's JWT is still unexpired) ===
revoked dlg-123: deleted [delegation:dlg-123 active_delegation account:acme]

rep> Refund order 1042 for another $15.

agent> I'll process that additional refund now.
  [tool call]   issue_refund {"order_id": "1042", "amount_cents": 1500}
  [tool result] {"denied": true, "reason": "delegation_revoked"}

agent> That refund was denied. The reason given: delegation_revoked — the
delegated authority to act on your behalf has been revoked.
```

The full transcript is in [`docs/demo-transcript.txt`](docs/demo-transcript.txt).
The audit event behind that last denial is the point of the whole build:

```json
{
  "subject": "rep-alice",
  "actor": "warrant-agent",
  "delegation_id": "dlg-123",
  "action": "issue_refund",
  "resource": "order:1042",
  "account_id": "acme",
  "amount_cents": 1500,
  "decision": "deny",
  "reason": "delegation_revoked",
  "policy_checks": {
    "rep_assigned": true,
    "principal_bound": true,
    "actor_bound": true,
    "delegation_active": false,
    "refund_within_cap": true
  },
  "decisive_check": "delegation_active",
  "token_valid_at_decision": true,
  "authz_latency_ms": 10.8
}
```

The refund was under the cap. The token was cryptographically valid. The
*authority* was gone — and the log proves all three at once.

## What's being demonstrated

**Delegation, not impersonation.** The rep's login is exchanged (RFC 8693)
for a token whose claims separate the principal from the actor:

```json
{
  "sub": "rep-alice",
  "azp": "warrant-agent",
  "act": { "sub": "warrant-agent" },
  "aud": "orders-api",
  "delegation_id": "dlg-123",
  "scope": "orders:read refunds:issue"
}
```

The resource server enforces `act.sub == azp == warrant-agent`, so actor
attribution is tied to the authenticated OAuth client, not just a claim
string.

**One policy engine for relationships, attributes, and revocation.** OpenFGA
holds a small delegation graph — the rep's account assignment (ReBAC), a
first-class `delegation` object binding principal and actor, an
`active_delegation` grant, and a `refund_grant` conditioned on
`amount_cents <= max_refund_cents` (ABAC). Every tool call is one BatchCheck
(4 checks for reads, 5 for refunds); the policy adapter composes the
correlated results into one decision with a named `decisive_check`, so a
revoked grant and an over-cap refund produce distinguishable denials.

**An honest kill switch.** Revoking the agent does not pretend to invalidate
an issued JWT — bearer tokens don't work that way. Instead, revocation
deletes one relationship tuple (`delegation:dlg-123 active_delegation
account:acme`), and the very next call fails closed at the PDP. Checks run
with `HIGHER_CONSISTENCY` and the OpenFGA check cache disabled so the
transcript can never observe a stale cached allow.

**The token never enters model context.** The MCP client attaches it to the
connection's `Authorization` header, out of band. The model supplies only the
requested amount; the server derives the account and order attributes from
the order record. Integer cents everywhere. No raw JWTs in logs (selected
claims plus a `jti` hash).

## Architecture

```
[make bootstrap] --DCR (once) + Admin REST config--> [Keycloak: stable agent client]
                 --writes delegation tuples--------> [OpenFGA]

[Rep login] --rep token (aud includes warrant-agent)-->
[Keycloak Standard Token Exchange V2, requester=warrant-agent, audience=orders-api]
    --API token: sub=rep, azp=agent, act.sub=agent, delegation_id, aud=orders-api-->
[Agent loop (Claude + MCP client)] --tool call (token attached out of band)-->
[MCP tool server (FastAPI/MCP Streamable HTTP)]
    | validate: signature, iss, exp, aud, sub, scope, act.sub == azp
    v
[PDP: OpenFGA BatchCheck (4 checks read / 5 refund)]  (check cache off)
    |
  policy adapter composes decision + reason --> [audit log JSONL] --> order store

[scripts/revoke_delegation.py] --deletes active_delegation tuple--> OpenFGA
```

## Run it

Prereqs: Docker, Python 3.11+, an `ANTHROPIC_API_KEY` in the environment
(the curl demo needs no API key).

```bash
make bootstrap    # keycloak + openfga up, agent registered via DCR,
                  # mappers + token exchange configured, delegation tuples written
make demo         # Claude agent, the four-outcome transcript above
                  # (spawns the MCP tool server on :8091 itself if needed)

make token        # prove the token exit criterion: decoded delegated token, 8 checks
make audit-report # replay the audit log: decisions, scope sprawl, kill-switch proof
make bench        # authz latency percentiles (never executes refunds)

make mcp-server   # optional: run the MCP server in the foreground yourself
make server       # optional: REST surface on :8090
make demo-curl    # the same outcomes via curl, no LLM required
```

`make bootstrap` is idempotent and also restores a revoked delegation, so
`make bootstrap && make demo` doubles as the repeatable demo reset (the order
store is in-memory per server process; the demo spawning its own server gets
a fresh one each run).

Observed on a laptop (`make bench`, 200 iterations per case):

```text
jwt_validate (local JWKS)     p50=0.3ms   p95=0.7ms
batch_check read (4 checks)   p50=8.8ms   p95=13.5ms
batch_check refund (5 checks) p50=8.1ms   p95=13.7ms
```

## Design notes, candidly

- **Keycloak's native delegation support is experimental.** This
  implementation uses standard token exchange plus a client-specific protocol
  mapper to emit the `act` structure, while OpenFGA enforces the actual
  delegation grant. That split is the architecture, not an apology: Keycloak
  authenticates and identifies subject and actor; the token names the
  delegation; OpenFGA decides whether that delegation remains authorized;
  revocation removes the authorization relationship without pretending to
  invalidate an issued JWT.
- **Delegation IDs are provisioned, not requested.** Bootstrap creates
  `dlg-123`, writes its tuples, and configures the agent client's mapper to
  emit it — the exchange request cannot invent a delegation. Dynamic
  per-task delegation issuance is future work.
- **MCP conformance:** tools are exposed over MCP-compatible Streamable HTTP
  and protected with audience-bound OAuth access tokens. This does not claim
  full MCP authorization-spec conformance — RFC 9728 protected-resource
  discovery metadata is future work.
- **OpenFGA** was created at Auth0 and is now a CNCF project. Keycloak keeps
  the repo reproducible with one `docker compose up`; the same flow maps to a
  managed IdP such as PingOne (token exchange + client registration are the
  same moving parts).
- The registration flow uses Keycloak's client registration service with a
  one-use initial access token; bootstrap is idempotent (it looks up the
  client by ID and only mints a new initial access token when the client
  doesn't exist).

## Threat framing (OWASP Agentic)

Two items from the OWASP Agentic Top 10 shape the design. *Excessive agency*:
the agent's authority is externally bounded — scopes name the two operations
it can attempt, the PDP enforces the account relationship and the refund cap
per call, and the grant is revocable independently of the token, so the blast
radius of a misbehaving agent is capped by policy, not by prompt. *Identity
spoofing*: the agent cannot claim to be the rep (top-level `sub` stays the
human; the actor rides in `act`), and it cannot claim to be a different agent
(`act.sub` must equal the authenticated client's `azp`). The audit log makes
both properties observable after the fact: every event names the human
subject, the agent actor, and the delegation that connected them.

## Future work

Dynamic per-task delegation issuance · refund idempotency keys ·
hash-chained audit log (until then the log is append-only by convention, not
tamper-evident) · a security-invariant test suite (missing `act` denied,
wrong audience denied, `act.sub != azp` denied, revoked delegation denied,
duplicate refund) · order-state and remaining-refundable-amount rules ·
RFC 9728 MCP discovery metadata · DPoP sender-constrained tokens.

---

Built with [Claude Code](https://claude.com/product/claude-code); the agent
loop runs on Claude (`claude-opus-4-8`) via the Anthropic API with the SDK's
tool runner and MCP helpers.
