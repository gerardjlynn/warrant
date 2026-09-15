# warrant

**An agent acts under a warrant, not a vibe — and a warrant can take more than
one person to issue.**

A customer-service agent that can check orders and issue refunds on behalf of a
human rep, under authority that several people had to agree to before it
existed and that any one of them it still depends on can end. The grant is a
*request* with a declared condition — `all_of([alice, bob])`, a threshold, an
optional veto — held in an append-only register. Pending is a real state:
silence is not assent, there are no timers, and nothing counts as agreement
except an approval act.

Underneath it, the machinery that makes the grant mean something rather than
describe something: a stable registered agent identity, an RFC 8693-shaped
delegated token with an `act` claim, per-call authorization by a single policy
engine, an audit log, and a kill switch that ends authority while the agent's
JWT is still cryptographically valid — and proves all three at once.

**Why the multi-party part is the point.** An agent holding delegated authority
is no longer the hard problem. Microsoft Entra Agent ID reached general
availability in May 2026 with a named autonomous, non-OBO pattern; Stripe
ships virtual cards agents purchase with under real-time spend controls;
machine-to-machine rails close the loop with no human in the action path at all.
But every one of those schemes is single-principal — one cardholder, one account
owner, one sponsor, one tenant administrator granting consent — and the limits
are per-agent, never per-approver. *Several people agreeing on the ceiling, and
on raising it,* is the part nobody has shipped. That is the part this builds,
and the rest is the substrate it needs in order to be more than a workflow.

## The demo

Claude drives three MCP tools under a delegated token. Ten outcomes in one
session, on one token that is never re-fetched. Act I is one grantor; Act II is
authority that took two people to create and one to end. Output of `make demo`,
abridged: tool results are folded onto one line, and Act II leaves out what the
agent said and the narration between steps. The unabridged run is
[`docs/demo-transcript.txt`](docs/demo-transcript.txt).

### Act I — one grantor

```text
obtained delegated token: sub=rep-alice, act.sub=warrant-agent, scopes=[orders:read refunds:issue]
no delegation_id claim — the resource server resolves the applicable delegation per call by reading the register
connected to MCP server; tools: ['get_order', 'list_orders', 'issue_refund']

rep> Please refund order 1042 for $40.

agent> I'll process that refund for you right away.
  [tool call]   issue_refund {"order_id": "1042", "amount_cents": 4000}
  [tool result] {"refund_id": "rf_0001", "order_id": "1042", "amount_cents": 4000}

agent> Done! I've refunded $40.00 to order 1042. The refund ID is rf_0001. Is there anything else I can help you with?

rep> Now refund order 2077 for $900.
  [tool call]   issue_refund {"order_id": "2077", "amount_cents": 90000}
  [tool result] {"denied": true, "reason": "over_refund_cap"}

agent> That refund was denied. Reason: the amount exceeds the refund cap (over_refund_cap). I'm unable to process the $900 refund on order 2077. Let me know how you'd like to proceed.

rep> List the orders for account globex.
  [tool call]   list_orders {"account_id": "globex"}
  [tool result] {"denied": true, "reason": "rep_not_assigned"}

agent> That request was denied. Reason: you're not assigned to that account (rep_not_assigned). I can't list orders for account globex. Is there anything else I can help with?

=== KILL SWITCH: rep-alice withdraws her approval of dlg-123 mid-session (the agent's JWT is still unexpired) ===
revoked dlg-123: rep-alice withdrew their approval on rev_04b9733a990d (via=token, authenticated by grantor-cli); grant is now pending, active_delegation tuple deleted in 5.2ms

rep> Refund order 1042 for another $15.

agent> I'll process that additional refund.
  [tool call]   issue_refund {"order_id": "1042", "amount_cents": 1500}
  [tool result] {"denied": true, "reason": "delegation_revoked"}

agent> That refund was denied. Reason: your delegated authority has been revoked (delegation_revoked). I'm unable to process the additional $15 refund on order 1042 right now. You may need to have your authorization restored before I can take further actions.
```

### Act II — authority that took two people

```text
  [register]    rep-alice revises dlg-123: all_of(rep-alice, rep-bob) — state: pending, awaiting: ['rep-alice', 'rep-bob']

rep> Refund order 1042 for $20.
  [tool call]   issue_refund {"order_id": "1042", "amount_cents": 2000}
  [tool result] {"denied": true, "reason": "delegation_revoked"}

  [register]    rep-alice approves dlg-123 — state: pending, awaiting: ['rep-bob']
  [register]    rep-bob approves dlg-123 — state: effective

rep> Try that $20 refund on order 1042 again.
  [tool call]   issue_refund {"order_id": "1042", "amount_cents": 2000}
  [tool result] {"refund_id": "rf_0002", "order_id": "1042", "amount_cents": 2000}

  [register]    rep-bob withdraws dlg-123 — state: pending, awaiting: ['rep-bob']

rep> Refund order 1042 for another $5.
  [tool call]   issue_refund {"order_id": "1042", "amount_cents": 500}
  [tool result] {"denied": true, "reason": "delegation_revoked"}

  [register]    rep-alice proposes dlg-200: any_of(rep-alice, rep-bob), veto: [rep-alice] — state: pending, awaiting: ['rep-alice', 'rep-bob']

rep> Refund order 2077 for $30.
  [tool call]   issue_refund {"order_id": "2077", "amount_cents": 3000}
  [tool result] {"denied": true, "reason": "ambiguous_delegation"}

  [register]    rep-alice closes dlg-123 (superseded by dlg-200) — state: closed
  [register]    rep-bob approves dlg-200 — state: effective, awaiting: ['rep-alice']
  [register]    rep-alice refuses dlg-200 — state: blocked

rep> Refund order 2077 for $30 again.
  [tool call]   issue_refund {"order_id": "2077", "amount_cents": 3000}
  [tool result] {"denied": true, "reason": "delegation_revoked"}

  [register]    rep-alice revises dlg-200: refund cap lowered to $250 — state: blocked, awaiting: ['rep-bob']

rep> Try the $30 refund on order 2077 once more.
  [tool call]   issue_refund {"order_id": "2077", "amount_cents": 3000}
  [tool result] {"denied": true, "reason": "delegation_revoked"}

  [register]    rep-alice closes dlg-200 (abandoned) — state: closed
```

Four things happen there that a single-approver design cannot express. Revising
the terms drops the authority at once, because acts bind to a revision and none
of them travels. The grant becomes effective on Bob's approval rather than on a
clock. It ends on Bob's withdrawal, though it took two people to create. And the
veto blocks a grant whose condition is *satisfied* — Bob's approval alone meets
`any_of` — and goes on blocking it across a revision, because a veto member's
refusal is the one act that does travel.

The `ambiguous_delegation` in the middle is deliberate. A second grant was
raised over the same account before the first was retired, and with the static
`delegation_id` claim gone there is nothing to choose between them, so the call
fails closed. Retiring the first is the fix and the ordinary answer: cancel, and
raise a new one.

Every one of those denials is a different line in the audit log:

```text
issue_refund   4000  allow  assigned_rep_and_within_limit  effective  dlg-123
issue_refund  90000  deny   over_refund_cap                effective  dlg-123
list_orders       -  deny   rep_not_assigned               absent     -
issue_refund   1500  deny   delegation_revoked             pending    dlg-123
issue_refund   2000  deny   delegation_revoked             pending    dlg-123
issue_refund   2000  allow  assigned_rep_and_within_limit  effective  dlg-123
issue_refund    500  deny   delegation_revoked             pending    dlg-123
issue_refund   3000  deny   ambiguous_delegation           absent     -
issue_refund   3000  deny   delegation_revoked             blocked    dlg-200
issue_refund   3000  deny   delegation_revoked             blocked    dlg-200
```

`token_valid_at_decision` is true on every one of them. The audit event behind
the first revocation is the point of the whole build:

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

**A grant several people have to agree to.** Multi-grantor logic lives *outside*
the policy decision point, and that decision is what keeps it small. OpenFGA can
express intersection and exclusion between named relations but not "every member
of a dynamically-sized set has approved" — modelling that means either fixed
grantor slots or a relation rewritten whenever the set changes, and both are
bad. So a grant register holds the request, collects the acts, evaluates the
declared condition (`named`, `all_of`, `any_of`, `threshold(n)`, with an
optional veto), and writes or deletes the single `active_delegation` tuple as a
result. The register is a pure function over an append-only log of who said
what: same log, same answer, whether it ran a moment ago or a week ago. It
contains no model, makes no inference, and never interprets what a term means.

Three consequences worth stating. Acts bind to an exact revision, so revising
the terms drops the authority at once rather than carrying old approvals
forward — with one exception, a veto member's standing refusal, which survives
revision until they withdraw it. A request can be retired outright when it is
abandoned, which is what makes cancel-and-redo work when a grantor leaves.
And the per-call check set does not change at all: still one BatchCheck, still
four checks on reads and five on refunds.

**The person who ends it is authenticated, not asserted.** Every operation on a
grant — propose, revise, approve, refuse, withdraw, close — is recorded against
a Keycloak token the actor holds, over a separate audience and a separate client
from anything the agent ever sees. The author is read off the token; no request
field could name anyone. The agent cannot replay the
rep login it holds for token exchange to approve its own authority, and a
delegated token is refused outright: an act is a person acting for themselves.
The register keeps a second door for in-process operator seeding, and every
entry says which door it came through. What this buys is authentication *as*
the grantor, not proof the act came *from* them — closing that needs the
grantor to sign the act with a key the IdP does not hold, which is future work.

**Delegation, not impersonation.** The rep's login is exchanged (RFC 8693)
for a token whose claims separate the principal from the actor:

```json
{
  "sub": "rep-alice",
  "azp": "warrant-agent",
  "act": { "sub": "warrant-agent" },
  "aud": "orders-api",
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
an issued JWT — bearer tokens don't work that way. Instead the grantor
withdraws her approval; the grant register recomputes and deletes one
relationship tuple (`delegation:dlg-123 active_delegation account:acme`), and
the very next call fails closed at the PDP. Checks run with
`HIGHER_CONSISTENCY` and the OpenFGA check cache disabled so the transcript
can never observe a stale cached allow.

**No static delegation in the token.** The exchanged token names no delegation.
The resource server derives which grant applies per call from the authenticated
subject, the bound actor, the account and the action, by reading the register —
a hardcoded claim can only ever be right for one grant, and it hides collisions
between several. Resolution is a reason-override rather than a gate: the
BatchCheck still runs, so "you are not the rep for this account" stays the
answer when it is the truer one, and an unresolved delegation is always a
denial.

**A surface a person actually uses.** `make surface` serves the page where a
grantor reads a grant and answers it. Sign-in is the authorization code flow
with PKCE — a public client is not handed a password, and a surface that
collected one would be the pretending this project is otherwise careful to
avoid. The load-bearing rule is what it shows: the page renders the terms *as
of a revision hash*, and the answer binds to that hash and no other. If the
terms change while someone is reading them, their answer is refused and they
are shown the new terms and asked again — because approving while looking at
terms other than the ones your act will bind to is ceremony. Ordinary language
on the page is a rendering of the structured fields, one way only; no prose a
person types ever reaches the register.

**The token never enters model context.** The MCP client attaches it to the
connection's `Authorization` header, out of band. The model supplies only the
requested amount; the server derives the account and order attributes from
the order record. Integer cents everywhere. No raw JWTs in logs (selected
claims plus a `jti` hash).

## Architecture

```
[make bootstrap] --DCR (once) + Admin REST config--> [Keycloak: agent client,
                                                     grantor-cli, grant-register]
                 --account tuples-----------------> [OpenFGA]
                 --seeds dlg-123 (operator door)--> [Grant register]

[Rep login] --rep token (aud includes warrant-agent)-->
[Keycloak Standard Token Exchange V2, requester=warrant-agent, audience=orders-api]
    --API token: sub=rep, azp=agent, act.sub=agent, aud=orders-api-->
[Agent loop (Claude + MCP client)] --tool call (token attached out of band)-->
[MCP tool server (FastAPI/MCP Streamable HTTP)]
    | validate: signature, iss, exp, aud, sub, scope, act.sub == azp
    | resolve: which delegation applies (register read; no token claim)
    v
[PDP: OpenFGA BatchCheck (4 checks read / 5 refund)]  (check cache off)
    |
  policy adapter composes decision + reason --> [audit log JSONL] --> order store

[Person on the authoring surface (:8090/surface)]
    --OIDC authorization code + PKCE--> [Keycloak] --> session, server-side-->
[Grantor login (grantor-cli, aud=grant-register)]
    --propose / revise / approve / refuse / withdraw / close,
      author read off the token, never from the body-->
[Grant register (server/register.py, in the same service)]
    | recompute the condition from the append-only act log
    v
  writes or deletes the active_delegation tuple --> OpenFGA
                                               --> [register log JSONL]

[scripts/revoke_delegation.py] --authenticates as rep-alice, records a
                                 withdraw act--> the register
```

## Run it

Prereqs: Docker, Python 3.11+, an `ANTHROPIC_API_KEY` in the environment
(the curl demo needs no API key).

```bash
make bootstrap    # keycloak + openfga up, agent registered via DCR, mappers +
                  # token exchange configured, seed grant approved via the register
make demo         # Claude agent, the ten-outcome transcript above
                  # (spawns the MCP tool server on :8091 and the orders-api
                  #  service on :8090 itself if they aren't already running)

make token        # decode the delegated token and run 9 checks against it
make audit-report # replay the audit log: decisions, scope sprawl, kill-switch proof
make bench        # authz latency percentiles (never executes refunds)

make surface      # the authoring surface on :8090 — sign in as rep-alice/alice
                  # or rep-bob/bob, read a grant, answer it
make walkthrough  # put the grant in the state worth looking at (needs two
                  # people) and print the steps to click through
make try-refund   # one refund as the agent, with the decision that governed it
make mcp-server   # optional: run the MCP server in the foreground yourself
make server       # optional: REST surface on :8090
make demo-curl    # the Act I outcomes via curl, no LLM required
```

`make bootstrap` is idempotent and restores the starting state — it re-approves
a revoked grant, seeds a fresh one if the last was retired, and closes anything
a half-finished run left applicable to the account — so `make bootstrap && make
demo` is the repeatable demo reset (the order store is in-memory per server
process; the demo spawning its own server gets a fresh one each run).

Observed on a laptop (`make bench`, 100 iterations per case — the default):

```text
jwt_validate (local JWKS)     p50=0.2ms   p95=0.4ms
batch_check read (4 checks)   p50=6.1ms   p95=8.8ms
batch_check refund (5 checks) p50=6.6ms   p95=10.4ms
```

The register's own tuple write is measured per act rather than sampled:
`tuple_write_latency_ms` is on every state change in the register log, so "the
very next call dies" is a number in the log rather than a sentence here.

## Design notes, candidly

- **Keycloak's native delegation support is experimental.** This
  implementation uses standard token exchange plus a client-specific protocol
  mapper to emit the `act` structure, while OpenFGA enforces the actual
  delegation grant. That split is the architecture, not an apology: Keycloak
  authenticates and identifies subject and actor; the register records the
  delegation and who agreed to it; OpenFGA decides whether that delegation remains authorized;
  revocation removes the authorization relationship without pretending to
  invalidate an issued JWT.
- **Delegations are registered, not requested.** A grant exists because someone
  proposed it and the declared people approved it; the register is the only
  writer of any tuple naming it. The exchange request cannot invent a
  delegation, and neither can the token name one — v2.1's hardcoded
  `delegation_id` mapper is gone, because a static claim can only ever be right
  for one grant and it silently hides collisions between several. The resource
  server resolves the applicable grant per call instead. Credentials scoped to a
  single grant, issued by the register, are future work.
- **MCP conformance:** tools are exposed over MCP-compatible Streamable HTTP
  and protected with audience-bound OAuth access tokens. This does not claim
  full MCP authorization-spec conformance — RFC 9728 protected-resource
  discovery metadata is future work.
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

Multi-party grants tighten both. Against *excessive agency*, widening the
authority takes everyone the condition names, so one compromised approver
cannot raise a ceiling alone — and one who holds a veto can lower it alone.
Against *identity spoofing*, the agent cannot approve its own authority: acts
are authenticated over an audience and a client the agent never holds, and a
token carrying an `act` claim is refused at the register outright. The closest
thing to a confused deputy here would be replaying the rep login that feeds
token exchange, and that login is good for neither.

## Future work

Proposing and revising from the surface — today they are API-only, because they
need real forms and the surface answers grants rather than authoring them from
scratch. Then: delegation-scoped credentials issued by the register (the token naming its
own grant, rather than the resource server resolving it) · succession declared
at grant creation, so a grantor leaving is a substitution rather than a
cancel-and-redo · grantor-signed acts, so an approval is evidence rather than
testimony and survives a realm administrator resetting a password ·
hash-chained audit log — the same instinct, and they belong together; until
both, the logs are append-only by convention, not tamper-evident · refund
idempotency keys · the rest of the token-level security invariants (missing
`act` denied, duplicate refund; wrong audience, `act.sub != azp` and revoked
delegation are covered) · order-state and remaining-refundable-amount rules ·
RFC 9728 MCP discovery metadata · DPoP sender-constrained tokens.

---

Built with [Claude Code](https://claude.com/product/claude-code); the agent
loop runs on Claude (`claude-opus-4-8`) via the Anthropic API with the SDK's
tool runner and MCP helpers.
