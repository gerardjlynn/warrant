#!/usr/bin/env python3
"""The demo: Claude drives the order tools over MCP under a delegated token,
in one session, on one token that is never re-fetched.

Act I is v2.1, now running through a grant seeded in the register: allow,
over_refund_cap, rep_not_assigned, then a mid-session revocation ->
delegation_revoked while the JWT is still valid.

Act II is what v3.2 adds: authority that took two people to create and one to
end. The grant is revised to require Bob as well, which drops it at once
because acts bind to a revision; it is pending until he answers; it works when
he does; it dies when he takes it back. Then a veto: a grant whose condition is
satisfied and which is blocked anyway, and which stays blocked across a
revision because a veto member's refusal survives one.

Register acts go through the authenticated door over HTTP -- each one carries
the actor's own Keycloak token, and the register reads the name off it. The
agent's delegated token is attached to the MCP connection out of band and never
enters model context; it is also refused by the register, and the grantors'
tokens are refused by the tool server.
"""

import asyncio
import inspect
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

# Run as `python agent/run_demo.py`, so the repo root is not on the path; the
# demo reads the register to resolve grant ids the way the tool server does.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import httpx2  # noqa: E402
import requests  # noqa: E402
from anthropic import AsyncAnthropic
from anthropic.lib.tools.mcp import async_mcp_tool
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from server.register import Register  # noqa: E402  (needs ROOT on the path)
ENV = dict(line.split("=", 1)
           for line in (ROOT / ".env.generated").read_text().splitlines()
           if "=" in line)

MODEL = "claude-opus-4-8"
MCP_URL = "http://localhost:8091/mcp"
API_URL = "http://localhost:8090"
KC_TOKEN = f"{ENV['KC_URL']}/realms/{ENV['KC_REALM']}/protocol/openid-connect/token"
ALICE, BOB = "rep-alice", "rep-bob"
PASSWORDS = {ALICE: "alice", BOB: "bob"}

SYSTEM = (
    "You are a customer-service agent acting on behalf of a human rep under "
    "delegated authority. Use the order tools to fulfil requests. Amounts are "
    "integer cents ($40 = 4000). The rep's message is your authorization to "
    "act — carry out each request directly without asking for confirmation; "
    "the policy engine, not you, decides what is permitted. "
    "Your authority is granted, changed and revoked outside this conversation "
    "and can differ from one message to the next, so never treat an earlier "
    "denial as the answer to a later request: attempt every request the rep "
    "makes and let the policy engine decide. Within a single request, do not "
    "repeat a call that was just denied. If a tool result says denied, report "
    "the reason to the rep plainly and do not speculate beyond it."
)

ACT_I = [
    "Please refund order 1042 for $40.",
    "Now refund order 2077 for $900.",
    "List the orders for account globex.",
    "Refund order 1042 for another $15.",
]


def get_delegated_token() -> str:
    kc = f"{ENV['KC_URL']}/realms/{ENV['KC_REALM']}/protocol/openid-connect/token"
    rep = requests.post(kc, data={
        "grant_type": "password", "client_id": "rep-cli",
        "username": "rep-alice", "password": "alice",
    })
    rep.raise_for_status()
    r = requests.post(kc, data={
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": ENV["KC_AGENT_CLIENT_ID"],
        "client_secret": ENV["KC_AGENT_CLIENT_SECRET"],
        "subject_token": rep.json()["access_token"],
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "audience": "orders-api",
    })
    r.raise_for_status()
    return r.json()["access_token"]


class RegisterDoor:
    """The register's HTTP surface, driven with each person's own token.

    Nothing here passes a name. Alice's acts carry Alice's token and Bob's carry
    Bob's, and the register takes the grantor off the token -- so what the log
    records is not this script's opinion about who agreed.
    """

    def __init__(self):
        self.tokens = {who: self._login(who, pw)
                       for who, pw in PASSWORDS.items()}

    @staticmethod
    def _login(username: str, password: str) -> str:
        r = requests.post(KC_TOKEN, data={
            "grant_type": "password", "client_id": "grantor-cli",
            "username": username, "password": password})
        r.raise_for_status()
        return r.json()["access_token"]

    def _post(self, path: str, who: str, body: dict) -> dict:
        r = requests.post(f"{API_URL}/register{path}", json=body,
                          headers={"Authorization": f"Bearer {self.tokens[who]}"})
        if r.status_code >= 400:
            sys.exit(f"register refused {path} for {who}: {r.text}")
        return r.json()

    def revision(self, grant_id: str) -> str:
        r = requests.get(f"{API_URL}/register/grants/{grant_id}",
                         headers={"Authorization": f"Bearer {self.tokens[ALICE]}"})
        r.raise_for_status()
        return r.json()["revision"]

    def _say(self, who: str, what: str, result: dict) -> dict:
        awaiting = result.get("awaiting")
        tail = f", awaiting: {awaiting}" if awaiting else ""
        print(f"  [register]    {who} {what} — state: {result['state']}{tail}")
        return result

    def propose(self, grant_id: str, who: str, summary: str, **fields) -> dict:
        return self._say(who, f"proposes {grant_id}: {summary}",
                         self._post("/grants", who,
                                    {"grant_id": grant_id, **fields}))

    def revise(self, grant_id: str, who: str, summary: str, **changes) -> dict:
        return self._say(who, f"revises {grant_id}: {summary}",
                         self._post(f"/grants/{grant_id}/revisions", who, changes))

    def act(self, grant_id: str, who: str, act_type: str,
            reason: str | None = None) -> dict:
        return self._say(who, f"{act_type}s {grant_id}",
                         self._post(f"/grants/{grant_id}/acts", who,
                                    {"act_type": act_type, "reason": reason,
                                     "grant_revision": self.revision(grant_id)}))

    def close(self, grant_id: str, who: str, reason: str) -> dict:
        return self._say(who, f"closes {grant_id} ({reason})",
                         self._post(f"/grants/{grant_id}/close", who,
                                    {"reason": reason}))


def _port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def ensure_server(port: int, argv: list[str], label: str) -> subprocess.Popen | None:
    """Spawn a server if its port isn't already serving, so
    `make bootstrap && make demo` works standalone. Server-management
    chatter goes to stderr to keep the stdout transcript clean."""
    if _port_open(port):
        print(f"using {label} already running on :{port}", file=sys.stderr)
        return None
    print(f"starting {label} on :{port} ...", file=sys.stderr)
    proc = subprocess.Popen(argv, cwd=ROOT, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    for _ in range(80):
        if _port_open(port):
            return proc
        time.sleep(0.25)
    proc.terminate()
    sys.exit(f"could not start {label} on :{port}")


def ensure_servers() -> list[subprocess.Popen]:
    """The MCP tool server the agent calls, and the orders-api service the
    register's HTTP door is mounted on."""
    procs = [
        ensure_server(8091, [sys.executable, "-m", "server.mcp_app"],
                      "MCP tool server"),
        ensure_server(8090, [sys.executable, "-m", "uvicorn",
                             "server.app:app", "--port", "8090"],
                      "orders-api (register door)"),
    ]
    return [p for p in procs if p is not None]


def revoke(grant_id: str) -> None:
    print(f"\n=== KILL SWITCH: rep-alice withdraws her approval of {grant_id} "
          "mid-session (the agent's JWT is still unexpired) ===")
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "revoke_delegation.py")],
        check=True,
    )


def show_assistant(message) -> None:
    for block in message.content:
        if block.type == "text" and block.text.strip():
            print(f"\nagent> {block.text.strip()}")
        elif block.type == "tool_use":
            print(f"  [tool call]   {block.name} {json.dumps(block.input)}")


def show_tool_results(tool_response: dict) -> None:
    for tr in tool_response.get("content", []):
        content = tr.get("content")
        if isinstance(content, list):
            content = " ".join(
                b.get("text", "") for b in content if b.get("type") == "text")
        print(f"  [tool result] {str(content)[:200]}")


async def run_turn(client, tools, messages: list) -> None:
    runner = client.beta.messages.tool_runner(
        model=MODEL, max_tokens=2048, system=SYSTEM,
        tools=tools, messages=messages,
    )
    async for message in runner:
        show_assistant(message)
        # Mirror the history — the runner keeps its own copy.
        messages.append({"role": "assistant", "content": message.content})
        tool_response = runner.generate_tool_call_response()
        if inspect.isawaitable(tool_response):
            tool_response = await tool_response
        if tool_response is not None:
            show_tool_results(tool_response)
            messages.append(tool_response)


async def main() -> None:
    # Line-buffer stdout so our prints interleave correctly with the
    # revoke_delegation.py subprocess output in piped transcripts.
    sys.stdout.reconfigure(line_buffering=True)
    token = get_delegated_token()
    print("obtained delegated token: sub=rep-alice, act.sub=warrant-agent, "
          "scopes=[orders:read refunds:issue]")
    print("no delegation_id claim — the resource server resolves the applicable "
          "delegation per call by reading the register")
    door = RegisterDoor()

    client = AsyncAnthropic()
    # mcp 2.x takes an httpx2 client rather than a headers kwarg, and yields
    # (read, write). The delegated token still rides the connection out of band
    # -- it never reaches the model.
    async with (
        httpx2.AsyncClient(
            headers={"Authorization": f"Bearer {token}"}) as http_client,
        streamable_http_client(MCP_URL, http_client=http_client) as (read, write),
    ):
        async with ClientSession(read, write) as mcp_session:
            await mcp_session.initialize()
            listed = await mcp_session.list_tools()
            tools = [async_mcp_tool(t, mcp_session) for t in listed.tools]
            print(f"connected to MCP server; tools: "
                  f"{[t.name for t in listed.tools]}")

            messages: list = []

            async def turn(text: str) -> None:
                print(f"\nrep> {text}")
                messages.append({"role": "user", "content": text})
                await run_turn(client, tools, messages)

            seed = seed_grant_id()
            banner(f"ACT I — one grantor ({seed}: named(rep-alice))")
            for i, user_turn in enumerate(ACT_I):
                if i == 3:
                    revoke(seed)
                await turn(user_turn)

            await act_two(door, seed, turn)

    print("\ndemo complete — audit.log.jsonl has the decision trail, "
          "register.log.jsonl has who agreed to what")


def banner(text: str) -> None:
    print(f"\n\n{'=' * len(text)}\n{text}\n{'=' * len(text)}")


def seed_grant_id() -> str:
    """Whatever bootstrap seeded, resolved the way the resource server resolves
    it rather than read off a name -- after a run that closes it, the next seed
    is a new request with a new id."""
    ids = Register().applicable(ALICE, ENV["KC_AGENT_CLIENT_ID"], "acme",
                                "refunds:issue")
    if len(ids) != 1:
        sys.exit(f"expected one applicable delegation on acme, got {ids}. "
                 "Run `make bootstrap` first.")
    return ids[0]


def free_grant_id() -> str:
    """A grant id this register has never seen. Acts and requests are never
    deleted, so a repeatable demo cannot reuse one: proposing over an existing
    id is `duplicate_grant`, closed or not."""
    grants = Register().grants()
    n = 0
    while f"dlg-2{n:02d}" in grants:
        n += 1
    return f"dlg-2{n:02d}"


async def act_two(door: RegisterDoor, seed: str, turn) -> None:
    banner("ACT II — authority that took two people")

    print("\n-- the same grant, revised to require Bob as well. It is still\n"
          "   pending from Alice's withdrawal, and acts bind to a revision, so\n"
          "   the new terms start with nobody's approval standing: both of\n"
          "   them have to answer them.")
    door.revise(seed, ALICE, "all_of(rep-alice, rep-bob)",
                grantors=[ALICE, BOB],
                condition={"op": "all_of", "grantors": [ALICE, BOB]})
    await turn("Refund order 1042 for $20.")

    print("\n-- Alice re-approves on the new terms. Still pending: silence is\n"
          "   not assent, and there are no timers.")
    door.act(seed, ALICE, "approve", reason="re-approving the two-person terms")

    print("\n-- Bob answers. The register writes the tuple, and the grant\n"
          "   becomes effective on his act rather than on any clock.")
    door.act(seed, BOB, "approve", reason="agreed")
    await turn("Try that $20 refund on order 1042 again.")

    print("\n-- Bob takes it back. Authority established by two people, ended\n"
          "   by one of them, with the agent's JWT still unexpired.")
    door.act(seed, BOB, "withdraw", reason="changed my mind")
    await turn("Refund order 1042 for another $5.")

    print("\n-- A second grant is raised over the same account before the first\n"
          "   is retired. Two apply, nothing chooses between them, and every\n"
          "   call on the account dies -- the failure that made a way to close\n"
          "   a request the thing to build first.")
    second = free_grant_id()
    door.propose(second, ALICE, "any_of(rep-alice, rep-bob), veto: [rep-alice]",
                 principal=[ALICE], grantors=[ALICE, BOB], veto=[ALICE],
                 actor=ENV["KC_AGENT_CLIENT_ID"], account="acme",
                 action_scope=["orders:read", "refunds:issue"],
                 call_time_conditions={"max_refund_cents": 50000},
                 condition={"op": "any_of", "grantors": [ALICE, BOB]})
    await turn("Refund order 2077 for $30.")

    print("\n-- Cancel and redo, the ordinary answer. Closing retires the\n"
          "   request; it is not a refusal and not a withdrawal.")
    door.close(seed, ALICE, f"superseded by {second}")

    print(f"\n-- Bob approves {second}, which satisfies any_of on its own.")
    door.act(second, BOB, "approve", reason="fine by me")

    print("\n-- and Alice, who holds the veto, refuses. The condition is still\n"
          "   satisfied. The grant is blocked anyway, and blocked reads\n"
          "   differently in the log from nobody having answered.")
    door.act(second, ALICE, "refuse", reason="not without a second look")
    await turn("Refund order 2077 for $30 again.")

    print("\n-- Alice revises the terms. Her refusal was recorded on the old\n"
          "   revision and it survives, because a veto member's refusal is the\n"
          "   one act that travels. Revising is not a way around it.")
    door.revise(second, ALICE, "refund cap lowered to $250",
                call_time_conditions={"max_refund_cents": 25000})
    await turn("Try the $30 refund on order 2077 once more.")

    print("\n-- and the blocked request is retired in its turn, so the account\n"
          "   is left carrying nothing stale. That is the whole of the answer\n"
          "   to a grantor who has left: cancel, and raise a new one.")
    door.close(second, ALICE, "abandoned")


if __name__ == "__main__":
    procs = ensure_servers()
    try:
        asyncio.run(main())
    finally:
        for proc in procs:
            proc.terminate()
