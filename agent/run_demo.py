#!/usr/bin/env python3
"""Sunday AM demo: Claude drives the order tools over MCP under a delegated
token. Four outcomes in one session — allow, over_refund_cap, rep_not_assigned,
then a mid-session revocation -> delegation_revoked while the JWT is still
valid. The token is attached to the MCP connection out of band and never
enters model context.
"""

import asyncio
import inspect
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

import requests
from anthropic import AsyncAnthropic
from anthropic.lib.tools.mcp import async_mcp_tool
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

ROOT = Path(__file__).resolve().parent.parent
ENV = dict(line.split("=", 1)
           for line in (ROOT / ".env.generated").read_text().splitlines()
           if "=" in line)

MODEL = "claude-opus-4-8"
MCP_URL = "http://localhost:8091/mcp"

SYSTEM = (
    "You are a customer-service agent acting on behalf of a human rep under "
    "delegated authority. Use the order tools to fulfil requests. Amounts are "
    "integer cents ($40 = 4000). The rep's message is your authorization to "
    "act — carry out each request directly without asking for confirmation; "
    "the policy engine, not you, decides what is permitted. If a tool result "
    "says denied, report the denial reason to the rep plainly — do not retry "
    "the same call, and do not speculate beyond the reason given."
)

TURNS = [
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


def _port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def ensure_mcp_server() -> subprocess.Popen | None:
    """Spawn the MCP tool server if :8091 isn't already serving, so
    `make bootstrap && make demo` works standalone. Server-management
    chatter goes to stderr to keep the stdout transcript clean."""
    if _port_open(8091):
        print("using MCP tool server already running on :8091", file=sys.stderr)
        return None
    print("starting MCP tool server on :8091 ...", file=sys.stderr)
    proc = subprocess.Popen(
        [sys.executable, "-m", "server.mcp_app"], cwd=ROOT,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    for _ in range(40):
        if _port_open(8091):
            return proc
        time.sleep(0.25)
    proc.terminate()
    sys.exit("could not start the MCP tool server on :8091")


def revoke() -> None:
    print("\n=== KILL SWITCH: operator revokes dlg-123 mid-session "
          "(the agent's JWT is still unexpired) ===")
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
          "delegation_id=dlg-123, scopes=[orders:read refunds:issue]")

    client = AsyncAnthropic()
    async with streamablehttp_client(
        MCP_URL, headers={"Authorization": f"Bearer {token}"},
    ) as (read, write, _):
        async with ClientSession(read, write) as mcp_session:
            await mcp_session.initialize()
            listed = await mcp_session.list_tools()
            tools = [async_mcp_tool(t, mcp_session) for t in listed.tools]
            print(f"connected to MCP server; tools: "
                  f"{[t.name for t in listed.tools]}")

            messages: list = []
            for i, user_turn in enumerate(TURNS):
                if i == 3:
                    revoke()
                print(f"\nrep> {user_turn}")
                messages.append({"role": "user", "content": user_turn})
                await run_turn(client, tools, messages)

    print("\ndemo complete — see audit.log.jsonl for the decision trail")


if __name__ == "__main__":
    server_proc = ensure_mcp_server()
    try:
        asyncio.run(main())
    finally:
        if server_proc is not None:
            server_proc.terminate()
