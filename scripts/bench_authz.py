#!/usr/bin/env python3
"""Authorization-path latency percentiles: repeated JWT validation and OpenFGA
BatchChecks against the live stack. Drives the authz path only — it never
executes refunds and never touches the order store or the audit log."""

import argparse
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests

from server import auth, pdp
from server.config import AGENT_CLIENT_ID, ENV, KC_REALM, KC_URL


def get_token() -> str:
    kc = f"{KC_URL}/realms/{KC_REALM}/protocol/openid-connect/token"
    rep = requests.post(kc, data={
        "grant_type": "password", "client_id": "rep-cli",
        "username": "rep-alice", "password": "alice",
    })
    rep.raise_for_status()
    r = requests.post(kc, data={
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": AGENT_CLIENT_ID,
        "client_secret": ENV["KC_AGENT_CLIENT_SECRET"],
        "subject_token": rep.json()["access_token"],
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "audience": "orders-api",
    })
    r.raise_for_status()
    return r.json()["access_token"]


def timed(fn, n: int) -> list[float]:
    samples = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000)
    return samples


def report(name: str, samples: list[float]) -> None:
    s = sorted(samples)
    def pct(p: float) -> float:
        return s[min(len(s) - 1, int(p / 100 * len(s)))]
    print(f"  {name:<28} n={len(s):<5} p50={statistics.median(s):6.1f}ms  "
          f"p95={pct(95):6.1f}ms  p99={pct(99):6.1f}ms  max={s[-1]:6.1f}ms")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iterations", type=int, default=100)
    args = ap.parse_args()
    n = args.iterations

    token = get_token()
    auth.validate(token)  # warm the JWKS cache before timing
    print(f"warrant authz benchmark — {n} iterations per case\n")

    report("jwt_validate (local JWKS)",
           timed(lambda: auth.validate(token), n))
    report("batch_check read (4 checks)",
           timed(lambda: pdp.batch_check(
               "rep-alice", "warrant-agent", "acme", "dlg-123"), n))
    report("batch_check refund (5 checks)",
           timed(lambda: pdp.batch_check(
               "rep-alice", "warrant-agent", "acme", "dlg-123",
               amount_cents=4000), n))

    print("\nall checks run with consistency=HIGHER_CONSISTENCY and the "
          "OpenFGA check cache disabled")


if __name__ == "__main__":
    main()
