#!/usr/bin/env python3
"""Replay audit.log.jsonl and print the observability report: decisions by
action and reason, decisive policy checks, scope sprawl, delegation-chain
anomalies, and the kill-switch proof. Read-only — this is reporting, not
benchmarking (controlled latency percentiles live in bench_authz.py)."""

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

LOG = Path(__file__).resolve().parent.parent / "audit.log.jsonl"


def main() -> None:
    if not LOG.exists():
        sys.exit(f"no audit log at {LOG}")
    events = [json.loads(l) for l in LOG.read_text().splitlines() if l.strip()]
    if not events:
        sys.exit("audit log is empty")

    print(f"warrant audit report — {len(events)} events")

    print("\n== decisions by action ==")
    per_action = defaultdict(Counter)
    for e in events:
        per_action[e["action"]][e["decision"]] += 1
    for action, c in sorted(per_action.items()):
        print(f"  {action:<14} allow={c['allow']:<3} deny={c['deny']}")

    denies = Counter(e["reason"] for e in events if e["decision"] == "deny")
    if denies:
        print("\n== denial reasons ==")
        for reason, n in denies.most_common():
            print(f"  {reason:<24} {n}")

    decisive = Counter(e["decisive_check"] for e in events
                       if e.get("decisive_check"))
    if decisive:
        print("\n== decisive policy checks (PDP denials) ==")
        for check, n in decisive.most_common():
            print(f"  {check:<24} {n}")

    print("\n== scope sprawl ==")
    granted, exercised = set(), set()
    for e in events:
        granted.update(e.get("scopes_granted") or [])
        if e["decision"] == "allow" and e.get("required_scope"):
            exercised.add(e["required_scope"])
    unused = granted - exercised
    print(f"  scopes granted:   {sorted(granted)}")
    print(f"  scopes exercised: {sorted(exercised)}")
    print(f"  granted but never exercised: {sorted(unused) if unused else 'none'}")

    print("\n== delegation-chain anomalies ==")
    pre_pdp = [e for e in events if e.get("policy_checks") is None]
    missing_dlg = [e for e in events
                   if e["decision"] == "allow" and not e.get("delegation_id")]
    reasons = dict(Counter(e["reason"] for e in pre_pdp))
    print(f"  calls rejected before the PDP: {len(pre_pdp)}"
          + (f"  {reasons}" if pre_pdp else ""))
    print(f"  allowed calls missing a delegation id: {len(missing_dlg)}")

    lat = sorted(e["authz_latency_ms"] for e in events
                 if e.get("authz_latency_ms") is not None)
    if lat:
        def pct(p: float) -> float:
            return lat[min(len(lat) - 1, int(p / 100 * len(lat)))]
        print("\n== authz latency observed in this log ==")
        print(f"  n={len(lat)}  p50={pct(50)}ms  p95={pct(95)}ms  max={lat[-1]}ms")
        print("  (controlled percentiles: scripts/bench_authz.py)")

    print("\n== kill-switch proof ==")
    proof = [e for e in events if e.get("reason") == "delegation_revoked"
             and e.get("token_valid_at_decision")]
    if proof:
        e = proof[-1]
        print(f"  {len(proof)} call(s) denied delegation_revoked while the "
              f"JWT was still cryptographically valid")
        print(f"  latest: action={e['action']} subject={e['subject']} "
              f"actor={e['actor']} delegation={e['delegation_id']}")
        print(f"  policy_checks={json.dumps(e['policy_checks'])}")
        print(f"  decisive_check={e.get('decisive_check')} "
              f"token_valid_at_decision={e['token_valid_at_decision']}")
    else:
        print("  none recorded (run the demo's revocation step)")


if __name__ == "__main__":
    main()
