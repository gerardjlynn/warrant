#!/usr/bin/env python3
"""Replay audit.log.jsonl and print the observability report: decisions by
action and reason, decisive policy checks, scope sprawl, delegation-chain
anomalies, the life of each delegation, and the kill-switch proof. Read-only --
this is reporting, not benchmarking (controlled latency percentiles live in
bench_authz.py).

The delegation section reads both logs. That pairing is the claim: the register
log shows authority being assembled from several people and taken apart by one
of them, and the call log shows the agent's access appearing and disappearing in
step with it. Neither log makes the point alone.
"""

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOG = ROOT / "audit.log.jsonl"
REGISTER_LOG = ROOT / "register.log.jsonl"


def delegations(events: list[dict]) -> None:
    """For each delegation: who granted it, on which revision, when it became
    effective, who ended it, and how many calls happened in between."""
    if not REGISTER_LOG.exists():
        return
    entries = [json.loads(l) for l in REGISTER_LOG.read_text().splitlines()
               if l.strip()]
    if not entries:
        return

    print("\n== delegations: how each one was assembled and unmade ==")
    calls = defaultdict(list)
    for e in events:
        if e.get("delegation_id"):
            calls[e["delegation_id"]].append(e)

    for grant_id in dict.fromkeys(e["grant_id"] for e in entries
                                  if e.get("grant_id")):
        own = [e for e in entries if e.get("grant_id") == grant_id]
        proposed = next((e for e in own if e["type"] == "grant_proposed"), None)
        if proposed is None:
            continue
        request = proposed["request"]
        cond = request["condition"]
        named = cond.get("grantor") or ", ".join(cond.get("grantors", []))
        shape = (f"{cond['op']}({named})"
                 + (f" veto[{', '.join(request['veto'])}]" if request["veto"]
                    else ""))
        print(f"\n  {grant_id}: {shape} on account:{request['account']}")
        print(f"    proposed by {proposed['grantor']} "
              f"({proposed['grant_revision']}, "
              f"via={proposed.get('via', 'operator')})")

        # In log order, so the sequence reads as it happened: an approval that
        # stopped counting because the terms changed under it is only legible
        # next to the revision that changed them.
        latency = None
        for e in own:
            t, via = e["type"], e.get("via", "operator")
            if t == "tuple_written" or t == "tuple_deleted":
                latency = e.get("tuple_write_latency_ms")
            elif t == "act_recorded":
                why = f'  "{e["act_reason"]}"' if e.get("act_reason") else ""
                print(f"    {e['grantor']:<10} {e['act_type']:<9} "
                      f"on {e['grant_revision']} via={via}{why}")
            elif t == "revision_superseded":
                print(f"    {e['grantor']:<10} revised    "
                      f"{e['from_revision']} -> {e['grant_revision']} via={via}"
                      "   (acts bound to the old revision stop counting)")
            elif t == "grant_became_effective":
                print(f"    {'':<10} -> effective on {e['grantor']}'s act"
                      + (f", tuple written in {latency}ms" if latency else ""))
            elif t == "grant_ceased_to_be_effective":
                print(f"    {'':<10} -> {e['state']} on {e['grantor']}'s act"
                      + (f", tuple deleted in {latency}ms" if latency else ""))
            elif t == "grant_closed":
                why = f": {e['close_reason']}" if e.get("close_reason") else ""
                print(f"    {'':<10} -> closed by {e['grantor']}{why}")

        mine = calls[grant_id]
        allowed = sum(1 for e in mine if e["decision"] == "allow")
        print(f"    {len(mine)} call(s) decided against it: "
              f"{allowed} allowed, {len(mine) - allowed} denied")
        states = Counter(e.get("grant_state_at_decision") for e in mine
                         if e["decision"] == "deny")
        if states:
            print("    denials by grant state at decision: "
                  + ", ".join(f"{k}={v}" for k, v in sorted(states.items())))


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

    delegations(events)

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
