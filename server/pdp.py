"""PDP adapter: one OpenFGA BatchCheck per tool call, composed into one
application-level decision and reason. Reads send checks 1-4; refunds add the
conditioned cap check, so a revoked grant and an over-cap refund produce
distinguishable denials.
"""

import time

import requests

from .config import FGA_MODEL_ID, FGA_STORE_ID, FGA_URL

# Priority order for classifying a denial: the first failed check is decisive.
CHECK_ORDER = ["rep_assigned", "principal_bound", "actor_bound",
               "delegation_active", "refund_within_cap"]

DENY_REASONS = {
    "rep_assigned": "rep_not_assigned",
    "principal_bound": "delegation_binding_mismatch",
    "actor_bound": "delegation_binding_mismatch",
    "delegation_active": "delegation_revoked",
    "refund_within_cap": "over_refund_cap",
}


def batch_check(rep: str, agent: str, account: str, delegation: str,
                amount_cents: int | None = None) -> tuple[dict, float]:
    """Returns ({check_name: bool}, authz_latency_ms)."""
    checks = [
        {"correlation_id": "c1", "tuple_key": {
            "user": f"user:{rep}", "relation": "assigned_rep",
            "object": f"account:{account}"}},
        {"correlation_id": "c2", "tuple_key": {
            "user": f"user:{rep}", "relation": "principal",
            "object": f"delegation:{delegation}"}},
        {"correlation_id": "c3", "tuple_key": {
            "user": f"agent:{agent}", "relation": "actor",
            "object": f"delegation:{delegation}"}},
        {"correlation_id": "c4", "tuple_key": {
            "user": f"delegation:{delegation}", "relation": "active_delegation",
            "object": f"account:{account}"}},
    ]
    names = {"c1": "rep_assigned", "c2": "principal_bound",
             "c3": "actor_bound", "c4": "delegation_active"}
    if amount_cents is not None:
        checks.append({"correlation_id": "c5",
                       "tuple_key": {"user": f"delegation:{delegation}",
                                     "relation": "refund_grant",
                                     "object": f"account:{account}"},
                       "context": {"amount_cents": amount_cents}})
        names["c5"] = "refund_within_cap"

    t0 = time.perf_counter()
    r = requests.post(
        f"{FGA_URL}/stores/{FGA_STORE_ID}/batch-check",
        json={"checks": checks,
              "authorization_model_id": FGA_MODEL_ID,
              "consistency": "HIGHER_CONSISTENCY"},
    )
    r.raise_for_status()
    latency_ms = round((time.perf_counter() - t0) * 1000, 1)
    result = r.json()["result"]
    policy_checks = {names[cid]: bool(result.get(cid, {}).get("allowed"))
                     for cid in names}
    return policy_checks, latency_ms


def decide(policy_checks: dict, action: str) -> tuple[str, str, str | None]:
    """Compose (decision, reason, decisive_check) from the correlated results."""
    for name in CHECK_ORDER:
        if name in policy_checks and not policy_checks[name]:
            return "deny", DENY_REASONS[name], name
    reason = ("assigned_rep_and_within_limit" if action == "issue_refund"
              else "assigned_rep_with_active_delegation")
    return "allow", reason, None
