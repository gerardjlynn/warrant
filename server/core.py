"""Transport-agnostic tool pipeline: authn -> derive context server-side ->
one BatchCheck -> audit -> act. Used by both the REST endpoints (app.py)
and the MCP server (mcp_app.py)."""

import hashlib
import uuid

from . import auth, orders, pdp
from .audit import audit
from .config import FGA_MODEL_ID


class ToolDenied(Exception):
    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


def _jti_hash(claims: dict) -> str | None:
    jti = claims.get("jti")
    return hashlib.sha256(jti.encode()).hexdigest()[:16] if jti else None


def _base_event(request_id: str, claims: dict, action: str, resource: str,
                required_scope: str) -> dict:
    return {
        "request_id": request_id,
        "subject": claims.get("preferred_username"),
        "actor": claims.get("azp"),
        "delegation_id": claims.get("delegation_id"),
        "action": action,
        "resource": resource,
        "scopes_granted": claims.get("scope", "").split() or None,
        "required_scope": required_scope,
        "token_exp": claims.get("exp"),
        "jti_hash": _jti_hash(claims),
    }


def _authn(authorization: str | None, request_id: str, action: str,
           resource: str, required_scope: str) -> dict:
    """Token validation + scope check. Audits and raises on failure (pre-PDP)."""
    token = (authorization or "").removeprefix("Bearer ").strip()
    try:
        claims = auth.validate(token)
    except auth.AuthError as e:
        audit(**_base_event(request_id, e.claims, action, resource, required_scope),
              decision="deny", reason=e.reason, policy_checks=None,
              token_valid_at_decision=e.token_valid)
        raise ToolDenied(401, e.reason)
    if required_scope not in claims.get("scope", "").split():
        audit(**_base_event(request_id, claims, action, resource, required_scope),
              decision="deny", reason="missing_scope", policy_checks=None,
              token_valid_at_decision=True)
        raise ToolDenied(403, "missing_scope")
    return claims


def _authorize(claims: dict, request_id: str, action: str, resource: str,
               account_id: str, required_scope: str,
               amount_cents: int | None = None) -> None:
    """One BatchCheck; audit the composed decision; raise on deny."""
    policy_checks, latency_ms = pdp.batch_check(
        rep=claims["preferred_username"],
        agent=claims["azp"],
        account=account_id,
        delegation=claims["delegation_id"],
        amount_cents=amount_cents,
    )
    decision, reason, decisive = pdp.decide(policy_checks, action)
    event = _base_event(request_id, claims, action, resource, required_scope)
    event.update(account_id=account_id, amount_cents=amount_cents,
                 decision=decision, reason=reason, policy_checks=policy_checks,
                 policy_model_id=FGA_MODEL_ID, token_valid_at_decision=True,
                 authz_latency_ms=latency_ms)
    if decisive:
        event["decisive_check"] = decisive
    audit(**event)
    if decision != "allow":
        raise ToolDenied(403, reason)


def _get_order_or_404(order_id: str, request_id: str, claims: dict,
                      action: str, required_scope: str) -> dict:
    order = orders.ORDERS.get(order_id)
    if order is None:
        audit(**_base_event(request_id, claims, action, f"order:{order_id}",
                            required_scope),
              decision="deny", reason="order_not_found", policy_checks=None,
              token_valid_at_decision=True)
        raise ToolDenied(404, "order_not_found")
    return order


def get_order(authorization: str | None, order_id: str) -> dict:
    request_id = f"req_{uuid.uuid4().hex[:12]}"
    resource = f"order:{order_id}"
    claims = _authn(authorization, request_id, "get_order", resource, "orders:read")
    order = _get_order_or_404(order_id, request_id, claims,
                              "get_order", "orders:read")
    # Account derived from the order record, never from the caller.
    _authorize(claims, request_id, "get_order", resource,
               account_id=order["account_id"], required_scope="orders:read")
    return order


def list_orders(authorization: str | None, account_id: str) -> list[dict]:
    request_id = f"req_{uuid.uuid4().hex[:12]}"
    resource = f"account:{account_id}"
    claims = _authn(authorization, request_id, "list_orders", resource, "orders:read")
    _authorize(claims, request_id, "list_orders", resource,
               account_id=account_id, required_scope="orders:read")
    return [o for o in orders.ORDERS.values() if o["account_id"] == account_id]


def issue_refund(authorization: str | None, order_id: str,
                 amount_cents: int) -> dict:
    request_id = f"req_{uuid.uuid4().hex[:12]}"
    resource = f"order:{order_id}"
    claims = _authn(authorization, request_id, "issue_refund", resource,
                    "refunds:issue")
    if not isinstance(amount_cents, int) or amount_cents <= 0:
        audit(**_base_event(request_id, claims, "issue_refund", resource,
                            "refunds:issue"),
              decision="deny", reason="invalid_amount", policy_checks=None,
              token_valid_at_decision=True)
        raise ToolDenied(400, "invalid_amount")
    order = _get_order_or_404(order_id, request_id, claims,
                              "issue_refund", "refunds:issue")
    _authorize(claims, request_id, "issue_refund", resource,
               account_id=order["account_id"], required_scope="refunds:issue",
               amount_cents=amount_cents)
    return orders.issue_refund(order_id, amount_cents)
