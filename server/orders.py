"""Fake order store. rep-alice is assigned to acme; globex is not hers."""

ORDERS = {
    "1042": {"order_id": "1042", "account_id": "acme", "total_cents": 12000,
             "refunded_cents": 0, "status": "shipped"},
    "2077": {"order_id": "2077", "account_id": "acme", "total_cents": 95000,
             "refunded_cents": 0, "status": "shipped"},
    "3001": {"order_id": "3001", "account_id": "globex", "total_cents": 30000,
             "refunded_cents": 0, "status": "shipped"},
}

REFUNDS = []


def issue_refund(order_id: str, amount_cents: int) -> dict:
    order = ORDERS[order_id]
    order["refunded_cents"] += amount_cents
    refund = {
        "refund_id": f"rf_{len(REFUNDS) + 1:04d}",
        "order_id": order_id,
        "amount_cents": amount_cents,
    }
    REFUNDS.append(refund)
    return refund
