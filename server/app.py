"""warrant orders-api: REST surface over the shared tool pipeline (core.py).
Kept curl-testable; the MCP surface lives in mcp_app.py."""

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from . import core

app = FastAPI(title="warrant orders-api")


class GetOrderIn(BaseModel):
    order_id: str


class ListOrdersIn(BaseModel):
    account_id: str


class IssueRefundIn(BaseModel):
    order_id: str
    amount_cents: int = Field(gt=0)


def _call(fn, authorization, **params):
    try:
        return fn(authorization, **params)
    except core.ToolDenied as e:
        raise HTTPException(e.status, e.reason)


@app.post("/tools/get_order")
def get_order(body: GetOrderIn, authorization: str | None = Header(None)):
    return _call(core.get_order, authorization, order_id=body.order_id)


@app.post("/tools/list_orders")
def list_orders(body: ListOrdersIn, authorization: str | None = Header(None)):
    return _call(core.list_orders, authorization, account_id=body.account_id)


@app.post("/tools/issue_refund")
def issue_refund(body: IssueRefundIn, authorization: str | None = Header(None)):
    return _call(core.issue_refund, authorization,
                 order_id=body.order_id, amount_cents=body.amount_cents)
