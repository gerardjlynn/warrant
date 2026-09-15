"""warrant orders-api: REST surface over the shared tool pipeline (core.py),
plus the grant register's HTTP door (register_api.py) and the authoring
surface a person uses to answer a grant (surface.py).
Kept curl-testable; the MCP surface lives in mcp_app.py."""

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from . import core, register_api, surface

app = FastAPI(title="warrant orders-api")
# The grant register's authenticated door. Same service, different audience:
# /tools/* takes the agent's delegated token, /register/* takes a person's own.
app.include_router(register_api.router)
# ...and the surface a person uses to read and answer one. Same service, and
# the same authenticated door underneath: the surface holds the person's token
# and the register reads the name off it, exactly as it would for any other
# surface talking to /register over HTTP.
app.include_router(surface.router)


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
