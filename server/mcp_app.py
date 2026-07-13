"""warrant MCP tool server: the same pipeline over MCP Streamable HTTP.

The delegated token arrives as the Authorization header on the MCP
connection — attached out of band by the MCP client, never visible to the
model. Denials are returned as structured tool results (not exceptions) so
the agent can explain them to the rep.
"""

from mcp.server.fastmcp import Context, FastMCP

from . import core

mcp = FastMCP("warrant-orders", host="127.0.0.1", port=8091)


def _call(fn, ctx: Context, **params):
    authorization = ctx.request_context.request.headers.get("authorization")
    try:
        return fn(authorization, **params)
    except core.ToolDenied as e:
        return {"denied": True, "reason": e.reason}


@mcp.tool()
def get_order(order_id: str, ctx: Context) -> dict:
    """Look up a single order by its order ID. Amounts are integer cents."""
    return _call(core.get_order, ctx, order_id=order_id)


@mcp.tool()
def list_orders(account_id: str, ctx: Context) -> list | dict:
    """List all orders for an account ID."""
    return _call(core.list_orders, ctx, account_id=account_id)


@mcp.tool()
def issue_refund(order_id: str, amount_cents: int, ctx: Context) -> dict:
    """Issue a refund against an order. amount_cents is a positive integer
    number of cents (e.g. $40 = 4000)."""
    return _call(core.issue_refund, ctx, order_id=order_id,
                 amount_cents=amount_cents)


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
