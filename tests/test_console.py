"""The agent console's queue and event stream -- the parts that run without a
model. The agent loop itself needs Claude and a running stack, and is exercised
by hand (`make console`)."""

import asyncio

from agent import console


def run(coro):
    return asyncio.run(coro)


def make_queue(pace=0.0, n=3):
    events = console.Events()
    tickets = [{"id": f"T-{i}", "order_id": str(i), "text": "..."}
               for i in range(n)]
    return console.TicketQueue(tickets, events, pace=pace), events


def test_the_queue_hands_out_tickets_in_order_then_says_empty():
    q, _ = make_queue()

    async def drain():
        return [await q.take() for _ in range(4)]

    got = run(drain())
    assert [t["id"] for t in got[:3]] == ["T-0", "T-1", "T-2"]
    assert got[3] is None


def test_each_ticket_is_announced_and_paced():
    q, events = make_queue(pace=0.01, n=1)
    run(q.take())
    kinds = [e["kind"] for e in events.items]
    assert kinds == ["waiting", "ticket"]
    assert events.items[0]["seconds"] == 0.01
    # The ticket's own id must not clobber the event's sequence number, which
    # is what a reconnecting page replays from.
    assert [e["id"] for e in events.items] == [0, 1]
    assert events.items[1]["ticket"] == "T-0"


def test_a_withdrawal_closes_the_queue_and_puts_the_ticket_back():
    """The prompt tells the agent to stop on delegation_revoked; the queue does
    not rely on it. Once closed it hands out nothing, and the ticket the agent
    was on -- never resolved -- is first when the run resumes."""
    q, _ = make_queue()

    async def scenario():
        await q.take()                 # T-0, done
        await q.take()                 # T-1, authority withdrawn during it
        q.closed = True
        refused = await q.take()
        q.requeue_current()
        resumed = await q.take()
        return refused, resumed

    refused, resumed = run(scenario())
    assert refused is None
    assert resumed["id"] == "T-1"
    assert q.remaining == ["T-2"]


def test_start_again_resets_the_queue():
    q, _ = make_queue()
    run(q.take())
    q.closed = True
    q.reset()
    assert (q.next_index, q.current, q.closed) == (0, None, False)


def test_a_late_page_replays_every_event_in_order():
    events = console.Events()

    async def scenario():
        for i in range(3):
            await events.emit("note", text=str(i))
        got = []
        async for item in events.since(1):
            got.append(item)
            if len(got) == 2:
                break
        return got

    assert [e["text"] for e in run(scenario())] == ["1", "2"]


def test_denials_are_read_off_the_tool_servers_structured_result():
    assert console.decision_of('{"denied": true, "reason": "delegation_revoked"}') \
        == ("deny", "delegation_revoked")
    assert console.decision_of('{"refund_id": "rf_0001"}') == ("allow", None)
    assert console.decision_of("not json") == ("allow", None)
