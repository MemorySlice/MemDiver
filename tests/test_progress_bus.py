"""Tests for api.services.progress_bus — per-task ring buffer + fan-out."""

from __future__ import annotations

import asyncio

from api.services.progress_bus import DEFAULT_RING_SIZE, Event, ProgressBus


def _evt(task_id: str = "t1", type_: str = "progress", **kw) -> Event:
    return Event(task_id=task_id, type=type_, **kw)


# ---------- publish / replay ----------


def test_publish_assigns_monotonic_seq():
    bus = ProgressBus()
    e1 = bus.publish(_evt(msg="first"))
    e2 = bus.publish(_evt(msg="second"))
    e3 = bus.publish(_evt(msg="third"))
    assert (e1.seq, e2.seq, e3.seq) == (1, 2, 3)
    # Each event gets a non-zero timestamp.
    assert all(e.ts > 0 for e in (e1, e2, e3))


def test_replay_returns_all_when_since_zero():
    bus = ProgressBus()
    for i in range(5):
        bus.publish(_evt(msg=str(i)))
    got = bus.replay("t1", since_seq=0)
    assert [e.msg for e in got] == ["0", "1", "2", "3", "4"]


def test_replay_filters_by_since_seq():
    bus = ProgressBus()
    for i in range(5):
        bus.publish(_evt(msg=str(i)))
    got = bus.replay("t1", since_seq=3)
    assert [e.seq for e in got] == [4, 5]


def test_replay_unknown_task_empty():
    bus = ProgressBus()
    assert bus.replay("does-not-exist") == []


def test_ring_drops_oldest_on_overflow():
    bus = ProgressBus(ring_size=4)
    for i in range(6):
        bus.publish(_evt(msg=str(i)))
    retained = bus.replay("t1", since_seq=0)
    # Ring size 4 keeps only the last 4 events (seq 3..6).
    assert [e.seq for e in retained] == [3, 4, 5, 6]
    # first_seq tracks the smallest retained.
    assert bus.first_seq("t1") == 3


def test_first_seq_empty_channel_is_one():
    bus = ProgressBus()
    assert bus.first_seq("never") == 1


# ---------- subscribe / fan-out ----------


def test_subscribe_receives_live_events_and_terminates_on_done():
    async def scenario():
        bus = ProgressBus()
        received: list[Event] = []

        async def consumer():
            async for ev in bus.subscribe("t1"):
                received.append(ev)

        task = asyncio.create_task(consumer())
        await asyncio.sleep(0)  # let subscriber attach
        bus.publish(_evt(msg="a"))
        bus.publish(_evt(msg="b"))
        bus.publish(_evt(type_="done", msg="bye"))
        await asyncio.wait_for(task, timeout=1.0)
        return received

    received = asyncio.run(scenario())
    assert [e.msg for e in received] == ["a", "b", "bye"]
    assert received[-1].type == "done"


def test_multi_subscriber_fanout():
    async def scenario():
        bus = ProgressBus()
        r1: list[Event] = []
        r2: list[Event] = []

        async def consume(target):
            async for ev in bus.subscribe("t1"):
                target.append(ev)

        tasks = [asyncio.create_task(consume(r1)), asyncio.create_task(consume(r2))]
        await asyncio.sleep(0)
        for i in range(3):
            bus.publish(_evt(msg=str(i)))
        bus.publish(_evt(type_="done"))
        await asyncio.gather(*tasks)
        return r1, r2

    r1, r2 = asyncio.run(scenario())
    assert [e.seq for e in r1] == [1, 2, 3, 4]
    assert [e.seq for e in r2] == [1, 2, 3, 4]


def test_subscribe_terminates_on_error_event():
    async def scenario():
        bus = ProgressBus()
        received: list[Event] = []

        async def consume():
            async for ev in bus.subscribe("t1"):
                received.append(ev)

        task = asyncio.create_task(consume())
        await asyncio.sleep(0)
        bus.publish(_evt(msg="last"))
        bus.publish(_evt(type_="error", error="bang"))
        await asyncio.wait_for(task, timeout=1.0)
        return received

    received = asyncio.run(scenario())
    assert received[-1].type == "error"


# ---------- serialization ----------


def test_event_to_dict_drops_none_fields():
    e = _evt(msg="hi", stage="bf", pct=0.25)
    d = e.to_dict()
    assert d == {
        "task_id": "t1",
        "type": "progress",
        "seq": 0,
        "ts": 0.0,
        "stage": "bf",
        "pct": 0.25,
        "msg": "hi",
    }


def test_default_ring_size_is_512():
    assert DEFAULT_RING_SIZE == 512
