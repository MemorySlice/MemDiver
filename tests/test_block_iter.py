"""Tests for continuation block merging."""

import pytest
from uuid import UUID, uuid4

from msl.enums import BlockFlag
from msl.types import MslBlockHeader
from msl.block_iter import merge_continuations


def _hdr(block_uuid=None, parent_uuid=None, flags=0, offset=0):
    return MslBlockHeader(
        block_type=0x0001, flags=flags, block_length=200,
        payload_version=1,
        block_uuid=block_uuid or uuid4(),
        parent_uuid=parent_uuid or UUID(int=0),
        prev_hash=b"\x00" * 32,
        file_offset=offset, payload_offset=offset + 80,
    )


def test_no_continuations():
    """Regular blocks pass through unchanged."""
    h1 = _hdr()
    h2 = _hdr()
    blocks = [(h1, b"aaa"), (h2, b"bbb")]
    result = list(merge_continuations(iter(blocks)))
    assert len(result) == 2
    assert result[0] == (h1, b"aaa")
    assert result[1] == (h2, b"bbb")


def test_parent_with_continuation():
    """Parent + continuation blocks are merged."""
    parent_uuid = uuid4()
    parent = _hdr(block_uuid=parent_uuid, flags=BlockFlag.HAS_CHILDREN)
    cont = _hdr(
        parent_uuid=parent_uuid, flags=BlockFlag.CONTINUATION, offset=200,
    )
    tail = _hdr(offset=400)  # regular block triggers flush

    blocks = [(parent, b"part1"), (cont, b"part2"), (tail, b"other")]
    result = list(merge_continuations(iter(blocks)))
    assert len(result) == 2
    merged_hdr, merged_payload = result[0]
    assert merged_hdr.block_uuid == parent_uuid
    assert merged_payload == b"part1part2"
    assert result[1] == (tail, b"other")


def test_multiple_continuations():
    """Parent with multiple continuation blocks merges all payloads."""
    parent_uuid = uuid4()
    parent = _hdr(block_uuid=parent_uuid, flags=BlockFlag.HAS_CHILDREN)
    c1 = _hdr(parent_uuid=parent_uuid, flags=BlockFlag.CONTINUATION, offset=200)
    c2 = _hdr(parent_uuid=parent_uuid, flags=BlockFlag.CONTINUATION, offset=400)
    tail = _hdr(offset=600)

    blocks = [(parent, b"a"), (c1, b"b"), (c2, b"c"), (tail, b"d")]
    result = list(merge_continuations(iter(blocks)))
    assert len(result) == 2
    assert result[0][1] == b"abc"
    assert result[1] == (tail, b"d")


def test_parent_at_end_of_stream():
    """Parent with continuations at end of stream is flushed."""
    parent_uuid = uuid4()
    parent = _hdr(block_uuid=parent_uuid, flags=BlockFlag.HAS_CHILDREN)
    cont = _hdr(parent_uuid=parent_uuid, flags=BlockFlag.CONTINUATION, offset=200)

    blocks = [(parent, b"p1"), (cont, b"p2")]
    result = list(merge_continuations(iter(blocks)))
    assert len(result) == 1
    assert result[0][0].block_uuid == parent_uuid
    assert result[0][1] == b"p1p2"


def test_orphaned_continuation():
    """Continuation without a parent is yielded as-is with warning."""
    orphan = _hdr(
        parent_uuid=uuid4(), flags=BlockFlag.CONTINUATION, offset=100,
    )
    result = list(merge_continuations(iter([(orphan, b"lost")])))
    assert len(result) == 1
    assert result[0] == (orphan, b"lost")


def test_merge_disabled_passthrough():
    """Without merge_continuations wrapper, blocks pass through as-is."""
    parent_uuid = uuid4()
    parent = _hdr(block_uuid=parent_uuid, flags=BlockFlag.HAS_CHILDREN)
    cont = _hdr(
        parent_uuid=parent_uuid, flags=BlockFlag.CONTINUATION, offset=200,
    )
    blocks = [(parent, b"p1"), (cont, b"p2")]
    result = list(iter(blocks))
    assert len(result) == 2
