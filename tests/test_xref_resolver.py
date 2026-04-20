"""Tests for msl/xref_resolver.py -- cross-reference resolver."""

import random
import struct
import sys
from pathlib import Path
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from msl.xref_resolver import Relationship, XrefEntry, XrefResolver
from tests.fixtures.generate_msl_fixtures import (
    FILE_MAGIC, BLOCK_MAGIC, FILE_HEADER_SIZE, BLOCK_HEADER_SIZE,
    _pad8, _build_file_header, _build_block, _build_related_dump,
    _build_end_of_capture,
)


def _make_uuid(n: int) -> bytes:
    """Create a deterministic 16-byte UUID from an integer."""
    return UUID(int=n).bytes


def _build_msl_with_related(dump_uuid: bytes, related_refs: list,
                            timestamp_ns: int = 1_700_000_000_000_000_000) -> bytes:
    """Build a minimal MSL blob with a file header and related dump blocks.

    related_refs: list of (target_uuid_bytes, related_pid, relationship_int)
    """
    # Reset the RNG used by _build_block for block UUIDs
    from tests.fixtures import generate_msl_fixtures
    generate_msl_fixtures._RNG = random.Random(100)

    blob = _build_file_header(dump_uuid, timestamp_ns)
    for target_uuid, pid, rel in related_refs:
        block, _ = _build_related_dump(
            related_uuid=target_uuid, related_pid=pid, relationship=rel,
        )
        blob += block
    eoc, _ = _build_end_of_capture(timestamp_ns + 1_000_000_000)
    blob += eoc
    return blob


@pytest.fixture
def uuid_a():
    return _make_uuid(1)


@pytest.fixture
def uuid_b():
    return _make_uuid(2)


@pytest.fixture
def uuid_c():
    return _make_uuid(3)


@pytest.fixture
def msl_a(tmp_path, uuid_a, uuid_b):
    """MSL file A references file B."""
    p = tmp_path / "a.msl"
    p.write_bytes(_build_msl_with_related(uuid_a, [
        (uuid_b, 5678, Relationship.SAME_PROCESS_LATER),
    ]))
    return p


@pytest.fixture
def msl_b(tmp_path, uuid_b):
    """MSL file B with no related dump references."""
    p = tmp_path / "b.msl"
    p.write_bytes(_build_msl_with_related(uuid_b, []))
    return p


def test_index_file(msl_a, uuid_a, uuid_b):
    """Indexing a file captures its UUID and related dump entries."""
    resolver = XrefResolver()
    resolver.index_file(msl_a)
    assert UUID(bytes=uuid_a) in resolver._uuid_to_path
    assert len(resolver._entries) == 1
    entry = resolver._entries[0]
    assert entry.source_uuid == UUID(bytes=uuid_a)
    assert entry.target_uuid == UUID(bytes=uuid_b)
    assert entry.related_pid == 5678
    assert entry.relationship == Relationship.SAME_PROCESS_LATER


def test_index_directory(tmp_path, msl_a, msl_b):
    """index_directory finds all .msl files and returns the count."""
    resolver = XrefResolver()
    count = resolver.index_directory(tmp_path)
    assert count == 2
    assert len(resolver._uuid_to_path) == 2


def test_resolve_found(tmp_path, msl_a, msl_b, uuid_a, uuid_b):
    """When target UUID exists in the index, resolve populates target_path."""
    resolver = XrefResolver()
    resolver.index_directory(tmp_path)
    entries = resolver.resolve()
    assert len(entries) == 1
    entry = entries[0]
    assert entry.source_uuid == UUID(bytes=uuid_a)
    assert entry.target_uuid == UUID(bytes=uuid_b)
    assert entry.target_path == msl_b


def test_resolve_unresolved(msl_a, uuid_a, uuid_b):
    """When target UUID is not indexed, target_path stays None."""
    resolver = XrefResolver()
    resolver.index_file(msl_a)
    entries = resolver.resolve()
    assert len(entries) == 1
    assert entries[0].target_path is None


def test_get_related(tmp_path, msl_a, msl_b, uuid_a, uuid_b):
    """get_related returns entries for a specific source UUID."""
    resolver = XrefResolver()
    resolver.index_directory(tmp_path)
    resolver.resolve()
    related = resolver.get_related(UUID(bytes=uuid_a))
    assert len(related) == 1
    assert related[0].target_uuid == UUID(bytes=uuid_b)
    # File B has no related dumps
    related_b = resolver.get_related(UUID(bytes=uuid_b))
    assert len(related_b) == 0


def test_get_graph(tmp_path, uuid_a, uuid_b, uuid_c):
    """get_graph returns correct adjacency list."""
    # A -> B, A -> C
    p_a = tmp_path / "a.msl"
    p_a.write_bytes(_build_msl_with_related(uuid_a, [
        (uuid_b, 5678, Relationship.CHILD_PROCESS),
        (uuid_c, 9999, Relationship.SIBLING_PROCESS),
    ]))
    p_b = tmp_path / "b.msl"
    p_b.write_bytes(_build_msl_with_related(uuid_b, []))

    resolver = XrefResolver()
    resolver.index_directory(tmp_path)
    graph = resolver.get_graph()
    src = UUID(bytes=uuid_a)
    assert src in graph
    assert len(graph[src]) == 2
    assert UUID(bytes=uuid_b) in graph[src]
    assert UUID(bytes=uuid_c) in graph[src]


def test_empty_directory(tmp_path):
    """Empty directory returns 0 count and empty resolve."""
    resolver = XrefResolver()
    count = resolver.index_directory(tmp_path)
    assert count == 0
    entries = resolver.resolve()
    assert entries == []
