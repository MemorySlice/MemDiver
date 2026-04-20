"""Tests for msl/block_tree.py — block listing and grouping."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from msl.block_tree import BlockNode, group_blocks, list_blocks, _block_type_name
from msl.reader import MslReader
from tests.fixtures.generate_msl_fixtures import generate_msl_file


@pytest.fixture
def msl_reader(tmp_path):
    p = tmp_path / "test.msl"
    p.write_bytes(generate_msl_file())
    with MslReader(p) as r:
        yield r


def test_block_node_category():
    node = BlockNode(type_code=0x0001, type_name="MEMORY_REGION",
                     payload_size=4096, file_offset=64)
    assert node.category == "Memory"


def test_block_node_capture_time():
    node = BlockNode(type_code=0x0001, type_name="MEMORY_REGION",
                     payload_size=0, file_offset=0, is_capture_time=True)
    assert node.is_capture_time is True


def test_block_node_structural():
    node = BlockNode(type_code=0x1001, type_name="VAS_MAP",
                     payload_size=0, file_offset=0, is_capture_time=False)
    assert node.is_capture_time is False
    assert node.category == "Memory"


def test_group_blocks():
    nodes = [
        BlockNode(0x0001, "MEMORY_REGION", 100, 64),
        BlockNode(0x0001, "MEMORY_REGION", 200, 200),
        BlockNode(0x0020, "KEY_HINT", 50, 500),
        BlockNode(0x0040, "PROCESS_IDENTITY", 80, 600),
    ]
    groups = group_blocks(nodes)
    assert "Memory" in groups
    assert len(groups["Memory"]) == 2
    assert "Crypto" in groups
    assert len(groups["Crypto"]) == 1
    assert "Process Context" in groups


def test_group_blocks_unknown_type():
    nodes = [BlockNode(0x9999, "UNKNOWN_0x9999", 10, 0)]
    groups = group_blocks(nodes)
    assert "Other" in groups


def test_block_type_name_known():
    assert _block_type_name(0x0001) == "MEMORY_REGION"
    assert _block_type_name(0x0020) == "KEY_HINT"
    assert _block_type_name(0x0FFF) == "END_OF_CAPTURE"
    assert _block_type_name(0x1001) == "VAS_MAP"


def test_block_type_name_unknown():
    name = _block_type_name(0xBEEF)
    assert "0xBEEF" in name


def test_empty_group():
    groups = group_blocks([])
    assert groups == {}


def test_list_blocks_against_real_reader(msl_reader):
    """Regression: list_blocks() used to call UUID.hex() as a method,
    which raises TypeError in Python 3.11+ (UUID.hex is a property).
    The bare except swallowed the error and returned []."""
    nodes = list_blocks(msl_reader)
    assert len(nodes) > 0, "list_blocks must return real blocks, not []"
    # Every returned node must carry a non-empty 32-char hex UUID.
    for node in nodes:
        assert isinstance(node.block_uuid, str)
        assert len(node.block_uuid) == 32
    # The fixture always emits a MEMORY_REGION, so groupings must
    # contain the Memory category.
    groups = group_blocks(nodes)
    assert "Memory" in groups


def test_list_blocks_uuids_match_iter_blocks(msl_reader):
    """Every listed block's UUID must match the iter_blocks UUID in
    hex form — guards against a regression where list_blocks renders
    UUIDs differently than the underlying reader."""
    direct_uuids = [hdr.block_uuid.hex for hdr, _p in msl_reader.iter_blocks()]
    listed_uuids = [n.block_uuid for n in list_blocks(msl_reader)]
    assert direct_uuids == listed_uuids
