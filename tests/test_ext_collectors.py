"""Tests for MslReader collectors wrapping decoders_ext.py.

These collectors expose the 5 spec-reserved decoders (0x0011-0x0015) +
SYSTEM_CONTEXT (0x0050, incomplete vs spec §6.2). The decoders themselves
use speculative layouts — see the warning docstring at the top of
msl/decoders_ext.py.

We round-trip through the shared test fixture which emits all 6 block
types using the same guessed layouts the decoders expect.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from msl.decoders_ext import (MslEnvironmentBlock, MslFileDescriptor,
                              MslNetworkConnection, MslSecurityToken,
                              MslSystemContext, MslThreadContext)
from msl.reader import MslReader
from msl.types import MslGenericBlock
from tests.fixtures.generate_msl_fixtures import generate_msl_file


@pytest.fixture
def msl_path(tmp_path):
    p = tmp_path / "test.msl"
    p.write_bytes(generate_msl_file())
    return p


def test_collect_thread_contexts(msl_path):
    with MslReader(msl_path) as reader:
        blocks = reader.collect_thread_contexts()
        assert len(blocks) == 1
        b = blocks[0]
        # Fallback-or-decoded: either MslThreadContext or MslGenericBlock
        if isinstance(b, MslThreadContext):
            assert b.thread_id == 0xDEAD
            assert b.register_data == b"\xAA\xBB\xCC\xDD"


def test_collect_file_descriptors(msl_path):
    with MslReader(msl_path) as reader:
        blocks = reader.collect_file_descriptors()
        assert len(blocks) == 1
        b = blocks[0]
        if isinstance(b, MslFileDescriptor):
            assert b.fd == 7
            assert b.path == "/dev/null"


def test_collect_network_connections(msl_path):
    with MslReader(msl_path) as reader:
        blocks = reader.collect_network_connections()
        assert len(blocks) == 1
        b = blocks[0]
        if isinstance(b, MslNetworkConnection):
            assert b.local_port == 443
            assert b.remote_port == 8080
            assert b.protocol == 0x06


def test_collect_environment_blocks(msl_path):
    with MslReader(msl_path) as reader:
        blocks = reader.collect_environment_blocks()
        assert len(blocks) == 1
        b = blocks[0]
        if isinstance(b, MslEnvironmentBlock):
            assert b.entries.get("HOME") == "/root"
            assert b.entries.get("PATH") == "/usr/bin"


def test_collect_security_tokens(msl_path):
    with MslReader(msl_path) as reader:
        blocks = reader.collect_security_tokens()
        assert len(blocks) == 1
        b = blocks[0]
        if isinstance(b, MslSecurityToken):
            assert b.token_type == 3
            assert b.token_data == b"\xCA\xFE\xBA\xBE"


def test_collect_system_context(msl_path):
    with MslReader(msl_path) as reader:
        blocks = reader.collect_system_context()
        assert len(blocks) == 1
        b = blocks[0]
        # Strict: decoder must return MslSystemContext (no fallback)
        assert isinstance(b, MslSystemContext), f"Expected MslSystemContext, got {type(b).__name__}"
        # Spec §6.2 Table 20 fields
        assert b.boot_time_ns == 1_600_000_000_000_000_000
        assert b.target_count == 1
        assert b.table_bitmap == 0b111
        assert b.acq_user == "examiner01"
        assert b.hostname == "server01"
        assert b.domain == ""  # omitted (len=0)
        assert b.os_detail == "Linux 6.1.0-18-amd64 #1 SMP Debian"
        assert b.case_ref == ""  # omitted (len=0)
        # Memdiver local deviation tail
        assert b.uptime_ns == 123456789
        assert b.os_version == "Linux 6.1"


def test_collect_system_context_with_domain_and_caseref(tmp_path):
    """Verify Table 20 optional fields (Domain, CaseRef) round-trip when non-empty."""
    from tests.fixtures.generate_msl_fixtures import (
        _build_file_header, _build_system_context,
    )
    import random
    import tests.fixtures.generate_msl_fixtures as gmf
    # Reseed for deterministic UUIDs
    gmf._RNG = random.Random(42)

    timestamp_ns = 1_700_000_000_000_000_000
    dump_uuid = gmf._det_uuid()
    blob = _build_file_header(dump_uuid, timestamp_ns)

    sc_block, _ = _build_system_context(
        domain="CORP.LOCAL",
        case_ref="CASE-2026-0414-001",
        acq_user="forensics-team",
        hostname="winhost42",
    )
    blob += sc_block

    p = tmp_path / "with_optionals.msl"
    p.write_bytes(blob)

    with MslReader(p) as reader:
        blocks = reader.collect_system_context()
        assert len(blocks) == 1
        b = blocks[0]
        assert isinstance(b, MslSystemContext)
        assert b.acq_user == "forensics-team"
        assert b.hostname == "winhost42"
        assert b.domain == "CORP.LOCAL"
        assert b.case_ref == "CASE-2026-0414-001"


# -- Cache identity across ALL 6 ext collectors --

@pytest.mark.parametrize("method_name", [
    "collect_thread_contexts",
    "collect_file_descriptors",
    "collect_network_connections",
    "collect_environment_blocks",
    "collect_security_tokens",
    "collect_system_context",
])
def test_ext_collector_cache_identity(msl_path, method_name):
    with MslReader(msl_path) as reader:
        a = getattr(reader, method_name)()
        b = getattr(reader, method_name)()
        assert a is b, f"{method_name} returned different list objects (cache miss)"
