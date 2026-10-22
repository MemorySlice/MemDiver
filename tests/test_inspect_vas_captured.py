"""``vas_regions_result`` flags VAS_MAP-only ranges via ``captured``.

A range excluded at import keeps its VAS_MAP entry but has no MEMORY_REGION
block (no bytes); the VasChart greys those out. The flag is omitted entirely
when region headers cannot be read (no regions / encrypted without key).
"""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.mcp_server import tools_inspect  # noqa: E402
from memdiver.mcp_server.session import ToolSession  # noqa: E402
from memdiver.msl.types import MslVasEntry  # noqa: E402
from memdiver.msl.writer import MslEncryptionConfig, MslWriter  # noqa: E402

PAGE = 0x1000
CAPTURED_BASE = 0x400000
EXCLUDED_BASE = 0x7FFF0000


def _vas_entries():
    return [
        MslVasEntry(CAPTURED_BASE, PAGE, 0x05, 0x03, "/usr/lib/libssl.so"),
        MslVasEntry(EXCLUDED_BASE, 2 * PAGE, 0x03, 0x01, "[heap]"),
    ]


def _write(path: Path, *, with_region=True, encryption=None) -> str:
    w = MslWriter(path, pid=7, encryption=encryption)
    if with_region:
        w.add_memory_region(CAPTURED_BASE, b"\xAB" * PAGE)
    w.add_vas_map(_vas_entries())
    w.add_end_of_capture()
    w.write()
    return str(path)


def _by_base(result):
    return {e["base_addr"]: e for e in result.payload["vas_entries"]}


@pytest.fixture
def session():
    return ToolSession()


def test_entry_with_region_is_captured_and_other_is_not(session, tmp_path):
    msl = _write(tmp_path / "mixed.msl")
    entries = _by_base(tools_inspect.vas_regions_result(session, msl))
    assert entries[CAPTURED_BASE]["captured"] is True
    assert entries[EXCLUDED_BASE]["captured"] is False


def test_captured_key_omitted_without_regions(session, tmp_path):
    msl = _write(tmp_path / "noregions.msl", with_region=False)
    entries = tools_inspect.vas_regions_result(session, msl).payload["vas_entries"]
    assert len(entries) == 2
    assert all("captured" not in e for e in entries)


def test_partial_overlap_counts_as_captured(session, tmp_path):
    path = tmp_path / "overlap.msl"
    w = MslWriter(path, pid=7)
    # Region covers only the second page of the 2-page excluded-base entry.
    w.add_memory_region(EXCLUDED_BASE + PAGE, b"\xCD" * PAGE)
    w.add_vas_map(_vas_entries())
    w.add_end_of_capture()
    w.write()
    entries = _by_base(tools_inspect.vas_regions_result(session, str(path)))
    assert entries[EXCLUDED_BASE]["captured"] is True
    assert entries[CAPTURED_BASE]["captured"] is False


def test_captured_key_omitted_when_encrypted_without_key(session, tmp_path):
    from memdiver.msl import crypto
    from memdiver.msl.enums import EncAlgo

    if not crypto.cipher_is_available(EncAlgo.AES_256_GCM):
        pytest.skip("AES-256-GCM backend not installed")
    cfg = MslEncryptionConfig(raw_key=os.urandom(32))
    msl = _write(tmp_path / "enc.msl", encryption=cfg)
    entries = tools_inspect.vas_regions_result(session, msl).payload["vas_entries"]
    # Today the VAS_MAP is sealed too, so nothing is listed; should it ever be
    # readable while the regions are not, the flag must stay absent.
    assert all("captured" not in e for e in entries)
