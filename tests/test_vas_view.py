"""Tests for VAS and Session navigator views."""

import sys
from pathlib import Path
from unittest.mock import MagicMock
from dataclasses import dataclass, field
from typing import List, Optional
from uuid import UUID

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from msl.types import MslVasEntry


def _make_mo():
    """Create a mock marimo module."""
    mo = MagicMock()
    mo.md.return_value = MagicMock()
    mo.Html.return_value = MagicMock()
    return mo


def _make_vas_entries():
    return [
        MslVasEntry(0x00400000, 0x10000, 0x05, 0x03, "/usr/lib/libssl.so"),
        MslVasEntry(0x7FFF00000000, 0x21000, 0x07, 0x01, ""),
        MslVasEntry(0x7FFFFFFDE000, 0x22000, 0x03, 0x02, "[stack]"),
    ]


def test_render_vas_table_basic():
    """VAS table renders HTML with expected columns."""
    from ui.views.vas_view import render_vas_table
    mo = _make_mo()
    entries = _make_vas_entries()
    result = render_vas_table(mo, entries)
    mo.Html.assert_called_once()
    html = mo.Html.call_args[0][0]
    assert "Base Address" in html
    assert "0x400000" in html
    assert "[stack]" in html


def test_render_vas_table_empty():
    """Empty VAS entries returns fallback message."""
    from ui.views.vas_view import render_vas_table
    mo = _make_mo()
    render_vas_table(mo, [])
    mo.md.assert_called_once()


def test_render_vas_map_empty():
    """Empty VAS entries returns fallback message."""
    from ui.views.vas_view import render_vas_map
    mo = _make_mo()
    render_vas_map(mo, [])
    mo.md.assert_called_once()


def test_render_session_view_basic():
    """Session view renders process info."""
    from ui.views.session_view import render_session_view
    from msl.session_extract import SessionReport
    from msl.types import MslProcessIdentity, MslBlockHeader

    mo = _make_mo()
    hdr = MslBlockHeader(
        block_type=0x0040, flags=0, block_length=80,
        payload_version=1, block_uuid=UUID(int=1),
        parent_uuid=UUID(int=0), prev_hash=b"\x00" * 32,
        file_offset=0, payload_offset=80,
    )
    pi = MslProcessIdentity(
        block_header=hdr, ppid=1000, session_id=1,
        start_time_ns=0, exe_path="/usr/bin/test",
        cmd_line="test --flag",
    )
    report = SessionReport(
        dump_uuid=UUID(int=42), pid=1234,
        os_type="LINUX", arch_type="X86_64",
        timestamp_ns=1_700_000_000_000_000_000,
        process_identity=pi,
        region_count=1, total_region_size=4096,
        captured_page_count=1,
    )
    result = render_session_view(mo, report)
    mo.Html.assert_called_once()
    html = mo.Html.call_args[0][0]
    assert "1234" in html
    assert "LINUX" in html
    assert "/usr/bin/test" in html


def test_render_session_view_no_modules():
    """Session view handles empty modules gracefully."""
    from ui.views.session_view import render_session_view
    from msl.session_extract import SessionReport

    mo = _make_mo()
    report = SessionReport(
        dump_uuid=UUID(int=42), pid=1234,
        os_type="LINUX", arch_type="X86_64",
        timestamp_ns=1_700_000_000_000_000_000,
    )
    result = render_session_view(mo, report)
    mo.Html.assert_called_once()
    html = mo.Html.call_args[0][0]
    assert "Modules" not in html


def test_render_session_view_none():
    """None report returns fallback."""
    from ui.views.session_view import render_session_view
    mo = _make_mo()
    render_session_view(mo, None)
    mo.md.assert_called_once()
