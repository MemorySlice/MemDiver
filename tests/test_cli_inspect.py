"""Tests for the ``inspect`` CLI subcommand group.

Exercises both the parser (argument wiring, nested action dispatch, decrypt
flag parsing) and the handlers end-to-end against a synthetic MSL fixture.
The handlers reuse the same pure tool functions as the HTTP `/api/inspect`
endpoints, so these tests focus on the CLI adapter layer.
"""
import argparse
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from memdiver.cli import _build_parser
from tests.fixtures.generate_msl_fixtures import write_msl_fixture


@pytest.fixture
def msl_fixture(tmp_path) -> Path:
    """A complete synthetic .msl capture on disk."""
    return write_msl_fixture(tmp_path / "capture.msl")


# ---------------------------------------------------------------------------
# Parser wiring
# ---------------------------------------------------------------------------


def test_parser_inspect_hex_command():
    parser = _build_parser()
    args = parser.parse_args([
        "inspect", "hex", "/tmp/x.msl", "--offset", "0x10", "--length", "64",
        "--view", "vas",
    ])
    assert args.command == "inspect"
    assert args.inspect_action == "hex"
    assert args.dump_path == "/tmp/x.msl"
    assert args.offset == 0x10
    assert args.length == 64
    assert args.view == "vas"


def test_parser_inspect_byte_search_requires_pattern():
    parser = _build_parser()
    args = parser.parse_args([
        "inspect", "byte-search", "/tmp/x.msl", "--pattern", "0xdeadbeef",
    ])
    assert args.inspect_action == "byte-search"
    assert args.pattern == "0xdeadbeef"
    with pytest.raises(SystemExit):
        parser.parse_args(["inspect", "byte-search", "/tmp/x.msl"])


def test_parser_inspect_all_actions_build():
    """Every advertised action parses and dispatches to a distinct handler."""
    from memdiver.cli import _INSPECT_HANDLERS

    parser = _build_parser()
    for action in ("page-states", "session-info", "vas", "processes", "modules",
                   "handles", "xref"):
        args = parser.parse_args(["inspect", action, "/tmp/x.msl"])
        assert args.inspect_action == action
    assert set(_INSPECT_HANDLERS) == {
        # P2.4 added "region" — the per-offset investigation view, wired on all
        # four surfaces so its producer could leave EXEMPT_PRODUCERS.
        "hex", "entropy", "region", "strings", "byte-search",
        "page-states", "session-info", "vas", "processes", "modules", "handles",
        "xref", "structure",
    }


def test_parser_inspect_decrypt_flags_parse():
    """The decrypt parent parser is attached to inspect actions."""
    parser = _build_parser()
    args = parser.parse_args([
        "inspect", "session-info", "/tmp/x.msl",
        "--key-file", "/tmp/k.bin",
        "--passphrase", "hunter2",
        "--kem-key-file", "/tmp/kem.priv",
    ])
    assert args.key_file == "/tmp/k.bin"
    assert args.passphrase == "hunter2"
    assert args.kem_key_file == "/tmp/kem.priv"


# ---------------------------------------------------------------------------
# Handlers end-to-end against a fixture
# ---------------------------------------------------------------------------


def test_cmd_inspect_session_info(tmp_path, msl_fixture):
    from memdiver.cli import _cmd_inspect_session_info

    out = tmp_path / "session.json"
    args = argparse.Namespace(msl_path=str(msl_fixture), output=str(out))
    rc = _cmd_inspect_session_info(args)
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["pid"] == 1234
    assert data["region_count"] >= 1
    assert data["captured_page_count"] >= 1


def test_cmd_inspect_vas(tmp_path, msl_fixture):
    from memdiver.cli import _cmd_inspect_vas

    out = tmp_path / "vas.json"
    args = argparse.Namespace(msl_path=str(msl_fixture), output=str(out))
    rc = _cmd_inspect_vas(args)
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["region_count"] >= 1
    assert "total_region_size" in data
    assert isinstance(data["vas_coverage"], dict)
    entries = data["vas_entries"]
    assert len(entries) >= 1
    # The full five-field VAS entry shape the VasChart frontend consumes.
    assert set(entries[0]) == {
        "base_addr", "region_size", "region_type", "protection", "mapped_path",
    }
    # The fixture seeds a libssl mapping at the canonical base.
    libssl = next(e for e in entries if e["mapped_path"] == "/usr/lib/libssl.so")
    assert libssl["base_addr"] == 0x00400000
    assert libssl["region_size"] == 0x10000


def test_cmd_inspect_hex(tmp_path, msl_fixture):
    from memdiver.cli import _cmd_inspect_hex

    out = tmp_path / "hex.json"
    args = argparse.Namespace(
        dump_path=str(msl_fixture), offset=0, length=16,
        view="raw", output=str(out),
    )
    rc = _cmd_inspect_hex(args)
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["format"] == "msl"
    assert data["offset"] == 0
    assert data["length"] == 16
    assert len(data["hex_lines"]) == 1
    # The MSL container starts with the "MEMSLICE" magic.
    assert data["hex_lines"][0].split("|")[1].startswith("MEMSLICE")


def test_cmd_inspect_page_states(tmp_path, msl_fixture):
    from memdiver.cli import _cmd_inspect_page_states

    out = tmp_path / "pages.json"
    args = argparse.Namespace(msl_path=str(msl_fixture), output=str(out))
    rc = _cmd_inspect_page_states(args)
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["total_pages"] >= 1
    assert data["captured_pages"] >= 1
    assert data["coverage"] == pytest.approx(1.0)
    assert data["regions"]
    assert data["regions"][0]["intervals"][0]["state"] == "CAPTURED"


def test_cmd_inspect_processes(tmp_path, msl_fixture):
    from memdiver.cli import _cmd_inspect_processes

    out = tmp_path / "processes.json"
    args = argparse.Namespace(msl_path=str(msl_fixture), output=str(out))
    rc = _cmd_inspect_processes(args)
    assert rc == 0
    data = json.loads(out.read_text())
    assert "processes" in data
    procs = data["processes"]
    assert len(procs) >= 1
    entry = procs[0]
    assert set(entry) == {
        "pid", "ppid", "uid", "is_target", "start_time_ns",
        "rss", "exe_name", "cmd_line", "user",
    }
    pids = {p["pid"] for p in procs}
    assert 1234 in pids


def test_cmd_inspect_modules(tmp_path, msl_fixture):
    from memdiver.cli import _cmd_inspect_modules

    out = tmp_path / "modules.json"
    args = argparse.Namespace(msl_path=str(msl_fixture), output=str(out))
    rc = _cmd_inspect_modules(args)
    assert rc == 0
    data = json.loads(out.read_text())
    assert "modules" in data
    mods = data["modules"]
    assert len(mods) >= 1
    entry = mods[0]
    assert set(entry) == {"path", "base_addr", "size", "version"}
    assert isinstance(entry["base_addr"], int)


def test_cmd_inspect_handles(tmp_path, msl_fixture):
    from memdiver.cli import _cmd_inspect_handles

    out = tmp_path / "handles.json"
    args = argparse.Namespace(msl_path=str(msl_fixture), output=str(out))
    rc = _cmd_inspect_handles(args)
    assert rc == 0
    data = json.loads(out.read_text())
    assert "handles" in data
    handles = data["handles"]
    assert len(handles) >= 1
    entry = handles[0]
    assert set(entry) == {
        "pid", "fd", "handle_type", "handle_type_name", "path",
    }
    assert isinstance(entry["handle_type_name"], str)


def test_cmd_inspect_processes_missing_file(tmp_path, capsys):
    """A missing file yields an error dict and a non-zero exit code."""
    from memdiver.cli import _cmd_inspect_processes

    args = argparse.Namespace(msl_path=str(tmp_path / "nope.msl"), output=None)
    rc = _cmd_inspect_processes(args)
    assert rc == 1
    data = json.loads(capsys.readouterr().out)
    assert "error" in data


def test_cmd_inspect_byte_search(tmp_path, msl_fixture):
    from memdiver.cli import _cmd_inspect_byte_search

    out = tmp_path / "search.json"
    # The captured page begins with 0xAA*32 then 0xBB*32; "aabb" straddles it.
    args = argparse.Namespace(
        dump_path=str(msl_fixture), pattern="aabb",
        view="raw", max_results=500, output=str(out),
    )
    rc = _cmd_inspect_byte_search(args)
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["pattern_hex"] == "aabb"
    assert data["count"] >= 1


def test_cmd_inspect_entropy(tmp_path, msl_fixture):
    from memdiver.cli import _cmd_inspect_entropy

    out = tmp_path / "entropy.json"
    args = argparse.Namespace(
        dump_path=str(msl_fixture), offset=0, length=0,
        window=32, step=16, threshold=7.5, output=str(out),
    )
    rc = _cmd_inspect_entropy(args)
    assert rc == 0
    data = json.loads(out.read_text())
    assert "overall_entropy" in data
    assert "stats" in data


def test_cmd_inspect_session_info_missing_file(tmp_path, capsys):
    """A missing file yields an error dict and a non-zero exit code."""
    from memdiver.cli import _cmd_inspect_session_info

    args = argparse.Namespace(msl_path=str(tmp_path / "nope.msl"), output=None)
    rc = _cmd_inspect_session_info(args)
    assert rc == 1
    data = json.loads(capsys.readouterr().out)
    assert "error" in data


def test_cmd_inspect_dispatch_unknown_action(capsys):
    """`inspect` with no action prints the available actions and exits 1."""
    from memdiver.cli import _cmd_inspect

    rc = _cmd_inspect(argparse.Namespace(inspect_action=None))
    assert rc == 1
    assert "pick an action" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# byte-search --format (multi-format needles)
# ---------------------------------------------------------------------------


@pytest.fixture
def text_dump(tmp_path) -> Path:
    """A raw dump with an ASCII token at a known offset (8)."""
    p = tmp_path / "token.dump"
    p.write_bytes(b"\x00" * 8 + b"SECRET" + b"\x00" * 8)
    return p


def test_parser_inspect_byte_search_accepts_every_format():
    """``--format`` is wired to ``NEEDLE_FORMATS``, not a hand-copied list.

    Parametrising over the constant is what keeps the CLI from drifting behind
    the other three surfaces: a format added to the shared tuple but not to the
    parser would make this fail instead of silently being CLI-unreachable.
    """
    from memdiver.core.needle import NEEDLE_FORMATS

    parser = _build_parser()
    for fmt in NEEDLE_FORMATS:
        args = parser.parse_args([
            "inspect", "byte-search", "/tmp/x.msl", "--pattern", "SECRET",
            "--format", fmt,
        ])
        assert args.format == fmt


def test_parser_inspect_byte_search_format_defaults_to_hex():
    """The default is ``hex``, NOT ``auto``: an odd-length hex string is an
    error on the machine surfaces today, and under ``auto`` it would become a
    silent text search. A script pinned to this command must keep searching
    exactly the bytes it always did."""
    parser = _build_parser()
    args = parser.parse_args([
        "inspect", "byte-search", "/tmp/x.msl", "--pattern", "deadbeef",
    ])
    assert args.format == "hex"


def test_parser_inspect_byte_search_rejects_an_unknown_format():
    """argparse ``choices`` must reject a near-miss spelling at PARSE time.

    ``--format=utf16`` failing loudly with the valid list is the difference
    between a one-character fix and a search that quietly ran as something
    else.
    """
    parser = _build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([
            "inspect", "byte-search", "/tmp/x.msl", "--pattern", "SECRET",
            "--format", "utf16",
        ])


def test_cmd_inspect_byte_search_text_format(tmp_path, text_dump):
    """The handler forwards ``--format`` to the producer.

    Asserting the RESOLVED ``pattern_hex`` (not just a hit count) is what
    proves the text was encoded rather than parsed as hex: ``SECRET`` is not
    valid hex at all, so a handler that dropped the format would error instead
    of returning these bytes.
    """
    from memdiver.cli import _cmd_inspect_byte_search

    out = tmp_path / "search.json"
    args = argparse.Namespace(
        dump_path=str(text_dump), pattern="SECRET", format="text",
        view="raw", max_results=500, output=str(out),
    )
    rc = _cmd_inspect_byte_search(args)
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["pattern_hex"] == b"SECRET".hex()
    assert data["pattern_format"] == "text"
    assert data["offsets"] == [8]


def test_cmd_inspect_byte_search_without_a_format_attribute(tmp_path, text_dump):
    """A hand-built ``Namespace`` with NO ``format`` attribute still works.

    The handler reads it with ``getattr(args, "format", "hex")`` for exactly
    this reason: the CLI is also called programmatically (and by older tests)
    with a Namespace assembled by hand, and a bare ``args.format`` would turn
    every such caller into an AttributeError crash the moment the flag was
    added. The fallback must be ``hex``, so the pre-flag behaviour is what they
    get.
    """
    from memdiver.cli import _cmd_inspect_byte_search

    out = tmp_path / "search_nofmt.json"
    args = argparse.Namespace(
        dump_path=str(text_dump), pattern="534543524554",
        view="raw", max_results=500, output=str(out),
    )
    assert not hasattr(args, "format")
    rc = _cmd_inspect_byte_search(args)
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["pattern_format"] == "hex"
    assert data["pattern_hex"] == b"SECRET".hex()
    assert data["offsets"] == [8]


def test_cmd_inspect_byte_search_invalid_pattern_exits_nonzero(tmp_path, text_dump, capsys):
    """A bad needle is a caller error: an error dict on stdout and a non-zero
    exit code, matching every other inspect handler — not a traceback."""
    from memdiver.cli import _cmd_inspect_byte_search

    args = argparse.Namespace(
        dump_path=str(text_dump), pattern="abc", format="hex",
        view="raw", max_results=500, output=None,
    )
    rc = _cmd_inspect_byte_search(args)
    assert rc == 1
    data = json.loads(capsys.readouterr().out)
    assert "error" in data
