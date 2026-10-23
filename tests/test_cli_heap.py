"""Tests for the ``heap`` CLI subcommand group (cli/heap.py).

Parses real argv through the top-level parser and dispatches through
``_cmd_heap`` against a synthetic glibc heap (regioned raw dump with a
``libc.so.6`` mapping), checking both the JSON payload and the text report.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from memdiver.cli import _HEAP_HANDLERS, _build_parser, _cmd_heap
from memdiver.heap.analyze import clear_heap_cache
from tests.fixtures import synth_heap as sh

LIBC = (0x7F00_1000_0000, 0x2000, "/usr/lib/x86_64-linux-gnu/libc.so.6")


@pytest.fixture(autouse=True)
def _fresh_cache():
    clear_heap_cache()
    yield
    clear_heap_cache()


@pytest.fixture
def glibc():
    return sh.glibc_heap()


@pytest.fixture
def dump(tmp_path, glibc) -> str:
    return str(sh.as_regioned_raw(tmp_path, [glibc], modules=[LIBC]))


def _run(argv):
    args = _build_parser().parse_args(["heap", *argv])
    assert args.command == "heap"
    return _cmd_heap(args)


def _run_json(argv, capsys):
    rc = _run([*argv, "--json"])
    return rc, json.loads(capsys.readouterr().out)


# -- parser wiring ----------------------------------------------------------------


def test_every_action_parses_and_has_a_handler():
    parser = _build_parser()
    assert set(_HEAP_HANDLERS) == {"detect", "summary", "chunks", "at",
                                   "free-lists", "roles"}
    for action in _HEAP_HANDLERS:
        extra = ["--va", "0x10"] if action == "at" else []
        args = parser.parse_args(["heap", action, "/tmp/x.bin", *extra])
        assert args.heap_action == action
        assert args.dump_path == "/tmp/x.bin"
        assert args.allocator == "auto"
        assert args.base_va is None and args.json is False


def test_common_options_parse_hex_and_key_flags():
    args = _build_parser().parse_args([
        "heap", "summary", "/tmp/x.msl", "--allocator", "jemalloc",
        "--base-va", "0x7f0000000000", "--key-file", "k.bin",
        "--passphrase", "pw", "--kem-key-file", "kem.bin", "--json"])
    assert args.allocator == "jemalloc"
    assert args.base_va == 0x7F00_0000_0000
    assert (args.key_file, args.passphrase, args.kem_key_file) == (
        "k.bin", "pw", "kem.bin")
    assert args.json is True


def test_chunks_options_parse():
    args = _build_parser().parse_args([
        "heap", "chunks", "/tmp/x.bin", "--state", "cached", "--min-size",
        "0x20", "--max-size", "64", "--va-start", "0x1000", "--va-end",
        "0x2000", "--view", "raw", "--page", "2", "--page-size", "10"])
    assert (args.state, args.min_size, args.max_size) == ("cached", 0x20, 64)
    assert (args.va_start, args.va_end) == (0x1000, 0x2000)
    assert (args.view, args.page, args.page_size) == ("raw", 2, 10)


@pytest.mark.parametrize("argv", [
    ["summary", "/tmp/x.bin", "--allocator", "tcmalloc"],
    ["chunks", "/tmp/x.bin", "--state", "zombie"],
    ["chunks", "/tmp/x.bin", "--view", "file"],
    ["at", "/tmp/x.bin"],
    ["at", "/tmp/x.bin", "--va", "1", "--offset", "2"],
    ["detect", "/tmp/x.bin", "--base-va", "nope"],
])
def test_bad_arguments_are_rejected_by_the_parser(argv):
    with pytest.raises(SystemExit) as exc:
        _build_parser().parse_args(["heap", *argv])
    assert exc.value.code == 2


def test_missing_action_prints_choices(capsys):
    args = _build_parser().parse_args(["heap"])
    assert _cmd_heap(args) == 1
    assert "pick an action" in capsys.readouterr().err


# -- detect -----------------------------------------------------------------------


def test_detect_json(dump, capsys):
    rc, data = _run_json(["detect", dump], capsys)
    assert rc == 0
    assert data["best"] == "ptmalloc2"
    assert data["candidates"][0]["kind"] == "ptmalloc2"


def test_detect_text(dump, capsys):
    assert _run(["detect", dump]) == 0
    out = capsys.readouterr().out
    assert "Allocator:  ptmalloc2" in out
    assert "glibc mapped: libc.so.6" in out


def test_detect_honours_allocator_hint(dump, capsys):
    rc, data = _run_json(["detect", dump, "--allocator", "jemalloc"], capsys)
    assert rc == 0
    assert data["best"] == "jemalloc" and data["hinted"] is True


# -- summary ----------------------------------------------------------------------


def test_summary_json(dump, glibc, capsys):
    rc, data = _run_json(["summary", dump], capsys)
    assert rc == 0
    assert data["allocator"] == "ptmalloc2"
    assert data["chunk_count"] == len(glibc.chunks)
    assert data["counts_by_state"] == {"in_use": 4, "cached": 3, "free": 1}


def test_summary_text_report(dump, capsys):
    assert _run(["summary", dump]) == 0
    out = capsys.readouterr().out
    for needle in ("Allocator:  ptmalloc2", "Confidence: 1.0",
                   "Flags:      none", "Chunks by state:", "cached",
                   "Size histogram:", "32-63", "Evidence:"):
        assert needle in out


def test_summary_text_flags_heuristic_fallback(dump, capsys):
    assert _run(["summary", dump, "--allocator", "generic"]) == 0
    assert "heuristic" in capsys.readouterr().out.split("Format:")[0]


def test_summary_writes_output_file(dump, tmp_path):
    out = tmp_path / "summary.json"
    assert _run(["summary", dump, "-o", str(out)]) == 0
    assert json.loads(out.read_text())["allocator"] == "ptmalloc2"


# -- chunks -----------------------------------------------------------------------


def test_chunks_json_filters_by_state(dump, glibc, capsys):
    rc, data = _run_json(["chunks", dump, "--state", "cached"], capsys)
    assert rc == 0
    expected = [c.va for c in glibc.chunks if c.state.value == "cached"]
    assert [row["va"] for row in data["chunks"]] == expected
    assert data["filters"]["state"] == "cached"


def test_chunks_json_paging(dump, glibc, capsys):
    rc, data = _run_json(["chunks", dump, "--page", "1", "--page-size", "3"],
                         capsys)
    assert rc == 0
    assert data["page"] == 1 and data["page_size"] == 3
    assert [row["va"] for row in data["chunks"]] == [
        c.va for c in glibc.chunks[3:6]]


def test_chunks_text_table(dump, capsys):
    assert _run(["chunks", dump, "--page-size", "3"]) == 0
    out = capsys.readouterr().out
    assert "VA" in out and "STATE" in out and "VIEW_OFFSET" in out
    assert "tcache_perthread_struct" in out
    assert "page 1/3" in out


def test_chunks_va_and_offset_window_together_is_an_error(dump, capsys):
    rc = _run(["chunks", dump, "--va-start", "0x10", "--offset", "0",
               "--length", "4"])
    assert rc == 1
    assert "not both" in capsys.readouterr().err


def test_chunks_bad_page_size_json_error(dump, capsys):
    rc, data = _run_json(["chunks", dump, "--page-size", "0"], capsys)
    assert rc == 1
    assert "page_size" in data["error"]


# -- at ---------------------------------------------------------------------------


def test_at_va_json(dump, glibc, capsys):
    target = glibc.chunks[3]
    rc, data = _run_json(["at", dump, "--va", hex(target.va + 16)], capsys)
    assert rc == 0
    assert data["found"] is True
    assert data["chunk"]["va"] == target.va
    assert data["role"] == "user_data"
    assert data["prev"]["va"] == glibc.chunks[2].va


def test_at_offset_matches_va(dump, glibc, capsys):
    target = glibc.chunks[3]
    offset = target.va + 16 - glibc.base_va
    rc, data = _run_json(["at", dump, "--offset", hex(offset), "--view", "vas"],
                         capsys)
    assert rc == 0
    assert data["va"] == target.va + 16


def test_at_text_unmapped_address(dump, capsys):
    assert _run(["at", dump, "--va", "0x1"]) == 0
    out = capsys.readouterr().out
    assert "No chunk contains this address." in out
    assert "next" in out


def test_at_text_found(dump, capsys):
    assert _run(["at", dump, "--va", "0x555555559300"]) == 0
    out = capsys.readouterr().out
    assert "Role:      user_data" in out
    assert "chunk" in out and "prev" in out


# -- free-lists -------------------------------------------------------------------


def test_free_lists_json(dump, capsys):
    rc, data = _run_json(["free-lists", dump], capsys)
    assert rc == 0
    assert data["kinds"] == ["tcache"]
    assert data["list_count"] == 2


def test_free_lists_kind_filter(dump, capsys):
    rc, data = _run_json(["free-lists", dump, "--kind", "fastbin"], capsys)
    assert rc == 0
    assert data["list_count"] == 0


def test_free_lists_text(dump, capsys):
    assert _run(["free-lists", dump]) == 0
    out = capsys.readouterr().out
    assert "KIND" in out and "tcache" in out and "corrupt: 0" in out


# -- errors -----------------------------------------------------------------------


def test_missing_file_text_goes_to_stderr(tmp_path, capsys):
    assert _run(["summary", str(tmp_path / "nope.bin")]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "memdiver heap: ERROR" in captured.err


def test_missing_file_json_error(tmp_path, capsys):
    rc, data = _run_json(["detect", str(tmp_path / "nope.bin")], capsys)
    assert rc == 1
    assert "error" in data


# -- roles ------------------------------------------------------------------------


def test_roles_options_parse():
    args = _build_parser().parse_args([
        "heap", "roles", "/tmp/x.bin", "--view", "raw", "--offset", "0x100",
        "--length", "0x200"])
    assert (args.view, args.offset, args.length) == ("raw", 0x100, 0x200)
    defaults = _build_parser().parse_args(["heap", "roles", "/tmp/x.bin"])
    assert (defaults.view, defaults.offset, defaults.length) == ("vas", 0, 65536)


def test_roles_json(dump, glibc, capsys):
    rc, payload = _run_json(["roles", dump, "--length", "0x1000"], capsys)
    assert rc == 0
    assert payload["allocator"] == "ptmalloc2"
    assert payload["chunk_starts"] == [c.va - glibc.base_va for c in glibc.chunks]
    assert payload["runs"][0]["role"] == "allocator_meta"
    assert sum(r["length"] for r in payload["runs"]) == sh.PAGE


def test_roles_text(dump, capsys):
    assert _run(["roles", dump, "--length", "0x400"]) == 0
    out = capsys.readouterr().out
    assert "ROLE" in out and "allocator_meta" in out and "free_link" in out


def test_roles_too_long_json_error(dump, capsys):
    rc, payload = _run_json(["roles", dump, "--length", str((1 << 20) + 1)],
                            capsys)
    assert rc != 0 and "error" in payload
