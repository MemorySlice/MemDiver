"""Direct unit tests for small shared helpers that otherwise had only indirect coverage.

* ``analysis.plugin_store``: ``read_json_dict`` / ``json_dicts_in`` / ``put_versioned_json``
* ``cli._shared``: ``output_parent_parser`` / ``emit`` / ``_auto_int``
* ``app.tools_semantic._present_many`` over a raw dump
* ``core.sandbox_roots.configured_roots`` (``split_list_setting`` reuse)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from types import SimpleNamespace

import pytest

from memdiver.analysis import plugin_store
from memdiver.analysis.plugin_store import json_dicts_in, put_versioned_json, read_json_dict
from memdiver.cli._shared import _auto_int, emit, output_parent_parser


# -- plugin_store.read_json_dict -----------------------------------------------------

def test_read_json_dict_returns_the_object(tmp_path):
    path = tmp_path / "a.json"
    path.write_text(json.dumps({"k": [1, 2]}), encoding="utf-8")
    assert read_json_dict(path) == {"k": [1, 2]}


@pytest.mark.parametrize("content", ["[1, 2]", "3", '"s"', "null", "{not json", "\xff"])
def test_read_json_dict_rejects_non_objects_and_garbage(tmp_path, content):
    path = tmp_path / "a.json"
    path.write_bytes(content.encode("latin-1"))
    assert read_json_dict(path) is None


def test_read_json_dict_missing_file_and_directory(tmp_path):
    assert read_json_dict(tmp_path / "absent.json") is None
    assert read_json_dict(tmp_path) is None


# -- plugin_store.json_dicts_in ------------------------------------------------------

def test_json_dicts_in_yields_readable_objects_sorted_and_skips_the_rest(tmp_path):
    (tmp_path / "b.json").write_text('{"n": "b"}')
    (tmp_path / "a.json").write_text('{"n": "a"}')
    (tmp_path / "list.json").write_text("[1]")
    (tmp_path / "bad.json").write_text("{")
    (tmp_path / "other.txt").write_text('{"n": "txt"}')
    target = tmp_path / "outside.json"
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "nested.json").write_text('{"n": "nested"}')
    target.write_text('{"n": "outside"}')
    (sub / "link.json").symlink_to(target)
    got = [(p.name, body) for p, body in json_dicts_in(tmp_path)]
    assert got == [("a.json", {"n": "a"}), ("b.json", {"n": "b"}),
                   ("outside.json", {"n": "outside"})]
    assert [p.name for p, _ in json_dicts_in(sub)] == ["nested.json"]


def test_json_dicts_in_missing_directory_is_empty(tmp_path):
    assert list(json_dicts_in(tmp_path / "absent")) == []


# -- plugin_store.put_versioned_json -------------------------------------------------

def test_put_versioned_json_first_write_stamps_version_one(tmp_path, monkeypatch):
    monkeypatch.setattr(plugin_store, "utc_now", lambda: "T1")
    path = tmp_path / "x.json"
    out = put_versioned_json(path, "x", {"body": 1})
    text = path.read_text(encoding="utf-8")
    assert json.loads(text) == {"body": 1, "created": "T1", "updated": "T1", "version": 1}
    assert text.endswith("\n")
    assert out == {"body": 1, "created": "T1", "updated": "T1", "version": 1,
                   "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                   "path": str(path)}
    assert not (tmp_path / plugin_store.HISTORY_DIR).exists()


def test_put_versioned_json_rewrite_bumps_version_keeps_created_and_archives(tmp_path,
                                                                            monkeypatch):
    path = tmp_path / "x.json"
    monkeypatch.setattr(plugin_store, "utc_now", lambda: "T1")
    put_versioned_json(path, "x", {"body": 1})
    first_text = path.read_text(encoding="utf-8")
    monkeypatch.setattr(plugin_store, "utc_now", lambda: "T2")
    out = put_versioned_json(path, "x", {"body": 2})
    assert (out["created"], out["updated"], out["version"], out["body"]) == ("T1", "T2", 2, 2)
    history = list((tmp_path / plugin_store.HISTORY_DIR).iterdir())
    assert len(history) == 1
    assert history[0].name.startswith("x-") and history[0].suffix == ".json"
    assert history[0].read_text(encoding="utf-8") == first_text


def test_put_versioned_json_over_a_non_object_restarts_versioning(tmp_path, monkeypatch):
    monkeypatch.setattr(plugin_store, "utc_now", lambda: "T9")
    path = tmp_path / "x.json"
    path.write_text("[1, 2]", encoding="utf-8")
    out = put_versioned_json(path, "x", {"body": 3})
    assert (out["version"], out["created"]) == (1, "T9")
    archived = list((tmp_path / plugin_store.HISTORY_DIR).iterdir())
    assert [p.read_text(encoding="utf-8") for p in archived] == ["[1, 2]"]


# -- cli._shared ---------------------------------------------------------------------

def _parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(prog="t", parents=[output_parent_parser()])


def test_output_parent_parser_defaults_and_flags():
    assert vars(_parser().parse_args([])) == {"output": None, "verbose": False}
    args = _parser().parse_args(["-o", "out.json", "-v"])
    assert (args.output, args.verbose) == ("out.json", True)
    args = _parser().parse_args(["--output", "o.json", "--verbose"])
    assert (args.output, args.verbose) == ("o.json", True)


def test_output_parent_parser_adds_no_help_of_its_own():
    assert not any("-h" in a.option_strings for a in output_parent_parser()._actions)
    _parser()  # attaching it to a parser with -h does not conflict


def test_emit_to_stdout(capsys):
    assert emit(SimpleNamespace(output=None), {"a": 1}) == 0
    assert json.loads(capsys.readouterr().out) == {"a": 1}


def test_emit_to_file(tmp_path, capsys):
    out = tmp_path / "o.json"
    assert emit(SimpleNamespace(output=str(out)), {"a": [1]}) == 0
    assert json.loads(out.read_text()) == {"a": [1]}
    assert capsys.readouterr().out == ""


def test_emit_unwritable_target_exits_1(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        emit(SimpleNamespace(output=str(tmp_path / "missing" / "o.json")), {})
    assert exc.value.code == 1
    assert "cannot write output" in capsys.readouterr().err


@pytest.mark.parametrize("text,value", [("0", 0), ("42", 42), ("0x2a", 42), ("0X2A", 42),
                                        ("-0x10", -16), ("0o17", 15), ("0b101", 5)])
def test_auto_int_parses_hex_and_decimal(text, value):
    assert _auto_int(text) == value


def test_auto_int_rejection_names_the_type_in_the_usage_error(capsys):
    parser = argparse.ArgumentParser(prog="t")
    parser.add_argument("--n", type=_auto_int)
    with pytest.raises(SystemExit):
        parser.parse_args(["--n", "zz"])
    assert "invalid _auto_int value: 'zz'" in capsys.readouterr().err


# -- app.tools_semantic._present_many ------------------------------------------------

def test_present_many_over_a_raw_dump(tmp_path):
    from memdiver.app.tools_semantic import _present_in, _present_many
    from memdiver.core.dump_source import RawDumpSource

    here, there, absent = b"N" * 32, b"M" * 32, b"Q" * 32
    path = tmp_path / "d.dump"
    path.write_bytes(b"\0" * 100 + here + b"\0" * 5000 + there + b"\0" * 7)
    with RawDumpSource(path) as src:
        assert _present_many(src, "raw", []) == set()
        assert _present_many(src, "raw", [here, there, absent, here]) == {here, there}
        assert {n for n in (here, there, absent) if _present_in(src, "raw", n)} == {here, there}


# -- core.sandbox_roots.configured_roots ---------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    (None, []), ("", []), (os.pathsep, []),
    (f" /a {os.pathsep}{os.pathsep} /b/c ", ["/a", "/b/c"]),
    ("/only", ["/only"]),
])
def test_configured_roots_splits_on_pathsep(monkeypatch, raw, expected):
    from memdiver.core import sandbox_roots

    monkeypatch.setattr(sandbox_roots, "_settings",
                        lambda: SimpleNamespace(allowed_roots=raw))
    assert sandbox_roots.configured_roots() == expected
