"""``memdiver notebook`` and the case-explorer marimo template (T6.5)."""

import argparse
import importlib.util
import json
from pathlib import Path
from unittest import mock

import pyarrow as pa
import pytest

from memdiver.analysis.case import Case
from memdiver.cli import dataset
from memdiver.ui.notebooks import case_explorer_data as data

needs_marimo = pytest.mark.skipif(importlib.util.find_spec("marimo") is None,
                                  reason="marimo extra not installed")
CAPTURE = "ab" * 32


@pytest.fixture
def marimo_runnable(monkeypatch):
    """Skip marimo's matplotlib post-run hook (always, deterministically).

    marimo registers a matplotlib post-run hook whenever the package is
    *installed*; a NumPy-ABI-broken matplotlib then fails ``App.run`` itself (and
    importing it trips pytest-qt), none of which concerns this notebook.
    """
    from marimo._dependencies.dependencies import DependencyManager
    monkeypatch.setattr(DependencyManager.matplotlib, "has", lambda *a, **k: False)


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    c = Case.init(tmp_path / "nb_case")
    rows = [(1, 0, "init"), (2, 1, "sshd"), (3, 2, "bash"), (4, 99, "orphan")]
    table = pa.table({"pid": [r[0] for r in rows], "ppid": [r[1] for r in rows],
                      "comm": [r[2] for r in rows],
                      "offset_v": pa.array([0xFFFF800000001000 + 0x1000 * r[0] for r in rows],
                                           pa.uint64())})
    c.register_table(data.PSLIST_TABLE, table, capture_id=CAPTURE, producer="test",
                     locations={"offset_v": "kernel_va"})
    return c


def _args(case_ref, **kw):
    base = dict(case=str(case_ref), edit=False, port=None, headless=False)
    return argparse.Namespace(**{**base, **kw})


def test_cli_builds_marimo_run_argv(case):
    with mock.patch.object(dataset.subprocess, "call", return_value=0) as call, \
            mock.patch("importlib.util.find_spec", return_value=object()):
        assert dataset._cmd_notebook(_args(case.dir, port=2718, headless=True)) == 0
    argv = call.call_args[0][0]
    assert argv[1:4] == ["-m", "marimo", "run"]
    assert argv[4].endswith("ui/notebooks/case_explorer.py")
    assert "--port" in argv and "2718" in argv and "--headless" in argv
    assert argv[-3:] == ["--", "--case", str(case.dir)]


def test_cli_edit_flag(case):
    with mock.patch.object(dataset.subprocess, "call", return_value=0) as call, \
            mock.patch("importlib.util.find_spec", return_value=object()):
        dataset._cmd_notebook(_args(case.dir, edit=True))
    assert call.call_args[0][0][3] == "edit"


def test_cli_missing_marimo_prints_hint(case, capsys):
    with mock.patch("importlib.util.find_spec", return_value=None), \
            mock.patch.object(dataset.subprocess, "call") as call:
        assert dataset._cmd_notebook(_args(case.dir)) == 1
    call.assert_not_called()
    assert "marimo" in capsys.readouterr().err.lower()


def test_cli_bad_case_errors(tmp_path, capsys):
    assert dataset._cmd_notebook(_args(tmp_path / "nope")) == 1
    assert "not a case directory" in capsys.readouterr().err


def test_parser_registers_notebook():
    from memdiver.cli.main import build_parser
    ns = build_parser().parse_args(["notebook", "c", "--edit", "--port", "9"])
    assert (ns.command, ns.case, ns.edit, ns.port) == ("notebook", "c", True, 9)


def test_process_tree_and_missing_table(case, tmp_path):
    tree = data.process_tree(case)
    assert sorted(tree["roots"]) == [1, 4]       # orphan's parent is not in the run
    assert len(tree["nodes"]) == 4
    assert [r["process"] for r in data.tree_lines(tree)] == [
        "init", "    sshd", "        bash", "orphan"]
    empty = Case.init(tmp_path / "empty_case")
    assert "no vol3__linux_pslist" in data.process_tree(empty)["message"]


def test_process_tree_surfaces_truncation(case, monkeypatch):
    assert data.process_tree(case)["truncated"] is False
    monkeypatch.setattr(data, "PSLIST_ROW_LIMIT", 2)
    tree = data.process_tree(case)
    assert tree["truncated"] is True and len(tree["nodes"]) == 2


def test_hexdump_marks_absent_bytes_not_zero():
    out = data.hexdump(b"\x41\x00\x42", [True, False, True], 0x10)
    assert "41 -- 42" in out and "00" not in out.split("  ")[1]


def test_case_arg_prefers_cli_then_env(monkeypatch):
    monkeypatch.setenv("MEMDIVER_CASE", "from_env")
    assert data.case_arg({"case": "from_cli"}) == "from_cli"
    assert data.case_arg({}) == "from_env"


@needs_marimo
def test_template_runs_headless_on_synthetic_case(case, monkeypatch, marimo_runnable):
    monkeypatch.setenv("MEMDIVER_CASE", str(case.dir))
    from memdiver.ui.notebooks.case_explorer import app
    _outputs, defs = app.run()
    assert len(defs["tree"]["nodes"]) == 4
    assert defs["case"].name == "nb_case"


@needs_marimo
def test_template_without_case_does_not_raise(monkeypatch, marimo_runnable):
    monkeypatch.delenv("MEMDIVER_CASE", raising=False)
    from memdiver.ui.notebooks.case_explorer import app
    app.run()


REAL = Path.home() / ".memdiver" / "cases" / "p6_gate_wf1"


@pytest.mark.skipif(not REAL.is_dir(), reason="real p6 case not present")
def test_real_case_tree_and_hex():
    import memdiver
    c = memdiver.open_case(REAL)
    tree = data.process_tree(c)
    assert len(tree["nodes"]) == 122
    views = data.kernel_view_paths(c.dir)
    ctx = data.context_for_row(c.dir, tree["nodes"][1], views[0])
    assert ctx["captured"] == data.MAX_HEX_BYTES and ctx["layers"]
