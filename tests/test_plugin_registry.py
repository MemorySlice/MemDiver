"""Stored plugin sources (plan T2.5): the store, the producers, ``source_name`` resolution."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from memdiver.analysis.case import Case
from memdiver.analysis.plugin_store import MAX_SOURCE_BYTES, PluginStore
from memdiver.api.services.plugin_registry import PluginStore as ServicesPluginStore
from memdiver.app import tools_vol3, tools_vol3_sources as sources
from memdiver.core.service_errors import CapabilityError, ErrorCategory

SOURCE = "# plugin one\nprint('x')\n"


@pytest.fixture
def case(tmp_path):
    return Case.init(tmp_path / "case")


def _code(exc_info) -> str:
    return exc_info.value.code


def test_services_entry_point_is_the_store():
    assert ServicesPluginStore is PluginStore


def test_put_get_list_round_trip(case):
    store = PluginStore(case.dir)
    assert store.list() == []
    meta = store.put("scan_one", SOURCE)
    assert meta["version"] == 1 and meta["size"] == len(SOURCE)
    got = store.get("scan_one")
    assert got["source"] == SOURCE and got["sha256"] == meta["sha256"]
    assert got["modified_externally"] is False
    assert (case.dir / "plugins" / "scan_one.py").read_text() == SOURCE
    (listed,) = store.list()
    assert listed["name"] == "scan_one" and "source" not in listed
    assert oct((case.dir / "plugins" / "scan_one.py").stat().st_mode & 0o777) == "0o600"


def test_overwrite_archives_the_previous_source_and_bumps_version(case):
    store = PluginStore(case.dir)
    first = store.put("p", SOURCE)
    second = store.put("p", SOURCE + "# more\n")
    assert second["version"] == 2 and second["created"] == first["created"]
    history = list((case.dir / "plugins" / "history").glob("p-*.py"))
    assert [h.read_text() for h in history] == [SOURCE]
    assert store.get("p")["source"].endswith("# more\n")


def test_external_edit_is_flagged(case):
    store = PluginStore(case.dir)
    store.put("p", SOURCE)
    (case.dir / "plugins" / "p.py").write_text("# edited by hand\n")
    got = store.get("p")
    assert got["modified_externally"] is True and got["source"] == "# edited by hand\n"


@pytest.mark.parametrize("name", ["", "a/b", "../x", "a.b", "1abc", ".hidden", "x" * 65, "a b"])
def test_bad_names_are_refused(case, name):
    with pytest.raises(CapabilityError) as exc:
        PluginStore(case.dir).put(name, SOURCE)
    assert _code(exc) == "plugin.bad_name"


def test_size_cap_and_empty_source(case):
    store = PluginStore(case.dir)
    with pytest.raises(CapabilityError) as exc:
        store.put("big", "#" * (MAX_SOURCE_BYTES + 1))
    assert _code(exc) == "plugin.too_large"
    with pytest.raises(CapabilityError) as exc:
        store.put("empty", "  \n")
    assert _code(exc) == "plugin.source_required"


def test_missing_plugin_is_not_found(case):
    with pytest.raises(CapabilityError) as exc:
        PluginStore(case.dir).get("nope")
    assert exc.value.category is ErrorCategory.NOT_FOUND


def test_world_writable_plugin_dir_is_refused(case):
    store = PluginStore(case.dir)
    store.put("p", SOURCE)
    os.chmod(case.dir / "plugins", 0o777)
    with pytest.raises(CapabilityError) as exc:
        store.get("p")
    assert _code(exc) == "store.insecure_dir"
    with pytest.raises(CapabilityError):
        store.put("q", SOURCE)


def test_symlinked_plugin_dir_that_escapes_is_refused(tmp_path):
    case = Case.init(tmp_path / "case")
    outside = tmp_path / "outside"
    outside.mkdir()
    (case.dir / "plugins").rmdir()
    (case.dir / "plugins").symlink_to(outside)
    with pytest.raises(CapabilityError) as exc:
        PluginStore(case.dir).put("p", SOURCE)
    assert _code(exc) == "store.escape"
    assert list(outside.iterdir()) == []


def test_symlinked_plugin_file_is_refused(case, tmp_path):
    target = tmp_path / "secret.py"
    target.write_text("# not mine\n")
    PluginStore(case.dir).put("seed", SOURCE)       # creates plugins/
    (case.dir / "plugins" / "link.py").symlink_to(target)
    with pytest.raises(CapabilityError) as exc:
        PluginStore(case.dir).get("link")
    assert _code(exc) == "store.symlink"
    with pytest.raises(CapabilityError):
        PluginStore(case.dir).put("link", SOURCE)
    assert target.read_text() == "# not mine\n"
    assert [m["name"] for m in PluginStore(case.dir).list()] == ["seed"]


# -- producers -----------------------------------------------------------------

def test_producers_put_get_list(case, monkeypatch):
    from memdiver.app import tools_vol3_dev
    monkeypatch.setattr(tools_vol3_dev, "vol3_check_result",
                        lambda src, view=None, **kw: type("R", (), {"payload": {"ok": True}})())
    put = sources.vol3_source_put_result(str(case.dir), "demo", SOURCE).payload
    assert put["stored"]["name"] == "demo" and put["check"] == {"ok": True}
    assert sources.vol3_source_get_result(str(case.dir), "demo").payload["source"] == SOURCE
    listing = sources.vol3_source_list_result(str(case.dir)).payload
    assert listing["count"] == 1 and listing["sources"][0]["name"] == "demo"


def test_put_saves_a_plugin_that_does_not_load(case):
    pytest.importorskip("volatility3")
    put = sources.vol3_source_put_result(str(case.dir), "broken", "def (:\n").payload
    assert put["check"]["ok"] is False and put["check"]["error"]["type"] == "SyntaxError"
    assert PluginStore(case.dir).get("broken")["source"] == "def (:\n"


def test_not_a_case_is_refused(tmp_path):
    with pytest.raises(CapabilityError) as exc:
        sources.vol3_source_list_result(str(tmp_path / "nothing"))
    assert _code(exc) == "case.not_a_case"


def test_resolve_source_rules(case):
    PluginStore(case.dir).put("demo", SOURCE)
    assert sources._resolve_source("raw", None, None) == "raw"
    assert sources._resolve_source(None, "demo", str(case.dir)) == SOURCE
    for args, code in [(("raw", "demo", str(case.dir)), "vol3.source_ambiguous"),
                       ((None, "demo", None), "vol3.source_case_required")]:
        with pytest.raises(CapabilityError) as exc:
            sources._resolve_source(*args)
        assert _code(exc) == code


def test_run_describe_and_check_resolve_source_name(case, monkeypatch):
    PluginStore(case.dir).put("demo", SOURCE)
    seen = []
    monkeypatch.setattr(tools_vol3, "_plugin_info", lambda plugin, src: seen.append(src)
                        or type("I", (), {"cls": object})())
    monkeypatch.setattr(tools_vol3, "_runner", lambda: type(
        "R", (), {"describe_plugin": staticmethod(lambda info: {"d": 1})})())
    assert tools_vol3.vol3_describe_result("", source_name="demo",
                                           case_dir=str(case.dir)).payload == {"d": 1}
    assert seen == [SOURCE]
    # raw source keeps working
    tools_vol3.vol3_describe_result("", "raw text")
    assert seen[-1] == "raw text"
    from memdiver.app import tools_vol3_dev
    loaded = []
    monkeypatch.setattr(tools_vol3_dev, "_load_for_check",
                        lambda src: loaded.append(src) or (None, {"ok": False}))
    tools_vol3_dev.vol3_check_result(source_name="demo", case_dir=str(case.dir))
    assert loaded == [SOURCE]


def test_real_scaffold_runs_through_source_name_alma(case):
    view = Path("/private/tmp/claude-501/-Users-danielbaier-research-projects-github-issues-"
                "2024-fritap-issues-2026-success-memory-slice-git-MemDiver/"
                "5bdc82f6-3f6f-4afb-b122-28de170adcc9/scratchpad/views/alma9_kernel.mdview")
    if not view.is_file():
        pytest.skip("alma-9 kernel view not available")
    pytest.importorskip("volatility3")
    from memdiver.app.tools_vol3_dev import vol3_scaffold_result
    source = vol3_scaffold_result("kernel_tasks").payload["source"]
    put = sources.vol3_source_put_result(str(case.dir), "kernel_tasks", source).payload
    assert put["check"]["ok"] is True
    run = tools_vol3.vol3_run_result(str(view), "", case_dir=str(case.dir),
                                     source_name="kernel_tasks").payload
    assert run["row_count"] > 50
    assert json.dumps(run["columns"])
