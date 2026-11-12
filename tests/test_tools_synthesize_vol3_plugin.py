"""``app.tools_pipeline.synthesize_vol3_plugin`` (+ ``vol3_plugin_dir``).

A located key -> a standalone recipe-v2 Volatility 3 plugin with the oracle
inlined, then RUN in-process on the ``.msl``'s VA layer stack and judged by its
``Proven`` column. Synthetic ``.msl`` captures (``msl/writer.py``) holding the
``tests/_vol3_recipe_fixtures`` gocryptfs process image, plus a corpus test on
the real gocryptfs runs whose returned ``vol_command`` is executed under stock
``vol``.
"""

from __future__ import annotations

import json
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.msl.enums import ArchType, OSType
from memdiver.msl.writer import MslWriter
from memdiver.services import synthesize_vol3_plugin, vol3_plugin_dir
from tests import _vol3_recipe_fixtures as fx
from tests._oracle_gocryptfs_fixtures import GOCRYPTFS_CORPUS, HAVE_CORPUS, RUN_0001_MASTER_HEX

pytest.importorskip("cryptography")
pytest.importorskip("volatility3")

REGION_VA = 0x7F0000000000
KEY_VAS = {REGION_VA + site for site in fx.KEY_SITES}


def _write_msl(path: Path, master: bytes) -> Path:
    writer = MslWriter(path, pid=4242, os_type=OSType.LINUX, arch_type=ArchType.X86_64)
    writer.add_memory_region(REGION_VA, fx.process_buffer(master))
    writer.add_end_of_capture()
    writer.write()
    return path


@pytest.fixture
def case_dir(tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    return str(case)


@pytest.fixture
def two_runs(tmp_path):
    """Two synthetic gocryptfs captures with DIFFERENT keys, each with its own vault."""
    runs = []
    for label, master in (("a", fx.MASTER), ("b", fx.OTHER_MASTER)):
        run = tmp_path / f"run_{label}"
        run.mkdir()
        runs.append({"msl": str(_write_msl(run / "memslicer.msl", master)),
                     "vault": str(fx.write_vault(run / "cipher", master=master)),
                     "key": master.hex()})
    return runs


def _synth(runs, **kwargs):
    params = {"dump_paths": [r["msl"] for r in runs], "name": "memdiver_gocryptfs_test",
              "key_hex": [r["key"] for r in runs], "oracle_kind": fx.KIND,
              "oracle_sample_path": [r["vault"] for r in runs]}
    params.update(kwargs)
    return synthesize_vol3_plugin(**params)


def test_synthetic_msl_is_proven_and_stored(two_runs, tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    result = _synth(two_runs, case_dir=str(case))
    assert result["proven"] is True
    assert [v["status"] for v in result["verdicts"]] == ["proven", "proven"]
    assert {h["key_offset"] for h in result["verdicts"][0]["proven_hits"]} == KEY_VAS
    assert result["proven_hits"] == 4
    assert [v["oracle_sample_override"] for v in result["verdicts"]] == [False, True]
    assert result["self_test"]["proven"] >= 1
    stored = result["stored"]
    store = case / "vol3" / "plugins"
    assert Path(stored["path"]) == store / "memdiver_gocryptfs_test.py"
    assert Path(stored["recipe_path"]).is_file()
    assert result["plugin_dir"] == str(store)
    # The .yar sidecar is kept with a case too (the no-case path always kept it).
    assert Path(stored["yara_path"]) == store / "memdiver_gocryptfs_test.yar"
    assert Path(stored["yara_path"]).read_text().startswith("rule ")
    assert result["export_files"] == [stored["path"], stored["recipe_path"], stored["yara_path"]]
    assert result["oracle"]["kind"] == fx.KIND and result["oracle"]["sample_bytes"] > 0
    for text in (Path(stored["path"]).read_text(), Path(stored["recipe_path"]).read_text(),
                 json.dumps(result["recipe"]), json.dumps(result["verdicts"])):
        assert fx.MASTER.hex() not in text and fx.OTHER_MASTER.hex() not in text
    argv = shlex.split(result["vol_command"])
    assert argv[:2] == ["vol", "-p"]
    assert argv[2] == f"{vol3_plugin_dir()['path']};{store}"
    assert argv[3:] == ["-f", two_runs[0]["msl"], "memdiver_gocryptfs_test.MemDiverSynthGocryptfsTest"]
    assert "--oracle-sample" in shlex.split(result["verdicts"][1]["vol_command"])


def test_without_case_the_plugin_dir_is_kept_and_flagged(two_runs):
    result = _synth(two_runs, verify_on=())
    assert result["stored"] is None and result["verdicts"] == [] and result["proven"] is False
    plugin_dir = Path(result["plugin_dir"])
    try:
        assert (plugin_dir / "memdiver_gocryptfs_test.py").read_text() == result["source"]
        assert {Path(p).suffix for p in result["export_files"]} == {".py", ".json", ".yar"}
        codes = {d["code"] for d in result["diagnostics"]}
        assert "synth.vol3_plugin.plugin_dir_is_temporary" in codes
    finally:
        shutil.rmtree(plugin_dir, ignore_errors=True)


def test_wrong_vault_is_not_proven(two_runs, tmp_path, case_dir):
    wrong = str(fx.write_vault(tmp_path / "wrong", master=fx.OTHER_MASTER))
    result = _synth(two_runs, oracle_sample_path=wrong, case_dir=case_dir)
    assert result["proven"] is False
    assert result["verdicts"][0]["status"] == "not_proven"
    codes = {d["code"] for d in result["diagnostics"]}
    assert {"vol3_recipe.sample_does_not_prove_key", "synth.vol3_plugin.not_proven"} <= codes


def test_wrong_key_is_not_found(two_runs):
    with pytest.raises(CapabilityError) as caught:
        _synth(two_runs, key_hex=bytes(range(32)).hex())
    assert caught.value.category is ErrorCategory.NOT_FOUND
    assert caught.value.code == "synth.vol3_plugin.key_not_found"


def test_hit_form_reads_the_key_and_guards_a_single_key(two_runs, case_dir):
    run = two_runs[0]
    # One captured region at vas offset 0, so the key's vas offset is its site.
    hit = {"dump_path": run["msl"], "offset": fx.KEY_SITES[0], "length": 32, "view": "vas"}
    common = {"dump_paths": [run["msl"]], "name": "memdiver_hit", "hit": hit,
              "oracle_kind": fx.KIND, "oracle_sample_path": run["vault"]}
    with pytest.raises(CapabilityError) as caught:
        synthesize_vol3_plugin(**common)
    assert caught.value.category is ErrorCategory.PRECONDITION
    assert caught.value.code == "synth.vol3_plugin.high_entropy_context"
    result = synthesize_vol3_plugin(**common, allow_high_entropy_context=True,
                                    case_dir=case_dir)
    assert result["proven"] is True
    assert "vol3_recipe.high_entropy_context" in {d["code"] for d in result["diagnostics"]}


@pytest.mark.parametrize("kwargs, code", [
    ({"oracle_kind": "no-such-oracle"}, "synth.vol3_plugin.unknown_oracle"),
    ({"hit": {"key_hex": "00"}}, "synth.vol3_plugin.key_form"),
    ({"key_hex": ""}, "synth.vol3_plugin.key_form"),
    ({"verify_on": ("bogus",)}, "synth.vol3_plugin.unknown_target"),
    ({"oracle_sample_path": ["a", "b", "c"]}, "synth.vol3_plugin.length_mismatch"),
    ({"dump_paths": []}, "synth.vol3_plugin.no_dumps"),
])
def test_invalid_input_is_refused(two_runs, kwargs, code):
    with pytest.raises(CapabilityError) as caught:
        _synth(two_runs, **kwargs)
    assert caught.value.code == code
    assert caught.value.category is ErrorCategory.INVALID_INPUT


@pytest.mark.parametrize("bad", ["zz" + fx.MASTER.hex()[2:], fx.MASTER.hex()[:-1]])
def test_invalid_key_is_refused_without_echoing_it(two_runs, bad):
    with pytest.raises(CapabilityError) as caught:
        _synth(two_runs, key_hex=[bad, fx.OTHER_MASTER.hex()])
    assert caught.value.code == "synth.vol3_plugin.invalid_key"
    message = repr(caught.value) + str(caught.value)
    assert bad[2:-2] not in message and fx.MASTER.hex()[4:-4] not in message
    assert caught.value.__cause__ is None and caught.value.__suppress_context__


def test_hit_key_is_broadcast_to_every_dump(tmp_path, case_dir):
    dumps = [str(_write_msl(tmp_path / f"same_{i}.msl", fx.MASTER)) for i in range(2)]
    vault = str(fx.write_vault(tmp_path / "cipher"))
    result = synthesize_vol3_plugin(
        dump_paths=dumps, name="memdiver_hit_two", oracle_kind=fx.KIND,
        hit={"dump_path": dumps[0], "offset": fx.KEY_SITES[0], "length": 32, "view": "vas"},
        oracle_sample_path=vault, allow_high_entropy_context=True, case_dir=case_dir)
    assert [v["status"] for v in result["verdicts"]] == ["proven", "proven"]


def test_not_verified_is_explained(two_runs):
    result = _synth(two_runs, verify_on=())
    try:
        assert result["proven"] is False
        assert "synth.vol3_plugin.not_verified" in {d["code"] for d in result["diagnostics"]}
    finally:
        shutil.rmtree(result["plugin_dir"], ignore_errors=True)


def test_a_vol3_failure_is_an_error_verdict_and_flags_the_stored_plugin(
        two_runs, case_dir, monkeypatch):
    from volatility3.framework.exceptions import VolatilityException

    from memdiver.app import vol3_synth

    def boom(*_args, **_kwargs):
        raise VolatilityException("synthetic failure")

    monkeypatch.setattr(vol3_synth, "_synth_run_locked", boom)
    result = _synth(two_runs, case_dir=case_dir)
    assert [v["status"] for v in result["verdicts"]] == ["error", "error"]
    assert {v["error_code"] for v in result["verdicts"]} == {"synth.vol3_plugin.vol3_error"}
    assert result["proven"] is False
    assert "synth.vol3_plugin.stored_unproven" in {d["code"] for d in result["diagnostics"]}


def test_in_process_runs_leave_no_emitted_module_behind(two_runs, case_dir):
    import sys

    before = set(sys.modules)
    _synth(two_runs, case_dir=case_dir)
    assert not [m for m in set(sys.modules) - before if m.startswith("memdiver_emitted_vol3_")]


def test_storing_twice_archives_plugin_and_recipe_outside_the_vol_dir(two_runs, case_dir):
    first = _synth(two_runs, case_dir=case_dir, verify_on=())
    second = _synth(two_runs, case_dir=case_dir, verify_on=(), context=48)
    store, history = Path(second["plugin_dir"]), Path(second["stored"]["history_dir"])
    assert first["source"] != second["source"]
    assert sorted(p.name for p in store.iterdir()) == [
        "memdiver_gocryptfs_test.py", "memdiver_gocryptfs_test.recipe.json",
        "memdiver_gocryptfs_test.yar"]
    archived = sorted(p.name for p in history.iterdir())
    assert len(archived) == 3 and archived[0].endswith(".py")
    assert archived[1:] == [archived[0][:-3] + ".recipe.json", archived[0][:-3] + ".yar"]
    assert (history / archived[0]).read_text() == first["source"]
    assert history.parent == store.parent and history not in store.parents
    if shutil.which("vol") is None:
        return
    cache = Path(case_dir) / "cache"
    cache.mkdir()
    completed = subprocess.run(
        ["vol", "-q", "--cache-path", str(cache), "-p",
         f"{vol3_plugin_dir()['path']};{store}", "-h"],
        capture_output=True, text=True, timeout=600)
    assert completed.stdout.count("MemDiverSynthGocryptfsTest") == 1, completed.stdout[-3000:]
    shutil.rmtree(store / "__pycache__", ignore_errors=True)


@pytest.mark.skipif(shutil.which("vol") is None, reason="stock `vol` not on PATH")
def test_full_image_runs_the_recipe_class_under_stock_vol(two_runs, case_dir):
    """The image is the SECOND run's capture: its own key + sample must be selected."""
    result = _synth(two_runs, case_dir=case_dir, verify_on=(), full_image=two_runs[1]["msl"])
    (verdict,) = result["verdicts"]
    assert verdict["target"] == "full_image" and verdict["status"] == "proven", verdict
    assert verdict["matched_dump_index"] == 1 and verdict["oracle_sample_override"]
    assert {h["key_offset"] for h in verdict["proven_hits"]} == KEY_VAS
    assert "MemDiverSynthGocryptfsTest" in verdict["vol_command"]
    assert not (Path(result["plugin_dir"]) / "__pycache__").exists()


def test_full_image_argv_names_the_recipe_class_not_the_first_class(monkeypatch):
    from types import SimpleNamespace

    from memdiver.app.tools_pipeline import _synth_display_spec, _synth_image_run
    from memdiver.engine import vol3_subproc

    seen = {}

    def fake_run_vol(launcher, spec, **_kwargs):
        seen["argv"] = spec.argv(launcher)
        return vol3_subproc.VolRun(tuple(seen["argv"]), 0, [], "", None)
    monkeypatch.setattr(vol3_subproc, "run_vol", fake_run_vol)
    display = _synth_display_spec("/pkg", Path("/case/vol3/plugins"), "memdiver_x.MemDiverSynthX",
                                  Path("/img.lime"), ["--pid", "7", "--oracle-sample", "/v"])
    _synth_image_run(SimpleNamespace(argv=("vol",)), display,
                     plugin_dirs=("/pkg", "/case/vol3/plugins"), cache="/c")
    argv = seen["argv"]
    assert argv[argv.index("-f") + 2] == "memdiver_x.MemDiverSynthX"
    assert argv[-4:] == ["--pid", "7", "--oracle-sample", "/v"]
    assert argv[argv.index("-p") + 1] == "/pkg;/case/vol3/plugins"


def test_missing_case_dir_is_refused_before_any_work(two_runs, tmp_path):
    from memdiver.core.service_errors import FileNotFoundServiceError

    with pytest.raises(FileNotFoundServiceError, match="Case directory"):
        _synth(two_runs, case_dir=str(tmp_path / "no_such_case"))


def test_vol3_plugin_dir_is_the_vol3plugins_package():
    path = Path(vol3_plugin_dir()["path"])
    assert path.name == "vol3plugins"
    assert (path / "msl_layer.py").is_file() and (path / "memdiver_stackers.py").is_file()


# -- real corpus, and the returned vol_command under stock vol ---------------------------

def _run_vol(command: str, cache: Path) -> list:
    argv = shlex.split(command)
    argv = [argv[0], "-q", "-r", "json", "--cache-path", str(cache), *argv[1:]]
    completed = subprocess.run(argv, capture_output=True, text=True, timeout=900)
    assert completed.returncode == 0, completed.stderr[-2000:]
    return json.loads(completed.stdout[completed.stdout.index("["):])


@pytest.mark.skipif(not HAVE_CORPUS, reason="gocryptfs corpus not present")
@pytest.mark.skipif(shutil.which("vol") is None, reason="stock `vol` not on PATH")
def test_corpus_runs_are_proven_and_vol_command_proves_under_stock_vol(tmp_path, case_dir):
    runs = [GOCRYPTFS_CORPUS / "run_0001", GOCRYPTFS_CORPUS / "run_0002"]
    captures = [run / "memslicer.msl" for run in runs]
    if not all(c.is_file() for c in captures):
        pytest.skip("run_0001/run_0002 have no memslicer.msl")
    keys = [json.loads((run / "meta.json").read_text())["master_key_hex"] for run in runs]
    result = synthesize_vol3_plugin(
        dump_paths=[str(c) for c in captures], name="memdiver_gocryptfs", key_hex=keys,
        oracle_kind=fx.KIND, oracle_sample_path=[str(r / "cipher") for r in runs],
        case_dir=case_dir)
    assert result["proven"] is True
    assert {h["key_offset"] for h in result["verdicts"][0]["proven_hits"]} == {
        0xC0000BC220, 0xC0000BC4A0}
    assert keys[0] not in Path(result["stored"]["recipe_path"]).read_text()
    cache = tmp_path / "vol_cache"
    cache.mkdir()
    for verdict, key in zip(result["verdicts"], keys):
        rows = _run_vol(verdict["vol_command"], cache)
        proven = [r for r in rows if r["Proven"] == f"oracle:{fx.KIND}"]
        assert {r["KeyHex"] for r in proven} == {key}
        assert {r["KeyOffset"] for r in proven} == {h["key_offset"] for h in verdict["proven_hits"]}
    assert keys[0] == RUN_0001_MASTER_HEX
    assert result["vol_command"] == result["verdicts"][0]["vol_command"]


@pytest.mark.skipif(not HAVE_CORPUS, reason="gocryptfs corpus not present")
@pytest.mark.skipif(shutil.which("vol") is None, reason="stock `vol` not on PATH")
@pytest.mark.parametrize("image_index", [0, 1])
def test_corpus_full_image_path_end_to_end(case_dir, image_index):
    runs = [GOCRYPTFS_CORPUS / "run_0001", GOCRYPTFS_CORPUS / "run_0002"]
    captures = [run / "memslicer.msl" for run in runs]
    if not all(c.is_file() for c in captures):
        pytest.skip("run_0001/run_0002 have no memslicer.msl")
    keys = [json.loads((run / "meta.json").read_text())["master_key_hex"] for run in runs]
    result = synthesize_vol3_plugin(
        dump_paths=[str(c) for c in captures], name="memdiver_gocryptfs", key_hex=keys,
        oracle_kind=fx.KIND, oracle_sample_path=[str(r / "cipher") for r in runs],
        case_dir=case_dir, verify_on=(), full_image=str(captures[image_index]))
    (verdict,) = result["verdicts"]
    assert verdict["status"] == "proven", verdict
    assert verdict["matched_dump_index"] == image_index
    assert result["proven"] is True


# -- the .yar sidecar in <case>/vol3/plugins -----------------------------------------

def test_case_store_keeps_the_yar_without_listing_it_or_feeding_it_to_vol(tmp_path):
    from types import SimpleNamespace

    from memdiver.analysis.case import Case
    from memdiver.app import tools_vol3_sources as sources
    from memdiver.app.tools_pipeline import _synth_store

    case = Case.init(tmp_path / "case")
    recipe = SimpleNamespace(name="synth_yar", to_json=lambda: "{}")
    stored = _synth_store(str(case.dir), recipe, "# v1\n", "rule r1 { condition: true }\n")
    plugins = case.dir / "vol3" / "plugins"
    assert Path(stored["yara_path"]) == plugins / "synth_yar.yar"
    assert (plugins / "synth_yar.yar").read_text() == "rule r1 { condition: true }\n"
    rows = sources.vol3_source_list_result(str(case.dir)).payload["sources"]
    assert [(r["name"], Path(r["path"]).suffix) for r in rows] == [("synth_yar", ".py")]
    # A replacement archives the old rule with its plugin; one emitted without a
    # rule leaves no stale .yar beside the new plugin.
    again = _synth_store(str(case.dir), recipe, "# v2\n", None)
    assert again["yara_path"] is None and not (plugins / "synth_yar.yar").exists()
    assert len(list((case.dir / "vol3" / "history").glob("synth_yar-*.yar"))) == 1


def test_vol_plugin_import_ignores_non_py_files():
    """``vol -p <case>/vol3/plugins`` imports only .py/.pyc: the .yar sidecar is inert."""
    framework = pytest.importorskip("volatility3.framework")
    assert not framework._filter_files("synth_yar.yar")
    assert not framework._filter_files("synth_yar.recipe.json")
    assert framework._filter_files("synth_yar.py")
