"""artifact_model.export + artifact_model.validate: producers and 4 surfaces."""

from __future__ import annotations

import argparse
import dataclasses
import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("volatility3")
from memdiver.architect.artifact_model import ArtifactModel, Validation  # noqa: E402
from memdiver.core.service_errors import CapabilityError, ErrorCategory  # noqa: E402
from memdiver.msl.enums import Protection, RegionType  # noqa: E402
from memdiver.msl.writer import MslWriter  # noqa: E402
from tests.test_artifact_export import FAR, RID, SECRET, PAGE, _model, _put  # noqa: E402

RW = Protection.READ | Protection.WRITE
BASE_VA = 0x30000000
KEYLOG = (f"SECRET {RID.hex()} {SECRET.hex()}\nFAR {RID.hex()} {FAR.hex()}\n"
          "# comment\nnot a line\n")


def _write_msl(path: Path) -> str:
    buf = bytearray(PAGE * 6)
    _put(buf, PAGE + 64)
    w = MslWriter(str(path), pid=7, imported=False)
    w.add_memory_region(BASE_VA, bytes(buf), protection=RW, region_type=int(RegionType.ANONYMOUS))
    w.add_end_of_capture()
    w.write()
    return str(path)


@pytest.fixture()
def env(tmp_path):
    model = dataclasses.replace(_model(), validation=Validation(
        learned_on=(str(tmp_path / "learned" / "train.msl"),)))
    model_path = tmp_path / "model.json"
    model_path.write_text(json.dumps(model.to_dict()))
    keylog = tmp_path / "keylog.txt"
    keylog.write_text(KEYLOG)
    return {"model": str(model_path), "dump": _write_msl(tmp_path / "held.msl"),
            "keylog": str(keylog), "tmp": tmp_path}


def _session():
    from memdiver.app.composition import build_tool_session
    return build_tool_session()


def _export(env, out, **kw):
    from memdiver.app.tools_semantic import artifact_model_export_result
    return artifact_model_export_result(_session(), model_path=env["model"], out_path=str(out), **kw)


def _validate(env, **kw):
    from memdiver.app.tools_semantic import artifact_model_validate_result
    args = dict(model_path=env["model"],
                held_out=[{"dump_path": env["dump"], "keylog_path": env["keylog"]}])
    args.update(kw)
    return artifact_model_validate_result(_session(), **args)


# -- export ---------------------------------------------------------------------

def test_export_happy(env):
    import hashlib
    out = env["tmp"] / "p.py"
    payload = _export(env, out).payload
    assert out.is_file() and payload["path"] == str(out)
    assert hashlib.sha256(out.read_bytes()).hexdigest() == payload["sha256"]
    assert payload["locator_kind"] == "structure" and payload["bytes"] == out.stat().st_size
    assert f"class {payload['class_name']}(" in out.read_text()


def test_export_invalid_model(env):
    bad = env["tmp"] / "bad.json"
    data = json.loads(Path(env["model"]).read_text())
    data["assertions"].append({"field": "ghost", "meaning": "x"})
    bad.write_text(json.dumps(data))
    from memdiver.app.tools_semantic import artifact_model_export_result
    with pytest.raises(CapabilityError) as exc:
        artifact_model_export_result(_session(), model_path=str(bad), out_path=str(env["tmp"] / "x.py"))
    assert exc.value.category is ErrorCategory.INVALID_INPUT and "ghost" in str(exc.value)
    junk = env["tmp"] / "junk.json"
    junk.write_text("[1")
    with pytest.raises(CapabilityError) as exc:
        artifact_model_export_result(_session(), model_path=str(junk), out_path=str(env["tmp"] / "y.py"))
    assert exc.value.category is ErrorCategory.INVALID_INPUT


def test_export_out_path_rules(env):
    existing = env["tmp"] / "e.py"
    existing.write_text("x")
    for bad in (str(existing), str(env["tmp"] / "p.txt"), ""):
        with pytest.raises(CapabilityError) as exc:
            _export(env, bad)
        assert exc.value.category is ErrorCategory.INVALID_INPUT
    assert existing.read_text() == "x"


# -- validate -------------------------------------------------------------------

def test_validate_keylog_pass_and_model_written(env):
    out = env["tmp"] / "validated.json"
    payload = _validate(env, out_path=str(out)).payload
    assert payload["verdict"] == "pass" and payload["labels"] == ["FAR", "SECRET"]
    totals = payload["totals"]
    assert (totals["expected"], totals["tp"], totals["fp"], totals["fn"]) == (2, 2, 0, 0)
    assert totals["relationships_correct"] == totals["relationships_checked"] == 2
    assert len(payload["plugin_sha256"]) == 64 and payload["seconds"] >= 0
    written = ArtifactModel.from_dict(json.loads(out.read_text()))
    assert written.validation.verdict == "pass" and len(written.validation.held_out) == 1
    assert written.validation.learned_on == (str(env["tmp"] / "learned" / "train.msl"),)


def test_validate_expected_fail_on_missing_value(env):
    exp = [{"label": "SECRET", "owner_hex": RID.hex(), "value_hex": SECRET.hex()},
           {"label": "SECRET", "owner_hex": RID.hex(), "value_hex": "ee" * 8}]
    payload = _validate(env, held_out=[{"dump_path": env["dump"], "expected": exp}],
                        labels=["SECRET"]).payload
    assert payload["verdict"] == "fail" and payload["totals"]["fn"] == 1


def test_validate_plugin_path_used(env):
    out = env["tmp"] / "p.py"
    sha = _export(env, out).payload["sha256"]
    assert _validate(env, plugin_path=str(out)).payload["plugin_sha256"] == sha


def test_validate_refuses_leak_by_resolved_path(env):
    learned = env["tmp"] / "learned"
    learned.mkdir()
    train = _write_msl(learned / "train.msl")
    data = json.loads(Path(env["model"]).read_text())
    data["validation"]["learned_on"] = [train]
    model = env["tmp"] / "leak_learned.json"
    model.write_text(json.dumps(data))
    with pytest.raises(CapabilityError) as exc:
        _validate(env, model_path=str(model),
                  held_out=[{"dump_path": train, "keylog_path": env["keylog"]}])
    assert exc.value.category is ErrorCategory.INVALID_INPUT
    assert exc.value.code == "semantic.held_out_leak"


def test_validate_accepts_same_file_name_in_another_run(env):
    """gocryptfs names every run's capture memslicer.msl: a name is not an identity."""
    data = json.loads(Path(env["model"]).read_text())
    data["validation"]["learned_on"] = [str(Path("/elsewhere") / Path(env["dump"]).name)]
    model = env["tmp"] / "same_name.json"
    model.write_text(json.dumps(data))
    result = _validate(env, model_path=str(model),
                       held_out=[{"dump_path": env["dump"], "keylog_path": env["keylog"]}])
    assert result.payload["verdict"] in ("pass", "fail")


def test_validate_input_rules(env):
    both = {"dump_path": env["dump"], "keylog_path": env["keylog"], "expected": [{"x": 1}]}
    neither = {"dump_path": env["dump"]}
    for held in ([both], [neither], []):
        with pytest.raises(CapabilityError) as exc:
            _validate(env, held_out=held)
        assert exc.value.category is ErrorCategory.INVALID_INPUT


def test_validate_no_va_view_is_precondition(env, monkeypatch):
    import memdiver.app.tools_consensus as tc

    class NoVa:
        def va_span_start(self):
            return None
    monkeypatch.setattr(tc, "_open_one", lambda stack, path, km, rf=None: NoVa())
    with pytest.raises(CapabilityError) as exc:
        _validate(env)
    assert exc.value.category is ErrorCategory.PRECONDITION
    assert exc.value.code == "semantic.no_va_view"


def test__parse_keylog_expected_filters_labels():
    from memdiver.app.tools_semantic import _parse_keylog_expected
    assert _parse_keylog_expected(KEYLOG, ["FAR"]) == {("FAR", RID.hex(), FAR.hex())}
    assert len(_parse_keylog_expected(KEYLOG)) == 2


# -- surfaces -------------------------------------------------------------------

def test_library_surface_exports():
    import memdiver.services as services
    assert {"artifact_model_export_result", "artifact_model_validate_result"} <= set(services.__all__)


def test_web_routes(env):
    from fastapi.testclient import TestClient
    from memdiver.api.main import create_app

    client = TestClient(create_app())
    out = env["tmp"] / "web.py"
    ok = client.post("/api/semantic/model-export",
                     json={"model_path": env["model"], "out_path": str(out)})
    assert ok.status_code in (200, 403), ok.text   # 403 only if a write root is configured
    body = {"model_path": env["model"],
            "held_out": [{"dump_path": env["dump"], "keylog_path": env["keylog"]}]}
    resp = client.post("/api/semantic/model-validate", json=body)
    assert resp.status_code == 200, resp.text
    assert resp.json()["verdict"] == "pass"
    assert client.post("/api/semantic/model-validate",
                       json={**body, "model_path": "/nope.json"}).status_code == 404


def test_mcp_tools(env):
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server

    tools = {t.name: t for t in create_server()._tool_manager.list_tools()}
    out = env["tmp"] / "mcp.py"
    exported = json.loads(tools["artifact_model_export"].fn(
        model_path=env["model"], out_path=str(out)))
    assert out.is_file() and exported["locator_kind"] == "structure"
    result = json.loads(tools["artifact_model_validate"].fn(
        model_path=env["model"],
        held_out=[{"dump_path": env["dump"], "keylog_path": env["keylog"]}]))
    assert result["verdict"] == "pass"


def test_cli_commands(env):
    from memdiver.cli.main import build_parser
    from memdiver.cli.semantic import _cmd_model_export, _cmd_model_validate

    out = env["tmp"] / "cli.py"
    args = build_parser().parse_args(["model-export", env["model"], "--out-path", str(out)])
    assert isinstance(args, argparse.Namespace)
    with redirect_stdout(io.StringIO()):
        assert _cmd_model_export(args) == 0
        assert _cmd_model_export(args) == 1      # exists -> refused
    run = env["tmp"] / "run"
    (run / "dumps" / "msl").mkdir(parents=True)
    _write_msl(run / "dumps" / "msl" / "r.msl")
    (run / "keylog.csv").write_text(KEYLOG)
    result = env["tmp"] / "res.json"
    args = build_parser().parse_args(
        ["model-validate", env["model"], "--keylog-run-dir", str(run), "-o", str(result)])
    with redirect_stdout(io.StringIO()):
        assert _cmd_model_validate(args) == 0
    assert json.loads(result.read_text())["verdict"] == "pass"
    (env["tmp"] / "h.json").write_text(json.dumps(
        [{"dump_path": env["dump"], "keylog_path": env["keylog"]}]))
    args = build_parser().parse_args(
        ["model-validate", env["model"], "--held-out-file", str(env["tmp"] / "h.json")])
    with redirect_stdout(io.StringIO()):
        assert _cmd_model_validate(args) == 0


# -- review regressions ----------------------------------------------------------

def test_validate_label_typo_is_indeterminate_not_pass(env):
    exp = [{"label": "SECRET", "owner_hex": RID.hex(), "value_hex": SECRET.hex()}]
    payload = _validate(env, held_out=[{"dump_path": env["dump"], "expected": exp}],
                        labels=["SECERT"]).payload
    assert payload["verdict"] == "indeterminate"
    assert payload["captures"][0]["verdict"] == "indeterminate"


def test_validate_model_without_owned_by_can_pass(env):
    data = json.loads(Path(env["model"]).read_text())
    data["relationships"] = []
    model = env["tmp"] / "no_rel.json"
    model.write_text(json.dumps(data))
    payload = _validate(env, model_path=str(model)).payload
    assert payload["verdict"] == "pass"
    assert payload["totals"]["relationships_checked"] == 0
    assert payload["captures"][0]["verdict"] == "pass" and payload["captures"][0]["scanned_runs"] >= 1


def test_web_plugin_path_outside_roots_is_403(env, monkeypatch):
    from fastapi.testclient import TestClient
    from memdiver.api.main import create_app

    from memdiver.api.config import get_settings
    monkeypatch.setenv("MEMDIVER_ALLOWED_ROOTS", str(env["tmp"] / "only_here"))
    get_settings.cache_clear()
    (env["tmp"] / "only_here").mkdir()
    plugin = env["tmp"] / "evil.py"
    plugin.write_text("raise SystemExit")
    resp = TestClient(create_app()).post("/api/semantic/model-validate", json={
        "model_path": env["model"], "plugin_path": str(plugin),
        "held_out": [{"dump_path": env["dump"], "keylog_path": env["keylog"]}]})
    get_settings.cache_clear()
    assert resp.status_code == 403, resp.text


def test_web_world_writable_plugin_refused(env):
    from fastapi.testclient import TestClient
    from memdiver.api.main import create_app

    plugin = env["tmp"] / "loose.py"
    plugin.write_text("x = 1")
    plugin.chmod(0o666)
    resp = TestClient(create_app()).post("/api/semantic/model-validate", json={
        "model_path": env["model"], "plugin_path": str(plugin),
        "held_out": [{"dump_path": env["dump"], "keylog_path": env["keylog"]}]})
    assert resp.status_code == 400 and "world-writable" in resp.text, resp.text


def test_plugin_path_logs_sha256(env, caplog):
    import hashlib
    out = env["tmp"] / "logged.py"
    sha = _export(env, out).payload["sha256"]
    with caplog.at_level("WARNING"):
        _validate(env, plugin_path=str(out))
    assert hashlib.sha256(out.read_bytes()).hexdigest() == sha
    assert any(sha in r.getMessage() for r in caplog.records)
