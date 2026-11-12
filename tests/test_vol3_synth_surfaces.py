"""``synth.vol3_plugin``, ``vol3.plugin_dir`` and ``vol3.exec`` on the CLI, REST and MCP surfaces.

Synthesis runs for real on synthetic gocryptfs ``.msl`` captures
(``tests/_vol3_recipe_fixtures``); ``vol3 exec`` uses a fake ``vol.py``
launcher except in the corpus end-to-end test, which synthesizes from the real
gocryptfs ``run_0001`` + ``run_0002`` through the CLI (keys from each run's
``meta.json``, passed via ``--key-hex-file``) and then runs the stored plugin
under stock ``vol`` through ``vol3 exec``.

Keys are secrets: every surface test asserts the key hex appears in no output.
"""

from __future__ import annotations

import io
import json
import shlex
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from memdiver.core.service_errors import CapabilityError
from memdiver.msl.enums import ArchType, OSType
from memdiver.msl.writer import MslWriter
from tests import _vol3_recipe_fixtures as fx
from tests._oracle_gocryptfs_fixtures import GOCRYPTFS_CORPUS, HAVE_CORPUS

pytest.importorskip("cryptography")
pytest.importorskip("volatility3")

PLUGIN = "memdiver_gocryptfs_surface"


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("MEMDIVER_HOME", str(tmp_path / "home"))


def _write_msl(path: Path, master: bytes) -> Path:
    writer = MslWriter(path, pid=4242, os_type=OSType.LINUX, arch_type=ArchType.X86_64)
    writer.add_memory_region(0x7F0000000000, fx.process_buffer(master))
    writer.add_end_of_capture()
    writer.write()
    return path


@pytest.fixture
def two_runs(tmp_path):
    runs = []
    for label, master in (("a", fx.MASTER), ("b", fx.OTHER_MASTER)):
        run = tmp_path / f"run_{label}"
        run.mkdir()
        runs.append({"msl": str(_write_msl(run / "memslicer.msl", master)),
                     "vault": str(fx.write_vault(run / "cipher", master=master)),
                     "key": master.hex()})
    return runs


@pytest.fixture
def case(tmp_path):
    from memdiver.analysis.case import Case
    return Case.init(str(tmp_path / "case"))


def _no_key(runs, *texts):
    for text in texts:
        for run in runs:
            assert run["key"] not in text


# -- analysis.case.existing_case_dir ------------------------------------------------

def test_existing_case_dir_resolves_names_and_paths_and_refuses_plain_dirs(tmp_path, case):
    from memdiver.analysis.case import Case, existing_case_dir
    assert existing_case_dir(None) is None and existing_case_dir("  ") is None
    assert existing_case_dir(str(case.dir)) == str(case.dir)
    named = Case.init("named_case")
    assert existing_case_dir("named_case") == str(named.dir)
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(CapabilityError) as exc:
        existing_case_dir(str(plain))
    assert exc.value.code == "case.not_a_case"


# -- CLI ----------------------------------------------------------------------------

def _cli(argv, capsys):
    from memdiver.cli import _build_parser, _cmd_vol3
    rc = _cmd_vol3(_build_parser().parse_args(["vol3", *argv]))
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def test_cli_plugin_dir(capsys):
    from memdiver.app.tools_pipeline import vol3_plugin_dir
    rc, out, _ = _cli(["plugin-dir"], capsys)
    assert rc == 0 and json.loads(out) == vol3_plugin_dir()


def _synth_argv(runs, *extra):
    return ["synthesize", *[r["msl"] for r in runs], "--name", PLUGIN,
            "--oracle-kind", fx.KIND, *sum((["--oracle-sample", r["vault"]] for r in runs), []),
            *extra]


def test_cli_synthesize_reads_keys_from_a_file_and_never_echoes_them(
        two_runs, case, tmp_path, capsys):
    keys = tmp_path / "keys.txt"
    keys.write_text("\n".join(r["key"] for r in two_runs) + "\n", encoding="utf-8")
    out_file = tmp_path / "synth.json"
    rc, out, err = _cli(_synth_argv(two_runs, "--key-hex-file", str(keys),
                                    "--case", str(case.dir), "-o", str(out_file)), capsys)
    payload = json.loads(out_file.read_text())
    assert rc == 0 and payload["proven"] is True, err
    assert [v["status"] for v in payload["verdicts"]] == ["proven", "proven"]
    assert payload["plugin_dir"] == str(case.dir / "vol3" / "plugins")
    assert "proven=True" in err
    _no_key(two_runs, out, err, out_file.read_text())


def test_cli_synthesize_reads_one_key_from_stdin(two_runs, case, monkeypatch, capsys):
    run = two_runs[:1]
    monkeypatch.setattr(sys, "stdin", io.StringIO(run[0]["key"] + "\n"))
    rc, out, err = _cli(_synth_argv(run, "--key-hex-file", "-", "--case", str(case.dir),
                                    "--allow-high-entropy-context"), capsys)
    assert rc == 0 and json.loads(out)["proven"] is True, err
    _no_key(run, out, err)


def test_cli_synthesize_resolves_a_bare_case_name(two_runs, capsys):
    from memdiver.analysis.case import Case
    named = Case.init("synth_named")
    rc, out, _ = _cli(_synth_argv(two_runs[:1], "--key-hex", two_runs[0]["key"],
                                  "--case", "synth_named", "--allow-high-entropy-context"),
                      capsys)
    assert rc == 0 and json.loads(out)["plugin_dir"] == str(named.dir / "vol3" / "plugins")


def test_cli_synthesize_refuses_a_directory_that_is_not_a_case(two_runs, tmp_path, capsys):
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(CapabilityError) as exc:
        _cli(_synth_argv(two_runs[:1], "--key-hex", two_runs[0]["key"],
                         "--case", str(plain)), capsys)
    assert exc.value.code == "case.not_a_case"
    assert not (plain / "vol3").exists()


def test_cli_synthesize_unproven_exits_3(two_runs, capsys):
    wrong = two_runs[1]["vault"]  # run a's key cannot open run b's vault
    rc, out, err = _cli(["synthesize", two_runs[0]["msl"], "--name", PLUGIN,
                         "--oracle-kind", fx.KIND, "--oracle-sample", wrong,
                         "--key-hex", two_runs[0]["key"], "--allow-high-entropy-context"],
                        capsys)
    assert rc == 3 and json.loads(out)["proven"] is False
    _no_key(two_runs, out, err)


def test_cli_synthesize_forwards_every_option(monkeypatch, tmp_path, capsys):
    from memdiver.app import tools_pipeline
    seen = {}

    def fake(**kwargs):
        seen.update(kwargs)
        return {"proven": False, "proven_hits": 0, "verdicts": [], "diagnostics": []}
    monkeypatch.setattr(tools_pipeline, "synthesize_vol3_plugin", fake)
    image_key = tmp_path / "image.key"
    image_key.write_text("aa" * 32, encoding="utf-8")
    rc, _, _ = _cli(["synthesize", "d1", "d2", "--name", "n", "--oracle-kind", "k",
                     "--key-hex", "11", "--key-hex", "22", "--oracle-param", "x=1",
                     "--context", "32", "--no-verify", "--full-image", "img", "--pid", "9",
                     "--full-image-sample", "vault", "--full-image-key-hex-file", str(image_key),
                     "-s", "sym1", "-s", "sym2", "--vol-bin", "vb", "--vol-python", "vp",
                     "--allow-high-entropy-context"], capsys)
    assert rc == 0
    assert seen["key_hex"] == ["11", "22"] and seen["oracle_params"] == {"x": 1}
    assert (seen["context"], seen["verify_on"], seen["pid"]) == (32, (), 9)
    assert seen["full_image_key_hex"] == "aa" * 32 and seen["symbol_dirs"] == ["sym1", "sym2"]
    assert (seen["vol_bin"], seen["vol_python"], seen["case_dir"]) == ("vb", "vp", None)
    assert seen["oracle_sample_path"] is None and seen["allow_high_entropy_context"] is True


def test_cli_synthesize_key_forms_are_exclusive():
    from memdiver.cli import _build_parser
    with pytest.raises(SystemExit):
        _build_parser().parse_args(["vol3", "synthesize", "d", "--name", "n",
                                    "--oracle-kind", "k", "--key-hex", "11", "--hit", "{}"])
    with pytest.raises(SystemExit):
        _build_parser().parse_args(["vol3", "synthesize", "d", "--name", "n",
                                    "--oracle-kind", "k"])


FAKE_VOL = '''\
import json, sys
sys.stderr.write("Volatility 3 Framework 9.8.7\\n")
print(json.dumps([{"argv": sys.argv[1:]}]))
sys.exit(1 if "--fail" in sys.argv else 0)
'''


@pytest.fixture
def fake_vol(tmp_path):
    path = tmp_path / "bin" / "vol.py"
    path.parent.mkdir()
    path.write_text(FAKE_VOL, encoding="utf-8")
    return str(path)


@pytest.fixture
def image(tmp_path):
    path = tmp_path / "img.raw"
    path.write_bytes(b"\0" * 64)
    return str(path)


def test_cli_exec_passes_plugin_args_after_the_name(fake_vol, image, capsys):
    rc, out, _ = _cli(["exec", "--image", image, "--vol-bin", fake_vol,
                       "--vol-python", sys.executable, "--no-memdiver-plugins",
                       "linux.pslist.PsList", "--pid", "1"], capsys)
    payload = json.loads(out)
    assert rc == 0 and payload["ok"] is True
    assert payload["rows"][0]["argv"][-3:] == ["linux.pslist.PsList", "--pid", "1"]
    # A vol global option after the plugin name (here the trap `-o` placed late) is refused.
    with pytest.raises(CapabilityError) as exc:
        _cli(["exec", "--image", image, "--vol-bin", fake_vol, "--vol-python", sys.executable,
              "msl.info", "-o", "x"], capsys)
    assert exc.value.code == "vol3.exec.global_option"


def test_cli_exec_failure_exits_1(fake_vol, image, capsys):
    rc, out, err = _cli(["exec", "--image", image, "--vol-bin", fake_vol,
                         "--vol-python", sys.executable, "msl.info", "--fail"], capsys)
    assert rc == 1 and json.loads(out)["ok"] is False and "vol exited 1" in err


# -- REST ---------------------------------------------------------------------------

@pytest.fixture
def client(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from memdiver.api.config import get_settings
    from memdiver.api.main import create_app
    monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS", raising=False)
    monkeypatch.setenv("MEMDIVER_UPLOAD_DIR", str(tmp_path / "uploads"))
    get_settings.cache_clear()
    yield TestClient(create_app())
    get_settings.cache_clear()


def test_rest_plugin_dir(client):
    from memdiver.app.tools_pipeline import vol3_plugin_dir
    resp = client.get("/api/vol3/plugin-dir")
    assert resp.status_code == 200 and resp.json() == vol3_plugin_dir()


def _synth_body(runs, **extra):
    return {"dump_paths": [r["msl"] for r in runs], "name": PLUGIN, "oracle_kind": fx.KIND,
            "secret_hex": [r["key"] for r in runs],
            "oracle_sample_path": [r["vault"] for r in runs], **extra}


def test_rest_synthesize_proves_into_a_named_case_without_echoing_the_key(client, two_runs):
    from memdiver.analysis.case import Case
    named = Case.init("rest_case")
    resp = client.post("/api/vol3/synthesize", json=_synth_body(two_runs, case_dir="rest_case"))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["proven"] is True and body["stored"]["path"].startswith(str(named.dir))
    _no_key(two_runs, resp.text)


def test_rest_synthesize_refuses_a_plain_directory_and_bad_fields(client, two_runs, tmp_path):
    from memdiver.api.read_roots import write_roots
    plain = Path(write_roots()[0]) / "plain_not_a_case"
    plain.mkdir(parents=True, exist_ok=True)
    resp = client.post("/api/vol3/synthesize", json=_synth_body(two_runs, case_dir=str(plain)))
    assert resp.status_code == 400 and "case.not_a_case" in resp.text
    resp = client.post("/api/vol3/synthesize", json=_synth_body(two_runs, key_hexx="00"))
    assert resp.status_code == 422
    outside = str(tmp_path / "elsewhere")
    resp = client.post("/api/vol3/synthesize", json=_synth_body(two_runs, case_dir=outside))
    assert resp.status_code == 403


def test_rest_synthesize_forwards_the_wire_names(client, monkeypatch):
    """Inline without ``full_image``; with one the same kwargs go to a job (E3)."""
    from memdiver.app import tools_pipeline
    seen, submitted = {}, []
    monkeypatch.setattr(tools_pipeline, "synthesize_vol3_plugin",
                        lambda **kw: seen.update(kw) or {"proven": True})
    monkeypatch.setattr(tools_pipeline, "preflight_synthesize_vol3_plugin", lambda **kw: None)
    monkeypatch.setattr("memdiver.api.routers.vol3.task_manager_or_503", lambda: SimpleNamespace(
        artifact_store=SimpleNamespace(root="/tasks"),
        submit=lambda **kw: submitted.append(kw) or SimpleNamespace(
            task_id="t", status=SimpleNamespace(value="pending"))))
    body = {"dump_paths": ["d"], "name": "n", "oracle_kind": "k", "secret_hex": "11",
            "pid": 7, "full_image_sample": "v", "full_image_secret_hex": "22",
            "symbol_dirs": ["s"], "verify_on": [], "vol_bin": "vb", "vol_python": "vp",
            "context": 16}
    resp = client.post("/api/vol3/synthesize", json=body)
    assert resp.status_code == 200, resp.text
    assert (seen["key_hex"], seen["full_image_key_hex"]) == ("11", "22")
    assert (seen["full_image"], seen["pid"], seen["symbol_dirs"]) == (None, 7, ["s"])
    assert seen["verify_on"] == () and seen["case_dir"] is None and seen["key_material"] == {}
    resp = client.post("/api/vol3/synthesize", json={**body, "full_image": "img"})
    assert resp.json() == {"task_id": "t", "status": "pending"}
    kwargs = submitted[0]["params"]["kwargs"]
    assert (kwargs["key_hex"], kwargs["full_image_key_hex"]) == ("11", "22")
    assert (kwargs["full_image"], kwargs["pid"], kwargs["symbol_dirs"]) == ("img", 7, ["s"])


def test_rest_exec_runs_and_contains_out_dir(client, fake_vol, image, tmp_path):
    resp = client.post("/api/vol3/exec", json={
        "plugin": "msl.info", "image_path": image, "args": ["--pid", "1"],
        "vol_bin": fake_vol, "vol_python": sys.executable})
    assert resp.status_code == 200, resp.text
    assert resp.json()["ok"] is True and resp.json()["rows"][0]["argv"][-3:] == [
        "msl.info", "--pid", "1"]
    resp = client.post("/api/vol3/exec", json={
        "plugin": "msl.info", "image_path": image, "out_dir": str(tmp_path / "elsewhere"),
        "vol_bin": fake_vol, "vol_python": sys.executable})
    assert resp.status_code == 403


def test_rest_exec_refuses_a_history_plugin_dir(client, fake_vol, image, tmp_path):
    (tmp_path / "c" / "vol3" / "history").mkdir(parents=True)
    resp = client.post("/api/vol3/exec", json={
        "plugin": "msl.info", "image_path": image, "plugin_dirs": [str(tmp_path / "c")],
        "vol_bin": fake_vol, "vol_python": sys.executable})
    assert resp.status_code == 400 and "vol3.exec.history_dir" in resp.text


def test_rest_read_sandbox_covers_the_new_path_fields(client, monkeypatch, tmp_path):
    from memdiver.api.config import get_settings
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    monkeypatch.setenv("MEMDIVER_ALLOWED_ROOTS", str(allowed))
    get_settings.cache_clear()
    other = str(tmp_path / "other")
    inside = str(allowed / "x")
    for extra in ({"oracle_sample_path": other}, {"full_image": other},
                  {"full_image_sample": other}, {"symbol_dirs": [other]}):
        body = {"dump_paths": [inside], "name": "n", "oracle_kind": "k", **extra}
        assert client.post("/api/vol3/synthesize", json=body).status_code == 403, extra
    for extra in ({"image_path": other}, {"plugin_dirs": [other]}, {"symbol_dirs": [other]}):
        body = {"plugin": "msl.info", "image_path": inside, **extra}
        assert client.post("/api/vol3/exec", json=body).status_code == 403, extra


# -- MCP ----------------------------------------------------------------------------

@pytest.fixture
def mcp_tools():
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server
    return {t.name: t for t in create_server()._tool_manager.list_tools()}


def test_mcp_plugin_dir_and_exec(mcp_tools, fake_vol, image):
    from memdiver.app.tools_pipeline import vol3_plugin_dir
    assert json.loads(mcp_tools["vol3_plugin_dir"].fn()) == vol3_plugin_dir()
    result = mcp_tools["vol3_exec"].fn("msl.info", image, args=["--pid", "2"],
                                       vol_bin=fake_vol, vol_python=sys.executable)
    payload = result.payload if hasattr(result, "payload") else json.loads(result)
    assert payload["ok"] is True and payload["rows"][0]["argv"][-3:] == ["msl.info", "--pid", "2"]


def test_mcp_synthesize_into_a_named_case(mcp_tools, two_runs):
    from memdiver.analysis.case import Case
    named = Case.init("mcp_case")
    out = mcp_tools["synthesize_vol3_plugin"].fn(
        dump_paths=[r["msl"] for r in two_runs], name=PLUGIN, oracle_kind=fx.KIND,
        key_hex=[r["key"] for r in two_runs],
        oracle_sample_path=[r["vault"] for r in two_runs], case_dir="mcp_case")
    payload = json.loads(out)
    assert payload["proven"] is True and payload["plugin_dir"] == str(
        named.dir / "vol3" / "plugins")
    _no_key(two_runs, out)


def test_mcp_synthesize_refuses_a_plain_directory(mcp_tools, two_runs, tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    out = mcp_tools["synthesize_vol3_plugin"].fn(
        dump_paths=[two_runs[0]["msl"]], name=PLUGIN, oracle_kind=fx.KIND,
        key_hex=two_runs[0]["key"], oracle_sample_path=two_runs[0]["vault"],
        case_dir=str(plain))
    assert "case.not_a_case" in out and not (plain / "vol3").exists()
    _no_key(two_runs, out)


# -- real corpus: CLI synthesize on run_0001 + run_0002, then vol3 exec of the result -

@pytest.mark.skipif(not HAVE_CORPUS, reason="gocryptfs corpus not present")
@pytest.mark.skipif(shutil.which("vol") is None, reason="stock `vol` not on PATH")
def test_corpus_cli_synthesize_then_exec_proves_the_key(tmp_path, case, capsys):
    runs = [GOCRYPTFS_CORPUS / "run_0001", GOCRYPTFS_CORPUS / "run_0002"]
    captures = [run / "memslicer.msl" for run in runs]
    if not all(c.is_file() for c in captures):
        pytest.skip("run_0001/run_0002 have no memslicer.msl")
    keys = [json.loads((run / "meta.json").read_text())["master_key_hex"] for run in runs]
    key_file = tmp_path / "keys.txt"
    key_file.write_text("\n".join(keys) + "\n", encoding="utf-8")
    rc, out, err = _cli(["synthesize", *map(str, captures), "--name", "memdiver_gocryptfs",
                         "--oracle-kind", fx.KIND,
                         *sum((["--oracle-sample", str(r / "cipher")] for r in runs), []),
                         "--key-hex-file", str(key_file), "--case", str(case.dir)], capsys)
    payload = json.loads(out)
    assert rc == 0 and payload["proven"] is True, err
    assert [v["status"] for v in payload["verdicts"]] == ["proven", "proven"]
    assert not any(k in out or k in err for k in keys)
    argv = shlex.split(payload["vol_command"])
    target = argv[argv.index("-f") + 2]
    rc, out, err = _cli(["exec", "--image", str(captures[0]), "-p", payload["plugin_dir"],
                         "--timeout", "900", target], capsys)
    rows = json.loads(out)["rows"]
    proven = [r for r in rows if r.get("Proven") == f"oracle:{fx.KIND}"]
    assert rc == 0 and {r["KeyHex"] for r in proven} == {keys[0]}, err


# -- review fixes: launcher sandbox, request bounds, 422 echo -------------------------

def test_rest_sandbox_confines_vol_bin_and_vol_python(client, monkeypatch, tmp_path):
    """Also tightens the pre-existing POST /api/scan/verify-plugin (intended)."""
    from memdiver.api.config import get_settings
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    monkeypatch.setenv("MEMDIVER_ALLOWED_ROOTS", str(allowed))
    get_settings.cache_clear()
    inside, outside = str(allowed / "x"), str(tmp_path / "outside" / "vol.py")
    for key in ("vol_bin", "vol_python"):
        for url, body in (
                ("/api/vol3/exec", {"plugin": "msl.info", "image_path": inside}),
                ("/api/vol3/synthesize", {"dump_paths": [inside], "name": "n",
                                          "oracle_kind": "k"}),
                ("/api/scan/verify-plugin", {"dump_paths": [inside], "plugin_source": "x=1",
                                             "mode": "subprocess"})):
            resp = client.post(url, json={**body, key: outside})
            assert resp.status_code == 403, (url, key, resp.text)


@pytest.mark.parametrize("timeout_s", [0, 901, 10 ** 7])
def test_rest_exec_timeout_is_bounded(client, image, timeout_s):
    resp = client.post("/api/vol3/exec", json={"plugin": "msl.info", "image_path": image,
                                               "timeout_s": timeout_s})
    assert resp.status_code == 422


def test_rest_synthesize_bounds_dumps_and_the_vol_budget(client):
    body = {"name": "n", "oracle_kind": "k", "secret_hex": "11"}
    resp = client.post("/api/vol3/synthesize", json={**body, "dump_paths": ["d"] * 17})
    assert resp.status_code == 422
    resp = client.post("/api/vol3/synthesize", json={**body, "dump_paths": []})
    assert resp.status_code == 422
    resp = client.post("/api/vol3/synthesize", json={**body, "dump_paths": ["d"] * 5,
                                                     "full_image": "img"})
    assert resp.status_code == 400 and "synth.vol3_plugin.vol_budget" in resp.text


def test_surface_limit_checks():
    from memdiver.app.vol3_surface_limits import check_exec_timeout, check_synth_request
    check_exec_timeout(1)
    check_exec_timeout(900)
    for bad in (0, 901):
        with pytest.raises(CapabilityError, match="timeout_s"):
            check_exec_timeout(bad)
    check_synth_request(["d"] * 16, None, None)
    check_synth_request(["d"] * 3, "img", "vault")  # 4 attempts x 900 s == 3600 s budget
    with pytest.raises(CapabilityError) as exc:
        check_synth_request(["d"] * 17, None, None)
    assert exc.value.code == "synth.vol3_plugin.too_many_dumps"
    with pytest.raises(CapabilityError) as exc:
        check_synth_request(["d"] * 4, "img", "vault")
    assert exc.value.code == "synth.vol3_plugin.vol_budget"


def test_mcp_exec_timeout_and_synth_budget_are_bounded(mcp_tools, image):
    out = mcp_tools["vol3_exec"].fn("msl.info", image, timeout_s=901)
    text = out if isinstance(out, str) else json.dumps(out.payload)
    assert "vol3.exec.timeout_range" in text
    out = mcp_tools["synthesize_vol3_plugin"].fn(
        dump_paths=["d"] * 17, name="n", oracle_kind="k", key_hex="11")
    assert "synth.vol3_plugin.too_many_dumps" in out


def test_rest_422_never_echoes_the_submitted_values(client):
    secret = "c0ffee" * 8
    for extra in ({"secret_hexx": secret}, {"secret_hex": {"k": secret}},
                  {"passphrase": {"p": secret}}, {"hit": secret},
                  {"full_image_secret_hex": [secret]}):
        resp = client.post("/api/vol3/synthesize", json={
            "dump_paths": ["/x"], "name": "n", "oracle_kind": "k", **extra})
        assert resp.status_code == 422 and secret not in resp.text, extra
        for error in resp.json()["detail"]:
            assert {"type", "loc", "msg"} <= set(error) and not {"input", "ctx"} & set(error)
