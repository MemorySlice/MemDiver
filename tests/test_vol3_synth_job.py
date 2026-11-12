"""``POST /api/vol3/synthesize`` as a background job (contest E3).

* routing: inline without ``async`` / ``full_image``, a job with either; a bad
  request is refused BEFORE a job exists;
* the job's artifact is the inline answer; progress names phases, never keys;
* ``vol3_subproc.run_cancellable``: a cancelled / timed-out / interrupted run
  kills vol's whole process group within ~1 s; ``_run`` and ``run_vol`` (every
  plugin run: ``run_plugin``, ``run_named_plugin``, the full-image synthesis)
  go through it with or without ``cancel``;
* a SIGTERM or SIGKILL to a worker running vol leaves no vol behind (lifeline);
* a real TaskManager: cancel kills vol and the next job starts promptly, and a
  finished job's task dir and GET responses hold no secret.

A fake ``vol.py`` stands in for stock vol: it reads the ``-f`` image, and an
image starting with ``SLOW`` makes it spawn a grandchild, write both pids
next to the image and sleep; any other image answers ``[]`` at once.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from memdiver.engine import vol3_subproc
from memdiver.engine.progress import Cancelled
from memdiver.msl.enums import ArchType, OSType
from memdiver.msl.writer import MslWriter
from tests import _vol3_recipe_fixtures as fx

pytest.importorskip("cryptography")
pytest.importorskip("volatility3")

PLUGIN = "memdiver_gocryptfs_job"
PASSPHRASE = "container-passphrase-never-stored"
IMAGE_TRUTH = "c0ffee" * 10 + "c0ff"
#: Generous on purpose: the real runs measure ~0.25 s, but a machine running
#: other vol scans (load average 30 seen) delays process exit by seconds.
GONE_WITHIN_S = 5.0

SLOW_SCRIPT = textwrap.dedent('''\
    import os, subprocess, sys, time
    pidfile = sys.argv[1]
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    with open(pidfile + ".tmp", "w") as fh:
        fh.write(f"{os.getpid()} {child.pid}")
    os.replace(pidfile + ".tmp", pidfile)
    print("started", flush=True)
    time.sleep(120)
''')

FAKE_VOL = textwrap.dedent('''\
    import json, os, subprocess, sys, time
    image = sys.argv[sys.argv.index("-f") + 1]
    if open(image, "rb").read(4) == b"SLOW":
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
        with open(image + ".pids.tmp", "w") as fh:
            fh.write(f"{os.getpid()} {child.pid}")
        os.replace(image + ".pids.tmp", image + ".pids")
        time.sleep(120)
    print(json.dumps([]))
''')


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


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
def fake_vol(tmp_path):
    path = tmp_path / "bin" / "vol.py"
    path.parent.mkdir()
    path.write_text(FAKE_VOL, encoding="utf-8")
    return str(path)


def _image(tmp_path: Path, name: str, slow: bool) -> Path:
    path = tmp_path / name
    path.write_bytes((b"SLOW" if slow else b"FAST") + bytes(60))
    return path


def _secrets(runs):
    return [r["key"] for r in runs] + [IMAGE_TRUTH, PASSPHRASE]


def _synth_body(runs, **extra):
    return {"dump_paths": [r["msl"] for r in runs], "name": PLUGIN, "oracle_kind": fx.KIND,
            "secret_hex": [r["key"] for r in runs],
            "oracle_sample_path": [r["vault"] for r in runs], **extra}


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:  # pragma: no cover - reused by another user's process
        return True
    # A zombie still answers kill(0); ps tells the truth.
    state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True,
                           text=True).stdout.strip()
    return bool(state) and not state.startswith("Z")


def _assert_gone(pids, within=GONE_WITHIN_S):
    deadline = time.monotonic() + within
    while time.monotonic() < deadline and any(_pid_alive(p) for p in pids):
        time.sleep(0.05)
    alive = [p for p in pids if _pid_alive(p)]
    for pid in alive:  # never leave a sleeper behind a failing test
        os.kill(pid, signal.SIGKILL)
    assert not alive, f"still alive after {within} s: {alive}"


def _wait_for_file(path: Path, timeout: float = 120.0) -> float:
    deadline = time.monotonic() + timeout
    while not path.is_file():
        assert time.monotonic() < deadline, f"{path} never appeared"
        time.sleep(0.05)
    return time.monotonic()


def _pids(path: Path):
    return [int(p) for p in path.read_text().split()]


# --------------------------------------------------------------------------- run_cancellable

def test_every_run_goes_through_run_cancellable(tmp_path, monkeypatch):
    """``_run`` (the version probe) and ``run_vol`` (every plugin run) share the one runner."""
    seen = []

    def fake(argv, cwd, **kwargs):
        seen.append(kwargs)
        stdout = kwargs["stdout"]
        if stdout is not subprocess.PIPE:
            stdout.write(b"[]")
        return subprocess.CompletedProcess(list(argv), 0, "", "")

    monkeypatch.setattr(vol3_subproc, "run_cancellable", fake)
    monkeypatch.setattr(vol3_subproc.subprocess, "run", None)  # must not be reached
    vol3_subproc._run(("vol", "-h"), tmp_path, timeout=5)
    launcher = vol3_subproc.Vol3Launcher(("vol",), tmp_path, None, "test")
    never = lambda: False  # noqa: E731
    vol3_subproc.run_named_plugin(launcher, "msl.info", tmp_path / "x.msl", timeout=7, cancel=never)
    spec = vol3_subproc.VolSpec(plugin="m.C", image=tmp_path / "x.msl")
    vol3_subproc.run_vol(launcher, spec, timeout=8, cancel=never)
    assert [(k["timeout"], k["cancel"], k.get("text", False)) for k in seen] == [
        (5, None, True), (7, never, False), (8, never, False)]
    assert all(k["env"]["PYTHONDONTWRITEBYTECODE"] == "1" for k in seen[1:])


def test_run_cancellable_has_two_call_sites_only():
    """Every plugin run is ``run_vol``: nothing else in the package spawns vol by hand."""
    import re

    root = Path(vol3_subproc.__file__).resolve().parent.parent
    sites = {}
    for path in [*root.glob("engine/*.py"), *root.glob("app/**/*.py"), *root.glob("api/**/*.py"),
                 *root.glob("cli/*.py"), *root.glob("mcp_server/*.py")]:
        hits = re.findall(r"^def (\w+)|(run_cancellable\()", path.read_text(), re.M)
        current = None
        for name, call in hits:
            current = name or current
            if call:
                sites.setdefault(f"{path.name}:{current}", 0)
    assert set(sites) == {"vol3_subproc.py:_run", "vol3_subproc.py:run_vol"}


def test_run_plugin_named_plugin_and_synth_route_through_run_vol(tmp_path, monkeypatch):
    from memdiver.app import tools_pipeline as tp

    specs = []

    def fake_run_vol(launcher, spec, *, timeout, cancel=None, **caps):
        specs.append((spec, cancel, caps))
        return vol3_subproc.VolRun(tuple(spec.argv(launcher)), 0, [], "", None)

    monkeypatch.setattr(vol3_subproc, "run_vol", fake_run_vol)
    launcher = vol3_subproc.Vol3Launcher(("vol",), tmp_path, None, "test")
    plugin = tmp_path / "p.py"
    plugin.write_text("class P(object):\n    pass\n")
    never = lambda: False  # noqa: E731
    vol3_subproc.run_plugin(launcher, plugin, tmp_path / "d", cancel=never)
    vol3_subproc.run_named_plugin(launcher, "msl.info", tmp_path / "d")
    display = tp._synth_display_spec("/pkg", tmp_path, "m.C", tmp_path / "d")
    tp._synth_image_run(launcher, display, plugin_dirs=("/pkg", tmp_path), cache="/c",
                        cancel=never)
    assert [s.plugin for s, _, _ in specs] == ["p.P", "msl.info", "m.C"]
    assert [c for _, c, _ in specs] == [never, None, never]
    assert specs[2][2]["stderr_tail"] == tp.SYNTH_VOL_STDERR_TAIL


def test_run_answers_like_subprocess_run(tmp_path):
    argv = (sys.executable, "-c",
            "import sys; print('out'); sys.stderr.write('err\\n'); sys.exit(3)")
    plain = subprocess.run(argv, cwd=tmp_path, capture_output=True, text=True, check=False)
    for cancel in (None, lambda: False):
        ran = vol3_subproc._run(argv, tmp_path, timeout=30, cancel=cancel)
        assert (ran.returncode, ran.stdout, ran.stderr) == (
            plain.returncode, plain.stdout, plain.stderr) == (3, "out\n", "err\n")


def test_a_sigkilled_child_is_reported_as_killed_not_as_a_lifeline_crash(tmp_path):
    # SIGKILL (the OOM killer) cannot take a handler: the lifeline must still
    # pass the signal death on instead of crashing with exit 1 and a traceback.
    argv = (sys.executable, "-c", "import os, signal; os.kill(os.getpid(), signal.SIGKILL)")
    ran = vol3_subproc._run(argv, tmp_path, timeout=30)
    assert ran.returncode == -signal.SIGKILL
    assert "Traceback" not in ran.stderr


def _slow(tmp_path: Path):
    script = tmp_path / "slow.py"
    script.write_text(SLOW_SCRIPT, encoding="utf-8")
    pidfile = tmp_path / "slow.pids"
    return [sys.executable, str(script), str(pidfile)], pidfile


def test_cancel_kills_the_whole_process_group_promptly(tmp_path):
    argv, pidfile = _slow(tmp_path)
    started = {}

    def cancel():
        if pidfile.is_file():
            started.setdefault("at", time.monotonic())
            return True
        return False

    with pytest.raises(Cancelled):
        vol3_subproc._run(argv, tmp_path, timeout=60, cancel=cancel)
    assert time.monotonic() - started["at"] < GONE_WITHIN_S
    _assert_gone(_pids(pidfile))


def test_run_vol_cancel_kills_the_whole_group_of_a_fake_vol(tmp_path, fake_vol):
    """The lifeline PoC through ``run_vol``: vol AND its grandchild are gone on cancel."""
    image = _image(tmp_path, "slow.lime", slow=True)
    pidfile = Path(str(image) + ".pids")
    launcher = vol3_subproc.Vol3Launcher((sys.executable, fake_vol), tmp_path, None, "test")
    spec = vol3_subproc.VolSpec(plugin="m.C", image=image)
    with pytest.raises(Cancelled):
        vol3_subproc.run_vol(launcher, spec, timeout=60, cancel=pidfile.is_file)
    _assert_gone(_pids(pidfile))


@pytest.mark.parametrize("cancel", [None, lambda: False], ids=["no-cancel", "cancel"])
def test_timeout_still_raises_and_kills_the_group(tmp_path, cancel):
    argv, pidfile = _slow(tmp_path)
    t0 = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        vol3_subproc._run(argv, tmp_path, timeout=3, cancel=cancel)
    assert 3 <= time.monotonic() - t0 < 6
    _assert_gone(_pids(pidfile))


def test_an_exception_mid_wait_kills_the_group(tmp_path):
    """A terminal Ctrl-C in the worker raises KeyboardInterrupt inside the wait."""
    argv, pidfile = _slow(tmp_path)

    def interrupt():
        if pidfile.is_file():
            raise KeyboardInterrupt
        return False

    with pytest.raises(KeyboardInterrupt):
        vol3_subproc.run_cancellable(argv, tmp_path, timeout=60, cancel=interrupt,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _assert_gone(_pids(pidfile))


def test_a_signal_death_of_vol_keeps_its_returncode(tmp_path):
    argv = (sys.executable, "-c", "import os, signal; os.kill(os.getpid(), signal.SIGTERM)")
    plain = subprocess.run(argv, cwd=tmp_path, check=False)
    assert vol3_subproc._run(argv, tmp_path, timeout=30).returncode == \
        plain.returncode == -signal.SIGTERM


def test_the_lifeline_enforces_the_deadline_without_the_parent(tmp_path, monkeypatch):
    """Even a wedged parent that never polls cannot let the group outlive its budget."""
    monkeypatch.setattr(vol3_subproc, "LIFELINE_GRACE_S", 0.0)
    argv, pidfile = _slow(tmp_path)
    proc, lifeline = vol3_subproc._start_group(argv, tmp_path, 1.0, stdout=subprocess.DEVNULL,
                                               stderr=subprocess.DEVNULL)
    try:
        _wait_for_file(pidfile)
        assert proc.wait(timeout=GONE_WITHIN_S + 2) == -signal.SIGKILL
        _assert_gone(_pids(pidfile))
    finally:
        os.close(lifeline)


SIGKILL_CHILD = textwrap.dedent('''\
    import subprocess, sys
    from memdiver.engine import vol3_subproc
    vol3_subproc.run_cancellable(sys.argv[1:], ".", timeout=120, cancel=lambda: False,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
''')


def test_sigkill_of_the_worker_takes_vol_down_through_the_lifeline(tmp_path):
    """No handler runs on SIGKILL (or OOM): the group's own watchdog must notice."""
    argv, pidfile = _slow(tmp_path)
    child = subprocess.Popen([sys.executable, "-c", SIGKILL_CHILD, *argv], cwd=tmp_path)
    try:
        _wait_for_file(pidfile)
        child.kill()
        child.wait(timeout=5)
        _assert_gone(_pids(pidfile))
    finally:
        if child.poll() is None:
            child.kill()


# --------------------------------------------------------------------------- SIGTERM

def test_sigterm_of_the_worker_takes_vol_down_through_the_lifeline(tmp_path):
    """The default SIGTERM disposition proceeds; the lifeline kills vol right after."""
    argv, pidfile = _slow(tmp_path)
    child = subprocess.Popen([sys.executable, "-c", SIGKILL_CHILD, *argv], cwd=tmp_path)
    try:
        _wait_for_file(pidfile)
        t0 = time.monotonic()
        child.send_signal(signal.SIGTERM)
        assert child.wait(timeout=5) == -signal.SIGTERM  # the default disposition proceeded
        assert time.monotonic() - t0 < GONE_WITHIN_S
        _assert_gone(_pids(pidfile))
    finally:
        if child.poll() is None:
            child.kill()


# --------------------------------------------------------------------------- REST routing

class _FakeManager:
    def __init__(self, root):
        self.artifact_store = SimpleNamespace(root=root)
        self.submitted = []

    def submit(self, *, kind, params, runner_dotted, stage_names=None):
        self.submitted.append({"kind": kind, "params": params, "runner": runner_dotted,
                               "stages": stage_names})
        return SimpleNamespace(task_id="t" * 32, status=SimpleNamespace(value="pending"))


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


@pytest.fixture
def manager(monkeypatch, tmp_path):
    fake = _FakeManager(str(tmp_path / "tasks"))
    monkeypatch.setattr("memdiver.api.routers.vol3.task_manager_or_503", lambda: fake)
    return fake


@pytest.fixture
def producer(monkeypatch):
    """A fake producer recording its kwargs; the payload is derived from them."""
    from memdiver.app import tools_pipeline
    calls = []

    def fake(**kwargs):
        calls.append(kwargs)
        if kwargs.get("on_progress"):
            kwargs["on_progress"](0.5, "half way")
        return {"proven": True, "name": kwargs["name"], "dumps": kwargs["dump_paths"],
                "full_image": kwargs["full_image"], "verdicts": [], "diagnostics": []}
    real = tools_pipeline.synthesize_vol3_plugin
    monkeypatch.setattr(tools_pipeline, "synthesize_vol3_plugin", fake)
    return SimpleNamespace(calls=calls, real=real)


def test_plain_request_stays_inline(client, manager, producer, two_runs):
    resp = client.post("/api/vol3/synthesize", json=_synth_body(two_runs))
    assert resp.status_code == 200 and resp.json()["proven"] is True
    assert len(producer.calls) == 1 and not manager.submitted


@pytest.mark.parametrize("extra", [{"async": True}, {"full_image": "IMAGE"}])
def test_async_or_full_image_is_a_job(client, manager, producer, two_runs, tmp_path, extra):
    if "full_image" in extra:
        extra = {"full_image": str(_image(tmp_path, "img.lime", slow=False))}
    resp = client.post("/api/vol3/synthesize", json=_synth_body(
        two_runs, passphrase=PASSPHRASE, **extra))
    assert resp.status_code == 200 and resp.json() == {"task_id": "t" * 32, "status": "pending"}
    assert not producer.calls
    (job,) = manager.submitted
    assert job["kind"] == "vol3_synth" and job["stages"] == ["vol3_synth"]
    assert job["runner"] == "memdiver.app.pipeline.vol3_synth_task_runner.run_synth_job"
    assert job["params"]["key_material_hex"] == {"passphrase": PASSPHRASE, "key_hex": None,
                                                 "kem_key_hex": None}
    assert job["params"]["kwargs"]["key_hex"] == [r["key"] for r in two_runs]


def test_a_bad_request_is_refused_before_any_job(client, manager, producer, two_runs, tmp_path):
    from memdiver.api.read_roots import write_roots
    plain = Path(write_roots()[0]) / "plain_not_a_case"
    plain.mkdir(parents=True, exist_ok=True)
    image = str(_image(tmp_path, "img.lime", slow=False))
    refusals = [
        (_synth_body(two_runs, case_dir=str(plain), **{"async": True}), "case.not_a_case"),
        (_synth_body(two_runs, key_hex="zz", **{"async": True}), "Invalid key material"),
        (_synth_body(two_runs * 2, full_image=image, full_image_sample=two_runs[0]["vault"]),
         "synth.vol3_plugin.vol_budget"),
    ]
    for body, marker in refusals:
        resp = client.post("/api/vol3/synthesize", json=body)
        assert resp.status_code == 400 and marker in resp.text, resp.text
    assert not manager.submitted and not producer.calls


@pytest.mark.parametrize("change, status, code", [
    ({"oracle_kind": "no-such-oracle"}, 400, "synth.vol3_plugin.unknown_oracle"),
    ({"verify_on": ["nope"]}, 400, "synth.vol3_plugin.unknown_target"),
    ({"hit": {"key_hex": "aa" * 32}}, 400, "synth.vol3_plugin.key_form"),
    ({"secret_hex": ""}, 400, "synth.vol3_plugin.key_form"),
    ({"secret_hex": ["zz" * 32, "aa" * 32]}, 400, "synth.vol3_plugin.invalid_key"),
    ({"secret_hex": ["aa" * 32] * 3}, 400, "synth.vol3_plugin.length_mismatch"),
    ({"dump_paths": ["/no/such/dump.msl"], "secret_hex": "aa" * 32,
      "oracle_sample_path": None}, 404, "File not found"),
    ({"oracle_sample_path": "/no/such/cipher"}, 404, "Oracle sample not found"),
    ({"full_image": "/no/such/image.lime"}, 404, "File not found"),
    ({"full_image": "IMAGE", "full_image_sample": "/no/such/vault"}, 404, "File not found"),
    ({"full_image": "IMAGE", "symbol_dirs": ["/a;b"]}, 400, "synth.vol3_plugin.semicolon_in_path"),
    ({"full_image": "IMAGE", "vol_bin": "/no/such/vol"}, 400, "synth.vol3_plugin.no_launcher"),
])
def test_the_job_path_refuses_like_inline_before_any_job(client, manager, producer, two_runs,
                                                         tmp_path, monkeypatch, change, status,
                                                         code):
    """The producer's own pre-flight runs before submit: same 4xx as inline, no job."""
    from memdiver.app import tools_pipeline
    image = str(_image(tmp_path, "img.lime", slow=False))
    change = {k: (image if v == "IMAGE" else v) for k, v in change.items()}
    body = {**_synth_body(two_runs), **change, "async": True}
    resp = client.post("/api/vol3/synthesize", json=body)
    assert resp.status_code == status and code in resp.text, resp.text
    assert not manager.submitted
    # the very same refusal the inline producer raises
    monkeypatch.setattr(tools_pipeline, "synthesize_vol3_plugin", producer.real)
    inline = client.post("/api/vol3/synthesize", json={**body, "async": False}) \
        if "full_image" not in change else None
    if inline is not None:
        assert (inline.status_code, inline.json().get("code")) == (
            resp.status_code, resp.json().get("code"))


# --------------------------------------------------------------------------- the worker, in-process

class _Ctx:
    def __init__(self, task_id="job1", cancel_after=None):
        self.task_id, self.events, self._cancel_after = task_id, [], cancel_after

    def emit(self, event_type, **fields):
        self.events.append({"type": event_type, **fields})

    def is_cancelled(self):
        progress = sum(e["type"] == "progress" for e in self.events)
        return self._cancel_after is not None and progress >= self._cancel_after


def _run_job(params, tmp_path, ctx=None):
    from memdiver.app.pipeline.vol3_synth_task_runner import run_synth_job
    ctx = ctx or _Ctx()
    result = run_synth_job({**params, "artifact_dir": str(tmp_path / "artifact")}, ctx)
    return result, ctx


def test_job_artifact_equals_the_inline_answer(client, manager, producer, two_runs, tmp_path):
    inline = client.post("/api/vol3/synthesize", json=_synth_body(two_runs)).json()
    client.post("/api/vol3/synthesize", json=_synth_body(two_runs, **{"async": True}))
    result, ctx = _run_job(manager.submitted[0]["params"], tmp_path)
    artifact = tmp_path / "artifact" / result["artifacts"][0]["relpath"]
    assert result["artifacts"][0]["name"] == "vol3_synth_result"
    assert json.loads(artifact.read_text()) == inline == result["summary"]
    assert {"type": "progress", "stage": "vol3_synth", "pct": 0.5, "msg": "half way"} in ctx.events
    assert producer.calls[1]["key_material"] == {} and producer.calls[1]["verify_on"] == ("msl",)


def _params(runs, **kwargs):
    base = {"dump_paths": [r["msl"] for r in runs], "name": PLUGIN, "oracle_kind": fx.KIND,
            "key_hex": [r["key"] for r in runs],
            "oracle_sample_path": [r["vault"] for r in runs], "verify_on": ["msl"]}
    return {"kwargs": {**base, **kwargs},
            "key_material_hex": {"passphrase": None, "key_hex": None, "kem_key_hex": None}}


def test_job_reports_each_phase_and_never_a_key(two_runs, tmp_path):
    result, ctx = _run_job(_params(two_runs), tmp_path)
    assert result["summary"]["proven"] is True
    progress = [e for e in ctx.events if e["type"] == "progress"]
    messages = [e["msg"] for e in progress]
    assert messages[0] == "locating the key and building the recipe"
    assert "emitting and self-testing the plugin" in messages
    assert "verifying on dump 1/2: run_a/memslicer.msl" in messages
    assert "verifying on dump 2/2: run_b/memslicer.msl" in messages
    pcts = [e["pct"] for e in progress]
    assert pcts == sorted(pcts) and 0 <= pcts[0] and pcts[-1] <= 0.99
    assert [ctx.events[0]["type"], ctx.events[-1]["type"]] == ["stage_start", "stage_end"]
    text = json.dumps([e for e in ctx.events if e["type"] != "stage_end"])
    assert not any(secret in text for secret in _secrets(two_runs))


def _emission_dirs():
    import tempfile
    return set(Path(tempfile.gettempdir()).glob("memdiver_vol3_synth_*"))


@pytest.fixture
def private_tempdir(tmp_path, monkeypatch):
    """Point ``tempfile`` at a directory only THIS test creates entries in.

    The system temp dir is shared with every other pytest-xdist worker, so a
    glob over it also sees their ``memdiver_vol3_synth_*`` dirs. ``gettempdir``
    caches, hence ``tempfile.tempdir`` is set directly (monkeypatch restores it).
    """
    import tempfile
    private = tmp_path / "tmp"
    private.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(private))
    return private


def test_job_cancel_stops_between_steps_and_drops_the_unstored_plugin(
    two_runs, tmp_path, private_tempdir,
):
    before = _emission_dirs()
    ctx = _Ctx(cancel_after=2)  # after "emitting": the plugin exists, no case keeps it
    with pytest.raises(RuntimeError, match="cancelled"):
        _run_job(_params(two_runs), tmp_path, ctx)
    assert ctx.events[-1] == {"type": "error", "error": "cancelled"}
    assert not any("verifying" in e.get("msg", "") for e in ctx.events)
    assert _emission_dirs() - before == set()  # the temporary emission dir is removed
    assert not (tmp_path / "artifact").exists()


def test_a_cancel_between_emit_and_self_test_skips_the_self_test(two_runs, tmp_path,
                                                                 monkeypatch):
    from memdiver.architect import vol3_recipe as vr
    ran = []
    monkeypatch.setattr(vr, "self_test", lambda *a, **k: ran.append(a))
    ctx = _Ctx(cancel_after=2)  # true from the "emitting" report on: after emit, before the test
    with pytest.raises(RuntimeError, match="cancelled"):
        _run_job(_params(two_runs), tmp_path, ctx)
    assert ran == []


def test_without_a_cancel_the_split_emit_still_self_tests(two_runs, tmp_path):
    result, _ = _run_job(_params(two_runs, verify_on=[]), tmp_path)
    assert result["summary"]["self_test"]["rows"] >= 1


def test_job_refusal_event_has_code_and_category(two_runs, tmp_path):
    ctx = _Ctx()
    with pytest.raises(ValueError):
        _run_job(_params(two_runs, oracle_kind="no-such-oracle"), tmp_path, ctx)
    error = ctx.events[-1]
    assert error["type"] == "error" and "no-such-oracle" in error["error"]
    assert error["extra"] == {"code": "synth.vol3_plugin.unknown_oracle",
                              "category": "INVALID_INPUT"}


# --------------------------------------------------------------------------- encrypted dumps
#
# The preflight on the request thread opens no dump: an encrypted .msl's key is
# probed on block 0 (one key derivation, no full AEAD pass). A run decrypts each
# dump ONCE (the run's KeyedSources pool) for the guard, a hit read and the
# recipe build; the "msl" verify target then opens each dump through its own
# vol3 layer (vol3plugins.msl_layer.open_slice), exactly as stock vol would.

CONTAINER_KEY = bytes(range(0x20, 0x40))
WRONG_CONTAINER_KEY = bytes(range(0x40, 0x60))
LOCKED = "encrypted_dump_locked"


def _write_encrypted_msl(path: Path, master: bytes) -> Path:
    from memdiver.msl.writer import MslEncryptionConfig

    writer = MslWriter(path, pid=4242, os_type=OSType.LINUX, arch_type=ArchType.X86_64,
                       encryption=MslEncryptionConfig(raw_key=CONTAINER_KEY))
    writer.add_memory_region(0x7F0000000000, fx.process_buffer(master))
    writer.add_end_of_capture()
    writer.write()
    return path


@pytest.fixture
def enc_runs(tmp_path):
    """Three encrypted captures (one container key) of two different secrets."""
    runs = []
    for label, master in (("a", fx.MASTER), ("b", fx.OTHER_MASTER), ("c", fx.MASTER)):
        run = tmp_path / f"enc_{label}"
        run.mkdir()
        runs.append({"msl": str(_write_encrypted_msl(run / "memslicer.msl", master)),
                     "vault": str(fx.write_vault(run / "cipher", master=master)),
                     "key": master.hex()})
    return runs


def _flip_last_ciphertext_byte(path: str) -> None:
    """A tamper beyond block 0: the probe cannot see it, the full tag pass can."""
    from memdiver.msl.aead_seek import TAG_LEN
    from memdiver.msl.reader import MslReader

    with MslReader(Path(path), key=CONTAINER_KEY) as reader:
        offset = reader.post_tag_offset - TAG_LEN - 1
    data = bytearray(Path(path).read_bytes())
    data[offset] ^= 0x01
    Path(path).write_bytes(bytes(data))


@pytest.fixture
def counts(monkeypatch):
    """Counters on the expensive steps, patched where they are LOOKED UP."""
    from memdiver.core import dump_source
    from memdiver.engine import key_location
    from memdiver.msl import reader as reader_mod

    seen = {"open_dump": 0, "reader_open": 0, "probe": 0, "kdf": 0, "full_pass": 0}

    def counting(name, real):
        def wrapper(*args, **kwargs):
            seen[name] += 1
            return real(*args, **kwargs)
        return wrapper
    for module in (dump_source, key_location):
        monkeypatch.setattr(module, "open_dump", counting("open_dump", module.open_dump))
    for name, attr in (("kdf", "derive_cek_consumer"), ("full_pass", "verify_tag_streaming")):
        monkeypatch.setattr(reader_mod, attr, counting(name, getattr(reader_mod, attr)))
    for name, attr in (("reader_open", "open"), ("probe", "probe_key")):
        monkeypatch.setattr(reader_mod.MslReader, attr,
                            counting(name, getattr(reader_mod.MslReader, attr)))

    def take():
        snapshot = dict(seen)
        seen.update({k: 0 for k in seen})
        return snapshot
    return take


def _enc_body(runs, **extra):
    return _synth_body(runs, key_hex=CONTAINER_KEY.hex(), **extra)


@pytest.mark.parametrize("wire", [{}, {"key_hex": WRONG_CONTAINER_KEY.hex()}],
                         ids=["no-key", "wrong-key"])
def test_a_locked_dump_is_refused_by_the_job_route_like_inline(client, manager, enc_runs,
                                                               counts, wire):
    """A missing / wrong container key: the same 400 before any job, without a full pass."""
    body = {**_synth_body(enc_runs), **wire, "async": True}
    job = client.post("/api/vol3/synthesize", json=body)
    assert not manager.submitted
    assert counts()["full_pass"] == 0  # the probe only
    inline = client.post("/api/vol3/synthesize", json={**body, "async": False})
    assert (job.status_code, job.json()["code"]) == (inline.status_code, inline.json()["code"])
    assert job.status_code == 400 and job.json()["code"] == LOCKED
    assert job.json() == inline.json()  # code, category and the KeyStatus hint


def test_a_tampered_ciphertext_is_a_job_that_fails_with_the_locked_code(client, manager,
                                                                        enc_runs, tmp_path):
    _flip_last_ciphertext_byte(enc_runs[1]["msl"])
    body = _enc_body(enc_runs, **{"async": True})
    accepted = client.post("/api/vol3/synthesize", json=body)
    assert accepted.status_code == 200 and accepted.json()["task_id"]
    ctx = _Ctx()
    with pytest.raises(ValueError):
        _run_job(manager.submitted[0]["params"], tmp_path, ctx)
    assert ctx.events[-1]["type"] == "error"
    assert ctx.events[-1]["extra"] == {"code": LOCKED, "category": "PRECONDITION"}
    inline = client.post("/api/vol3/synthesize", json={**body, "async": False})
    assert inline.status_code == 400 and inline.json()["code"] == LOCKED


def test_a_hit_outside_its_dump_is_a_job_that_fails_with_bad_hit(client, manager, enc_runs,
                                                                 tmp_path):
    hit = {"dump_path": enc_runs[0]["msl"], "offset": 1 << 40, "length": 32, "view": "vas"}
    body = {**_enc_body(enc_runs[:1], **{"async": True}), "secret_hex": "", "hit": hit}
    accepted = client.post("/api/vol3/synthesize", json=body)
    assert accepted.status_code == 200 and accepted.json()["task_id"]
    ctx = _Ctx()
    with pytest.raises(ValueError):
        _run_job(manager.submitted[0]["params"], tmp_path, ctx)
    assert ctx.events[-1]["extra"] == {"code": "synth.vol3_plugin.bad_hit",
                                       "category": "INVALID_INPUT"}
    inline = client.post("/api/vol3/synthesize", json={**body, "async": False})
    assert inline.status_code == 400 and inline.json()["code"] == "synth.vol3_plugin.bad_hit"


def test_a_bad_hit_shape_is_refused_before_any_job_without_a_dump_open(client, manager,
                                                                      enc_runs, counts):
    hit = {"dump_path": enc_runs[0]["msl"], "offset": -1, "length": 32}
    body = {**_enc_body(enc_runs[:1], **{"async": True}), "secret_hex": "", "hit": hit}
    resp = client.post("/api/vol3/synthesize", json=body)
    assert resp.status_code == 400 and resp.json()["code"] == "synth.vol3_plugin.bad_hit"
    assert not manager.submitted and counts() == dict.fromkeys(
        ("open_dump", "reader_open", "probe", "kdf", "full_pass"), 0)


@pytest.mark.parametrize("hit_dump, status, code", [
    ("missing", 404, None), ("locked", 400, LOCKED)], ids=["missing", "locked"])
def test_a_hit_on_its_own_dump_is_guarded_like_the_dumps(client, manager, enc_runs, tmp_path,
                                                         hit_dump, status, code):
    """A hit's ``dump_path`` outside ``dump_paths``: the same 404 / locked refusal, job and inline.

    The listed dump is a PLAINTEXT ``.msl`` and no container key is sent, so only
    the hit's own dump (absent, or encrypted) can trigger the refusal.
    """
    import gzip

    plain = tmp_path / "plain.msl"
    plain.write_bytes(gzip.decompress(
        (Path(__file__).resolve().parents[1] / "samples" / "gocryptfs_aes.msl.gz").read_bytes()))
    own = tmp_path / "absent.msl" if hit_dump == "missing" else Path(enc_runs[0]["msl"])
    body = {**_synth_body(enc_runs[:1]), "dump_paths": [str(plain)], "secret_hex": "",
            "hit": {"dump_path": str(own), "offset": 0, "length": 32}}
    job = client.post("/api/vol3/synthesize", json={**body, "async": True})
    inline = client.post("/api/vol3/synthesize", json={**body, "async": False})
    assert not manager.submitted
    assert job.status_code == inline.status_code == status, (job.text, inline.text)
    assert job.json() == inline.json()
    if code:
        assert job.json()["code"] == code


@pytest.mark.parametrize("asynchronous", [True, False], ids=["job", "inline"])
def test_a_bad_key_hex_fails_with_no_dump_open_and_no_probe(client, manager, enc_runs, counts,
                                                            asynchronous):
    bad = ["zz" * 32] + [r["key"] for r in enc_runs[1:]]
    resp = client.post("/api/vol3/synthesize",
                       json=_enc_body(enc_runs, secret_hex=bad, **{"async": asynchronous}))
    assert resp.status_code == 400 and resp.json()["code"] == "synth.vol3_plugin.invalid_key"
    assert not manager.submitted
    assert counts() == dict.fromkeys(("open_dump", "reader_open", "probe", "kdf",
                                      "full_pass"), 0)


def test_each_dump_is_decrypted_once_per_run_and_never_by_the_preflight(
        client, manager, enc_runs, counts, tmp_path, monkeypatch):
    n = len(enc_runs)
    accepted = client.post("/api/vol3/synthesize",
                           json=_enc_body(enc_runs, verify_on=[], **{"async": True}))
    assert accepted.status_code == 200
    preflight = counts()
    assert preflight["probe"] == n and preflight["kdf"] == n  # one derivation per dump
    assert preflight["full_pass"] == 0 and preflight["reader_open"] == 0
    assert preflight["open_dump"] == n  # the format sniff only: nothing is opened

    result, _ = _run_job(manager.submitted[0]["params"], tmp_path / "plain_run")
    assert result["summary"]["recipe"]["provenance"]["dumps"]
    run = counts()
    # guard + locate + windows + reference slice share ONE open per dump
    assert run["full_pass"] == n and run["reader_open"] == n and run["kdf"] == n
    assert run["probe"] == 0

    # verify_on=("msl",): the in-process verify opens each dump through its OWN vol3
    # layer (vol3plugins.msl_layer.open_slice), as stock vol would: N + N in total.
    key_file = tmp_path / "container.key"
    key_file.write_bytes(CONTAINER_KEY)
    monkeypatch.setenv("MEMDIVER_MSL_KEY_FILE", str(key_file))
    client.post("/api/vol3/synthesize",
                json=_enc_body(enc_runs, verify_on=["msl"], **{"async": True}))
    assert counts()["full_pass"] == 0
    result, _ = _run_job(manager.submitted[1]["params"], tmp_path / "msl_run")
    assert result["summary"]["proven"] is True
    assert counts()["full_pass"] == n + n


# --------------------------------------------------------------------------- a real TaskManager

@pytest.fixture
def task_manager(tmp_path):
    import asyncio

    from memdiver.api.services.artifact_store import ArtifactStore
    from memdiver.api.services.progress_bus import ProgressBus
    from memdiver.api.services.task_manager import TaskManager

    mgr = TaskManager(task_root=tmp_path / "tasks", artifact_store=ArtifactStore(tmp_path / "tasks"),
                      progress_bus=ProgressBus(), max_workers=2)
    loop = asyncio.new_event_loop()
    loop.run_until_complete(mgr.startup(loop))
    try:
        yield mgr, loop
    finally:
        mgr.shutdown(grace_s=0.0)
        stragglers = asyncio.all_tasks(loop)
        for task in stragglers:
            task.cancel()
        if stragglers:
            loop.run_until_complete(asyncio.gather(*stragglers, return_exceptions=True))
        loop.close()


def _pump_until(loop, predicate, timeout, what):
    import asyncio
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        loop.run_until_complete(asyncio.sleep(0.05))
        if predicate():
            return time.monotonic()
    raise AssertionError(f"never reached {what}")


def _submit_slow_synth(mgr, runs, tmp_path, fake_vol):
    image = _image(tmp_path, "slow.lime", slow=True)
    params = _params(runs, verify_on=[], full_image=str(image), vol_bin=fake_vol,
                     vol_python=sys.executable)
    record = mgr.submit(kind="vol3_synth", params={**params, "task_root": str(tmp_path / "tasks")},
                        runner_dotted="memdiver.app.pipeline.vol3_synth_task_runner.run_synth_job",
                        stage_names=["vol3_synth"])
    return record.task_id, Path(f"{image}.pids")


def test_cancel_kills_vol_and_the_next_job_starts_promptly(task_manager, two_runs, tmp_path,
                                                          fake_vol, monkeypatch):
    from memdiver.api.services import task_manager as tm
    from memdiver.api.services.task_manager import TaskStatus
    monkeypatch.setattr(tm, "CANCEL_GATE_GRACE_S", 120.0)  # the backstop must not be what frees it
    mgr, loop = task_manager
    task_id, pidfile = _submit_slow_synth(mgr, two_runs, tmp_path, fake_vol)
    _pump_until(loop, pidfile.is_file, 120, "vol running")
    t0 = time.monotonic()
    assert mgr.cancel(task_id)
    _assert_gone(_pids(pidfile))
    assert mgr.get(task_id).status == TaskStatus.CANCELLED
    nxt = mgr.submit(kind="echo", params={"x": 1}, runner_dotted="tests._task_runners.echo_runner",
                     stage_names=["echo"])
    done = _pump_until(loop, lambda: mgr.get(nxt.task_id).status == TaskStatus.SUCCEEDED, 30,
                       "the next job done")
    # Freed by the worker returning (the stuck-worker backstop is 120 s here).
    assert done - t0 < 20.0


def test_sigterm_to_the_worker_leaves_no_vol(task_manager, two_runs, tmp_path, fake_vol):
    mgr, loop = task_manager
    _, pidfile = _submit_slow_synth(mgr, two_runs, tmp_path, fake_vol)
    _pump_until(loop, pidfile.is_file, 120, "vol running")
    workers = list(mgr._pool._processes.values())
    for worker in workers:
        worker.terminate()  # SIGTERM, what TaskManager._reap_workers sends first
    _assert_gone(_pids(pidfile))
    _assert_gone([w.pid for w in workers])


def test_rest_job_end_to_end_keeps_no_secret(tmp_path, monkeypatch, two_runs, fake_vol):
    from fastapi.testclient import TestClient

    from memdiver.api.config import get_settings
    from memdiver.api.main import create_app
    task_root = tmp_path / "tasks"
    for sub, env in (("tasks", "MEMDIVER_TASK_ROOT"), ("uploads", "MEMDIVER_UPLOAD_DIR")):
        (tmp_path / sub).mkdir()
        monkeypatch.setenv(env, str(tmp_path / sub))
    monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS", raising=False)
    get_settings.cache_clear()
    image = _image(tmp_path, "fast.lime", slow=False)
    body = _synth_body(two_runs, full_image=str(image), full_image_secret_hex=IMAGE_TRUTH,
                       vol_bin=fake_vol, vol_python=sys.executable, passphrase=PASSPHRASE)
    try:
        with TestClient(create_app()) as client:
            ticket = client.post("/api/vol3/synthesize", json=body).json()
            task_id = ticket["task_id"]
            deadline = time.monotonic() + 180
            while client.get(f"/api/tasks/{task_id}").json()["status"] in ("pending", "running"):
                assert time.monotonic() < deadline
                time.sleep(0.2)
            responses = [client.get(url) for url in (
                "/api/tasks/", f"/api/tasks/{task_id}", f"/api/tasks/{task_id}/result",
                f"/api/tasks/{task_id}/events?since=0")]
    finally:
        get_settings.cache_clear()
    record, result = responses[1].json(), responses[2].json()
    assert record["status"] == "succeeded", record
    assert record["params"]["kwargs"]["key_hex"] == "<redacted>"
    assert record["params"]["kwargs"]["full_image_key_hex"] == "<redacted>"
    assert record["params"]["key_material_hex"] == "<redacted>"
    verdicts = result["payload"]["verdicts"]  # the two .msl dumps, then the fake vol's image
    assert [v["target"] for v in verdicts] == ["msl", "msl", "full_image"]
    assert [v["status"] for v in verdicts] == ["proven", "proven", "not_proven"]
    texts = [r.text for r in responses]
    texts += [p.read_text(errors="replace") for p in task_root.rglob("*") if p.is_file()]
    for secret in _secrets(two_runs):
        assert not any(secret in text for text in texts), secret
    shutil.rmtree(result["payload"]["plugin_dir"], ignore_errors=True)  # kept without a case


def test_a_refused_key_is_reported_by_length_only():
    from memdiver.app import tools_pipeline as tp
    key = "zz" + "ab" * 31
    assert tp._synth_redacted(key) == "<64 chars>"
    with pytest.raises(Exception) as info:
        tp._synth_parse_key(key, 0)
    assert "zz" not in str(info.value) and "ab" not in str(info.value)


def test_the_recipe_build_checks_cancel_once_per_dump(two_runs, monkeypatch):
    """The key is located dump by dump; a cancel after the first stops before the second."""
    from memdiver.architect import vol3_recipe as vr
    from memdiver.engine import key_location
    located, checks = [], []
    real = key_location.locate_key_across_dumps

    def spy(paths, *a, **k):
        located.extend(paths)
        return real(paths, *a, **k)
    monkeypatch.setattr(key_location, "locate_key_across_dumps", spy)

    def is_cancelled():
        checks.append(len(located))
        return len(located) >= 1
    with pytest.raises(Cancelled):
        vr.recipe_from_located_key([r["msl"] for r in two_runs], [r["key"] for r in two_runs],
                                   oracle_kind=fx.KIND, is_cancelled=is_cancelled)
    assert located == [two_runs[0]["msl"]] and checks == [0, 1]
    # without the callable nothing changes: both dumps located
    recipe, _ = vr.recipe_from_located_key([r["msl"] for r in two_runs],
                                           [r["key"] for r in two_runs], oracle_kind=fx.KIND,
                                           oracle_sample_path=two_runs[0]["vault"])
    assert recipe.name
