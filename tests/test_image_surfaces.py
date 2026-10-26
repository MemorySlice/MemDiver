"""The ``image.*`` capabilities on all four surfaces (plan T1.7).

Everything that needs a real Volatility 3 image is faked (``ImageContext.build``,
``get_image_context``, the pslist iteration, the profile chain and the
``extract_process_to_msl`` writer that another module owns); the descriptor,
cache, sha256, REST and job plumbing underneath are real. The gated real-image
proof lives in the last test (``MEMDIVER_IMAGE_CORPUS``).
"""
from __future__ import annotations

import json
import os
import sys
import time
import threading
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

from memdiver.app import tools_image as ti
from memdiver.core.image.context import ImageContext, file_sha256
from memdiver.core.image.profiles import (
    ProfileChain,
    ProfileResolution,
    write_cached_isf,
)
from memdiver.core.image.view_descriptor import MAGIC, ViewDescriptor, ViewKind
from memdiver.core.service_errors import CapabilityError, ErrorCategory


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


@pytest.fixture
def image(tmp_path):
    path = tmp_path / "img" / "box.lime"
    path.parent.mkdir()
    path.write_bytes(b"\x00" * 8192)
    return path


@pytest.fixture
def isf(tmp_path):
    path = tmp_path / "img" / "box.isf.json"
    path.write_text("{}", encoding="utf-8")
    return path


class FakeLayer:
    maximum_address = 0x1FFF


def fake_image_ctx(*, tasks=()):
    layers = {"phys": FakeLayer()}
    return SimpleNamespace(
        context=SimpleNamespace(layers=layers, tasks=list(tasks)),
        physical_layer="phys", kernel=SimpleNamespace(name="kernel"),
        canonical_kernel_va=_canonical57, lock=threading.RLock(),
        describe=lambda: {"physical_layer_chain": ["LimeLayer", "FileLayer"],
                          "kernel": None})


def _canonical57(address):
    """Sign-extend a de-canonicalized 57-bit (LA57) address, like vol3's canonicalize."""
    return address | (0xFFFF_FFFF_FFFF_FFFF ^ ((1 << 57) - 1)) if address >> 56 & 1 else address


@pytest.fixture
def fake_build(monkeypatch):
    calls = []

    def build(image_path, isf_path=None, *a, **k):
        calls.append((Path(image_path), isf_path))
        return fake_image_ctx()
    monkeypatch.setattr(ImageContext, "build", staticmethod(build))
    return calls


# -- probe ---------------------------------------------------------------------


def test_probe_reports_layers_versions_and_never_hashes(image, fake_build):
    out = ti.image_probe_result(str(image)).payload
    assert out["size"] == 8192 and out["physical_layer_chain"] == ["LimeLayer", "FileLayer"]
    assert out["image_sha256"] is None and out["profile"]["status"] == "unknown"
    assert "banners" not in out and set(out["versions"]) == {"volatility3", "pakunoda"}
    assert fake_build == [(image.resolve(), None)]


def test_probe_sees_cached_profile_after_hashing(image, isf, fake_build):
    sha = file_sha256(image)
    write_cached_isf(sha, "pakunoda", {"x": 1}, "pakunoda", {"banner": "Linux version 5"})
    out = ti.image_probe_result(str(image)).payload
    assert out["image_sha256"] == sha
    assert out["profile"]["status"] == "found" and out["profile"]["origin"] == "cache"
    explicit = ti.image_probe_result(str(image), isf=str(isf)).payload["profile"]
    assert explicit["origin"] == "explicit"


def test_probe_cache_miss_is_missing_not_error(image, fake_build):
    file_sha256(image)
    out = ti.image_probe_result(str(image)).payload
    assert out["profile"]["status"] == "missing" and out["profile"]["attempts"]


def test_probe_banners_are_opt_in(image, fake_build):
    image.write_bytes(b"junk" + b"Linux version 5.14.0-test (gcc)\n" + b"\0" * 64)
    out = ti.image_probe_result(str(image), banners=True).payload
    assert out["banners"] == ["Linux version 5.14.0-test (gcc)"]


@pytest.mark.parametrize("call,category", [
    (lambda p: ti.image_probe_result(""), ErrorCategory.INVALID_INPUT),
    (lambda p: ti.image_probe_result(str(p) + ".nope"), ErrorCategory.NOT_FOUND),
    (lambda p: ti.image_probe_result(str(p), isf=str(p) + ".nope"), ErrorCategory.NOT_FOUND),
])
def test_probe_bad_input(image, call, category):
    with pytest.raises(CapabilityError) as err:
        call(image)
    assert err.value.category is category


def test_probe_without_volatility_is_a_capability_error(image, monkeypatch):
    from memdiver.core.image import context as ctxmod

    def boom():
        raise CapabilityError("install memdiver[image]", category=ErrorCategory.UNSUPPORTED)
    monkeypatch.setattr(ctxmod, "require_volatility3", boom)
    with pytest.raises(CapabilityError) as err:
        ti.image_probe_result(str(image))
    assert err.value.category is ErrorCategory.UNSUPPORTED


# -- profile -------------------------------------------------------------------


class FakePakunoda:
    name = "pakunoda"
    last_reason = ""

    def __init__(self, isf_path):
        self.isf_path = isf_path
        self.calls = 0

    def resolve(self, image_path, image_sha256):
        self.calls += 1
        return ProfileResolution(self.isf_path, "ab" * 32, "pakunoda", "Linux version 5")


def _chain_with(fake, monkeypatch):
    from memdiver.core.image.profiles import CacheProvider, ExplicitProvider

    def chain(explicit, **_controls):
        return ProfileChain([ExplicitProvider(explicit), CacheProvider(), fake])
    monkeypatch.setattr(ti, "default_chain", chain)


def test_profile_resolves_through_pakunoda_and_can_disable_it(image, isf, monkeypatch):
    fake = FakePakunoda(isf)
    _chain_with(fake, monkeypatch)
    out = ti.image_profile_result(str(image)).payload
    assert out["origin"] == "pakunoda" and out["image_sha256"] == file_sha256(image)
    assert out["attempts"][-1] == ["pakunoda", "hit"] and fake.calls == 1
    with pytest.raises(CapabilityError) as err:
        ti.image_profile_result(str(image), allow_pakunoda=False)
    assert fake.calls == 1 and "no kernel profile" in err.value.message


def test_profile_explicit_isf_wins(image, isf, monkeypatch):
    fake = FakePakunoda(isf)
    _chain_with(fake, monkeypatch)
    out = ti.image_profile_result(str(image), isf=str(isf)).payload
    assert out["origin"] == "explicit" and fake.calls == 0


# -- open view -----------------------------------------------------------------


def test_open_physical_view_defaults_into_a_named_case(image):
    out = ti.image_open_view_result(str(image), "physical").payload
    path = Path(out["view_path"])
    assert path.parent.name == "views" and path.name == "box.physical.mdview"
    assert path.parent.parent.name == "box" and (path.parent.parent / "case.json").is_file()
    assert path.read_text().startswith(MAGIC)
    assert out["capture_id"] == file_sha256(image) == out["descriptor"]["image_sha256"]
    assert ViewDescriptor.read(path).view is ViewKind.PHYSICAL


@pytest.fixture(autouse=True)
def _no_open_time_profile_build(monkeypatch):
    """These fixtures use stub ISFs vol3 cannot load; the open-time check has its own tests."""
    monkeypatch.setattr(ti, "_check_profile_loads", lambda descriptor, target: None)


def test_open_process_view_uses_explicit_isf_and_case_dir(image, isf, tmp_path):
    out = ti.image_open_view_result(str(image), "process", pid=22176, isf=str(isf),
                                    case_dir=str(tmp_path / "mycase")).payload
    assert out["view_path"].endswith(
        f"mycase/views/box.process.pid22176.isf-{file_sha256(isf)[:8]}.mdview")
    desc = ViewDescriptor.read(Path(out["view_path"]))
    assert desc.pid == 22176 and desc.profile.origin == "explicit"
    assert desc.profile.sha256 == file_sha256(isf)


def test_open_view_out_path_and_cached_profile(image, tmp_path):
    sha = file_sha256(image)
    write_cached_isf(sha, "pakunoda", {"x": 1}, "pakunoda", {})
    target = tmp_path / "deep" / "k.mdview"
    out = ti.image_open_view_result(str(image), "kernel", out_path=str(target)).payload
    assert Path(out["view_path"]) == target
    assert ViewDescriptor.read(target).profile.origin == "cache"


def test_open_kernel_view_without_profile_says_run_profile(image):
    with pytest.raises(CapabilityError) as err:
        ti.image_open_view_result(str(image), "kernel")
    assert "image profile" in err.value.message and err.value.category is ErrorCategory.PRECONDITION


@pytest.mark.parametrize("kwargs", [
    {"view": "bogus"}, {"view": "process"}, {"view": "kernel", "pid": 4},
    {"view": "physical", "pid": 4},
])
def test_open_view_rejects_bad_combinations(image, kwargs):
    with pytest.raises(CapabilityError) as err:
        ti.image_open_view_result(str(image), **kwargs)
    assert err.value.category is ErrorCategory.INVALID_INPUT


# -- processes -----------------------------------------------------------------


def _view(tmp_path, image, isf, kind=ViewKind.PROCESS, pid=7):
    profile = None if kind is ViewKind.PHYSICAL else __import__(
        "memdiver.core.image.view_descriptor", fromlist=["ProfileRef"]).ProfileRef(
            str(isf), "cd" * 32, "explicit")
    desc = ViewDescriptor(str(image), "ef" * 32, kind,
                          pid=pid if kind is ViewKind.PROCESS else None, profile=profile)
    return desc.write(tmp_path / f"{kind.value}.mdview")


@pytest.fixture
def fake_pslist(monkeypatch):
    pytest.importorskip("volatility3")
    from volatility3.plugins.linux import pslist

    def fields(task, decorate_comm=False):
        return SimpleNamespace(offset=task.offset, user_pid=task.pid, user_ppid=task.ppid,
                               name=task.comm, uid=task.uid)
    monkeypatch.setattr(pslist.PsList, "get_task_fields", classmethod(
        lambda cls, task, decorate_comm=False: fields(task)))

    def list_tasks(context, module, *a, **k):
        return iter(context.tasks)
    monkeypatch.setattr(pslist.PsList, "list_tasks", classmethod(
        lambda cls, context, module, *a, **k: list_tasks(context, module)))


def _task(pid, comm, mm=1, uid=0):
    return SimpleNamespace(pid=pid, ppid=1, comm=comm, uid=uid, mm=mm, offset=0xFFFF0000 + pid)


def test_processes_rows_carry_a_kernel_va_location(tmp_path, image, isf, fake_pslist, monkeypatch):
    ctx = fake_image_ctx(tasks=[_task(1, "systemd"), _task(2, "kthreadd", mm=0, uid=None)])
    monkeypatch.setattr(ti, "get_image_context", lambda *a, **k: ctx)
    out = ti.image_processes_result(str(_view(tmp_path, image, isf))).payload
    assert out["count"] == 2 and out["row_source"] == "pslist"
    first, second = out["processes"]
    assert first == {"pid": 1, "ppid": 1, "comm": "systemd", "uid": 0, "has_mm": True,
                     "task_offset": 0xFFFF0001,
                     "location": {"space": "kernel_va", "value": 0xFFFF0001,
                                  "capture_id": "ef" * 32}}
    assert second["has_mm"] is False and second["uid"] is None
    assert len(ti.image_processes_result(str(_view(tmp_path, image, isf)), limit=1)
               .payload["processes"]) == 1


def test_processes_zero_rows_is_an_error_never_empty_success(tmp_path, image, isf,
                                                             fake_pslist, monkeypatch):
    monkeypatch.setattr(ti, "get_image_context", lambda *a, **k: fake_image_ctx())
    with pytest.raises(CapabilityError) as err:
        ti.image_processes_result(str(_view(tmp_path, image, isf)))
    assert "no tasks" in err.value.message and err.value.category is ErrorCategory.PRECONDITION


def test_processes_input_errors(tmp_path, image, isf):
    with pytest.raises(CapabilityError) as err:
        ti.image_processes_result(str(_view(tmp_path, image, isf, ViewKind.PHYSICAL)))
    assert err.value.category is ErrorCategory.INVALID_INPUT
    for bad in ("", str(tmp_path / "missing.mdview")):
        with pytest.raises(CapabilityError):
            ti.image_processes_result(bad)
    junk = tmp_path / "junk.mdview"
    junk.write_text("not a view")
    with pytest.raises(CapabilityError) as err:
        ti.image_processes_result(str(junk))
    assert err.value.code == "invalid_view_descriptor"


# -- extract -------------------------------------------------------------------


class FakeSource:
    def __init__(self, path):
        self.path = path

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def metadata(self):
        return {"layer": {"view": "process", "pid": 7, "comm": "sshd",
                          "process_dtb": 0x274610000}}


@pytest.fixture
def fake_extractor(monkeypatch):
    seen = {}

    def extract(source, output_path, *, note_fields, physical_ranges=None):
        seen.update(source=source, output=output_path, notes=note_fields,
                    ranges=list(physical_ranges or ()))
        Path(output_path).write_bytes(b"MSL")
        return SimpleNamespace(output_path=Path(output_path), pid=7, regions_written=3,
                               captured_bytes=12288, state_bytes={"captured": 12288},
                               # the real ExtractResult COUNTS the ranges (an int)
                               physical_ranges=len(seen["ranges"]))
    module = types.ModuleType("memdiver.msl.image_extract")
    module.extract_process_to_msl = extract
    monkeypatch.setitem(sys.modules, "memdiver.msl.image_extract", module)
    monkeypatch.setattr("memdiver.core.dump_source.open_dump", lambda p, **k: FakeSource(p))
    monkeypatch.setattr(ti, "get_image_context", lambda *a, **k: fake_image_ctx())
    return seen


def test_extract_builds_provenance_notes_and_physical_ranges(tmp_path, image, isf,
                                                             fake_extractor):
    view = _view(tmp_path, image, isf)
    out = ti.image_extract_process_result(str(view), str(tmp_path / "o" / "p.msl")).payload
    assert out["regions_written"] == 3 and out["state_bytes"] == {"captured": 12288}
    assert out["physical_ranges"] == [[0, 0x1FFF, "System RAM"]]
    assert (tmp_path / "o" / "p.msl").read_bytes() == b"MSL"
    notes = fake_extractor["notes"]
    assert notes["image_sha256"] == "ef" * 32 and notes["isf_sha256"] == "cd" * 32
    assert notes["isf_origin"] == "explicit" and notes["pid"] == "7"
    assert notes["comm"] == "sshd" and notes["dtb"] == hex(0x274610000)
    assert set(notes) >= {"vol3", "pakunoda", "banner"}
    assert fake_extractor["ranges"][0].label == "System RAM"


def test_extract_requires_a_process_view_and_an_output(tmp_path, image, isf, fake_extractor):
    with pytest.raises(CapabilityError) as err:
        ti.image_extract_process_result(
            str(_view(tmp_path, image, isf, ViewKind.KERNEL)), str(tmp_path / "x.msl"))
    assert err.value.code == "process_view_required"
    with pytest.raises(CapabilityError) as err:
        ti.image_extract_process_result(str(_view(tmp_path, image, isf)), " ")
    assert err.value.code == "out_path_required"


def test_extract_without_the_extractor_module_is_unsupported(tmp_path, image, isf,
                                                             monkeypatch):
    monkeypatch.setitem(sys.modules, "memdiver.msl.image_extract", None)  # import raises
    with pytest.raises(CapabilityError) as err:
        ti.image_extract_process_result(str(_view(tmp_path, image, isf)),
                                        str(tmp_path / "x.msl"))
    assert err.value.category is ErrorCategory.UNSUPPORTED


# -- CLI -----------------------------------------------------------------------


def _cli(argv, capsys):
    from memdiver.cli import _build_parser, _cmd_image
    rc = _cmd_image(_build_parser().parse_args(["image", *argv]))
    return rc, capsys.readouterr().out


def test_cli_probe_open_processes_extract(tmp_path, image, isf, fake_build, fake_pslist,
                                          fake_extractor, capsys, monkeypatch):
    rc, out = _cli(["probe", str(image)], capsys)
    assert rc == 0 and json.loads(out)["size"] == 8192
    target = tmp_path / "v.mdview"
    _, out = _cli(["open", str(image), "--view", "process", "--pid", "7", "--isf", str(isf),
                   "--out", str(target)], capsys)
    assert json.loads(out)["view_path"] == str(target)
    ctx = fake_image_ctx(tasks=[_task(7, "sshd")])
    monkeypatch.setattr(ti, "get_image_context", lambda *a, **k: ctx)
    _, out = _cli(["processes", str(target)], capsys)
    assert json.loads(out)["processes"][0]["comm"] == "sshd"
    dest = tmp_path / "p.msl"
    _, out = _cli(["extract", str(target), "--out", str(dest)], capsys)
    assert json.loads(out)["regions_written"] == 3 and dest.exists()
    report = tmp_path / "r.json"
    _cli(["probe", str(image), "-o", str(report)], capsys)
    assert json.loads(report.read_text())["size"] == 8192


def test_cli_profile_flags_and_errors(tmp_path, image, isf, monkeypatch, capsys):
    _chain_with(FakePakunoda(isf), monkeypatch)
    _, out = _cli(["profile", str(image)], capsys)
    assert json.loads(out)["origin"] == "pakunoda"
    with pytest.raises(CapabilityError):
        _cli(["profile", str(image), "--no-pakunoda"], capsys)
    with pytest.raises(CapabilityError):
        _cli(["open", str(image), "--view", "process"], capsys)


def test_cli_no_action_and_bad_view(capsys):
    from memdiver.cli import _build_parser, _cmd_image
    assert _cmd_image(_build_parser().parse_args(["image"])) == 1
    with pytest.raises(SystemExit):
        _build_parser().parse_args(["image", "open", "x", "--view", "bogus"])


# -- REST ----------------------------------------------------------------------


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


class FakeManager:
    def __init__(self, root):
        self.artifact_store = SimpleNamespace(root=root)
        self.submitted = []

    def submit(self, *, kind, params, runner_dotted, stage_names=None):
        self.submitted.append(dict(kind=kind, params=params, runner=runner_dotted))
        return SimpleNamespace(task_id="t" * 32, status=SimpleNamespace(value="pending"))


@pytest.fixture
def manager(monkeypatch, tmp_path):
    fake = FakeManager(tmp_path / "tasks")
    monkeypatch.setattr("memdiver.api.routers.image.task_manager_or_503", lambda: fake)
    return fake


def test_rest_probe_and_processes_are_inline(client, image, isf, tmp_path, fake_build,
                                             fake_pslist, monkeypatch):
    r = client.get("/api/image/probe", params={"image_path": str(image), "banners": "false"})
    assert r.status_code == 200 and r.json()["physical_layer_chain"][0] == "LimeLayer"
    view = _view(tmp_path, image, isf)
    ctx = fake_image_ctx(tasks=[_task(7, "sshd")])
    monkeypatch.setattr(ti, "get_image_context", lambda *a, **k: ctx)
    r = client.get("/api/image/processes", params={"view_path": str(view)})
    assert r.status_code == 200 and r.json()["processes"][0]["pid"] == 7
    r = client.get("/api/image/probe", params={"image_path": str(image) + ".nope"})
    assert r.status_code == 404


def test_rest_slow_endpoints_submit_jobs_with_contained_writes(client, manager, image,
                                                              tmp_path):
    uploads = tmp_path / "uploads"
    r = client.post("/api/image/profile", json={"image_path": str(image),
                                                "allow_pakunoda": False})
    assert r.status_code == 200 and r.json() == {"task_id": "t" * 32, "status": "pending"}
    r = client.post("/api/image/open-view", json={
        "image_path": str(image), "view": "process", "pid": 7,
        "out_path": str(uploads / "v.mdview")})
    assert r.status_code == 200
    r = client.post("/api/image/extract-process", json={
        "view_path": str(uploads / "v.mdview"), "out_path": str(uploads / "p.msl")})
    assert r.status_code == 200
    jobs = [s["params"] for s in manager.submitted]
    assert [j["job"] for j in jobs] == ["profile", "open_view", "extract_process"]
    assert jobs[0]["args"] == {"image_path": str(image), "isf": None, "allow_pakunoda": False}
    assert jobs[1]["args"]["out_path"] == str((uploads / "v.mdview").resolve())
    assert all(s["runner"].endswith("image_task_runner.run_image_job")
               for s in manager.submitted)
    assert all(j["task_root"] == str(tmp_path / "tasks") for j in jobs)


def test_rest_writes_outside_the_write_roots_are_refused(client, manager, image, tmp_path):
    outside = tmp_path / "elsewhere"
    r = client.post("/api/image/open-view", json={
        "image_path": str(image), "view": "physical", "out_path": str(outside / "v.mdview")})
    assert r.status_code == 403
    r = client.post("/api/image/open-view", json={
        "image_path": str(image), "view": "physical", "case_dir": str(outside)})
    assert r.status_code == 403
    r = client.post("/api/image/extract-process", json={
        "view_path": "v", "out_path": str(outside / "p.msl")})
    assert r.status_code == 403 and not manager.submitted and not outside.exists()


@pytest.mark.parametrize("url,body", [
    ("/api/image/profile", {"image_path": "x", "isf_path": "y"}),
    ("/api/image/open-view", {"image_path": "x", "view": "physical", "pidd": 1}),
    ("/api/image/extract-process", {"view_path": "x", "out_path": "y", "force": True}),
    ("/api/image/profile", {"allow_pakunoda": True}),
])
def test_rest_misspelled_or_missing_fields_are_422(client, manager, url, body):
    assert client.post(url, json=body).status_code == 422
    assert not manager.submitted


def test_rest_read_sandbox_applies_to_image_paths(client, manager, monkeypatch, tmp_path):
    from memdiver.api.config import get_settings
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    monkeypatch.setenv("MEMDIVER_ALLOWED_ROOTS", str(allowed))
    get_settings.cache_clear()
    other = str(tmp_path / "other" / "x.lime")
    assert client.get("/api/image/probe", params={"image_path": other}).status_code == 403
    assert client.get("/api/image/processes", params={"view_path": other}).status_code == 403
    assert client.post("/api/image/profile", json={"image_path": other}).status_code == 403
    assert client.post("/api/image/profile", json={
        "image_path": str(allowed / "x.lime"), "isf": other}).status_code == 403
    assert not manager.submitted


class _Ctx:
    task_id = "abc"

    def __init__(self):
        self.events = []

    def emit(self, kind, **fields):
        self.events.append((kind, fields))

    def is_cancelled(self):
        return False


def test_job_runner_returns_the_producer_payload_as_artifact_and_summary(image, tmp_path):
    from memdiver.app.pipeline.image_task_runner import run_image_job
    ctx = _Ctx()
    out = run_image_job({"job": "open_view", "task_root": str(tmp_path / "tasks"),
                         "args": {"image_path": str(image), "view": "physical",
                                  "out_path": str(tmp_path / "v.mdview")}}, ctx)
    assert out["summary"]["view_path"] == str(tmp_path / "v.mdview")
    (artifact,) = out["artifacts"]
    assert artifact["name"] == "image_result" and artifact["relpath"] == "image/result.json"
    stored = json.loads((tmp_path / "tasks" / "abc" / "image" / "result.json").read_text())
    assert stored == out["summary"]
    assert [k for k, _ in ctx.events] == ["stage_start", "stage_end"]


def test_job_runner_turns_capability_errors_into_value_errors(tmp_path):
    from memdiver.app.pipeline.image_task_runner import run_image_job
    ctx = _Ctx()
    with pytest.raises(ValueError, match="memory image not found"):
        run_image_job({"job": "profile", "task_root": str(tmp_path),
                       "args": {"image_path": str(tmp_path / "gone.lime")}}, ctx)
    assert ctx.events[-1][0] == "error"
    with pytest.raises(ValueError, match="unknown image job"):
        run_image_job({"job": "nope"}, ctx)


def _wait_terminal(client, task_id, timeout=90.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        record = client.get(f"/api/tasks/{task_id}").json()
        if record["status"] in ("succeeded", "failed", "cancelled"):
            return record
        time.sleep(0.25)
    raise AssertionError("task did not finish")


@pytest.fixture
def live_client(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from memdiver.api.config import get_settings
    from memdiver.api.main import create_app
    monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS", raising=False)
    monkeypatch.setenv("MEMDIVER_UPLOAD_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("MEMDIVER_TASK_ROOT", str(tmp_path / "tasks"))
    monkeypatch.setenv("MEMDIVER_PIPELINE_MAX_WORKERS", "1")
    get_settings.cache_clear()
    with TestClient(create_app()) as c:
        yield c
    get_settings.cache_clear()


def test_rest_job_end_to_end_in_a_real_worker(live_client, image, tmp_path):
    out = tmp_path / "uploads" / "v.mdview"
    r = live_client.post("/api/image/open-view", json={
        "image_path": str(image), "view": "physical", "out_path": str(out)})
    task_id = r.json()["task_id"]
    record = _wait_terminal(live_client, task_id)
    assert record["status"] == "succeeded", record
    assert [a["name"] for a in record["artifacts"]] == ["image_result"]
    assert ViewDescriptor.read(out).capture_id == file_sha256(image)
    r = live_client.get(f"/api/pipeline/runs/{task_id}/artifacts/image_result")
    assert r.status_code == 200 and r.json()["view_path"] == str(out.resolve())


def test_rest_job_failure_carries_the_capability_message(live_client, tmp_path):
    r = live_client.post("/api/image/profile", json={"image_path": str(tmp_path / "gone.lime")})
    record = _wait_terminal(live_client, r.json()["task_id"])
    assert record["status"] == "failed" and "memory image not found" in record["error"]


# -- MCP -----------------------------------------------------------------------


@pytest.fixture(scope="module")
def server():
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server
    return create_server()


@pytest.fixture
def tools(server):
    return {t.name: t for t in server._tool_manager.list_tools()}


def _mcp(tools, name, **kw):
    return json.loads(tools[name].fn(**kw))


def test_mcp_tools_match_producers(tools, image, isf, tmp_path, fake_build, fake_pslist,
                                   fake_extractor, monkeypatch):
    assert _mcp(tools, "image_probe", image_path=str(image))["size"] == 8192
    target = tmp_path / "m.mdview"
    opened = _mcp(tools, "image_open_view", image_path=str(image), view="process", pid=7,
                  isf=str(isf), out_path=str(target))
    assert opened["view_path"] == str(target)
    ctx = fake_image_ctx(tasks=[_task(7, "sshd")])
    monkeypatch.setattr(ti, "get_image_context", lambda *a, **k: ctx)
    assert _mcp(tools, "image_processes", view_path=str(target))["count"] == 1
    out = _mcp(tools, "image_extract_process", view_path=str(target),
               out_path=str(tmp_path / "m.msl"))
    assert out["regions_written"] == 3


def test_mcp_profile_and_errors_are_structured(tools, image, isf, monkeypatch):
    _chain_with(FakePakunoda(isf), monkeypatch)
    assert _mcp(tools, "image_profile", image_path=str(image))["origin"] == "pakunoda"
    out = _mcp(tools, "image_open_view", image_path=str(image), view="kernel")
    assert "image profile" in out["error"]
    assert "error" in _mcp(tools, "image_probe", image_path=str(image) + ".nope")


# -- real image (gated) --------------------------------------------------------

_ROOT = os.environ.get("MEMDIVER_IMAGE_CORPUS", "")
_ALMA9 = "alma-9_5.14.0-427.el9"
_HAS_REAL = bool(_ROOT) and all((Path(_ROOT) / f"{_ALMA9}{e}").is_file()
                                for e in (".lime", ".gt.isf.json"))


@pytest.mark.skipif(not _HAS_REAL, reason="set MEMDIVER_IMAGE_CORPUS to pakunoda dumps/acquired")
def test_real_alma9_probe_open_processes(tmp_path):
    lime = str(Path(_ROOT) / f"{_ALMA9}.lime")
    gt = str(Path(_ROOT) / f"{_ALMA9}.gt.isf.json")
    probe = ti.image_probe_result(lime).payload
    assert probe["size"] == os.path.getsize(lime) and probe["physical_layer_chain"]
    assert probe["profile"]["status"] == "unknown"
    opened = ti.image_open_view_result(lime, "process", pid=22176, isf=gt,
                                       out_path=str(tmp_path / "sshd.mdview")).payload
    assert opened["descriptor"]["pid"] == 22176 and opened["descriptor"]["profile"]["isf"] == str(Path(gt).resolve())
    procs = ti.image_processes_result(opened["view_path"]).payload
    assert procs["count"] == 122
    sshd = [p for p in procs["processes"] if p["pid"] == 22176]
    assert sshd and sshd[0]["comm"] == "sshd" and sshd[0]["has_mm"] is True
    assert sshd[0]["location"]["capture_id"] == opened["capture_id"]


def test_processes_locations_are_canonical_kernel_vas(tmp_path, image, isf, fake_pslist,
                                                      monkeypatch):
    """vol3 hands out DE-canonical offsets (alma-9: 0x01424db6c9e68000); a kernel_va
    Location must be canonical (0xff424db6c9e68000) or it never matches its region."""
    task = _task(22176, "sshd")
    task.offset = 0x01424DB6C9E68000
    monkeypatch.setattr(ti, "get_image_context", lambda *a, **k: fake_image_ctx(tasks=[task]))
    row = ti.image_processes_result(str(_view(tmp_path, image, isf))).payload["processes"][0]
    assert row["location"]["value"] == row["task_offset"] == 0xFF424DB6C9E68000


# -- per-variant default view names (no silent overwrite) ------------------------


def _open(image, case, view="kernel", **kw):
    out = ti.image_open_view_result(str(image), view, case_dir=str(case), **kw).payload
    return Path(out["view_path"])


def _fake_drafts(monkeypatch, isf):
    class FakeDraft:
        last_reason = ""

        def __init__(self, case_dir, draft, upto):
            self.state = upto or "s0"

        def resolve(self, image_path, sha):
            return ProfileResolution(isf, file_sha256(isf), "draft",
                                     details={"state_id": self.state * 8})
    monkeypatch.setattr(ti, "DraftProvider", FakeDraft)


def test_each_profile_variant_gets_its_own_default_view_file(image, isf, tmp_path,
                                                             monkeypatch):
    _fake_drafts(monkeypatch, isf)
    case = tmp_path / "c"
    nop = {"pgd_phys": 0x1000, "arch": "x86_64", "va_bits": 48}
    first = _open(image, case, no_profile=True, paging=nop)
    assert first.name == "box.kernel.noprofile-1000.mdview"
    before = first.read_bytes()
    other_pgd = _open(image, case, no_profile=True, paging={**nop, "pgd_phys": 0x2000})
    with_isf = _open(image, case, isf=str(isf))
    draft_a = _open(image, case, draft="my draft", draft_version="a")
    draft_b = _open(image, case, draft="my draft", draft_version="b")
    proc = _open(image, case, "process", pid=7, isf=str(isf))
    names = [p.name for p in (first, other_pgd, with_isf, draft_a, draft_b, proc)]
    assert len(set(names)) == 6
    assert with_isf.name == f"box.kernel.isf-{file_sha256(isf)[:8]}.mdview"
    assert draft_a.name == "box.kernel.draft-my-draft-aaaaaaaa.mdview"
    assert proc.name == f"box.process.pid7.isf-{file_sha256(isf)[:8]}.mdview"
    assert first.read_bytes() == before


def test_reopening_the_same_variant_reuses_the_same_path(image, isf, tmp_path):
    case = tmp_path / "c"
    one = _open(image, case, isf=str(isf))
    content = one.read_bytes()
    assert _open(image, case, isf=str(isf)) == one
    assert one.read_bytes() == content
