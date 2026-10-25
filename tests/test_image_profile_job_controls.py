"""pakunoda job controls (progress + cancel) through provider, producer, task runner, CLI."""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

from memdiver.app.pipeline import image_task_runner
from memdiver.app.tools_image import image_profile_result
from memdiver.core.image import profiles
from memdiver.core.service_errors import CapabilityError

BANNER = b"Linux version 6.1.0-test (gcc) #1 SMP Mon Jan 1 00:00:00 UTC 2024\n"


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


@pytest.fixture
def image(tmp_path) -> Path:
    path = tmp_path / "dump.lime"
    path.write_bytes(b"\x00" * 4096 + BANNER + b"\x00" * 4096)
    return path


def _install_fake(monkeypatch, stages=("scan", "emit"), cancelled=False):
    """Fake ``pakunoda``; records the kwargs it received."""
    seen = {}
    mod = types.ModuleType("pakunoda")
    mod.__version__ = "9.9.9"

    def extract_isf(path, arch="auto", **kw):
        seen.update(kw)
        for i, stage in enumerate(stages):
            if "progress" in kw:
                kw["progress"](stage, float(i))
        if cancelled:
            return types.SimpleNamespace(success=False, isf_json=None, loadability=None,
                                         errors=["Cancelled by the caller after 3.0s"])
        return types.SimpleNamespace(success=True, isf_json={"metadata": {}},
                                     banner_bytes=BANNER, kernel_version="6.1.0",
                                     loadability=None, errors=[])
    mod.extract_isf = extract_isf
    monkeypatch.setitem(sys.modules, "pakunoda", mod)
    return seen


def test_provider_forwards_controls_only_when_set(monkeypatch, image):
    seen = _install_fake(monkeypatch)
    profiles.PakunodaLinuxProvider().resolve(image, "sha1")
    assert seen == {}
    stages = []
    cancel = lambda: False  # noqa: E731
    profiles.PakunodaLinuxProvider(progress=lambda s, e: stages.append(s), cancel=cancel
                                   ).resolve(image, "sha2")
    assert seen["cancel"] is cancel and stages == ["scan", "emit"]


def test_cancel_raises_and_skips_later_providers(monkeypatch, image):
    _install_fake(monkeypatch, cancelled=True)

    class Later:
        name, calls = "later", 0

        def resolve(self, *_):
            Later.calls += 1

    chain = profiles.ProfileChain([profiles.PakunodaLinuxProvider(cancel=lambda: True),
                                   Later()])
    with pytest.raises(CapabilityError) as info:
        chain.resolve(image, "sha")
    assert info.value.code == "cancelled" and Later.calls == 0


def test_error_text_alone_marks_cancel(monkeypatch, image):
    _install_fake(monkeypatch, cancelled=True)
    with pytest.raises(CapabilityError) as info:
        profiles.PakunodaLinuxProvider(progress=lambda *_: None).resolve(image, "sha")
    assert info.value.code == "cancelled"


def test_producer_threads_controls_to_pakunoda(monkeypatch, image):
    seen = _install_fake(monkeypatch)
    stages = []
    out = image_profile_result(str(image), progress=lambda s, e: stages.append((s, e))).payload
    assert out["origin"] == "pakunoda" and stages == [("scan", 0.0), ("emit", 1.0)]
    assert "progress" in seen


class _Ctx:
    def __init__(self, cancelled=False):
        self.events, self._cancelled = [], cancelled

    def emit(self, kind, **fields):
        self.events.append((kind, fields))

    def is_cancelled(self):
        return self._cancelled


def test_runner_emits_progress_event_shape(monkeypatch, image, tmp_path):
    _install_fake(monkeypatch)
    ctx = _Ctx()
    params = {"job": "profile", "args": {"image_path": str(image)},
              "artifact_dir": str(tmp_path / "art")}
    image_task_runner.run_image_job(params, ctx)
    progress = [f for k, f in ctx.events if k == "progress"]
    assert progress[0] == {"stage": "image", "pct": 0.0, "msg": "scan",
                           "extra": {"pakunoda_stage": "scan", "elapsed_s": 0.0}}
    assert [p["extra"]["pakunoda_stage"] for p in progress] == ["scan", "emit"]


def test_runner_maps_cancel_to_runtime_error(monkeypatch, image, tmp_path):
    _install_fake(monkeypatch, cancelled=True)
    ctx = _Ctx(cancelled=True)
    params = {"job": "profile", "args": {"image_path": str(image)},
              "artifact_dir": str(tmp_path / "art")}
    with pytest.raises(RuntimeError, match="image profile cancelled"):
        image_task_runner.run_image_job(params, ctx)
    assert ("error", {"error": "cancelled"}) in ctx.events


def test_other_jobs_get_no_controls():
    assert image_task_runner._job_controls("open_view", _Ctx()) == {}


def test_cli_prints_stages_to_stderr(monkeypatch, image, capsys):
    from memdiver.cli import _build_parser, _cmd_image
    _install_fake(monkeypatch)
    rc = _cmd_image(_build_parser().parse_args(["image", "profile", str(image)]))
    captured = capsys.readouterr()
    assert rc == 0
    assert "scan" in captured.err and "emit" in captured.err
    assert '"origin": "pakunoda"' in captured.out and "scan" not in captured.out
