"""Shared job-runner / router helpers: artifact spec, progress adapter, job submit, strict body."""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from memdiver.api.routers._common import SYNC_MAX_BYTES, StrictModel, submit_job
from memdiver.app.pipeline.artifact_paths import task_result_artifact, write_json_artifact
from memdiver.app.pipeline.progress_emitter import progress_emitter


class _Ctx:
    task_id = "t-1"

    def __init__(self):
        self.events = []

    def emit(self, kind, **kw):
        self.events.append((kind, kw))


def test_write_json_artifact_spec(tmp_path):
    spec = write_json_artifact({"a": 1}, tmp_path, name="x_result", relpath="x/result.json")
    out = tmp_path / "x" / "result.json"
    assert out.read_text() == json.dumps({"a": 1}, indent=2)
    assert spec == {"name": "x_result", "relpath": "x/result.json",
                    "media_type": "application/json", "size": out.stat().st_size,
                    "sha256": hashlib.sha256(out.read_bytes()).hexdigest()}


def test_task_result_artifact_uses_kind_and_task_root(tmp_path):
    spec = task_result_artifact({"ok": True}, {"task_root": str(tmp_path)}, _Ctx(), "yara")
    assert spec["name"] == "yara_result" and spec["relpath"] == "yara/result.json"
    assert (tmp_path / "t-1" / "yara" / "result.json").is_file()


@pytest.mark.parametrize("scale,value,pct", [(1.0, 0.5, 0.5), (1.0, 2.0, 0.99),
                                             (1.0, -1.0, 0.0), (100.0, 50.0, 0.5),
                                             (100.0, 100.0, 0.99)])
def test_progress_emitter_scales_and_clamps(scale, value, pct):
    ctx = _Ctx()
    progress_emitter(ctx, "s", "default", scale=scale)(value, "")
    assert ctx.events == [("progress", {"stage": "s", "pct": pct, "msg": "default"})]


def test_progress_emitter_keeps_description():
    ctx = _Ctx()
    progress_emitter(ctx, "s", "default")(0.1, "window 3")
    assert ctx.events[0][1]["msg"] == "window 3"


def test_submit_job_shape_and_params():
    calls = []

    class _Manager:
        artifact_store = SimpleNamespace(root="/root")

        def submit(self, **kw):
            calls.append(kw)
            return SimpleNamespace(task_id="abc", status=SimpleNamespace(value="pending"))

    out = submit_job(_Manager(), "image", "mod.fn", {"job": "profile", "args": {"x": 1}})
    assert out == {"task_id": "abc", "status": "pending"}
    assert calls == [{"kind": "image", "runner_dotted": "mod.fn", "stage_names": ["image"],
                      "params": {"job": "profile", "args": {"x": 1}, "task_root": "/root"}}]


def test_strict_model_forbids_extra_fields():
    class _Req(StrictModel):
        a: int = 0

    with pytest.raises(ValidationError):
        _Req(a=1, typo=2)
    assert SYNC_MAX_BYTES == 64 * 1024 * 1024


def test_write_json_artifact_spec_matches_the_file_on_disk(tmp_path):
    from memdiver.core.artifact_util import sha256_streamed

    payload = {"name": "ä€", "nested": {"xs": [1, 2, 3]}}
    spec = write_json_artifact(payload, tmp_path, name="n", relpath="deep/er/r.json")
    out = tmp_path / "deep" / "er" / "r.json"
    assert json.loads(out.read_text()) == payload
    assert spec["size"] == out.stat().st_size
    assert spec["sha256"] == sha256_streamed(out)
