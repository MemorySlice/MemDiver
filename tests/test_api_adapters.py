"""Unit tests for ``api.adapters`` — the single Pydantic -> core conversion seam.

These assert, field-by-field, that each converter maps a representative
Pydantic request model onto the correct core dataclass (or the JSON-friendly
pool ``params`` dict the router hands to ``TaskManager.submit``). A drift guard
pins the params-dict key set to the core ``AnalyzeRequest`` field list so the
wire model and the core dataclass cannot silently diverge.
"""

from __future__ import annotations

from dataclasses import fields
from pathlib import Path

from memdiver.api.adapters import (
    analyze_run_params,
    batch_run_params,
    to_analyze_request,
    to_batch_request,
)
from memdiver.api.models import AnalyzeRequestAPI, BatchJobDTO, BatchRunRequest
from memdiver.core.input_schemas import AnalyzeRequest, BatchRequest


def test_to_analyze_request_maps_every_field(tmp_path: Path):
    lib = tmp_path / "lib"
    lib.mkdir()
    model = AnalyzeRequestAPI(
        library_dirs=[str(lib)],
        phase="pre_handshake",
        protocol_version="12",
        keylog_filename="secrets.csv",
        template_name="OpenSSL",
        max_runs=5,
        normalize=True,
        expand_keys=False,
        algorithms=["entropy_scan", "pattern_match"],
    )

    req = to_analyze_request(model)

    assert isinstance(req, AnalyzeRequest)
    assert req.library_dirs == [lib]
    assert all(isinstance(d, Path) for d in req.library_dirs)
    assert req.phase == "pre_handshake"
    assert req.protocol_version == "12"
    assert req.keylog_filename == "secrets.csv"
    assert req.template_name == "OpenSSL"
    assert req.max_runs == 5
    assert req.normalize is True
    assert req.expand_keys is False
    assert req.algorithms == ["entropy_scan", "pattern_match"]
    # template is server-side only; never populated from the wire model.
    assert req.template is None


def test_to_analyze_request_defaults(tmp_path: Path):
    lib = tmp_path / "lib"
    lib.mkdir()
    model = AnalyzeRequestAPI(
        library_dirs=[str(lib)], phase="p", protocol_version="12"
    )

    req = to_analyze_request(model)

    assert req.keylog_filename == "keylog.csv"
    assert req.template_name == "Auto-detect"
    assert req.max_runs == 10
    assert req.normalize is False
    assert req.expand_keys is True
    assert req.algorithms is None


def test_to_batch_request_maps_jobs_and_drops_workers(tmp_path: Path):
    lib = tmp_path / "lib"
    lib.mkdir()
    model = BatchRunRequest(
        jobs=[
            BatchJobDTO(
                library_dirs=[str(lib)], phase="p1", protocol_version="12"
            ),
            BatchJobDTO(
                library_dirs=[str(lib)], phase="p2", protocol_version="13"
            ),
        ],
        output_format="jsonl",
        workers=4,
    )

    req = to_batch_request(model)

    assert isinstance(req, BatchRequest)
    assert req.output_format == "jsonl"
    assert len(req.jobs) == 2
    assert all(isinstance(j, AnalyzeRequest) for j in req.jobs)
    assert req.jobs[0].phase == "p1"
    assert req.jobs[1].protocol_version == "13"
    # workers is a pool concern with no core counterpart -> not on BatchRequest.
    assert not hasattr(req, "workers")


def test_analyze_run_params_shape_and_types():
    model = AnalyzeRequestAPI(
        library_dirs=["/does/not/need/to/exist"],
        phase="pre_handshake",
        protocol_version="12",
        algorithms=["entropy_scan"],
    )

    params = analyze_run_params(model, task_root="/tasks")

    assert params == {
        "task_root": "/tasks",
        "library_dirs": ["/does/not/need/to/exist"],
        "phase": "pre_handshake",
        "protocol_version": "12",
        "keylog_filename": "keylog.csv",
        "template_name": "Auto-detect",
        "max_runs": 10,
        "normalize": False,
        "expand_keys": True,
        "algorithms": ["entropy_scan"],
    }
    # Dict-based on purpose: no early validation of the bogus library_dir.
    assert isinstance(params["library_dirs"], list)


def test_analyze_run_params_keys_track_core_dataclass():
    """Drift guard: the pool params must mirror the core AnalyzeRequest fields.

    ``task_root`` is a pool-only addition; ``template`` is a server-side-only
    core field that is never sent over the wire. Any other divergence (a new
    core field, a renamed wire field) breaks this assertion.
    """
    model = AnalyzeRequestAPI(
        library_dirs=["x"], phase="p", protocol_version="12"
    )
    param_keys = set(analyze_run_params(model, task_root="/t")) - {"task_root"}
    core_keys = {f.name for f in fields(AnalyzeRequest)} - {"template"}
    assert param_keys == core_keys


def test_batch_run_params_shape():
    model = BatchRunRequest(
        jobs=[
            BatchJobDTO(
                library_dirs=["/a"], phase="p", protocol_version="12"
            )
        ],
        output_format="json",
        workers=2,
    )

    params = batch_run_params(model, task_root="/tasks")

    assert params["task_root"] == "/tasks"
    assert params["output_format"] == "json"
    assert params["workers"] == 2
    assert isinstance(params["jobs"], list) and len(params["jobs"]) == 1
    # jobs are model_dump()'d DTOs (JSON-friendly), not dataclasses.
    assert params["jobs"][0]["library_dirs"] == ["/a"]
    assert params["jobs"][0]["phase"] == "p"
