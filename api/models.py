"""Pydantic v2 request/response models for the MemDiver API."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from memdiver.core.input_schemas import OUTPUT_FORMATS


class ScanRequest(BaseModel):
    """Request body for dataset scanning."""

    root: str
    keylog_filename: str = "keylog.csv"
    protocols: list[str] | None = None


class AnalyzeRequestAPI(BaseModel):
    """Request body for library analysis."""

    library_dirs: list[str]
    phase: str
    protocol_version: str
    keylog_filename: str = "keylog.csv"
    template_name: str = "Auto-detect"
    max_runs: int = 10
    normalize: bool = False
    expand_keys: bool = True
    algorithms: list[str] | None = None


class KeyMaterialFields(BaseModel):
    """Mixin of optional decryption fields for encrypted ``.msl`` inputs.

    Same shape as ``POST /api/inspect/tag-status``: ``passphrase`` (utf-8),
    ``key_hex`` (raw symmetric key, hex), ``kem_key_hex`` (KEM private key,
    hex). All optional — omit for plaintext dumps (spec §10).
    """

    passphrase: str | None = None
    key_hex: str | None = None
    kem_key_hex: str | None = None


class ConsensusRequest(KeyMaterialFields):
    """Request body for consensus matrix computation."""

    dump_paths: list[str]
    normalize: bool = False


class AnalyzeFileRequest(KeyMaterialFields):
    """Request body for single-file analysis."""

    dump_path: str
    algorithms: list[str] = ["entropy_scan", "pattern_match", "structure_scan"]
    user_regex: str | None = None
    custom_patterns: list[dict] | None = None


class ConvergenceRequest(BaseModel):
    """Request body for convergence sweep analysis."""

    dump_paths: list[str]
    n_values: list[int] | None = None
    normalize: bool = False
    max_fp: int = 0


class VerifyKeyRequest(KeyMaterialFields):
    """Request body for candidate key decryption verification."""

    dump_path: str
    offset: int
    length: int = 32
    ciphertext_hex: str
    iv_hex: str | None = None
    nonce_hex: str | None = None
    aad_hex: str | None = None
    tag_hex: str | None = None
    cipher: str = "AES-256-CBC"


class AutoExportRequest(KeyMaterialFields):
    """Request body for auto-detect key region and export."""

    dump_paths: list[str]
    format: str = "volatility3"
    name: str = "memdiver_pattern"
    align: bool = True
    context: int = 32


class ExportKeylogRequest(BaseModel):
    """Request body for Wireshark NSS key-log export from recovered secrets.

    ``secrets`` is a list of ``{secret_type, client_random, secret}`` dicts
    (``client_random`` / ``secret`` are hex strings). ``output_path`` is an
    optional server-side path to also write the key log to.
    """

    secrets: list[dict]
    output_path: str | None = None


class BatchJobDTO(BaseModel):
    """JSON-friendly DTO for one batch job.

    Mirrors the fields of ``core.input_schemas.AnalyzeRequest`` but with
    ``library_dirs: list[str]`` instead of ``list[Path]`` so it
    serializes cleanly across the wire and across the multiprocessing
    queue boundary. The worker (``app.pipeline.batch_task_runner.run_batch``)
    re-hydrates each DTO into a real ``AnalyzeRequest``, which is the
    point at which dataclass __post_init__ validates the directories
    exist.
    """

    library_dirs: list[str] = Field(..., min_length=1)
    phase: str = Field(..., min_length=1)
    protocol_version: str = Field(..., min_length=1)
    keylog_filename: str = "keylog.csv"
    template_name: str = "Auto-detect"
    max_runs: int = Field(default=10, ge=1)
    normalize: bool = False
    expand_keys: bool = True
    algorithms: list[str] | None = None


class BatchRunRequest(BaseModel):
    """Request body for ``POST /api/analysis/batch``."""

    jobs: list[BatchJobDTO] = Field(..., min_length=1)
    output_format: str = "json"
    workers: int = Field(default=1, ge=1, le=32)

    @field_validator("output_format")
    @classmethod
    def _validate_output_format(cls, v: str) -> str:
        """Reject unknown formats at the wire boundary (HTTP 422) instead of
        deferring to an async worker failure. Shares ``OUTPUT_FORMATS`` with
        ``core.input_schemas.BatchRequest`` so the two cannot drift."""
        if v not in OUTPUT_FORMATS:
            raise ValueError(f"output_format {v!r} not in {set(OUTPUT_FORMATS)}")
        return v


class BatchRunResponse(BaseModel):
    """Response for a freshly-submitted batch task."""

    task_id: str
    status: str


class AnalysisRunResponse(BaseModel):
    """Response for a freshly-submitted ``run`` / ``run-file`` analysis task.

    Both endpoints now dispatch the GIL-bound algorithm work onto the
    TaskManager's ProcessPool (mirroring ``POST /api/analysis/batch`` and
    the pipeline endpoint) instead of blocking the request thread. The
    caller subscribes to ``/ws/tasks/{task_id}`` for progress and fetches
    the full ``AnalysisResult`` from the ``analysis_result`` artifact on
    completion.
    """

    task_id: str
    status: str
