"""Pydantic v2 request/response models for the MemDiver API."""

from __future__ import annotations

from pydantic import BaseModel


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


class ConsensusRequest(BaseModel):
    """Request body for consensus matrix computation."""

    dump_paths: list[str]
    normalize: bool = False


class AnalyzeFileRequest(BaseModel):
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


class VerifyKeyRequest(BaseModel):
    """Request body for candidate key decryption verification."""

    dump_path: str
    offset: int
    length: int = 32
    ciphertext_hex: str
    iv_hex: str | None = None
    cipher: str = "AES-256-CBC"


class AutoExportRequest(BaseModel):
    """Request body for auto-detect key region and export."""

    dump_paths: list[str]
    format: str = "volatility3"
    name: str = "memdiver_pattern"
    align: bool = True
    context: int = 32
