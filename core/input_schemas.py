"""Request dataclasses for headless CLI operations."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional


@dataclass
class AnalyzeRequest:
    """Request to analyze one or more library directories at a specific phase."""

    library_dirs: List[Path]
    phase: str
    protocol_version: str
    keylog_filename: str = "keylog.csv"
    template_name: str = "Auto-detect"
    max_runs: int = 10
    normalize: bool = False
    expand_keys: bool = True
    algorithms: Optional[List[str]] = None
    template: Any = None  # Resolved template object; None = resolve from template_name

    def __post_init__(self):
        if not self.library_dirs:
            raise ValueError("library_dirs must not be empty")
        for d in self.library_dirs:
            if not d.is_dir():
                raise ValueError(f"Library directory does not exist: {d}")
        if not self.phase:
            raise ValueError("phase must not be empty")
        if not self.protocol_version:
            raise ValueError("protocol_version must not be empty")


@dataclass
class ScanRequest:
    """Request to scan a dataset root for available protocols and libraries."""

    dataset_root: Path
    keylog_filename: str = "keylog.csv"
    protocols: Optional[List[str]] = None

    def __post_init__(self):
        if not self.dataset_root.is_dir():
            raise ValueError(f"Dataset root is not a directory: {self.dataset_root}")


@dataclass
class BatchRequest:
    """Request to run multiple analysis jobs in sequence."""

    jobs: List[AnalyzeRequest]
    output_format: str = "json"

    def __post_init__(self):
        if not self.jobs:
            raise ValueError("Batch must contain at least one job")
        allowed_formats = {"json", "jsonl"}
        if self.output_format not in allowed_formats:
            raise ValueError(
                f"output_format '{self.output_format}' not in {allowed_formats}"
            )
