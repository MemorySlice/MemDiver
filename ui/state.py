"""Application state management for MemDiver UI."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.config_schema import validate_config
from core.constants import TESTING, INPUT_DATASET

logger = logging.getLogger("memdiver.ui.state")


class AppState:
    """Centralized application state container.

    Holds all UI state that needs to persist across cell re-evaluations.
    Uses plain Python (no marimo dependency) so it's testable.
    """

    def __init__(self, config_path: Optional[Path] = None):
        # Dataset config
        self.dataset_root: str = ""
        self.keylog_filename: str = "keylog.csv"
        self.template_name: str = "Auto-detect"

        # Selection state
        self.protocol_version: str = ""
        self.protocol_name: str = "TLS"
        self.scenario: str = ""
        self.selected_libraries: List[str] = []
        self.selected_phase: str = ""
        self.max_runs: int = 10
        self.normalize_phases: bool = False

        # Analysis state
        self.algorithm: str = "exact_match"
        self.mode: str = TESTING  # "testing" or "research"
        self.scan_count: int = 0
        self.analysis_count: int = 0

        # Input mode (wizard)
        self.input_mode: str = INPUT_DATASET
        self.input_path: str = ""
        self.single_file_path: str = ""
        self.single_file_format: str = ""  # "raw" or "msl"
        self.ground_truth_mode: str = "auto"

        # Investigation state
        self.investigation_offset: Optional[int] = None
        self.bookmarks = None  # Lazy init: BookmarkStore
        self.navigation_history: List[int] = []

        # Cached results
        self.dataset_info: Any = None
        self.analysis_result: Any = None
        self.library_reports: Dict[str, Any] = {}

        # Load from config if available
        if config_path:
            self._load_config(config_path)

    def _load_config(self, path: Path) -> None:
        """Load initial values from config.json."""
        if not path.exists():
            return
        try:
            with open(path) as f:
                cfg = json.load(f)
            valid, errors = validate_config(cfg)
            if not valid:
                logger.warning("Config validation: %s", "; ".join(errors))
            raw = cfg.get("dataset_root", self.dataset_root)
            self.dataset_root = str(Path(raw).resolve()) if raw else ""
            self.keylog_filename = cfg.get("keylog_filename", self.keylog_filename)
            analysis = cfg.get("analysis", {})
            self.max_runs = analysis.get("max_runs", self.max_runs)
            self.algorithm = analysis.get("default_algorithm", self.algorithm)
            ui = cfg.get("ui", {})
            self.mode = ui.get("default_mode", self.mode)
            logger.info("Loaded config from %s", path)
        except Exception as e:
            logger.error("Failed to load config: %s", e)

    def reset_analysis(self) -> None:
        """Clear analysis results."""
        self.analysis_result = None
        self.library_reports = {}

    @property
    def tls_version(self) -> str:
        """Backward-compatible alias for protocol_version."""
        return self.protocol_version

    @tls_version.setter
    def tls_version(self, value: str) -> None:
        self.protocol_version = value

    def get_bookmarks(self):
        """Get or create the BookmarkStore (lazy init)."""
        if self.bookmarks is None:
            from ui.components.bookmark_store import BookmarkStore
            self.bookmarks = BookmarkStore()
        return self.bookmarks

    def build_lib_dir(self, library: str):
        """Build the library directory path for analysis."""
        from pathlib import Path as _Path
        from core.protocols import REGISTRY
        desc = REGISTRY.get(self.protocol_name)
        prefix = desc.dir_prefix if desc else "TLS"
        return _Path(self.dataset_root) / f"{prefix}{self.protocol_version}" / self.scenario / library

    def is_ready_for_analysis(self) -> bool:
        """Check if enough state is set to run analysis."""
        return bool(
            self.dataset_root
            and self.protocol_version
            and self.scenario
            and self.selected_libraries
            and self.selected_phase
        )

    def summary(self) -> Dict[str, Any]:
        """Return a summary of current state."""
        return {
            "mode": self.mode,
            "protocol_name": self.protocol_name,
            "dataset_root": self.dataset_root,
            "protocol_version": self.protocol_version,
            "scenario": self.scenario,
            "libraries": self.selected_libraries,
            "phase": self.selected_phase,
            "algorithm": self.algorithm,
            "scan_count": self.scan_count,
            "analysis_count": self.analysis_count,
        }
