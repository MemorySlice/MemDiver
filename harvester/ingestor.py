"""DumpIngestor - load dump files with optional metadata."""

import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.discovery import RunDiscovery, DatasetScanner, DatasetInfo
from core.dump_io import DumpReader
from core.models import RunDirectory

logger = logging.getLogger("memdiver.harvester.ingestor")


class DumpIngestor:
    """Load and organize dump files for analysis.

    Provides structured access to the dataset tree with optional
    sidecar metadata enrichment.
    """

    def __init__(self, root: Path, keylog_filename: str = "keylog.csv"):
        self.root = root
        self.keylog_filename = keylog_filename
        self._dataset_info: Optional[DatasetInfo] = None

    def scan(self) -> DatasetInfo:
        """Perform a fast scan of the dataset tree."""
        scanner = DatasetScanner(self.root, self.keylog_filename)
        self._dataset_info = scanner.fast_scan()
        logger.info(
            "Scanned dataset: %d TLS versions, %d total runs",
            len(self._dataset_info.tls_versions),
            self._dataset_info.total_runs,
        )
        return self._dataset_info

    @property
    def dataset_info(self) -> Optional[DatasetInfo]:
        return self._dataset_info

    def load_library_runs(
        self,
        tls_version: str,
        scenario: str,
        library: str,
        max_runs: int = 10,
        template=None,
    ) -> List[RunDirectory]:
        """Load run directories for a specific library."""
        lib_dir = self.root / f"TLS{tls_version}" / scenario / library
        if not lib_dir.is_dir():
            logger.warning("Library directory not found: %s", lib_dir)
            return []
        runs = RunDiscovery.discover_library_runs(
            lib_dir, max_runs=max_runs,
            keylog_filename=self.keylog_filename, template=template,
        )
        logger.info("Loaded %d runs for %s/%s/%s", len(runs), tls_version, scenario, library)
        return runs

    def load_dump_data(self, dump_path: Path) -> bytes:
        """Load raw dump data from a file."""
        with DumpReader(dump_path) as reader:
            return reader.read_all()

    def get_dump_paths_for_phase(
        self,
        runs: List[RunDirectory],
        phase: str,
    ) -> List[Path]:
        """Collect all dump file paths for a given phase across runs."""
        paths = []
        for run in runs:
            dump = run.get_dump_for_phase(phase)
            if dump:
                paths.append(dump.path)
        return paths

    def list_libraries(self, tls_version: str, scenario: str) -> List[str]:
        """List available libraries for a version/scenario."""
        if self._dataset_info is None:
            self.scan()
        libs = self._dataset_info.libraries.get(scenario, set())
        return sorted(libs)

    def list_scenarios(self, tls_version: str) -> List[str]:
        """List available scenarios for a TLS version."""
        if self._dataset_info is None:
            self.scan()
        return self._dataset_info.scenarios.get(tls_version, [])
