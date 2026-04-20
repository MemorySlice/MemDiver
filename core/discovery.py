"""RunDiscovery and DatasetScanner - navigate directory structure to find runs and dumps."""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .models import DumpFile, RunDirectory
from .keylog import KeylogParser
from .phase_normalizer import PhaseNormalizer
from .protocols import REGISTRY

logger = logging.getLogger("memdiver.discovery")

DUMP_PATTERN = re.compile(
    r"^(\d{8}_\d{6}_\d+)_(pre|post)_(.+)\.(dump|msl)$"
)

RUN_DIR_PATTERN = re.compile(
    r"^(.+?)_run_(\d+)_(\d+)$"
)


def _extract_msl_secrets(msl_paths: List[Path]) -> List["CryptoSecret"]:
    """Extract CryptoSecret objects from MSL key hints (lazy import)."""
    try:
        from msl.key_extract import extract_secrets_from_path
    except ImportError:
        logger.debug("msl.key_extract not available")
        return []
    secrets = []
    seen = set()
    for p in msl_paths:
        try:
            for s in extract_secrets_from_path(p):
                key = (s.secret_type, s.secret_value)
                if key not in seen:
                    seen.add(key)
                    secrets.append(s)
        except Exception:
            logger.warning("Failed to extract key hints from %s", p)
    return secrets


class RunDiscovery:
    """Navigate the directory structure to find runs and dumps."""

    @staticmethod
    def parse_dump_filename(filename: str) -> Optional[DumpFile]:
        m = DUMP_PATTERN.match(filename)
        if not m:
            return None
        return DumpFile(
            path=Path(),
            timestamp=m.group(1),
            phase_prefix=m.group(2),
            phase_name=m.group(3),
        )

    @staticmethod
    def parse_run_dirname(dirname: str) -> Optional[Tuple[str, str, int]]:
        m = RUN_DIR_PATTERN.match(dirname)
        if not m:
            return None
        return m.group(1), m.group(2), int(m.group(3))

    @staticmethod
    def load_run_directory(run_path: Path, keylog_filename: str = "keylog.csv", template=None) -> Optional[RunDirectory]:
        """Load a single run directory."""
        parsed = RunDiscovery.parse_run_dirname(run_path.name)
        if not parsed:
            return None

        library, ver, run_num = parsed
        run = RunDirectory(
            path=run_path,
            library=library,
            protocol_version=ver,
            run_number=run_num,
        )

        for f in sorted(run_path.iterdir()):
            if f.suffix in (".dump", ".msl") and f.is_file():
                dump = RunDiscovery.parse_dump_filename(f.name)
                if dump:
                    dump.path = f
                    run.dumps.append(dump)

        keylog_path = run_path / keylog_filename
        if keylog_path.exists():
            run.secrets = KeylogParser.parse(keylog_path, template=template)
            if run.secrets:
                run.secret_source = "keylog"

        # Fallback: extract secrets from MSL key hints if no keylog
        if not run.secrets:
            msl_files = [d.path for d in run.dumps if d.path.suffix == ".msl"]
            if msl_files:
                run.secrets = _extract_msl_secrets(msl_files)
                if run.secrets:
                    run.secret_source = "msl_hints"

        logger.debug("Loaded run %s: %d dumps, %d secrets (%s)", run_path.name, len(run.dumps), len(run.secrets), run.secret_source)

        return run

    @staticmethod
    def _resolve_library_dir(library_dir: Path) -> Path:
        if RunDiscovery.parse_run_dirname(library_dir.name):
            return library_dir.parent
        return library_dir

    @staticmethod
    def discover_library_runs(library_dir: Path, max_runs: int = 0,
                              keylog_filename: str = "keylog.csv", template=None) -> List[RunDirectory]:
        """Find all run directories inside a library directory."""
        if not library_dir.is_dir():
            return []

        library_dir = RunDiscovery._resolve_library_dir(library_dir)

        candidates = []
        for entry in sorted(library_dir.iterdir()):
            if not entry.is_dir():
                continue
            parsed = RunDiscovery.parse_run_dirname(entry.name)
            if parsed:
                candidates.append((parsed[2], entry))  # (run_number, path)

        candidates.sort(key=lambda x: x[0])
        if max_runs > 0:
            candidates = candidates[:max_runs]

        runs = []
        for _, entry in candidates:
            run = RunDiscovery.load_run_directory(entry, keylog_filename, template=template)
            if run:
                runs.append(run)

        logger.debug("Discovered %d runs in %s", len(runs), library_dir)
        return runs

    @staticmethod
    def list_available_phases(library_dir: Path) -> List[str]:
        runs = RunDiscovery.discover_library_runs(library_dir, max_runs=1)
        if not runs:
            return []
        return runs[0].available_phases()


@dataclass
class DatasetInfo:
    """Summary of a scanned dataset."""
    protocol_versions: Set[str] = field(default_factory=set)
    scenarios: Dict[str, List[str]] = field(default_factory=dict)  # ver -> scenario names
    libraries: Dict[str, Set[str]] = field(default_factory=dict)   # scenario -> library names
    phases: Dict[str, List[str]] = field(default_factory=dict)     # library_key -> phase names
    normalized_phases: Dict[str, List[str]] = field(default_factory=dict)  # lib_key -> canonical phase names
    total_runs: int = 0
    protocols_info: Dict[str, Set[str]] = field(default_factory=dict)
    root: Path = field(default_factory=Path)

    @property
    def tls_versions(self) -> Set[str]:
        """Backward-compatible alias for protocol_versions."""
        return self.protocol_versions

    @tls_versions.setter
    def tls_versions(self, value: Set[str]) -> None:
        self.protocol_versions = value


class DatasetScanner:
    """Scan protocol directory trees without reading dump contents."""

    def __init__(self, root: Path, keylog_filename: str = "keylog.csv"):
        self.root = root
        self.keylog_filename = keylog_filename

    def _detect_scan_level(self, prefixes: list) -> str:
        """Detect which level of the hierarchy self.root represents.

        Returns one of: 'dataset', 'protocol', 'scenario', 'library'.
        - dataset:  root contains protocol dirs (e.g. TLS13/)
        - protocol: root IS a protocol dir (e.g. root=TLS13/, children are scenarios)
        - scenario: root is a scenario dir (children are library dirs with run subdirs)
        - library:  root is a library dir (children are run dirs)
        """
        # Check if root itself starts with a protocol prefix
        for prefix in prefixes:
            if self.root.name.startswith(prefix):
                return "protocol"

        # Check children: are they protocol dirs?
        for child in self.root.iterdir():
            if not child.is_dir() or child.name.startswith('.'):
                continue
            for prefix in prefixes:
                if child.name.startswith(prefix):
                    return "dataset"

        # Check if children contain run dirs (root = library dir)
        for child in self.root.iterdir():
            if child.is_dir() and RunDiscovery.parse_run_dirname(child.name):
                return "library"

        # Check if grandchildren are run dirs (root = scenario dir)
        for child in self.root.iterdir():
            if not child.is_dir() or child.name.startswith('.'):
                continue
            for grandchild in child.iterdir():
                if grandchild.is_dir() and RunDiscovery.parse_run_dirname(grandchild.name):
                    return "scenario"

        return "dataset"  # fallback to default behavior

    def _scan_library_dir(
        self, lib_dir: Path, ver: str, scenario_name: str,
        info: "DatasetInfo", normalizer: "PhaseNormalizer",
    ) -> None:
        """Scan a single library directory for runs."""
        lib_name = lib_dir.name
        for run_dir in sorted(lib_dir.iterdir()):
            if not run_dir.is_dir():
                continue
            parsed = RunDiscovery.parse_run_dirname(run_dir.name)
            if parsed:
                info.total_runs += 1
                lib_key = f"{ver}/{scenario_name}/{lib_name}"
                if lib_key not in info.phases:
                    dumps = []
                    for f in sorted(run_dir.iterdir()):
                        if f.suffix in (".dump", ".msl"):
                            dump = RunDiscovery.parse_dump_filename(f.name)
                            if dump:
                                dump.path = f
                                dumps.append(dump)
                    info.phases[lib_key] = sorted(set(
                        d.full_phase for d in dumps
                    ))
                    if dumps:
                        lib, run_ver, run_num = parsed
                        lightweight_run = RunDirectory(
                            path=run_dir, library=lib,
                            protocol_version=run_ver,
                            run_number=run_num, dumps=dumps,
                        )
                        mappings = normalizer.normalize_run(lightweight_run)
                        info.normalized_phases[lib_key] = sorted(set(
                            m.canonical_phase for m in mappings.values()
                        ))

    def fast_scan(self, protocols: Optional[List[str]] = None) -> DatasetInfo:
        """Quick scan: enumerate versions, scenarios, libraries, phases without reading dumps.

        Supports pointing at any level of the directory hierarchy:
        - Dataset root (contains protocol dirs like TLS13/)
        - Protocol dir (e.g. TLS13/, contains scenario dirs)
        - Scenario dir (e.g. TLS13/scenario_a/, contains library dirs)
        - Library dir (e.g. .../boringssl/, contains run dirs)
        """
        info = DatasetInfo(root=self.root)
        _normalizer = PhaseNormalizer()

        # Determine which protocol prefixes to scan
        prefix_to_desc = {}
        if protocols:
            for name in protocols:
                desc = REGISTRY.get(name)
                if desc:
                    prefix_to_desc[desc.dir_prefix] = desc
        else:
            for name in REGISTRY.list_protocols():
                desc = REGISTRY.get(name)
                if desc:
                    prefix_to_desc[desc.dir_prefix] = desc
        prefixes = list(prefix_to_desc.keys())

        level = self._detect_scan_level(prefixes)
        logger.debug("Detected scan level: %s for root %s", level, self.root)

        if level == "library":
            # Root is a library dir — infer version from run dir names
            ver, scenario_name = self._infer_context_from_library(prefixes)
            info.protocol_versions.add(ver)
            info.scenarios[ver] = [scenario_name]
            info.libraries[scenario_name] = {self.root.name}
            self._scan_library_dir(self.root, ver, scenario_name, info, _normalizer)
            return info

        if level == "scenario":
            # Root is a scenario dir — children are library dirs
            ver, scenario_name = self._infer_context_from_scenario(prefixes)
            info.protocol_versions.add(ver)
            info.scenarios[ver] = [scenario_name]
            info.libraries[scenario_name] = set()
            for lib_dir in sorted(self.root.iterdir()):
                if not lib_dir.is_dir() or lib_dir.name.startswith('.'):
                    continue
                info.libraries[scenario_name].add(lib_dir.name)
                self._scan_library_dir(lib_dir, ver, scenario_name, info, _normalizer)
            return info

        # For 'protocol' level, wrap root as the only proto_dir to scan
        if level == "protocol":
            proto_dirs = [self.root]
        else:
            proto_dirs = sorted(self.root.iterdir())

        for proto_dir in proto_dirs:
            if not proto_dir.is_dir() or proto_dir.name.startswith('.'):
                continue

            # Match against any registered protocol prefix
            matched_prefix = None
            for prefix in prefixes:
                if proto_dir.name.startswith(prefix):
                    matched_prefix = prefix
                    break

            if matched_prefix is None:
                continue

            ver = proto_dir.name[len(matched_prefix):]
            desc = prefix_to_desc.get(matched_prefix)
            if desc:
                if desc.name not in info.protocols_info:
                    info.protocols_info[desc.name] = set()
                info.protocols_info[desc.name].add(ver)
            info.protocol_versions.add(ver)
            info.scenarios[ver] = []

            for scenario_dir in sorted(proto_dir.iterdir()):
                if not scenario_dir.is_dir() or scenario_dir.name.startswith('.'):
                    continue
                scenario_name = scenario_dir.name
                info.scenarios[ver].append(scenario_name)
                if scenario_name not in info.libraries:
                    info.libraries[scenario_name] = set()

                for lib_dir in sorted(scenario_dir.iterdir()):
                    if not lib_dir.is_dir() or lib_dir.name.startswith('.'):
                        continue
                    info.libraries[scenario_name].add(lib_dir.name)
                    self._scan_library_dir(lib_dir, ver, scenario_name, info, _normalizer)

        return info

    def _infer_context_from_library(self, prefixes: list) -> Tuple[str, str]:
        """Infer protocol version and scenario name from a library dir's path or run dirs."""
        # Try to extract version from parent path (e.g. .../TLS13/scenario/library)
        for ancestor in self.root.parents:
            for prefix in prefixes:
                if ancestor.name.startswith(prefix):
                    ver = ancestor.name[len(prefix):]
                    scenario = self.root.parent.name if self.root.parent != ancestor else "unknown"
                    return ver, scenario
        # Fallback: extract from first run dir name
        for child in self.root.iterdir():
            parsed = RunDiscovery.parse_run_dirname(child.name)
            if parsed:
                return str(parsed[1]), self.root.parent.name
        return "unknown", "unknown"

    def _infer_context_from_scenario(self, prefixes: list) -> Tuple[str, str]:
        """Infer protocol version and scenario name from a scenario dir's path."""
        for ancestor in self.root.parents:
            for prefix in prefixes:
                if ancestor.name.startswith(prefix):
                    return ancestor.name[len(prefix):], self.root.name
        # Fallback: look at grandchild run dirs
        for lib_dir in self.root.iterdir():
            if not lib_dir.is_dir():
                continue
            for run_dir in lib_dir.iterdir():
                parsed = RunDiscovery.parse_run_dirname(run_dir.name)
                if parsed:
                    return str(parsed[1]), self.root.name
        return "unknown", self.root.name
