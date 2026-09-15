"""RunDiscovery and DatasetScanner - navigate directory structure to find runs and dumps."""

import logging
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Set, Tuple, Union

from .dataset_metadata import DatasetMeta, load_run_meta, resolve_declared_subpath
from .models import DumpFile, RunDirectory
from .keylog import KeylogParser
from .phase_normalizer import PhaseNormalizer
from .protocols import REGISTRY

if TYPE_CHECKING:
    # Only needed for the "CryptoSecret" annotation on _extract_msl_secrets;
    # the real object is lazily imported inside that function to avoid a heavy
    # import at module load.
    from .models import CryptoSecret

logger = logging.getLogger("memdiver.discovery")

# Legacy timestamped phase dumps (e.g. ``20240101_120000_1_pre_handshake.msl``).
DUMP_PATTERN = re.compile(
    r"^(\d{8}_\d{6}_\d+)_(pre|post)_(.+)\.(dump|msl)$"
)

# Dataset-style dumps without a timestamp prefix (gcore.core, gdb_raw.bin,
# lldb_raw.bin, memslicer.msl). Matched separately so legacy runs keep their
# phase parsing while the new corpus gets first-class support.
DATASET_DUMP_SUFFIXES = (
    ".gcore.core",
    ".gdb_raw.bin",
    ".lldb_raw.bin",
    ".msl",
    ".core",
)

RUN_DIR_PATTERN = re.compile(
    r"^(.+?)_run_(\d+)_(\d+)$"
)

# A corpus run owns its own packet capture, stored in a sibling subdirectory of
# the dumps. ``load_run_directory`` only iterates *files*, so the capture is
# invisible to dump discovery and is probed explicitly by ``_find_capture``.
CAPTURE_SUBDIR = "run_data"

# Ordered candidates: a tuple (not a set) so the first match is deterministic
# when a run happens to carry more than one capture flavour.
CAPTURE_FILENAMES = ("traffic.pcap", "traffic.pcapng", "traffic.cap")

# Last-resort candidates, probed ONLY when the conventional layout above yields
# nothing: a capture sitting beside the dumps rather than in ``run_data/``.
#
# Ordered, and each glob's own matches are sorted, so a directory holding two
# captures resolves to the same one on every run. The whole list is APPENDED
# after the conventional candidates precisely so that this relaxation cannot
# change the answer for any corpus that follows the convention -- these
# candidates are unreachable until ``_find_capture`` would otherwise have
# returned ``"absent"``.
CAPTURE_SIBLING_GLOBS = ("*.pcap", "*.pcapng", "*.cap")


def _infer_dump_kind(path: Path) -> str:
    """Map a dump filename to a canonical :class:`DumpFile.kind` string."""
    name = path.name.lower()
    if name.endswith(".msl"):
        return "msl"
    if name.endswith("gdb_raw.bin"):
        return "gdb_raw"
    if name.endswith("lldb_raw.bin"):
        return "lldb_raw"
    if name.endswith(".core") or name.endswith("gcore.core"):
        return "gcore"
    if name.endswith(".dump"):
        return "raw"
    return "raw"


def _extract_msl_secrets(msl_paths: List[Path]) -> List["CryptoSecret"]:
    """Extract CryptoSecret objects from MSL key hints (lazy import)."""
    try:
        from memdiver.msl.key_extract import extract_secrets_from_path
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
        except (OSError, ValueError) as exc:
            logger.warning("Failed to extract key hints from %s: %s", p, exc)
        except Exception:
            logger.exception("Unexpected error extracting secrets from %s", p)
    return secrets


class RunDiscovery:
    """Navigate the directory structure to find runs and dumps."""

    @staticmethod
    def parse_dump_filename(filename: str) -> Optional[DumpFile]:
        """Parse a phase-style dump filename into a :class:`DumpFile`.

        Returns ``None`` for files that do not match the legacy
        ``<ts>_<pre|post>_<phase>.<ext>`` pattern. Non-phased dataset
        dumps (``gcore.core``, ``gdb_raw.bin`` ...) are created directly
        by :meth:`_build_dataset_dump` instead.
        """
        m = DUMP_PATTERN.match(filename)
        if not m:
            return None
        ext = m.group(4).lower()
        kind = "msl" if ext == "msl" else "raw"
        return DumpFile(
            path=Path(),
            timestamp=m.group(1),
            phase_prefix=m.group(2),
            phase_name=m.group(3),
            kind=kind,
        )

    @staticmethod
    def _build_dataset_dump(path: Path) -> Optional[DumpFile]:
        """Create a :class:`DumpFile` for a non-phased dataset dump.

        These files have no timestamp or phase markers — we synthesise a
        ``full`` phase so the rest of the pipeline (which keys everything
        by ``full_phase``) keeps working.
        """
        kind = _infer_dump_kind(path)
        if kind == "raw":
            return None
        return DumpFile(
            path=path,
            timestamp="",
            phase_prefix="full",
            phase_name=kind,
            kind=kind,
        )

    @staticmethod
    def parse_run_dirname(dirname: str) -> Optional[Tuple[str, str, int]]:
        m = RUN_DIR_PATTERN.match(dirname)
        if not m:
            return None
        return m.group(1), m.group(2), int(m.group(3))

    @staticmethod
    def load_run_directory(run_path: Path, keylog_filename: str = "keylog.csv", template=None, extract_secrets: bool = True) -> Optional[RunDirectory]:
        """Load a single run directory.

        When ``extract_secrets`` is False both the keylog parse and the MSL
        key-hint fallback are skipped. Callers that only need the dump
        inventory + ``meta.json`` (e.g. the dataset-browsing endpoint) can
        avoid the expensive per-file MSL parsing this entails.
        """
        parsed = RunDiscovery.parse_run_dirname(run_path.name)
        if not parsed:
            # Dataset-style runs (e.g. ``run_0001``) don't match the legacy
            # ``<lib>_run_<ver>_<num>`` shape; accept them if they contain a
            # ``meta.json`` or any recognised dump.
            if not RunDiscovery._looks_like_dataset_run(run_path):
                return None
            library, ver, run_num = run_path.name, "unknown", 0
        else:
            library, ver, run_num = parsed

        run = RunDirectory(
            path=run_path,
            library=library,
            protocol_version=ver,
            run_number=run_num,
        )

        for f in sorted(run_path.iterdir()):
            if not f.is_file():
                continue
            dump = RunDiscovery._dump_file_for(f)
            if dump is not None:
                run.dumps.append(dump)

        if extract_secrets:
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

        # Attach per-run meta.json (None when absent — legacy runs are ok).
        # Loaded BEFORE the capture probe: a corpus may declare its capture
        # location in meta.json, and ``_find_capture`` prefers that declaration
        # over the hardcoded filename probe.
        #
        # load_run_meta downgrades a malformed meta.json to None but starts with
        # ``Path.is_file()``, which only swallows ENOENT/ENOTDIR/EBADF/ELOOP --
        # EACCES (a mode-000 run dir) and ENAMETOOLONG still propagate. A single
        # unreadable run must be skipped, not abort a whole corpus sweep.
        try:
            run.meta = load_run_meta(run_path)
        except OSError as exc:
            logger.warning("Failed to read meta.json for run %s: %s", run_path, exc)
            run.meta = None

        # Attach the run's own packet capture (three-state; never raises).
        run.capture_path, run.capture_status = RunDiscovery._find_capture(
            run_path, run.meta
        )

        logger.debug("Loaded run %s: %d dumps, %d secrets (%s)", run_path.name, len(run.dumps), len(run.secrets), run.secret_source)

        return run

    @staticmethod
    def _find_capture(
        run_path: Path, meta: Optional[DatasetMeta] = None
    ) -> Tuple[Optional[Path], str]:
        """Locate the run's packet capture.

        A ``meta.json`` that declares a ``capture`` relative path is tried
        first, so a corpus can name a capture this module has never heard of;
        the hardcoded ``CAPTURE_SUBDIR`` x ``CAPTURE_FILENAMES`` probe follows.

        Returns ``(path, status)`` where status is one of ``"present"``,
        ``"absent"`` or ``"unreadable"``. A zero-byte or un-stat-able capture
        reports ``"unreadable"`` (with its path) rather than ``"absent"`` so a
        corpus denominator is never silently deflated.

        A ``"present"`` candidate ALWAYS wins over an earlier unusable one:
        every candidate is examined, and an ``"unreadable"`` verdict is only
        returned when no candidate is usable. Returning on the first non-absent
        verdict instead would let a zero-byte ``traffic.pcap`` both discard a
        perfectly good ``traffic.pcapng`` and desynchronise this function from
        :meth:`DatasetScanner._has_capture` (which skips the empty file and
        counts the run), inflating ``DatasetInfo.runs_with_capture`` above the
        number of runs that can actually be proven against their own traffic.

        Never raises: like :func:`core.dataset_metadata.load_run_meta`, scan
        paths must tolerate partial datasets, so an :class:`OSError` is logged
        and downgraded.

        NOTE: :meth:`DatasetScanner._has_capture` intentionally knows only the
        hardcoded probe -- the fast scan is stat-only and must not read a
        ``meta.json`` per run across thousands of runs. The two therefore agree
        on every corpus that uses the conventional layout, and a corpus that
        relocates its capture via ``meta.capture`` (or leaves it beside the
        dumps, see the sibling probe below) is found by the per-run load (which
        every consumer of ``capture_path`` goes through) while the fast scan's
        ``runs_with_capture`` counter under-counts it.
        """
        capture_dir = run_path / CAPTURE_SUBDIR
        declared = RunDiscovery._declared_capture_path(run_path, meta)
        candidates = [capture_dir / name for name in CAPTURE_FILENAMES]
        if declared is not None:
            candidates.insert(0, declared)
        # APPENDED, never inserted: a run that follows the convention has
        # already matched above, so the sibling probe cannot change any answer
        # this function used to give -- it only replaces some of the
        # ``"absent"`` ones. That ordering is what lets an ad-hoc directory
        # (one dump plus one capture, no ``run_data/``) be paired at all
        # without perturbing corpus resolution.
        candidates.extend(RunDiscovery._sibling_capture_candidates(run_path))

        unusable: Optional[Tuple[Path, str]] = None
        seen: set = set()
        for candidate in candidates:
            if candidate in seen:
                continue
            seen.add(candidate)
            status = RunDiscovery._classify_capture(candidate)
            if status == "present":
                return candidate, status
            if status is not None and unusable is None:
                # Remember the first unusable capture but keep looking: a later
                # candidate may be a capture we can actually read.
                unusable = (candidate, status)
        if unusable is not None:
            return unusable
        return None, "absent"

    @staticmethod
    def _sibling_capture_candidates(run_path: Path) -> List[Path]:
        """Captures sitting DIRECTLY in *run_path*, in a deterministic order.

        The last-resort half of :meth:`_find_capture`'s candidate list (see the
        comment on :data:`CAPTURE_SIBLING_GLOBS` for why it is appended rather
        than merged in). Each glob's matches are sorted, so two captures in one
        directory always resolve to the same one.

        Never raises: an unreadable or missing directory contributes nothing,
        matching the "scan paths tolerate partial datasets" posture of
        :meth:`_find_capture` itself.
        """
        found: List[Path] = []
        for pattern in CAPTURE_SIBLING_GLOBS:
            try:
                found.extend(sorted(run_path.glob(pattern)))
            except OSError as exc:
                # A mode-000 directory raises EACCES out of the scandir walk on
                # some platforms; one unreadable run must not abort a sweep.
                logger.debug(
                    "Cannot probe %s for %s captures: %s", run_path, pattern, exc
                )
        return found

    @staticmethod
    def find_capture_for(path: Union[str, Path]) -> Tuple[Optional[Path], str]:
        """Locate the capture that belongs to ONE dump (or run directory).

        The public entry point onto :meth:`_find_capture`, for callers that hold
        a *dump* path rather than a run directory. A file is normalised to its
        parent directory and a directory is used as-is; the probe itself --
        ``meta.capture``, then ``run_data/`` x :data:`CAPTURE_FILENAMES`, then
        the sibling globs -- is :meth:`_find_capture`'s, unchanged, so a dump
        and its run agree on which capture is theirs by construction.

        Returns the same three-state ``(path, status)`` pair
        (``"present"`` / ``"absent"`` / ``"unreadable"``), and never raises: the
        caller's job is to render "no capture for this dump" as a typed row, not
        to have the pairing pass abort on one directory.

        Used by ``app.tools_pipeline.locate_field_across_pairs`` to give each
        dump of an N-dump search a needle from ITS OWN capture.
        """
        # Both calls normalise the SAME input, so they agree on the run dir by
        # construction -- passing the already-normalised ``run_path`` instead
        # would re-walk a path whose parent is a different directory.
        run_path = RunDiscovery._run_dir_of(path)
        meta = RunDiscovery.meta_for_dump(path)
        return RunDiscovery._find_capture(run_path, meta)

    @staticmethod
    def meta_for_dump(path: Union[str, Path]) -> Optional[DatasetMeta]:
        """Load the ``meta.json`` of the run that owns ONE dump (or run dir).

        The normalisation callers holding a *dump* path would otherwise each
        reinvent: a file becomes its parent directory, a directory is used
        as-is. :meth:`find_capture_for` is one such caller, so the walk exists
        once rather than once per question asked about a dump's run.

        Returns ``None`` for a run with no ``meta.json`` -- and for one whose
        ``meta.json`` cannot be read, the same downgrade
        :meth:`load_run_directory` applies: a mode-000 run dir must not abort
        the sweep that reached it.
        """
        run_path = RunDiscovery._run_dir_of(path)
        try:
            return load_run_meta(run_path)
        except OSError as exc:
            logger.warning(
                "Failed to read meta.json for %s: %s", run_path, exc
            )
            return None

    @staticmethod
    def _run_dir_of(path: Union[str, Path]) -> Path:
        """The run directory owning ``path``: itself when a directory, else its parent."""
        run_path = Path(path)
        return run_path if run_path.is_dir() else run_path.parent

    @staticmethod
    def _declared_capture_path(
        run_path: Path, meta: Optional[DatasetMeta]
    ) -> Optional[Path]:
        """Resolve ``meta.capture`` against the run dir, or ``None``.

        The traversal guard itself is
        :func:`core.dataset_metadata.resolve_declared_subpath`, shared with
        ``DatasetMeta.vault_dir`` so the two cannot drift apart.
        """
        if meta is None:
            return None
        return resolve_declared_subpath(run_path, meta.capture, kind="capture")

    @staticmethod
    def _classify_capture(candidate: Path) -> Optional[str]:
        """Classify one capture candidate, or ``None`` to keep searching.

        ``None`` means "not a capture here" (missing, or not a regular file);
        the caller then tries the next candidate. Never raises.
        """
        try:
            info = candidate.stat()
        except (FileNotFoundError, NotADirectoryError):
            return None
        except OSError as exc:
            logger.warning("Failed to stat capture at %s: %s", candidate, exc)
            return "unreadable"
        if not stat.S_ISREG(info.st_mode):
            return None
        if info.st_size == 0:
            logger.warning("Zero-byte capture at %s", candidate)
            return "unreadable"
        if not os.access(candidate, os.R_OK):
            # ``stat()`` succeeds on a file the process cannot OPEN (mode 000,
            # a restrictive ACL, a read-only mount quirk), so without this a
            # capture nobody can read reported ``"present"`` -- overstating the
            # corpus denominator, which is precisely what the three-state status
            # exists to prevent. One extra syscall, so the stat-only fast-scan
            # budget is preserved.
            logger.warning("Capture at %s is not readable", candidate)
            return "unreadable"
        return "present"

    @staticmethod
    def dump_file_for(path: Path) -> Optional[DumpFile]:
        """Public seam for the file -> :class:`DumpFile` admission rule.

        Returns the :class:`DumpFile` ``load_run_directory`` would build for
        ``path``, or ``None`` when the filename is not a recognised dump.

        This exists because the admission rule ("is this filename a dump, and
        what phase does it carry?") is genuinely useful outside this class -
        ``engine.sweep_plan`` counts a corpus by applying exactly this rule to
        already-listed filenames, and any second implementation of it would be
        free to drift out of agreement with discovery. It delegates to the
        private :meth:`_dump_file_for`, which stays in place for the internal
        call sites.
        """
        return RunDiscovery._dump_file_for(path)

    @staticmethod
    def _dump_file_for(path: Path) -> Optional[DumpFile]:
        """Dispatch a single file to legacy or dataset-style parsing.

        Public callers should use :meth:`dump_file_for`.
        """
        legacy = RunDiscovery.parse_dump_filename(path.name)
        if legacy is not None:
            legacy.path = path
            return legacy
        return RunDiscovery._build_dataset_dump(path)

    @staticmethod
    def _looks_like_dataset_run(run_path: Path) -> bool:
        """True when a non-conforming dir still looks like a dataset run."""
        if (run_path / "meta.json").is_file():
            return True
        for suffix in DATASET_DUMP_SUFFIXES:
            if any(run_path.glob(f"*{suffix}")):
                return True
        return False

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
    libraries: Dict[str, Set[str]] = field(default_factory=dict)   # "ver/scenario" -> library names
    phases: Dict[str, List[str]] = field(default_factory=dict)     # library_key -> phase names
    normalized_phases: Dict[str, List[str]] = field(default_factory=dict)  # lib_key -> canonical phase names
    total_runs: int = 0
    runs_with_capture: int = 0                                      # runs owning a packet capture
    captures: Dict[str, int] = field(default_factory=dict)          # library_key -> capture count
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
        # Guard against a TOCTOU race: the root may have been deleted or
        # replaced (e.g. by a non-directory) between construction and scan.
        # Fail with a clear message instead of an opaque FileNotFoundError /
        # NotADirectoryError surfacing from a later iterdir() call.
        if not self.root.is_dir():
            raise NotADirectoryError(
                f"dataset scan root is not a directory (deleted or replaced?): "
                f"{self.root}"
            )

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
                if self._has_capture(run_dir):
                    info.runs_with_capture += 1
                    info.captures[lib_key] = info.captures.get(lib_key, 0) + 1
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

    @staticmethod
    def _has_capture(run_dir: Path) -> bool:
        """Stat-only capture probe for the fast scan.

        Deliberately does NOT call :meth:`RunDiscovery.load_run_directory`,
        which would open the keylog and every dump; this stays at a handful of
        stat calls per run so a 2600-run corpus scan keeps its current cost.

        Counts a capture only when it is a NON-EMPTY regular file, so this
        agrees with :meth:`RunDiscovery._find_capture`'s three-state verdict.
        A zero-byte capture is ``"unreadable"`` there, and counting it as
        present here would inflate ``DatasetInfo.runs_with_capture`` above the
        number of runs that can actually be proven against their capture --
        i.e. it would overstate the corpus denominator, which is the opposite
        of the reason the three-state status exists. ``stat()`` costs the same
        as ``is_file()`` (one syscall), so the agreement is free.
        """
        capture_dir = run_dir / CAPTURE_SUBDIR
        for name in CAPTURE_FILENAMES:
            try:
                st = (capture_dir / name).stat()
            except OSError:
                continue
            if (stat.S_ISREG(st.st_mode) and st.st_size > 0
                    and os.access(capture_dir / name, os.R_OK)):
                return True
        return False

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
            info.libraries[f"{ver}/{scenario_name}"] = {self.root.name}
            self._scan_library_dir(self.root, ver, scenario_name, info, _normalizer)
            return info

        if level == "scenario":
            # Root is a scenario dir — children are library dirs
            ver, scenario_name = self._infer_context_from_scenario(prefixes)
            info.protocol_versions.add(ver)
            info.scenarios[ver] = [scenario_name]
            info.libraries[f"{ver}/{scenario_name}"] = set()
            for lib_dir in sorted(self.root.iterdir()):
                if not lib_dir.is_dir() or lib_dir.name.startswith('.'):
                    continue
                info.libraries[f"{ver}/{scenario_name}"].add(lib_dir.name)
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
                if f"{ver}/{scenario_name}" not in info.libraries:
                    info.libraries[f"{ver}/{scenario_name}"] = set()

                for lib_dir in sorted(scenario_dir.iterdir()):
                    if not lib_dir.is_dir() or lib_dir.name.startswith('.'):
                        continue
                    info.libraries[f"{ver}/{scenario_name}"].add(lib_dir.name)
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
