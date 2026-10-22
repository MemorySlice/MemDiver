"""Capture report + its on-disk ``.capture.json`` manifest sidecar.

Every dump backend returns a :class:`CaptureReport`: what was written, and --
crucially -- every region that was *not* (unreadable, guard page, read error,
size cap, timeout) with its base, size and reason, so no region is dropped
silently. The report is persisted next to the dump as
``<stem>.capture.json`` so a later import / preview can warn about gaps and
about sidecars whose region names are unavailable (``names == "none"``).

The ``.maps`` sidecar itself only ever lists bytes that are present in the
``.bin`` (the :mod:`core.regioned_layout` contract); skipped spans live in the
manifest, never as fake zero-filled maps entries.
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("memdiver.core.capture_manifest")

MANIFEST_SCHEMA = 1
MANIFEST_SUFFIX = ".capture.json"

#: How region names in the ``.maps`` sidecar were obtained.
NAMES_PROC_MAPS = "proc_maps"        # the target's real /proc/<pid>/maps
NAMES_FRIDA_RANGES = "frida_ranges"  # Frida enumerateRanges file paths (partial)
NAMES_LLDB = "lldb"                  # lldb region names / module sections / stacks
NAMES_NONE = "none"                  # no names: every region classifies as anonymous

# Skip reasons (stable strings; surfaces localize them by key).
REASON_UNREADABLE = "unreadable"
REASON_READ_FAILED = "read_failed"
REASON_SHORT_READ = "short_read"
REASON_SIZE_CAP = "size_cap"
REASON_LARGE_READONLY = "large_readonly"
REASON_TIMEOUT = "timeout"

#: Skipped entries listed individually in warning text before summarising.
_MAX_LISTED = 5


@dataclass(frozen=True)
class SkippedRegion:
    """A span of the target's address space that is NOT in the dump."""

    base: int
    size: int
    reason: str

    def to_dict(self) -> dict:
        return {"base": self.base, "base_hex": f"{self.base:#x}",
                "size": self.size, "reason": self.reason}


@dataclass
class CaptureReport:
    """Outcome of one capture."""

    ok: bool
    tool: str
    output_path: str
    target: dict = field(default_factory=dict)
    maps_path: Optional[str] = None
    regions_captured: int = 0
    bytes_captured: int = 0
    names: Optional[str] = None
    skipped: List[SkippedRegion] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def skip(self, base: int, size: int, reason: str) -> None:
        self.skipped.append(SkippedRegion(int(base), int(size), reason))

    def summary_warnings(self) -> List[str]:
        """Human-readable warnings: explicit ones plus the skipped-region digest."""
        return [*self.warnings, *skipped_warnings(self.skipped),
                *names_warnings(self.names)]

    def to_dict(self) -> dict:
        data = asdict(self)
        data["skipped"] = [s.to_dict() for s in self.skipped]
        data["skipped_bytes"] = sum(s.size for s in self.skipped)
        data["summary_warnings"] = self.summary_warnings()
        return data


def skipped_warnings(skipped: List[SkippedRegion]) -> List[str]:
    """One digest line plus up to ``_MAX_LISTED`` example spans."""
    if not skipped:
        return []
    by_reason: dict = {}
    for entry in skipped:
        by_reason[entry.reason] = by_reason.get(entry.reason, 0) + 1
    reasons = ", ".join(f"{k}={v}" for k, v in sorted(by_reason.items()))
    total = sum(s.size for s in skipped)
    lines = [f"{len(skipped)} region(s) / {total} bytes not captured ({reasons})"]
    for entry in skipped[:_MAX_LISTED]:
        lines.append(f"not captured: {entry.base:#x}-{entry.base + entry.size:#x} "
                     f"({entry.size} bytes, {entry.reason})")
    return lines


def names_warnings(names: Optional[str]) -> List[str]:
    if names == NAMES_NONE:
        return ["region names unavailable: the .maps sidecar has no mapping "
                "names, so every region classifies as anonymous memory"]
    if names == NAMES_FRIDA_RANGES:
        return ["region names are partial (Frida file paths only): heap/stack "
                "pseudo-mappings are not named"]
    return []


def manifest_path_for(bin_path: Path) -> Path:
    """``foo.bin`` / ``foo.dump`` / ``foo.msl`` -> ``foo.capture.json``."""
    return Path(bin_path).with_suffix(MANIFEST_SUFFIX)


def write_manifest(report: CaptureReport) -> Path:
    path = manifest_path_for(Path(report.output_path))
    payload = {"schema": MANIFEST_SCHEMA, **report.to_dict()}
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def read_manifest(bin_path: Path) -> Optional[dict]:
    """The manifest beside *bin_path*, or ``None`` when absent/unreadable."""
    path = manifest_path_for(Path(bin_path))
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.warning("unreadable capture manifest %s: %s", path, exc)
        return None
    return data if isinstance(data, dict) else None


def manifest_warnings(bin_path: Path) -> List[str]:
    """Import/preview warnings derived from the capture manifest (if any)."""
    data = read_manifest(bin_path)
    if not data:
        return []
    skipped = [SkippedRegion(int(s.get("base", 0)), int(s.get("size", 0)),
                             str(s.get("reason", "")))
               for s in data.get("skipped") or [] if isinstance(s, dict)]
    return [*skipped_warnings(skipped), *names_warnings(data.get("names"))]
