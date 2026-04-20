"""Aggregate MSL session metadata into a single report."""

import logging
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional
from uuid import UUID

from .enums import ArchType, MslKeyType, OSType, RegionType
from .page_map import count_captured_pages
from .types import (
    MslModuleEntry,
    MslProcessIdentity,
    MslRelatedDump,
    MslVasEntry,
)

if TYPE_CHECKING:
    from .string_extract import MslStringReport

logger = logging.getLogger("memdiver.msl.session_extract")


@dataclass
class SessionReport:
    """Aggregated session metadata from an MSL file."""

    dump_uuid: UUID
    pid: int
    os_type: str
    arch_type: str
    timestamp_ns: int
    process_identity: Optional[MslProcessIdentity] = None
    modules: List[MslModuleEntry] = field(default_factory=list)
    related_dumps: List[MslRelatedDump] = field(default_factory=list)
    region_count: int = 0
    total_region_size: int = 0
    captured_page_count: int = 0
    vas_entries: List[MslVasEntry] = field(default_factory=list)
    key_hints_by_type: Dict[str, int] = field(default_factory=dict)
    vas_coverage: Dict[str, int] = field(default_factory=dict)
    string_summary: Optional["MslStringReport"] = None

    @property
    def timestamp_iso(self) -> str:
        """Format timestamp as ISO 8601 UTC string."""
        dt = datetime.fromtimestamp(self.timestamp_ns / 1e9, tz=timezone.utc)
        return dt.isoformat()

    @property
    def total_captured_bytes(self) -> int:
        """Estimate total captured bytes from page count (assumes 4K pages)."""
        return self.captured_page_count * 4096

    @property
    def key_hint_count(self) -> int:
        return sum(self.key_hints_by_type.values())

    @property
    def string_count(self) -> int:
        return self.string_summary.total_count if self.string_summary else 0


def _safe_enum_name(enum_cls, value: int) -> str:
    """Get enum name safely, returning 'UNKNOWN' on lookup failure."""
    try:
        return enum_cls(value).name
    except ValueError:
        return "UNKNOWN"


def extract_session_report(
    reader, include_strings: bool = False,
) -> SessionReport:
    """Build a SessionReport from an open MslReader.

    Args:
        reader: An open MslReader instance.
        include_strings: When True, also run ``extract_strings_from_msl``
            and populate ``string_summary``. Defaults to False because
            string extraction scans region data and can be slow for
            large captures.

    Returns:
        SessionReport aggregating all session metadata + per-type
        breakdowns for key hints and VAS coverage.
    """
    hdr = reader.file_header
    regions = reader.collect_regions()
    modules = reader.collect_modules()
    hints = reader.collect_key_hints()
    identities = reader.collect_process_identity()
    related = reader.collect_related_dumps()
    vas_maps = reader.collect_vas_map()

    total_region_size = sum(r.region_size for r in regions)
    captured_pages = sum(
        count_captured_pages(r.page_states) for r in regions
    )

    vas_entries: List[MslVasEntry] = []
    for vm in vas_maps:
        vas_entries.extend(vm.entries)

    key_hints_by_type = dict(Counter(
        _safe_enum_name(MslKeyType, h.key_type) for h in hints
    ))
    vas_coverage = dict(Counter(
        _safe_enum_name(RegionType, e.region_type) for e in vas_entries
    ))

    string_summary: Optional["MslStringReport"] = None
    if include_strings:
        try:
            from .string_extract import extract_strings_from_msl
            string_summary = extract_strings_from_msl(reader)
        except Exception as exc:
            logger.debug("String extraction skipped: %s", exc)

    report = SessionReport(
        dump_uuid=hdr.dump_uuid,
        pid=hdr.pid,
        os_type=_safe_enum_name(OSType, hdr.os_type),
        arch_type=_safe_enum_name(ArchType, hdr.arch_type),
        timestamp_ns=hdr.timestamp_ns,
        process_identity=identities[0] if identities else None,
        modules=modules,
        related_dumps=related,
        region_count=len(regions),
        total_region_size=total_region_size,
        captured_page_count=captured_pages,
        vas_entries=vas_entries,
        key_hints_by_type=key_hints_by_type,
        vas_coverage=vas_coverage,
        string_summary=string_summary,
    )

    logger.debug(
        "Session report: pid=%d, %d regions, %d modules, %d VAS entries, "
        "%d hint types, %d region types",
        report.pid, report.region_count, len(modules), len(vas_entries),
        len(key_hints_by_type), len(vas_coverage),
    )
    return report


def extract_session_from_path(
    msl_path: Path, include_strings: bool = False,
) -> SessionReport:
    """Convenience: open an MSL file, extract session info, and close."""
    from .reader import MslReader

    with MslReader(msl_path) as reader:
        return extract_session_report(reader, include_strings=include_strings)
