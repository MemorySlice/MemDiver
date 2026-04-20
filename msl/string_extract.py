"""Extract strings from MSL files -- regions and structured blocks."""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Tuple

from core.strings import StringMatch, extract_strings

from .enums import PageState
from .page_map import count_captured_pages
from .types import MslMemoryRegion

logger = logging.getLogger("memdiver.msl.string_extract")


@dataclass
class MslStringReport:
    """Aggregated string extraction from an MSL file."""

    region_strings: List[StringMatch] = field(default_factory=list)
    module_strings: List[str] = field(default_factory=list)
    process_strings: List[str] = field(default_factory=list)

    @property
    def total_count(self) -> int:
        return (
            len(self.region_strings)
            + len(self.module_strings)
            + len(self.process_strings)
        )


def _get_region_page_data(reader, region: MslMemoryRegion) -> bytes:
    """Read page data for a region, handling compressed blocks."""
    payload = reader.read_block_payload(region.block_header)
    map_bytes = ((region.num_pages + 3) // 4 + 7) & ~7
    data_start = 0x20 + map_bytes
    num_captured = count_captured_pages(region.page_states)
    end = data_start + num_captured * region.page_size
    return payload[data_start:end]


def extract_region_strings(
    reader,
    min_length: int = 4,
    max_regions: int = 100,
) -> List[StringMatch]:
    """Extract printable strings from MSL memory region page data.

    Offsets in returned matches are adjusted to absolute virtual addresses
    (region base_addr + in-region offset).

    Args:
        reader: An open MslReader instance.
        min_length: Minimum string length to report.
        max_regions: Maximum number of regions to scan.

    Returns:
        Deduplicated list of StringMatch objects.
    """
    regions = reader.collect_regions()[:max_regions]
    seen = set()
    result: List[StringMatch] = []

    for region in regions:
        page_data = _get_region_page_data(reader, region)
        if not page_data:
            continue
        matches = extract_strings(page_data, min_length)
        for m in matches:
            adjusted = StringMatch(
                offset=region.base_addr + m.offset,
                value=m.value,
                encoding=m.encoding,
                length=m.length,
            )
            if adjusted not in seen:
                seen.add(adjusted)
                result.append(adjusted)

    logger.debug(
        "Extracted %d region strings from %d regions",
        len(result), len(regions),
    )
    return result


def extract_structured_strings(
    reader,
) -> Tuple[List[str], List[str]]:
    """Extract strings from structured MSL blocks (modules, process identity).

    Returns:
        (module_strings, process_strings) -- each a list of non-empty strings.
    """
    module_strings: List[str] = []
    for m in reader.collect_modules():
        if m.path:
            module_strings.append(m.path)
        if m.version:
            module_strings.append(m.version)

    process_strings: List[str] = []
    for p in reader.collect_process_identity():
        if p.exe_path:
            process_strings.append(p.exe_path)
        if p.cmd_line:
            process_strings.append(p.cmd_line)

    return module_strings, process_strings


def extract_strings_from_msl(
    reader,
    min_length: int = 4,
) -> MslStringReport:
    """Full string extraction from an open MslReader.

    Combines region page-data strings with structured block strings.
    """
    region_strings = extract_region_strings(reader, min_length)
    module_strings, process_strings = extract_structured_strings(reader)
    return MslStringReport(
        region_strings=region_strings,
        module_strings=module_strings,
        process_strings=process_strings,
    )


def extract_strings_from_path(
    msl_path: Path,
    min_length: int = 4,
) -> MslStringReport:
    """Convenience: open an MSL file, extract strings, and close."""
    from .reader import MslReader

    with MslReader(msl_path) as reader:
        return extract_strings_from_msl(reader, min_length)
