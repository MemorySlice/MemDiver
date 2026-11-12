"""``msl.pagemap``: the page-state runs of a ``.msl`` capture, one row per run of pages.

Spec section 7 (Table 35) defines four states per page. They are not interchangeable:
Captured pages hold data; Failed (mapped but unreadable) and Unmapped (absent at read time)
hold none; NotResident (mapped, never touched) holds none either but its content is known to
be zero. On an imported capture the states were assigned by convention, not observed live
(header capability bit PAGE_STATES_INFERRED), and the ``Basis`` column says so.
"""

import logging
from typing import Any, Iterator, List, Optional, Tuple

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints

from .. import msl_slim
from .info import msl_reader_or_report

vollog = logging.getLogger(__name__)

STATE_LABELS = {int(msl_slim.PageState.CAPTURED): "Captured",
                int(msl_slim.PageState.FAILED): "Failed",
                int(msl_slim.PageState.UNMAPPED): "Unmapped",
                int(msl_slim.PageState.NOT_RESIDENT): "NotResident"}
STATE_CONTENT = {"Captured": "stored", "Failed": "none (unreadable)",
                 "Unmapped": "none (absent at read time)",
                 "NotResident": "none (content is zero)"}


def select_regions(regions: List[Any], wanted: Optional[str]) -> List[Tuple[int, Any]]:
    """``(file index, region)`` pairs; ``wanted`` is a decimal index or a block UUID (prefix)."""
    pairs = list(enumerate(regions))
    if not wanted:
        return pairs
    text = wanted.strip().lower().replace("-", "")
    if wanted.strip().isdigit():
        return [pair for pair in pairs if pair[0] == int(wanted)]
    return [pair for pair in pairs
            if str(pair[1].block_header.block_uuid).replace("-", "").startswith(text)]


def page_runs(region: Any) -> Iterator[Tuple[str, int, int, int]]:
    """``(state label, start VA, end VA, pages)`` for each run of the region's pages."""
    page_size = int(region.page_size)
    for interval in region.page_intervals:
        start = int(region.base_addr) + interval.start_page * page_size
        yield (STATE_LABELS[int(interval.state)], start,
               start + interval.count * page_size, int(interval.count))


class PageMap(interfaces.plugins.PluginInterface):
    """Lists the page-state runs (Captured/Failed/Unmapped/NotResident) of a MemDiver .msl."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary", description="Memory layer of the .msl capture"),
            requirements.StringRequirement(
                name="region", optional=True,
                description="Only this region: its index in the capture or its block UUID"),
        ]

    def _generator(self, reader: Any) -> Iterator[Tuple[int, Tuple]]:
        header = reader.file_header
        basis = "inferred on import" if header.page_states_inferred else "observed"
        pairs = select_regions(reader.collect_regions(), self.config.get("region"))
        if not pairs:
            vollog.error("msl.pagemap: no region matches %r", self.config.get("region"))
        for index, region in pairs:
            page_size = int(region.page_size)
            for state, start, end, pages in page_runs(region):
                yield 0, (index, str(region.block_header.block_uuid), format_hints.Hex(start),
                          format_hints.Hex(end), state, pages, pages * page_size,
                          STATE_CONTENT[state], basis)

    def run(self) -> renderers.TreeGrid:
        columns = [("Region", int), ("UUID", str), ("Start(V)", format_hints.Hex),
                   ("End(V)", format_hints.Hex), ("State", str), ("Pages", int),
                   ("Bytes", int), ("Content", str), ("Basis", str)]
        reader = msl_reader_or_report(self.context, self.config["primary"], "msl.pagemap")
        return renderers.TreeGrid(columns, self._generator(reader) if reader is not None
                                  else iter(()))
