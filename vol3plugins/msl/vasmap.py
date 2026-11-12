"""``msl.vasmap``: the memory regions of a ``.msl`` capture, one row per region."""

import bisect
import logging
from typing import Any, Iterator, List, Tuple

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints

from .. import msl_slim
from .info import PAGE_STATE_LABELS, enum_name, msl_reader_or_report

vollog = logging.getLogger(__name__)

PROTECTION_BITS = ((0x01, "r"), (0x02, "w"), (0x04, "x"))
STATE_SHORT = {"Captured": "C", "NotResident": "NR", "Failed": "F", "Unmapped": "U"}


def protection_text(protection: int) -> str:
    text = "".join(ch if protection & bit else "-" for bit, ch in PROTECTION_BITS)
    return text + ("g" if protection & 0x08 else "") + ("c" if protection & 0x10 else "")


class VasMap(interfaces.plugins.PluginInterface):
    """Lists the memory regions of a MemDiver .msl capture with page-state counts."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [requirements.TranslationLayerRequirement(
            name="primary", description="Memory layer of the .msl capture")]

    @staticmethod
    def _state_pages(regions: List[Any], start: int, end: int) -> Tuple[dict, int]:
        """``(pages per state label, captured bytes)`` of the regions based in [start, end)."""
        labels = {int(msl_slim.PageState[name]): label for name, label in PAGE_STATE_LABELS}
        counts = {label: 0 for _name, label in PAGE_STATE_LABELS}
        captured = 0
        bases = [int(r.base_addr) for r in regions]
        for region in regions[bisect.bisect_left(bases, start):bisect.bisect_left(bases, end)]:
            for interval in region.page_intervals:
                counts[labels[int(interval.state)]] += interval.count
                if int(interval.state) == 0:
                    captured += interval.count * int(region.page_size)
        return counts, captured

    @staticmethod
    def _module_for(modules: List[Any], start: int, end: int) -> str:
        for module in modules:
            if start < module.base_addr + module.module_size and module.base_addr < end:
                return module.path
        return ""

    def _generator(self, reader: Any, layer: Any) -> Iterator[Tuple[int, Tuple]]:
        regions = sorted(reader.collect_regions(), key=lambda r: int(r.base_addr))
        modules = reader.collect_modules()
        for row in layer.region_map():
            counts, captured = self._state_pages(regions, row.start, row.end)
            summary = " ".join(f"{STATE_SHORT[label]}:{counts[label]}"
                               for _name, label in PAGE_STATE_LABELS)
            kind = enum_name(msl_slim.RegionType, row.region_type)
            yield 0, (format_hints.Hex(row.start), format_hints.Hex(row.end),
                      format_hints.Hex(row.end - row.start), protection_text(row.protection),
                      kind, summary, captured,
                      row.path or self._module_for(modules, row.start, row.end))

    def run(self) -> renderers.TreeGrid:
        columns = [("Start(V)", format_hints.Hex), ("End(V)", format_hints.Hex),
                   ("Size", format_hints.Hex), ("Protection", str), ("Type", str),
                   ("PageState", str), ("Captured", int), ("Module/Path", str)]
        reader = msl_reader_or_report(self.context, self.config["primary"], "msl.vasmap")
        if reader is None:
            return renderers.TreeGrid(columns, iter(()))
        return renderers.TreeGrid(columns, self._generator(
            reader, self.context.layers[self.config["primary"]]))
