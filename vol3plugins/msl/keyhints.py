"""``msl.keyhints``: the KEY_HINT blocks of a ``.msl`` capture (spec 5.6, Table 20).

A hint names a region by block UUID and a byte offset into that region's PageData, which is
the concatenation of its Captured pages only. The plugin turns that into a virtual address
by walking the region's page-state runs; ``--dump`` writes each hinted key's bytes to
``keyhint_<n>.bin`` (``n`` counts hints in file order, from 0) when they can be read from
the slice.
"""

import logging
from typing import Any, Iterator, List, NamedTuple, Optional, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints

from .. import msl_slim
from .info import collected, enum_name, msl_reader_or_report

vollog = logging.getLogger(__name__)

CAPTURED = int(msl_slim.PageState.CAPTURED)


class HintPlacement(NamedTuple):
    """Where a hint's bytes live: ``pieces`` is ``[(va, length)]`` in PageData order."""

    pieces: Tuple[Tuple[int, int], ...]
    problem: str


def place_hint(region: Optional[Any], offset: int, length: int) -> HintPlacement:
    """Map PageData ``[offset, offset+length)`` of ``region`` to virtual-address pieces.

    The key may straddle two Captured runs that are not adjacent in the address space, so
    the answer is a list. ``problem`` says why there are no pieces.
    """
    if region is None:
        return HintPlacement((), "region UUID not in this capture")
    page_size = int(region.page_size)
    wanted_end = offset + max(length, 1)
    pieces: List[Tuple[int, int]] = []
    consumed = 0
    for interval in region.page_intervals:
        if int(interval.state) != CAPTURED:
            continue
        span = int(interval.count) * page_size
        lo, hi = max(offset, consumed), min(wanted_end, consumed + span)
        if lo < hi:
            va = int(region.base_addr) + interval.start_page * page_size + (lo - consumed)
            pieces.append((va, hi - lo))
        consumed += span
    covered = sum(piece[1] for piece in pieces)
    if covered < wanted_end - offset:
        return HintPlacement(tuple(pieces), "offset lies outside the region's captured pages")
    return HintPlacement(tuple(pieces), "")


class KeyHints(interfaces.plugins.PluginInterface):
    """Lists the key hints of a MemDiver .msl capture; --dump writes the hinted bytes."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary", description="Memory layer of the .msl capture"),
            requirements.BooleanRequirement(
                name="dump", optional=True, default=False,
                description="Write each readable hinted key to keyhint_<n>.bin"),
        ]

    def _key_bytes(self, placement: HintPlacement, length: int) -> Tuple[Optional[bytes], str]:
        """``(bytes, "")`` read through the capture layer, else ``(None, reason)``."""
        if placement.problem:
            return None, placement.problem
        if length <= 0:
            return None, "key length not recorded"
        layer = self.context.layers[self.config["primary"]]
        try:
            return b"".join(layer.read(va, size, pad=False) for va, size in placement.pieces), ""
        except exceptions.InvalidAddressException:
            return None, "bytes not readable from the slice"

    def _write(self, number: int, data: bytes) -> None:
        with self.open(f"keyhint_{number}.bin") as handle:
            handle.write(data)

    def _generator(self, reader: Any) -> Iterator[Tuple[int, Tuple]]:
        hints = collected(reader, "collect_key_hints", "msl.keyhints")
        regions = collected(reader, "collect_regions", "msl.keyhints")
        if hints is None or regions is None:
            return
        by_uuid = {region.block_header.block_uuid: region for region in regions}
        for number, hint in enumerate(hints):
            placement = place_hint(by_uuid.get(hint.region_uuid), hint.region_offset,
                                   hint.key_length)
            data, reason = self._key_bytes(placement, hint.key_length)
            if data is not None and self.config.get("dump"):
                self._write(number, data)
            yield 0, (number, str(hint.region_uuid), format_hints.Hex(hint.region_offset),
                      format_hints.Hex(placement.pieces[0][0]) if placement.pieces
                      else renderers.NotApplicableValue(),
                      hint.key_length or renderers.NotApplicableValue(),
                      enum_name(msl_slim.KeyType, hint.key_type),
                      enum_name(msl_slim.Protocol, hint.protocol),
                      enum_name(msl_slim.Confidence, hint.confidence),
                      enum_name(msl_slim.KeyState, hint.key_state), hint.note,
                      "yes" if data is not None else f"no: {reason}")

    def run(self) -> renderers.TreeGrid:
        columns = [("Hint", int), ("Region", str), ("Offset", format_hints.Hex),
                   ("VA", format_hints.Hex), ("Length", int), ("KeyType", str),
                   ("Protocol", str), ("Confidence", str), ("State", str), ("Note", str),
                   ("Readable", str)]
        reader = msl_reader_or_report(self.context, self.config["primary"], "msl.keyhints")
        return renderers.TreeGrid(columns, self._generator(reader) if reader is not None
                                  else iter(()))
