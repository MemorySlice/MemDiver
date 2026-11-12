"""``msl.modules``: the loaded modules of a ``.msl`` capture (MODULE_ENTRY blocks and the
Module List Index), one row per module, ordered by load address."""

import logging
import os
from typing import Any, Dict, Iterator, List, Tuple

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints

from .. import msl_slim
from .info import collected, enum_name, msl_reader_or_report

vollog = logging.getLogger(__name__)

ZERO_HASH = b"\x00" * 32


def module_rows(reader: Any, plugin: str = "msl.modules") -> List[Dict[str, Any]]:
    """Merged module records; an index entry is dropped when a MODULE_ENTRY has the same
    base, size and path (the writer emits both for every module)."""
    entries = collected(reader, "collect_modules", plugin)
    indexes = collected(reader, "collect_module_list_index", plugin)
    if entries is None or indexes is None:
        return []
    algo = enum_name(msl_slim.HashAlgo, reader.file_header.hash_algo).lower()
    rows: Dict[Tuple[int, int, str], Dict[str, Any]] = {}
    for entry in entries:
        rows[(entry.base_addr, entry.module_size, entry.path)] = {
            "base": entry.base_addr, "size": entry.module_size, "path": entry.path,
            "version": entry.version, "source": "MODULE_ENTRY",
            "hash": "" if entry.disk_hash in (ZERO_HASH, b"") else f"{algo}:{entry.disk_hash.hex()}"}
    for index in indexes:
        for item in index.entries:
            rows.setdefault((item.base_addr, item.module_size, item.path), {
                "base": item.base_addr, "size": item.module_size, "path": item.path,
                "version": "", "source": "MODULE_LIST_INDEX", "hash": ""})
    return sorted(rows.values(), key=lambda row: (row["base"], row["path"]))


class Modules(interfaces.plugins.PluginInterface):
    """Lists the modules recorded in a MemDiver .msl capture."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [requirements.TranslationLayerRequirement(
            name="primary", description="Memory layer of the .msl capture")]

    @staticmethod
    def _cell(text: str) -> Any:
        return text if text else renderers.NotApplicableValue()

    def _generator(self, reader: Any) -> Iterator[Tuple[int, Tuple]]:
        for row in module_rows(reader):
            yield 0, (format_hints.Hex(row["base"]), format_hints.Hex(row["size"]),
                      os.path.basename(row["path"]) or row["path"], row["path"],
                      self._cell(row["version"]), self._cell(row["hash"]), row["source"])

    def run(self) -> renderers.TreeGrid:
        columns = [("Base", format_hints.Hex), ("Size", format_hints.Hex), ("Name", str),
                   ("Path", str), ("Version", str), ("DiskHash", str), ("Source", str)]
        reader = msl_reader_or_report(self.context, self.config["primary"], "msl.modules")
        return renderers.TreeGrid(columns, self._generator(reader) if reader is not None
                                  else iter(()))
