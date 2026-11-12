"""``msl.info``: one key/value table describing a ``.msl`` capture (like ``windows.info``)."""

import datetime
import logging
from typing import Any, Dict, Iterator, List, Optional, Tuple

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements

from .. import msl_slim

vollog = logging.getLogger(__name__)

PAGE_STATE_LABELS = (("CAPTURED", "Captured"), ("NOT_RESIDENT", "NotResident"),
                     ("FAILED", "Failed"), ("UNMAPPED", "Unmapped"))


def msl_reader(context: interfaces.context.ContextInterface, layer_name: str) -> Optional[Any]:
    """The ``MslReader`` behind ``layer_name`` (an MslLayer or MslVasLayer), else ``None``.

    Uses the layers' public read-only ``reader`` property (``region_map`` marks them as
    msl_layer layers); the reader is shared, so callers must not close it.
    """
    layer = context.layers[layer_name]
    if not (hasattr(layer, "region_map") and hasattr(layer, "reader")):
        return None
    return layer.reader


def memdiver_missing(plugin: str) -> bool:
    """Whether MemDiver is not importable, logging one line naming the fix if so.

    The ``.msl`` layers and the ``msl.*`` plugins that read tables decode a plaintext,
    uncompressed capture without MemDiver (``msl_slim``); this is for what still needs it.
    """
    try:
        import memdiver  # noqa: F401
    except ImportError:
        vollog.error("%s needs MemDiver in vol's Python (the .msl layers do not): "
                     "pip install memdiver", plugin)
        return True
    return False


def msl_reader_or_report(context: interfaces.context.ContextInterface, layer_name: str,
                         plugin: str) -> Optional[Any]:
    """The reader *plugin* reads, or ``None`` after logging why it cannot run.

    The reader is MemDiver's ``MslReader`` or, without MemDiver, ``msl_slim``'s
    ``MslSlimReader`` (same attribute names for what the plugins read). A primary layer
    that is not an MSL layer leaves the plugin an empty table; this is where that is decided.
    """
    reader = msl_reader(context, layer_name)
    if reader is None:
        vollog.error("%s: the primary layer is not an MSL capture layer; "
                     "run it on a .msl file (vol -p <vol3plugins dir> -f x.msl %s)", plugin, plugin)
    return reader


def enum_name(enum_type: Any, code: int) -> str:
    """``enum_type(code).name``, or the decimal code for one the enum does not know."""
    return enum_type(code).name if code in set(enum_type) else str(code)


def collected(reader: Any, collector: str, plugin: str) -> Optional[List[Any]]:
    """``reader.<collector>()``, or ``None`` after logging when the slim reader cannot.

    Only a compressed block raises :class:`msl_slim.MslSlimUnsupported` there; MemDiver's
    reader decodes it, so with MemDiver this never returns ``None``.
    """
    try:
        return getattr(reader, collector)()
    except msl_slim.MslSlimUnsupported as excp:
        vollog.error("%s: %s", plugin, excp)
        return None


def blake3_module() -> Optional[Any]:
    """The ``blake3`` package when importable (MemDiver depends on it), else ``None``."""
    try:
        import blake3
    except ImportError:
        return None
    return blake3


def format_time(timestamp_ns: int) -> str:
    if not timestamp_ns:
        return "not recorded"
    moment = datetime.datetime.fromtimestamp(timestamp_ns / 1e9, datetime.timezone.utc)
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC")


def page_state_pages(regions: List[Any]) -> Dict[str, int]:
    """Pages per state label, summed over the decoded memory regions."""
    counts = {label: 0 for _name, label in PAGE_STATE_LABELS}
    labels = {int(msl_slim.PageState[name]): label for name, label in PAGE_STATE_LABELS}
    for region in regions:
        for interval in region.page_intervals:
            counts[labels[int(interval.state)]] += interval.count
    return counts


def integrity_status(reader: Any) -> str:
    """One word-or-sentence verdict on the hash chain, for the ``Integrity`` row.

    MemDiver's ``verify_chain`` when MemDiver imports (it also covers encrypted captures);
    else ``msl_slim.verify_container`` on the file, which needs the ``blake3`` package for
    the default BLAKE3 chain and says so when it is absent.
    """
    try:
        try:
            from memdiver.msl.integrity import verify_chain
        except ImportError:
            report = _slim_report(reader)
        else:
            report = verify_chain(reader)
        return "valid" if report.valid else "BROKEN: " + "; ".join(report.errors[:2])
    except Exception as excp:  # an unverifiable file must not hide the other rows
        return f"not verified ({excp})"


def _slim_report(reader: Any) -> Any:
    reader = msl_slim.MslSlimReader(reader.path, allow_compressed=True).open()
    try:
        return msl_slim.verify_container(reader, blake3_module())
    finally:
        reader.close()


class Info(interfaces.plugins.PluginInterface):
    """Summarises a MemDiver .msl process capture."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [requirements.TranslationLayerRequirement(
            name="primary", description="Memory layer of the .msl capture")]

    def _rows(self, reader: Any) -> Iterator[Tuple[str, Any]]:
        header = reader.file_header
        regions = reader.collect_regions()
        pages = page_state_pages(regions)
        page_sizes = sorted({int(r.page_size) for r in regions})
        captured_bytes = sum(int(r.page_size) * sum(
            i.count for i in r.page_intervals if int(i.state) == 0) for r in regions)
        yield "File", str(self.context.layers[self.config["primary"]].metadata.get("msl_path", ""))
        yield "Format version", f"{header.version_major}.{header.version_minor}"
        yield "OS", enum_name(msl_slim.OSType, header.os_type)
        yield "Architecture", enum_name(msl_slim.ArchType, header.arch_type)
        yield "PID", header.pid
        yield from self._identity_rows(reader)
        yield "Capture time", format_time(header.timestamp_ns)
        yield "Page size", ", ".join(str(s) for s in page_sizes) or "n/a"
        yield "Regions", len(regions)
        for _name, label in PAGE_STATE_LABELS:
            yield f"Pages {label}", pages[label]
        yield "Captured bytes", captured_bytes
        yield "VAS size", sum(int(r.region_size) for r in regions)
        yield "Encrypted", "yes" if header.encrypted else "no"
        yield "Compression", self._compression(regions)
        yield "Module count", self._count(reader, "collect_modules")
        yield "Key hint count", self._count(reader, "collect_key_hints")
        yield from self._provenance_rows(reader, header)
        yield from self._integrity_rows(reader)

    @staticmethod
    def _count(reader: Any, collector: str) -> Any:
        blocks = collected(reader, collector, "msl.info")
        return len(blocks) if blocks is not None else "not decoded (compressed blocks)"

    @staticmethod
    def _identity_rows(reader: Any) -> Iterator[Tuple[str, Any]]:
        identities = reader.collect_process_identity()
        if not identities:
            yield "Process", "not recorded"
            return
        identity = identities[0]
        yield "PPID", identity.ppid
        yield "Process exe path", identity.exe_path or "not recorded"
        if identity.cmd_line:
            yield "Process command line", identity.cmd_line

    @staticmethod
    def _compression(regions: List[Any]) -> str:
        names = {r.block_header.comp_algo.name if r.block_header.compressed else "NONE"
                 for r in regions}
        return ", ".join(sorted(names)) or "NONE"

    @staticmethod
    def _provenance_rows(reader: Any, header: Any) -> Iterator[Tuple[str, Any]]:
        for prov in reader.collect_import_provenance():
            name = enum_name(msl_slim.SourceFormat, prov.source_format)
            yield "Imported from", f"{name} via {prov.tool_name} at {format_time(prov.import_time_ns)}"
        if header.imported and not reader.collect_import_provenance():
            yield "Imported from", "unknown (imported flag set, no provenance block)"
        if header.page_states_inferred:
            yield "Page states", "inferred on import, not observed"

    @staticmethod
    def _integrity_rows(reader: Any) -> Iterator[Tuple[str, Any]]:
        eocs = reader.collect_end_of_capture()
        if eocs:
            yield "End of capture", f"present, ended {format_time(eocs[0].acq_end_ns)}"
        else:
            yield "End of capture", "absent (truncated or still streaming)"
        yield "Integrity", integrity_status(reader)

    def _generator(self, reader: Any) -> Iterator[Tuple[int, Tuple[str, str]]]:
        for variable, value in self._rows(reader):
            yield 0, (variable, str(value))

    def run(self) -> renderers.TreeGrid:
        reader = msl_reader_or_report(self.context, self.config["primary"], "msl.info")
        return renderers.TreeGrid([("Variable", str), ("Value", str)],
                                  self._generator(reader) if reader is not None else iter(()))
