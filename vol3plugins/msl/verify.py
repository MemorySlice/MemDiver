"""``msl.verify``: verifies the integrity chain of a ``.msl`` capture (spec 4.4, 4.6).

One row per capture-segment block (does its PrevHash match the hash of the block before it,
block 0 the file header), one row per extension segment, summary rows and a final
``verdict`` row that says ``valid`` or ``tampered``.

A PrevHash chain breaks at the block AFTER the modified bytes, so a ``link broken`` row
names that block and the Detail names the one before it, whose content (or whose own
PrevHash field) changed. The End-of-Capture FileHash is an independent second check over
every byte before the EoC block.

Plaintext captures are verified by ``msl_slim.verify_container`` (standard library:
SHA-256 and SHA-512/256 with ``hashlib``); the default BLAKE3 chain needs the ``blake3``
package, which MemDiver depends on, and without it the verdict is ``not verified``. An
encrypted capture is verified by MemDiver (its AEAD tag plus the plaintext chain).
"""

import logging
from typing import Any, Iterator, List, Optional, Tuple

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints

from .. import msl_slim
from .info import blake3_module, msl_reader_or_report

vollog = logging.getLogger(__name__)

BLOCK_TYPE_NAMES = {
    0x0001: "MEMORY_REGION", 0x0002: "MODULE_ENTRY", 0x0010: "MODULE_LIST_INDEX",
    0x0011: "THREAD_CONTEXT", 0x0012: "FILE_DESCRIPTOR", 0x0013: "NETWORK_CONNECTION",
    0x0014: "ENVIRONMENT_BLOCK", 0x0015: "SECURITY_TOKEN", 0x0020: "KEY_HINT",
    0x0030: "IMPORT_PROVENANCE", 0x0040: "PROCESS_IDENTITY", 0x0041: "RELATED_DUMP",
    0x0050: "SYSTEM_CONTEXT", 0x0051: "PROCESS_TABLE", 0x0052: "CONNECTION_TABLE",
    0x0053: "HANDLE_TABLE", 0x0055: "CONNECTIVITY_TABLE", 0x0059: "PHYSICAL_MEMORY_MAP",
    0x0FFE: "END_OF_EXTENSION", 0x0FFF: "END_OF_CAPTURE", 0x1001: "VAS_MAP",
    0x1003: "POINTER_GRAPH",
}

Row = Tuple[str, Any, Any, str, Any, str, str]


def block_type_name(code: int) -> str:
    return BLOCK_TYPE_NAMES.get(code, f"0x{code:04X}")


def _row(scope: str, index: Optional[int], offset: Optional[int], kind: str,
         length: Optional[int], result: str, detail: str = "") -> Row:
    return (scope, index if index is not None else renderers.NotApplicableValue(),
            format_hints.Hex(offset) if offset is not None else renderers.NotApplicableValue(),
            kind, length if length is not None else renderers.NotApplicableValue(),
            result, detail)


def _summary(kind: str, result: str, detail: str = "") -> Row:
    return _row("summary", None, None, kind, None, result, detail)


def _block_rows(report: Any) -> Iterator[Row]:
    previous = None
    for check in report.blocks:
        detail = ""
        if not check.ok and previous is None:
            detail = ("PrevHash does not match the file header: the header (bytes 0.."
                      "HeaderSize) or this block's PrevHash was altered")
        elif not check.ok:
            detail = (f"PrevHash does not match block {previous.index} "
                      f"({block_type_name(previous.block_type)} at 0x{previous.file_offset:X}): "
                      "that block's bytes, or this PrevHash, were altered")
        yield _row("block", check.index, check.file_offset, block_type_name(check.block_type),
                   check.block_length, "ok" if check.ok else "link broken", detail)
        previous = check


def _segment_rows(report: Any) -> Iterator[Row]:
    for seg in report.segments:
        result = ("verified" if seg.verified else
                  "unterminated" if not seg.terminated else "FAILED")
        yield _row("segment", seg.index, seg.start, "extension segment", seg.end - seg.start,
                   result, "; ".join(seg.errors))


def _chain_summary(report: Any) -> Iterator[Row]:
    first = report.broken_at
    if first is None:
        yield _summary("hash chain", "ok", f"{report.block_count} capture-segment blocks")
    else:
        yield _summary("hash chain", "tampered", f"first broken link at block offset 0x{first:X}")
    if report.file_hash_ok is None:
        yield _summary("EoC FileHash", "not recorded", "")
    else:
        yield _summary("EoC FileHash", "ok" if report.file_hash_ok else "tampered",
                       "covers every byte before the End-of-Capture block")
    yield _summary("block count", "ok" if report.block_count_ok else "inconsistent",
                   f"header {report.header_block_count}, EoC {report.eoc_block_count}, "
                   f"parsed {report.block_count} (0 = not recorded)")
    yield _summary("extension segments", f"{sum(s.verified for s in report.segments)}"
                   f"/{len(report.segments)} verified",
                   f"{report.trailing_bytes} trailing byte(s)")


def _hash_mismatch(report: Any) -> bool:
    return (report.broken_at is not None or report.file_hash_ok is False
            or any(not (s.chain_ok and (s.segment_hash_ok or not s.terminated))
                   for s in report.segments if s.terminated))


def _verdict(report: Any) -> Row:
    detail = "; ".join(report.errors[:3] + report.warnings[:2])
    if _hash_mismatch(report):
        return _summary("verdict", "tampered", detail)
    if report.errors:
        return _summary("verdict", "invalid structure", detail)
    return _summary("verdict", "valid", detail)


def slim_rows(path: str, blake3: Any) -> Iterator[Row]:
    """All rows for a plaintext capture; one ``not verified`` row when it cannot be hashed."""
    try:
        reader = msl_slim.MslSlimReader(path, allow_compressed=True).open()
    except msl_slim.MslSlimError as excp:
        yield _summary("verdict", "not verified", str(excp))
        return
    try:
        report = msl_slim.verify_container(reader, blake3)
    except msl_slim.MslSlimHashUnavailable as excp:
        yield _summary("verdict", "not verified", _hash_hint(excp))
        return
    except msl_slim.MslSlimError as excp:
        yield _summary("verdict", "not verified", str(excp))
        return
    finally:
        reader.close()
    yield from _block_rows(report)
    yield from _segment_rows(report)
    yield from _chain_summary(report)
    yield _verdict(report)


def _hash_hint(excp: msl_slim.MslSlimHashUnavailable) -> str:
    try:
        import memdiver  # noqa: F401
    except ImportError:
        return str(excp)
    return ("the container's chain is BLAKE3 and the blake3 package (a MemDiver dependency) "
            "is not importable in vol's Python: pip install blake3")


def memdiver_rows(reader: Any) -> Iterator[Row]:
    """Rows for a capture MemDiver opened (the encrypted case): summary and segments only."""
    from memdiver.msl.integrity import verify_chain

    report = verify_chain(reader)
    yield _summary("hash chain", "ok" if report.capture_ok else "tampered",
                   f"{report.block_count} capture-segment blocks (an encrypted capture is "
                   "protected by its AEAD tag; the plaintext chain is checked as well)")
    for seg in report.segments:
        yield _row("segment", seg.index, seg.start, "extension segment", seg.end - seg.start,
                   "verified" if seg.verified else "FAILED", "; ".join(seg.errors))
    errors: List[str] = list(report.errors[:3])
    yield _summary("verdict", "valid" if report.valid else "tampered", "; ".join(errors))


class Verify(interfaces.plugins.PluginInterface):
    """Verifies the hash chain and extension segments of a MemDiver .msl; says if tampered."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [requirements.TranslationLayerRequirement(
            name="primary", description="Memory layer of the .msl capture")]

    def _rows(self, reader: Any) -> Iterator[Row]:
        path = str(self.context.layers[self.config["primary"]].metadata.get("msl_path", ""))
        if reader.file_header.encrypted:
            if hasattr(reader, "_buf"):  # MemDiver's reader: AEAD already verified at open
                yield from memdiver_rows(reader)
            else:
                yield _summary("verdict", "not verified", msl_slim.INSTALL_HINT)
            return
        yield from slim_rows(path, blake3_module())

    def _generator(self, reader: Any) -> Iterator[Tuple[int, Row]]:
        for row in self._rows(reader):
            yield 0, row

    def run(self) -> renderers.TreeGrid:
        columns = [("Scope", str), ("Index", int), ("Offset", format_hints.Hex), ("Type", str),
                   ("Length", int), ("Result", str), ("Detail", str)]
        reader = msl_reader_or_report(self.context, self.config["primary"], "msl.verify")
        return renderers.TreeGrid(columns, self._generator(reader) if reader is not None
                                  else iter(()))
