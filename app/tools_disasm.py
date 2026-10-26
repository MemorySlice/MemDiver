"""Disassembly producer: decode the CAPTURED bytes at an address into rows.

The ``disasm`` helper. Bytes come through the dump-source layer in the address
space the view itself uses (kernel VA for a kernel ``.mdview``, process VA for a
process view, MSL VA for an ``.msl``, file offset for a flat file), and the two
semantic-workbench rules hold:

* **P2, every address carries its coordinate system.** Each row has a full
  ``location`` dict next to its hex ``addr``.
* **P3, absent bytes are never zeros.** Each captured stretch is disassembled
  on its own, so an instruction is never decoded across a gap; the gaps are
  returned in ``coverage`` with their reasons.

Bytes capstone cannot decode become a one-unit ``.byte`` row (``stop_reason``
set) and decoding resumes after it; ``stops`` lists every such place. Nothing is
skipped silently. ``capstone`` is an optional extra, imported lazily.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from memdiver.core.location import AddressSpace, Location
from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.core.service_result import ServiceResult

ARCHES: Tuple[str, ...] = ("x86_64", "x86", "aarch64", "arm", "mips", "mipsel")
ARM_MODES: Tuple[str, ...] = ("arm", "thumb")
DEFAULT_MAX_INSNS = 2000
#: Largest byte window one call reads.
MAX_LENGTH = 1 << 20

_MSL_ARCH = {0x0000: "x86", 0x0001: "x86_64", 0x0002: "aarch64", 0x0003: "arm"}
_ALIASES = {"amd64": "x86_64", "x64": "x86_64", "i386": "x86", "x86_32": "x86",
            "arm64": "aarch64", "arm32": "arm", "thumb": "arm"}
#: Bytes skipped past an undecodable position, per architecture / mode.
_SKIP = {"x86_64": 1, "x86": 1, "aarch64": 4, "arm": 4, "mips": 4, "mipsel": 4}


def _invalid(message: str, code: str) -> CapabilityError:
    return CapabilityError(message, category=ErrorCategory.INVALID_INPUT, code=code)


# -- capstone --------------------------------------------------------------------


def _capstone() -> Any:
    try:
        import capstone
    except ImportError as exc:
        from memdiver.core.install_hints import missing_package_message

        raise CapabilityError(
            "disassembly needs capstone. " + missing_package_message("capstone", "disasm"),
            category=ErrorCategory.PRECONDITION, code="disasm.capstone_missing") from exc
    return capstone


def _engine(cs: Any, arch: str, mode: Optional[str]) -> Any:
    table = {
        "x86_64": (cs.CS_ARCH_X86, cs.CS_MODE_64),
        "x86": (cs.CS_ARCH_X86, cs.CS_MODE_32),
        "aarch64": (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM),
        "arm": (cs.CS_ARCH_ARM, cs.CS_MODE_THUMB if mode == "thumb" else cs.CS_MODE_ARM),
        "mips": (cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32 | cs.CS_MODE_BIG_ENDIAN),
        "mipsel": (cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32 | cs.CS_MODE_LITTLE_ENDIAN),
    }
    return cs.Cs(*table[arch])


# -- validation / arch resolution ----------------------------------------------------


def _validated(address: int, length: int, max_insns: int, mode: Optional[str]) -> None:
    if address < 0:
        raise _invalid("address must be >= 0", "disasm.bad_address")
    if not 1 <= length <= MAX_LENGTH:
        raise _invalid(f"length must be between 1 and {MAX_LENGTH}", "disasm.bad_length")
    if max_insns < 1:
        raise _invalid("max_insns must be >= 1", "disasm.bad_max_insns")
    if mode is not None and mode not in ARM_MODES:
        raise _invalid(f"unknown mode {mode!r}; mode applies to arm only: "
                       f"{', '.join(ARM_MODES)}", "disasm.bad_mode")


_LAYER_ARCH = (("aarch64", "aarch64"), ("32e", "x86_64"), ("5level", "x86_64"),
               ("pae", "x86"), ("intel", "x86"))


def _arch_of_profiled_view(source: Any) -> str:
    """The arch of a profiled view from the paging layer vol3 built for it; never a guess."""
    from memdiver.app.tools_image import _context_for
    try:
        image_ctx = _context_for(source.descriptor, Path(source.path))
        layer = type(image_ctx.context.layers[image_ctx.kernel_paging.layer_name]).__name__
    except CapabilityError:
        raise
    except Exception:  # noqa: BLE001 - no usable kernel layer: arch stays unknown
        layer = ""
    for needle, arch in _LAYER_ARCH:
        if needle in layer.lower():
            return arch
    raise _invalid("cannot establish the architecture of this profiled view (paging layer "
                   f"{layer or 'unavailable'!r}); pass arch= one of: {', '.join(ARCHES)}",
                   "disasm.arch_undetected")


def _gap_row(gap: Any) -> Dict[str, Any]:
    """A coverage gap as JSON: ``start`` stays the int, ``start_hex`` is exact above 2**53."""
    row = gap.to_dict() if hasattr(gap, "to_dict") else dict(gap)
    return {**row, "start_hex": f"{int(row['start']):#x}"}


def _detected_arch(source: Any) -> Optional[str]:
    descriptor = getattr(source, "descriptor", None)
    if descriptor is not None:
        paging = getattr(descriptor, "paging", None)
        if paging is not None and paging.arch:
            return str(paging.arch)
        if descriptor.profile is not None:
            return _arch_of_profiled_view(source)
        return None
    return _MSL_ARCH.get(source.metadata().get("arch_type"))


def resolve_arch(source: Any, arch: str, mode: Optional[str]) -> Tuple[str, Optional[str]]:
    """``(arch, mode)`` to disassemble with; ``auto`` reads the view / ``.msl`` metadata."""
    name = (arch or "auto").lower()
    thumb = name == "thumb"
    if name == "auto":
        name = (_detected_arch(source) or "").lower()
        if not name:
            raise _invalid("cannot detect the architecture of this dump; pass arch= one "
                           f"of: {', '.join(ARCHES)}", "disasm.unknown_arch")
    name = _ALIASES.get(name, name)
    if name not in ARCHES:
        raise _invalid(f"unsupported architecture {arch!r}; choose one of: "
                       f"{', '.join(ARCHES)}", "disasm.unknown_arch")
    if mode is not None and name != "arm":
        raise _invalid("mode applies to arm only", "disasm.bad_mode")
    return name, ("thumb" if thumb else mode)


# -- reading ---------------------------------------------------------------------


def _read(source: Any, path: Path, address: int, length: int) -> Tuple[Any, Any, List[Tuple[int, bytes]], List[Dict[str, Any]]]:
    """``(space-Location factory, capture_id/pid info, stretches, gaps)`` of the window."""
    from memdiver.analysis.capture_id import capture_id_for

    if hasattr(source, "read_location"):
        result = source.read_location(address, length)
        gaps = [_gap_row(g) for g in result.coverage.gaps]
        return source.location, source.location(address), list(result.segments()), gaps
    capture_id = capture_id_for(path)
    if hasattr(source, "captured_runs"):
        meta = source.metadata()
        span = int(meta["va_span_start"])
        if address < span:
            raise _invalid(f"address {address:#x} is below the capture's first VA {span:#x}",
                           "disasm.bad_address")
        data, runs = source.read_range_valid(address - span, length, "va")
        stretches = [(address + s, data[s:s + n]) for s, n in runs]
        space = AddressSpace.MSL_VA
    else:
        data = source.read_range(address, length, "raw")
        stretches = [(address, data)] if data else []
        space = AddressSpace.FILE_OFFSET

    def factory(addr: int) -> Location:
        return Location(space, addr, capture_id=capture_id)

    return factory, factory(address), stretches, _gaps_of(address, length, stretches)


def _gaps_of(address: int, length: int,
             stretches: List[Tuple[int, bytes]]) -> List[Dict[str, Any]]:
    gaps, cursor = [], address
    for start, data in stretches + [(address + length, b"")]:
        if start > cursor:
            gaps.append(_gap_row({"start": cursor, "length": start - cursor,
                                  "reason": "not_captured"}))
        cursor = start + len(data)
    return gaps


# -- decoding --------------------------------------------------------------------


def _insn_row(factory: Any, addr: int, raw: bytes, mnemonic: str, op_str: str) -> Dict[str, Any]:
    return {"addr": f"{addr:#x}", "location": factory(addr).to_dict(), "bytes": raw.hex(),
            "mnemonic": mnemonic, "op_str": op_str, "size": len(raw)}


def _decode_stretch(md: Any, factory: Any, arch: str, mode: Optional[str], start: int,
                    data: bytes, budget: int, stops: List[Dict[str, Any]]
                    ) -> Tuple[List[Dict[str, Any]], bool]:
    """Rows of one stretch (at most ``budget``) and whether the budget cut it."""
    rows: List[Dict[str, Any]] = []
    skip = 2 if mode == "thumb" else _SKIP[arch]
    offset = 0
    while offset < len(data):
        for insn in md.disasm(data[offset:], start + offset):
            if len(rows) >= budget:
                return rows, True
            rows.append(_insn_row(factory, insn.address, bytes(insn.bytes),
                                  insn.mnemonic, insn.op_str))
            offset += insn.size
        if offset >= len(data):
            break
        if len(rows) >= budget:
            return rows, True
        raw = data[offset:offset + skip]
        stops.append({"addr": f"{start + offset:#x}", "offset": offset,
                      "stop_reason": "undecodable"})
        row = _insn_row(factory, start + offset, raw, ".byte", "0x" + raw.hex())
        row["stop_reason"] = "undecodable"
        rows.append(row)
        offset += len(raw)
    return rows, False


def _decode(md: Any, factory: Any, arch: str, mode: Optional[str],
            stretches: List[Tuple[int, bytes]], max_insns: int
            ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], bool]:
    rows: List[Dict[str, Any]] = []
    stops: List[Dict[str, Any]] = []
    for start, data in stretches:
        part, cut = _decode_stretch(md, factory, arch, mode, start, data,
                                    max_insns - len(rows), stops)
        rows += part
        if cut:
            return rows, stops, True
    return rows, stops, False


# -- case integration ------------------------------------------------------------


def _file_case(path: Path, rows: List[Dict[str, Any]], case_dir: str, location: Location,
               image_sha256: Optional[str], truncated: bool) -> Dict[str, Any]:
    from memdiver.analysis.exporters import export_disasm
    from memdiver.app.tools_case import _open

    table_rows = [{"addr": int(r["addr"], 16), "size": r["size"], "mnemonic": r["mnemonic"],
                   "op_str": r["op_str"], "bytes_hex": r["bytes"],
                   "stop_reason": r.get("stop_reason")} for r in rows]
    ref = export_disasm(_open(case_dir), table_rows, capture_id=location.capture_id,
                        space=location.space.value, pid=location.pid,
                        image_sha256=image_sha256, truncated=truncated)
    return {"table": ref.name, "run_id": ref.run_id, "rows": ref.row_count,
            "path": ref.path}


# -- the producer ----------------------------------------------------------------


def disasm_result(dump_path: str, address: int, length: int, *, arch: str = "auto",
                  view: Optional[str] = None, mode: Optional[str] = None,
                  max_insns: int = DEFAULT_MAX_INSNS,
                  case_dir: Optional[str] = None) -> "ServiceResult":
    """Disassemble ``length`` bytes at ``address`` of a dump, captured stretches only.

    ``address`` is in the view's own space (kernel/process VA for ``.mdview``,
    MSL VA for ``.msl``, file offset for a flat file). ``arch``: ``auto`` or one
    of :data:`ARCHES`; ``mode="thumb"`` selects Thumb for arm. ``view`` is
    accepted for surface symmetry; only the view's native address space is read.
    Rows: ``addr`` (hex), ``location``, ``bytes`` (hex), ``mnemonic``, ``op_str``,
    ``size``. ``truncated`` is set when ``max_insns`` cut the output; ``stops``
    lists undecodable positions (also present as ``.byte`` rows); ``coverage``
    reports the gaps. With ``case_dir`` the rows become the ``disasm`` table.
    """
    from memdiver.core.dump_source import open_dump

    _validated(address, length, max_insns, mode)
    path = Path(dump_path).expanduser() if dump_path and str(dump_path).strip() else None
    if path is None:
        raise _invalid("dump_path is required", "dump_path_required")
    if not path.is_file():
        raise CapabilityError(f"dump not found: {path}", category=ErrorCategory.NOT_FOUND,
                              code="dump_not_found")
    cs = _capstone()
    with open_dump(path) as source:
        name, arm_mode = resolve_arch(source, arch, mode)
        factory, location, stretches, gaps = _read(source, path, address, length)
        image_sha256 = getattr(getattr(source, "descriptor", None), "image_sha256", None)
        format_name = source.format_name
    rows, stops, truncated = _decode(_engine(cs, name, arm_mode), factory, name, arm_mode,
                                     stretches, max_insns)
    captured = sum(len(d) for _, d in stretches)
    payload: Dict[str, Any] = {
        "dump_path": str(path), "format": format_name, "arch": name, "mode": arm_mode,
        "space": location.space.value, "capture_id": location.capture_id,
        "address": f"{address:#x}", "length": length,
        "rows": rows, "row_count": len(rows), "max_insns": max_insns,
        "truncated": truncated, "stops": stops,
        "coverage": {"requested": length, "captured": captured, "gaps": gaps,
                     "complete": captured == length},
    }
    if case_dir:
        payload["case"] = _file_case(path, rows, case_dir, location, image_sha256, truncated)
    return ServiceResult.ok(payload)


__all__ = ["ARCHES", "DEFAULT_MAX_INSNS", "disasm_result", "resolve_arch"]
