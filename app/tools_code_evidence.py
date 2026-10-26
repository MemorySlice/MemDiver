"""Code-evidence producer: struct fields a kernel function touches (plan T5.5).

Library layer only. :func:`code_evidence_result` resolves a kallsyms function in
a FULL kernel image, reads its body through pakunoda's verified image reads (the
same path the ISF layout legs use), runs the code-evidence provider seam
(:mod:`memdiver.engine.code_evidence`) and returns plain JSON with a
``kernel_va`` ``Location`` per access. With ``isf`` it also reports the ISF
member each ``current`` (task_struct) access lands on.
"""

from __future__ import annotations

import bisect
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from memdiver.app.tools_isf import _Session, _image_file
from memdiver.core.image.context import require_pakunoda
from memdiver.core.location import AddressSpace, Location
from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.core.service_result import ServiceResult
from memdiver.engine.code_evidence import (CodeEvidence, CodeTarget, FieldAccess,
                                           PakunodaFieldAccessProvider, evidence_for)

DEFAULT_MAX_BYTES = 4096
_DEREF = re.compile(r"^deref\(current\+0x([0-9a-f]+)\)$")


def _err(message: str, code: str, category: ErrorCategory = ErrorCategory.INVALID_INPUT
         ) -> CapabilityError:
    return CapabilityError(message, category=category, code=f"code_evidence.{code}")


def _resolve_function(function: str, symbols: Mapping[str, int]) -> Tuple[str, int]:
    if not function or not str(function).strip():
        raise _err("function is required", "function_required")
    name = str(function).strip()
    if name in symbols:
        return name, symbols[name]
    try:
        va = int(name, 16) if name.lower().startswith("0x") else None
    except ValueError:
        va = None
    if va is None:
        raise _err(f"function {name!r} is not in this image's kallsyms", "unknown_function",
                   ErrorCategory.NOT_FOUND)
    names = [n for n, v in symbols.items() if v == va]
    return (sorted(names)[0] if names else f"sub_{va:x}"), va


def _function_size(va: int, symbols: Mapping[str, int]) -> Optional[int]:
    addresses = sorted(set(symbols.values()))
    i = bisect.bisect_right(addresses, va)
    return addresses[i] - va if i < len(addresses) else None


def _describe_placement(report: Any, anchor: Mapping[str, Any],
                        arch: Optional[str] = None) -> Dict[str, Any]:
    """How the reads were placed and which pakunoda self-tests ran (SKIPPED stays SKIPPED).

    ``kimage_voffset`` is an arm64 check: on another arch its SKIPPED is not news.
    """
    def outcome(check: Any) -> str:
        return str(getattr(check, "value", check))
    banner, voffset = outcome(report.banner), outcome(report.kimage_voffset)
    verified_via = anchor.get("source")
    notes = [f"reads placed via delta source {report.delta_source!r} "
             f"(init_task anchor verified via {verified_via!r})"]
    checks = [("banner", banner)]
    if arch is None or str(arch).lower() in ("aarch64", "arm64"):
        checks.append(("kimage_voffset", voffset))
    skipped = [n for n, v in checks if v == "skipped"]
    if skipped:
        notes.append("pakunoda self-tests SKIPPED (not passed): " + ", ".join(skipped))
    mismatch = getattr(report, "delta_mismatch", None)
    return {"delta_source": report.delta_source, "va_pa_delta": report.va_pa_delta,
            "init_task_anchor_source": verified_via,
            "self_tests": {"banner": banner, "kimage_voffset": voffset},
            "delta_mismatch": mismatch, "notes": notes}


def _read_body(session: _Session, symbols: Mapping[str, int], va: int, length: int,
               placement: Optional[Dict[str, Any]] = None) -> bytes:
    from pakunoda.recovery.layout.reads import image_reads_for
    anchor = session.init_task()
    if anchor["phys"] is None or not anchor.get("verified", False):
        raise _err("init_task is not verified in this image, so kernel VAs cannot be "
                   "translated trustworthily", "init_task_unverified", ErrorCategory.PRECONDITION)
    reads, report = image_reads_for(session.dump, session.arch, dict(symbols), anchor["phys"],
                                    va_pa_delta=anchor.get("va_to_pa_delta"))
    if reads is None:
        raise _err(f"the image could not be read at kernel VAs: {report}", "image_reads_failed",
                   ErrorCategory.PRECONDITION)
    if placement is not None:
        placement.update(_describe_placement(report, anchor, session.arch))
    code = reads.raw(va, length)
    if not code:
        raise _err(f"function body at {va:#x} is not captured in this image", "body_not_captured",
                   ErrorCategory.PRECONDITION)
    return bytes(code)


def _placement_warnings(placement: Mapping[str, Any]) -> List[str]:
    warnings = [n for n in placement["notes"][1:]]
    if placement.get("delta_mismatch"):
        warnings.append(f"delta mismatch: {placement['delta_mismatch']}")
    return warnings


def _current_task_vas(session: _Session, symbols: Mapping[str, int]) -> List[int]:
    names = PakunodaFieldAccessProvider().current_task_symbols(session.arch_name)
    return [symbols[n] for n in names if n in symbols]


def _load_isf_types(isf: str) -> Dict[str, Any]:
    path = Path(isf).expanduser()
    if not path.is_file():
        raise _err(f"ISF file not found: {path}", "isf_not_found", ErrorCategory.NOT_FOUND)
    try:
        doc = json.loads(path.read_text())
        return {**(doc.get("user_types") or {}), _BASES_KEY: doc.get("base_types") or {}}
    except (OSError, ValueError) as exc:
        raise _err(f"ISF file is not valid JSON: {exc}", "isf_invalid") from exc


_BASES_KEY = "__base_types__"
_FALLBACK_BASE_SIZES = {"pointer": 8, "char": 1, "unsigned char": 1, "signed char": 1,
                        "_Bool": 1, "short": 2, "int": 4, "unsigned int": 4}


def _base_size(types: Mapping[str, Any], name: str) -> Optional[int]:
    size = ((types.get(_BASES_KEY) or {}).get(name) or {}).get("size")
    return size if size is not None else _FALLBACK_BASE_SIZES.get(name)


def _type_size(types: Mapping[str, Any], t: Mapping[str, Any]) -> Optional[int]:
    """Byte size of an ISF type descriptor, from the ISF's own base/user types."""
    kind = t.get("kind")
    if kind == "pointer":
        return _base_size(types, "pointer")
    if kind == "base":
        return _base_size(types, t.get("name", ""))
    if kind in ("struct", "union"):
        return (types.get(t.get("name")) or {}).get("size")
    if kind == "array":
        elem = _type_size(types, t.get("subtype") or {})
        return elem * t["count"] if elem is not None and t.get("count") is not None else None
    if kind == "bitfield":
        return _type_size(types, t.get("type") or {"kind": "base", "name": "unsigned int"})
    return None


def _containing_field(types: Mapping[str, Any], struct: str, offset: int):
    """The field of ``struct`` whose byte range contains ``offset`` (latest start wins)."""
    fields = (types.get(struct) or {}).get("fields") or {}
    hits = []
    for name, f in fields.items():
        start = f.get("offset")
        if start is None or offset < start:
            continue
        size = _type_size(types, f.get("type") or {})
        if offset < start + (size if size else 1):
            hits.append((-start, name, f))
    if not hits:
        return None
    _, name, f = sorted(hits, key=lambda h: (h[0], h[1]))[0]
    return name, f


def _descend(types: Mapping[str, Any], t: Mapping[str, Any], inner: int):
    """Walk into an embedded struct/union/array: (path suffix, leaf type, leaf inner offset)."""
    kind = t.get("kind")
    if kind in ("struct", "union"):
        hit = _containing_field(types, t.get("name"), inner)
        if hit is None:
            return "", t, inner
        name, f = hit
        suffix, leaf, rest = _descend(types, f.get("type") or {}, inner - f["offset"])
        return f".{name}{suffix}", leaf, rest
    if kind == "array":
        sub = t.get("subtype") or {}
        elem = _type_size(types, sub)
        if not elem:
            return "", t, inner
        suffix, leaf, rest = _descend(types, sub, inner % elem)
        return f"[{inner // elem}]{suffix}", leaf, rest
    return "", t, inner


def _member_at(types: Mapping[str, Any], struct: str, offset: int) -> Optional[Dict[str, Any]]:
    """The innermost ISF member containing ``struct+offset`` (dotted path, ``[i]`` for arrays)."""
    hit = _containing_field(types, struct, offset)
    if hit is None:
        return None
    name, f = hit
    suffix, leaf, rest = _descend(types, f.get("type") or {}, offset - f["offset"])
    return {"struct": struct, "member": name + suffix, "offset": offset, "type": leaf,
            "isf_member_offset": offset - rest, "inner_offset": rest, "exact": rest == 0}


def _pointee(types: Mapping[str, Any], struct: str, offset: int) -> Optional[str]:
    member = _member_at(types, struct, offset)
    ptype = (member or {}).get("type") or {}
    sub = ptype.get("subtype") or {}
    if not (member and member["exact"]):
        return None
    return sub.get("name") if ptype.get("kind") == "pointer" and sub.get("kind") == "struct" else None


def _isf_member_for(access: FieldAccess, types: Mapping[str, Any],
                   current_struct: str = "task_struct") -> Optional[Dict[str, Any]]:
    """The ISF member an access lands on: ``current`` -> task_struct, one-deref -> pointee."""
    if access.base == "current":
        return _member_at(types, current_struct, access.offset)
    m = _DEREF.match(access.base)
    if m:
        pointee = _pointee(types, current_struct, int(m.group(1), 16))
        return _member_at(types, pointee, access.offset) if pointee else None
    return None


def _access_row(access: FieldAccess, capture: str, types: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    row = access.to_dict()
    row["location"] = Location(AddressSpace.KERNEL_VA, access.insn_va, capture_id=capture).to_dict()
    if types is not None:
        member = _isf_member_for(access, types)
        row["isf_member"] = member
        row["isf_member_offset"] = member["isf_member_offset"] if member else None
        row["inner_offset"] = member["inner_offset"] if member else None
    return row


def _isf_summary(evidence: CodeEvidence, types: Mapping[str, Any]) -> Dict[str, Any]:
    keyed = [a for a in evidence.accesses if a.base == "current" or _DEREF.match(a.base)]
    members = [_isf_member_for(a, types) for a in keyed]
    exact = sum(1 for m in members if m and m["exact"])
    contained = sum(1 for m in members if m and not m["exact"])
    return {"checked": len(keyed), "matched": exact + contained, "exact": exact,
            "contained": contained, "unresolved": len(members) - exact - contained}


def code_evidence_result(session: Any = None, *, image_path: str, function: str,
                         arch: Optional[str] = None, max_bytes: int = DEFAULT_MAX_BYTES,
                         base: Optional[str] = None, params: Optional[Mapping[str, Any]] = None
                         ) -> ServiceResult:
    """Decode the field accesses of kallsyms function ``function`` in a full kernel image.

    ``session`` is an optional open :class:`~memdiver.app.tools_isf._Session` (the
    caller closes it); without one a session is opened and closed here.
    ``params``: ``isf`` (ISF JSON path to join ``current`` accesses against).
    ``base`` filters the returned accesses to one symbolic base (e.g. ``current``).
    """
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise _err(f"max_bytes must be a positive integer, got {max_bytes!r}", "invalid_max_bytes")
    params = dict(params or {})
    types = _load_isf_types(params["isf"]) if params.get("isf") else None
    require_pakunoda()
    owned = session is None
    if owned:
        session = _Session(_image_file(image_path), arch or "auto", params)
    try:
        return ServiceResult.ok(_produce(session, function, max_bytes, base, types))
    finally:
        if owned:
            session.close()


def _produce(session: Any, function: str, max_bytes: int, base: Optional[str],
             types: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    symbols = session.symbols()
    if not symbols:
        raise _err("no kallsyms were found in this image", "no_kallsyms",
                   ErrorCategory.PRECONDITION)
    if not PakunodaFieldAccessProvider().supports(session.arch_name):
        raise _err(f"unsupported architecture {session.arch_name!r}", "unsupported_arch",
                   ErrorCategory.UNSUPPORTED)
    name, va = _resolve_function(function, symbols)
    size = _function_size(va, symbols)
    length = min(size, max_bytes) if size else max_bytes
    placement: Dict[str, Any] = {}
    code = _read_body(session, symbols, va, length, placement)
    target = CodeTarget(name, va, size, session.arch_name)
    evidence = evidence_for(code, target, provider="pakunoda",
                            current_task_vas=_current_task_vas(session, symbols))
    shown = [a for a in evidence.accesses if base is None or a.base == base]
    payload = evidence.to_dict()
    payload["accesses"] = [_access_row(a, session.capture, types) for a in shown]
    size_known = bool(size)
    truncated = bool(payload["coverage"].get("truncated") or not size_known
                     or size > max_bytes or len(code) < length)
    payload["coverage"] = {**payload["coverage"], "bytes_decoded": len(code),
                           "function_size": size, "max_bytes": max_bytes,
                           "bytes_requested": length, "bytes_read": len(code),
                           "size_known": size_known, "truncated": truncated}
    if placement:
        payload["image_reads"] = placement
        payload["warnings"] = list(payload.get("warnings") or []) + _placement_warnings(placement)
    payload["arch_source"] = session.arch_source
    payload["capture_id"] = session.capture
    if base is not None:
        payload["base_filter"] = base
    if types is not None:
        payload["isf_join"] = _isf_summary(evidence, types)
    return payload
