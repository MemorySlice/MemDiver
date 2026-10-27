"""Code evidence: which struct fields a kernel function body touches.

A *seam* between "a proposed layout / ISF draft says offset X is a field" and
"the code of a function that uses the object actually reads offset X through
this base". One provider ships (pakunoda's field-access decoder); others plug in
by satisfying :class:`CodeEvidenceProvider`.

Honesty rules:

* A decoder that declines (no decoder for the arch, short body) yields a
  :class:`CodeEvidence` with no accesses and ``coverage["declined"]`` set, so
  "could not decode" is never confused with "touches nothing".
* ``coverage`` states how many bytes were decoded, whether the decode reached a
  function end (``complete``) and why it stopped.
* Bases are symbolic (``current``, ``arg0``, ``static(sym)``,
  ``deref(arg0+0x10)``); the decoder never guesses a type.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple

ACCESS_KINDS = ("read", "write", "address", "unknown")
_KIND_MAP = {"load": "read", "store": "write", "address_of": "address"}


@dataclass(frozen=True)
class CodeTarget:
    """The function whose body is analysed."""

    name: str
    va: int
    size: Optional[int]
    arch: str

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "va": self.va, "size": self.size, "arch": self.arch}


@dataclass(frozen=True)
class FieldAccess:
    """One instruction addressing ``[base + offset]`` for a symbolic base."""

    insn_va: int
    base: str
    offset: int
    width: Optional[int]
    kind: str
    mnemonic: str = ""
    detail: str = ""
    base_delta: int = 0  # decoder's signed adjustment folded into ``offset`` (offset = disp + delta)

    def to_dict(self) -> Dict[str, Any]:
        return {"insn_va": self.insn_va, "base": self.base, "offset": self.offset,
                "width": self.width, "kind": self.kind, "mnemonic": self.mnemonic,
                "detail": self.detail, "base_delta": self.base_delta}


@dataclass(frozen=True)
class CodeEvidence:
    provider: str
    target: CodeTarget
    accesses: Tuple[FieldAccess, ...] = ()
    coverage: Dict[str, Any] = field(default_factory=dict)
    warnings: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {"provider": self.provider, "target": self.target.to_dict(),
                "accesses": [a.to_dict() for a in self.accesses],
                "coverage": dict(self.coverage), "warnings": list(self.warnings)}


class CodeEvidenceProvider(Protocol):
    name: str

    def supports(self, arch: str) -> bool: ...

    def field_accesses(self, code: bytes, target: CodeTarget, **context: Any) -> CodeEvidence: ...


def _kind_of(raw: Any) -> str:
    value = getattr(raw, "value", raw)
    return _KIND_MAP.get(str(value), "unknown")


class PakunodaFieldAccessProvider:
    """Wraps pakunoda's ``ArchDefinition.decode_field_accesses``.

    ``context``: ``current_task_vas`` (VAs of the arch's ``current_task_symbols``
    in this image; x86_64 needs them to recognise ``current``).
    """

    name = "pakunoda"

    def supports(self, arch: str) -> bool:
        try:
            from pakunoda import probes
            probes.resolve_arch(arch)
        except Exception:  # noqa: BLE001 - missing package or unknown arch: not supported
            return False
        return True

    def current_task_symbols(self, arch: str) -> Tuple[str, ...]:
        from pakunoda import probes
        return tuple(probes.resolve_arch(arch).current_task_symbols)

    def field_accesses(self, code: bytes, target: CodeTarget, **context: Any) -> CodeEvidence:
        from memdiver.core.image.context import require_pakunoda
        require_pakunoda()
        from pakunoda import probes
        try:
            arch = probes.resolve_arch(target.arch)
        except ValueError as exc:
            return self._declined(target, len(code), f"unsupported architecture: {exc}")
        vas = tuple(context.get("current_task_vas") or ())
        decoded = arch.decode_field_accesses(code, target.va, current_task_vas=vas)
        if not decoded.field_accesses and decoded.stop_reason.startswith("no decoder"):
            return self._declined(target, len(code), decoded.stop_reason)
        accesses = tuple(self._map(a) for a in decoded.field_accesses)
        warnings: List[str] = []
        if target.arch == "x86_64" and not vas:
            warnings.append("no current_task_vas given: `current` accesses cannot be recognised")
        coverage = {"bytes_given": len(code), "complete": bool(decoded.complete),
                    "stop_reason": decoded.stop_reason, "declined": None,
                    "truncated": not decoded.complete}
        return CodeEvidence(self.name, target, accesses, coverage, tuple(warnings))

    @staticmethod
    def _declined(target: CodeTarget, nbytes: int, reason: str) -> CodeEvidence:
        coverage = {"bytes_given": nbytes, "complete": False, "stop_reason": reason,
                    "declined": reason, "truncated": False}
        return CodeEvidence("pakunoda", target, (), coverage, (reason,))

    @staticmethod
    def _map(raw: Any) -> FieldAccess:
        base = raw.base
        parts = [f"base={base.describe()}"]
        if getattr(base, "delta", 0):
            parts.append(f"base_delta={base.delta:+#x}")
        if getattr(raw, "dest_reg", None):
            parts.append(f"dest_reg={raw.dest_reg}")
        return FieldAccess(insn_va=raw.insn_va, base=base.key, offset=raw.offset,
                           width=raw.width, kind=_kind_of(raw.kind), detail="; ".join(parts),
                           base_delta=int(getattr(base, "delta", 0) or 0))


_PROVIDERS: Tuple[CodeEvidenceProvider, ...] = (PakunodaFieldAccessProvider(),)


def providers() -> List[CodeEvidenceProvider]:
    """The registered providers (importable ones only are *usable*; see ``supports``)."""
    return list(_PROVIDERS)


def evidence_for(code: bytes, target: CodeTarget, provider: Optional[str] = None,
                 **context: Any) -> CodeEvidence:
    """Run the named provider, or the first that supports ``target.arch``."""
    for candidate in _PROVIDERS:
        if provider is not None and candidate.name != provider:
            continue
        if provider is not None or candidate.supports(target.arch):
            return candidate.field_accesses(code, target, **context)
    why = (f"no code-evidence provider named {provider!r}" if provider
           else f"no code-evidence provider supports architecture {target.arch!r}")
    return CodeEvidence(provider or "none", target, (),
                        {"bytes_given": len(code), "complete": False, "declined": why,
                         "stop_reason": why, "truncated": False}, (why,))


def support_for_fields(evidence: CodeEvidence, base: str,
                       offsets_sizes: Mapping[int, Optional[int]] | Iterable[Tuple[int, Optional[int]]]
                       ) -> Dict[int, List[FieldAccess]]:
    """For each proposed ``offset -> size``, the accesses through ``base`` that land in it.

    An access supports a field when its offset lies in ``[offset, offset+size)``
    (just ``offset`` when size is unknown). Every proposed offset is a key; an
    empty list means this function did not touch it.
    """
    pairs: Sequence[Tuple[int, Optional[int]]] = (
        list(offsets_sizes.items()) if isinstance(offsets_sizes, Mapping) else list(offsets_sizes))
    out: Dict[int, List[FieldAccess]] = {off: [] for off, _ in pairs}
    for acc in evidence.accesses:
        if acc.base != base:
            continue
        for off, size in pairs:
            if acc.offset == off or (size and off <= acc.offset < off + size):
                out[off].append(acc)
    return out
