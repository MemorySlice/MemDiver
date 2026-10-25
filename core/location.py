"""Addresses that carry their coordinate system, and reads that carry coverage.

Two rules of the semantic workbench (``docs/dev/semantic_workbench_plan.md``)
live here:

* **P2 — every address carries its coordinate system.** A bare ``int`` says
  nothing about whether it is a physical offset, a kernel VA, a VA inside one
  process, an offset inside a ``.msl`` file, ... A :class:`Location` says which
  :class:`AddressSpace` it belongs to and carries the qualifiers that space
  needs (``pid`` for a process VA, ``module`` for a module-relative offset, ...).
* **P3 — every read returns coverage.** A :class:`Coverage` states how many of
  the requested bytes were captured and, for every byte that was not, *why*
  (:class:`GapReason`). A failed page never silently becomes zeros:
  :meth:`ReadResult.to_dict` emits only captured segments, so filler bytes
  never cross a transport boundary.

Only NEW producers use these types; existing integer offsets stay as they are.
Stdlib only and picklable (frozen dataclasses + enums), like
:mod:`memdiver.core.service_result`. ``to_dict()`` key order is hand-written
and stable; :func:`dataclasses.asdict` is intentionally avoided.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, Iterator, Optional, Tuple


class AddressSpace(Enum):
    """The coordinate system a :class:`Location` value is expressed in."""

    PHYSICAL = "physical"          # offset in a physical address space (image)
    KERNEL_VA = "kernel_va"        # kernel virtual address (image + profile)
    PROCESS_VA = "process_va"      # VA inside one process (image + pid)
    MSL_VA = "msl_va"              # VA inside a .msl capture
    MSL_VAS = "msl_vas"            # offset in a .msl capture's packed VAS view
    MODULE_REL = "module_rel"      # offset relative to a module's base
    OBJECT_FIELD = "object_field"  # offset of a field inside one object
    FILE_OFFSET = "file_offset"    # byte offset inside the file on disk


# Qualifier each space cannot be interpreted without.
_REQUIRED_QUALIFIER: Dict[AddressSpace, str] = {
    AddressSpace.PROCESS_VA: "pid",
    AddressSpace.MODULE_REL: "module",
    AddressSpace.OBJECT_FIELD: "object_id",
}


@dataclass(frozen=True)
class Location:
    """An address together with the coordinate system it lives in.

    ``capture_id`` names the capture that owns the address space (an image's
    sha256 or a ``.msl`` integrity hash). It may be ``None`` only where the
    enclosing request is already scoped to one capture. ``view`` optionally
    names the interpretation (a ``.mdview`` descriptor, a profile hash).
    """

    space: AddressSpace
    value: int
    capture_id: Optional[str] = None
    pid: Optional[int] = None
    module: Optional[str] = None
    object_id: Optional[str] = None
    view: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.space, AddressSpace):
            raise TypeError(f"space must be an AddressSpace, got {self.space!r}")
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            raise TypeError(f"value must be an int, got {self.value!r}")
        if self.value < 0:
            raise ValueError(f"value must be >= 0, got {self.value}")
        required = _REQUIRED_QUALIFIER.get(self.space)
        if required is not None and getattr(self, required) is None:
            raise ValueError(f"a {self.space.value} Location requires '{required}'")

    def shifted(self, delta: int) -> "Location":
        """The same coordinate system, ``delta`` bytes further on."""
        return _replace_value(self, self.value + delta)

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"space": self.space.value, "value": self.value}
        for name in ("capture_id", "pid", "module", "object_id", "view"):
            if getattr(self, name) is not None:
                out[name] = getattr(self, name)
        return out

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Location":
        return cls(
            space=AddressSpace(data["space"]),
            value=int(data["value"]),
            capture_id=data.get("capture_id"),
            pid=data.get("pid"),
            module=data.get("module"),
            object_id=data.get("object_id"),
            view=data.get("view"),
        )


def _replace_value(loc: Location, value: int) -> Location:
    return Location(loc.space, value, loc.capture_id, loc.pid, loc.module,
                    loc.object_id, loc.view)


class GapReason(Enum):
    """Why bytes inside a requested range are not available.

    Mirrors the page-state model: ``FAILED`` = mapped but unreadable,
    ``NOT_RESIDENT`` = mapped but never backed (no translation / swapped),
    ``UNMAPPED`` = not mapped at all, ``NOT_CAPTURED`` = outside what the
    capture stored (e.g. a region excluded from a ``.msl``).
    """

    FAILED = "failed"
    NOT_RESIDENT = "not_resident"
    UNMAPPED = "unmapped"
    NOT_CAPTURED = "not_captured"


@dataclass(frozen=True)
class CoverageGap:
    """``length`` unavailable bytes starting at absolute offset ``start``."""

    start: int
    length: int
    reason: GapReason

    @property
    def end(self) -> int:
        return self.start + self.length

    def to_dict(self) -> Dict[str, Any]:
        return {"start": self.start, "length": self.length, "reason": self.reason.value}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CoverageGap":
        return cls(int(data["start"]), int(data["length"]), GapReason(data["reason"]))


@dataclass(frozen=True)
class Coverage:
    """How much of ``[start, start + requested)`` was captured, and why not the rest.

    Invariant (checked): gaps are sorted, non-empty, non-overlapping, inside the
    requested range, and ``captured == requested - sum(gap lengths)``. Build one
    with :meth:`from_gaps`, which sorts and merges adjacent same-reason gaps.
    """

    start: int
    requested: int
    captured: int
    gaps: Tuple[CoverageGap, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.start < 0 or self.requested < 0:
            raise ValueError("start and requested must be >= 0")
        _check_gaps(self.start, self.requested, self.gaps)
        missing = sum(g.length for g in self.gaps)
        if self.captured != self.requested - missing:
            raise ValueError(
                f"captured={self.captured} but requested={self.requested} "
                f"minus {missing} gap bytes = {self.requested - missing}")

    @classmethod
    def full(cls, start: int, requested: int) -> "Coverage":
        return cls(start, requested, requested)

    @classmethod
    def from_gaps(cls, start: int, requested: int,
                  gaps: Iterable[CoverageGap]) -> "Coverage":
        merged = _merge_gaps(g for g in gaps if g.length > 0)
        return cls(start, requested, requested - sum(g.length for g in merged), merged)

    @property
    def complete(self) -> bool:
        return self.captured == self.requested

    @property
    def failed_ranges(self) -> Tuple[Tuple[int, int], ...]:
        """``(start, length)`` of every gap, whatever its reason."""
        return tuple((g.start, g.length) for g in self.gaps)

    def captured_ranges(self) -> Iterator[Tuple[int, int]]:
        """``(start, length)`` of every captured stretch, in order."""
        cursor, end = self.start, self.start + self.requested
        for gap in self.gaps:
            if gap.start > cursor:
                yield cursor, gap.start - cursor
            cursor = gap.end
        if end > cursor:
            yield cursor, end - cursor

    def to_dict(self) -> Dict[str, Any]:
        return {"start": self.start, "requested": self.requested,
                "captured": self.captured, "gaps": [g.to_dict() for g in self.gaps]}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Coverage":
        gaps = tuple(CoverageGap.from_dict(g) for g in data.get("gaps", ()))
        return cls(int(data["start"]), int(data["requested"]), int(data["captured"]), gaps)


def _check_gaps(start: int, requested: int, gaps: Tuple[CoverageGap, ...]) -> None:
    cursor, end = start, start + requested
    for gap in gaps:
        if gap.length <= 0:
            raise ValueError(f"gap at {gap.start:#x} has non-positive length")
        if gap.start < cursor or gap.end > end:
            raise ValueError(f"gap [{gap.start:#x}, {gap.end:#x}) is unsorted, "
                             f"overlapping or outside [{start:#x}, {end:#x})")
        cursor = gap.end


def _merge_gaps(gaps: Iterable[CoverageGap]) -> Tuple[CoverageGap, ...]:
    merged: list = []
    for gap in sorted(gaps, key=lambda g: g.start):
        last = merged[-1] if merged else None
        if last is not None and last.reason is gap.reason and last.end == gap.start:
            merged[-1] = CoverageGap(last.start, last.length + gap.length, gap.reason)
        else:
            merged.append(gap)
    return tuple(merged)


@dataclass(frozen=True)
class ReadResult:
    """Bytes read at ``location`` plus the :class:`Coverage` of that read.

    ``data`` is ``coverage.requested`` bytes long so callers can index it, but
    bytes inside a gap are FILLER, not memory. Use :meth:`segments` to get only
    real bytes; :meth:`to_dict` serializes only those, never the filler.
    """

    location: Location
    data: bytes
    coverage: Coverage

    def __post_init__(self) -> None:
        if len(self.data) != self.coverage.requested:
            raise ValueError(f"data is {len(self.data)} bytes, coverage requested "
                             f"{self.coverage.requested}")
        if self.location.value != self.coverage.start:
            raise ValueError("location.value must equal coverage.start")

    def segments(self) -> Iterator[Tuple[int, bytes]]:
        """``(absolute offset, bytes)`` for every captured stretch."""
        base = self.coverage.start
        for start, length in self.coverage.captured_ranges():
            yield start, self.data[start - base:start - base + length]

    def to_dict(self) -> Dict[str, Any]:
        return {"location": self.location.to_dict(),
                "coverage": self.coverage.to_dict(),
                "segments": [{"start": s, "hex": b.hex()} for s, b in self.segments()]}

    @classmethod
    def from_dict(cls, data: Dict[str, Any], filler: int = 0) -> "ReadResult":
        """Rebuild a result; gap bytes become ``filler`` (still marked by coverage)."""
        coverage = Coverage.from_dict(data["coverage"])
        buf = bytearray([filler]) * coverage.requested
        for seg in data["segments"]:
            chunk = bytes.fromhex(seg["hex"])
            offset = int(seg["start"]) - coverage.start
            buf[offset:offset + len(chunk)] = chunk
        return cls(Location.from_dict(data["location"]), bytes(buf), coverage)
