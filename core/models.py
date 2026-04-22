"""Data structures for memory dump analysis."""

from __future__ import annotations

import functools
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

if TYPE_CHECKING:
    # Late import to avoid a cycle: dataset_metadata is a leaf module but
    # keeping the import behind TYPE_CHECKING makes the dependency edge
    # visible without forcing it at runtime.
    from .dataset_metadata import DatasetMeta


def deprecated_kwarg(cls, old_name: str, new_name: str):
    """Patch a dataclass __init__ to accept a deprecated kwarg name.

    When callers pass *old_name* as a keyword argument, it is silently
    mapped to *new_name* (unless *new_name* is also provided).
    """
    orig_init = cls.__init__

    @functools.wraps(orig_init)
    def wrapper(self, *args, **kwargs):
        if old_name in kwargs and new_name not in kwargs:
            kwargs[new_name] = kwargs.pop(old_name)
        orig_init(self, *args, **kwargs)

    cls.__init__ = wrapper


@dataclass
class CryptoSecret:
    """A parsed cryptographic secret from a keylog file."""
    secret_type: str
    identifier: bytes
    secret_value: bytes
    protocol: str = "TLS"

    @property
    def client_random(self) -> bytes:
        """Backward-compatible alias for identifier."""
        return self.identifier

    @client_random.setter
    def client_random(self, value: bytes) -> None:
        self.identifier = value

    def __hash__(self):
        return hash((self.secret_type, self.secret_value))

    def __eq__(self, other):
        if not isinstance(other, CryptoSecret):
            return NotImplemented
        return self.secret_type == other.secret_type and self.secret_value == other.secret_value


deprecated_kwarg(CryptoSecret, "client_random", "identifier")

# Backward-compatible alias
TLSSecret = CryptoSecret


@dataclass
class KeyOccurrence:
    """A found key occurrence in a dump file."""
    offset: int
    secret: CryptoSecret
    context_before: bytes
    key_bytes: bytes
    context_after: bytes

    @property
    def context_start_offset(self) -> int:
        return self.offset - len(self.context_before)


@dataclass
class DumpFile:
    """Metadata for a single dump file.

    ``kind`` tags the dump flavour so downstream code (discovery, API
    responses, UI) can branch without re-sniffing magic bytes. Valid
    values: ``"msl"``, ``"gdb_raw"``, ``"lldb_raw"``, ``"gcore"``,
    ``"raw"``.
    """
    path: Path
    timestamp: str
    phase_prefix: str
    phase_name: str
    canonical_phase: Optional[str] = None
    kind: str = "raw"

    @property
    def full_phase(self) -> str:
        return f"{self.phase_prefix}_{self.phase_name}"

    @property
    def canonical_or_raw(self) -> str:
        return self.canonical_phase if self.canonical_phase else self.full_phase


@dataclass
class RunDirectory:
    """A single run directory containing dumps and keylog.

    ``meta`` is populated from ``meta.json`` when present (see
    :func:`core.dataset_metadata.load_run_meta`). Legacy runs without a
    ``meta.json`` leave it ``None`` — discovery code must tolerate both.
    """
    path: Path
    library: str
    protocol_version: str
    run_number: int
    dumps: List[DumpFile] = field(default_factory=list)
    secrets: List[CryptoSecret] = field(default_factory=list)
    secret_source: str = "none"
    phase_mappings: Dict[str, str] = field(default_factory=dict)
    meta: Optional["DatasetMeta"] = None

    @property
    def tls_version(self) -> str:
        """Backward-compatible alias for protocol_version."""
        return self.protocol_version

    @tls_version.setter
    def tls_version(self, value: str) -> None:
        self.protocol_version = value

    def get_dump_for_phase(self, phase: str) -> Optional[DumpFile]:
        for d in self.dumps:
            if d.full_phase == phase:
                return d
        return None

    def available_phases(self) -> List[str]:
        return sorted(set(d.full_phase for d in self.dumps))


deprecated_kwarg(RunDirectory, "tls_version", "protocol_version")


@dataclass
class ComparisonRegion:
    """Aligned regions across dumps for multi-run comparison."""
    secret_type: str
    key_length: int
    context_size: int
    run_data: List[Tuple[bytes, bytes, bytes]] = field(default_factory=list)
    run_labels: List[str] = field(default_factory=list)
    run_offsets: List[int] = field(default_factory=list)
