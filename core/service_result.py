"""Neutral, picklable result envelope for MemDiver services.

This module is a companion to :mod:`memdiver.core.service_errors`: where that
module models the *error* path with a single transport-agnostic exception, this
module models the *success* path with a single transport-agnostic value type.

Design constraints (mirrored from ``service_errors``):

* **Stdlib + pure enum only.** The single non-stdlib import is the pure
  :class:`~memdiver.msl.enums.TagStatus` value enum. Nothing here imports
  ``fastapi``, ``mcp``, or the analysis ``engine`` — every layer (library,
  CLI, FastAPI route, MCP tool) can build and read these envelopes without
  dragging in an optional transport dependency.
* **Picklable.** Every type here is a frozen dataclass or a plain ``Enum`` with
  no closures, locks, or open handles, so a populated :class:`ServiceResult`
  survives a ``pickle`` round-trip and can therefore cross a ``ProcessPool``
  boundary.
* **Explicit resolution instead of ``None``/empty-as-signal.** A caller no
  longer has to guess whether an empty payload means "nothing found" or "could
  not compute": :class:`Resolution` says so, and any known blocker is attached
  as a :class:`Diagnostic` (or as the :class:`KeyStatus` for the common
  encrypted-dump case).

``to_dict()`` methods emit keys in a fixed, hand-written order so downstream
serialization is stable; :func:`dataclasses.asdict` is intentionally avoided.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Generic, Optional, Tuple, TypeVar

from memdiver.msl.enums import TagStatus

P = TypeVar("P")


class Severity(Enum):
    """Severity of a :class:`Diagnostic` attached to a result."""

    INFO = "info"
    WARNING = "warning"


class Resolution(Enum):
    """How completely the payload could be produced.

    * ``OK`` — payload is complete and trustworthy.
    * ``PARTIAL`` — payload is present but incomplete (some work was skipped).
    * ``UNRESOLVED`` — payload is empty because of a known blocker (e.g. an
      encrypted dump opened without a key). Replaces the old ``None``/empty
      list "signal" convention.
    """

    OK = "ok"
    PARTIAL = "partial"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class Diagnostic:
    """A single structured note explaining or qualifying a result."""

    code: str
    message: str
    severity: Severity = Severity.WARNING
    details: dict = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "severity": self.severity.value,
            "details": self.details,
        }


@dataclass(frozen=True)
class KeyStatus:
    """Decryption / key state for the dump behind a result.

    Built from any reader or dump source exposing a ``tag_status`` attribute.
    The two hint strings are deliberately NEUTRAL and surface-agnostic — they
    name no transport-specific remedy (no CLI flag names, no MCP parameter
    names). Each surface presenter appends its own actionable guidance (the CLI
    its decryption flags, the MCP server its tool parameters) so the wording can
    be tailored/i18n'd per transport without CLI presentation text ever leaking
    back into core.
    """

    tag_status: TagStatus = TagStatus.NOT_ENCRYPTED
    decrypted: bool = True
    hint: Optional[str] = None

    @classmethod
    def from_source(cls, reader_or_source: Any) -> "KeyStatus":
        status = getattr(reader_or_source, "tag_status", TagStatus.NOT_ENCRYPTED)
        if status == TagStatus.MISSING_KEY:
            return cls(
                status,
                decrypted=False,
                hint="dump is encrypted; no valid decryption key was supplied",
            )
        if status == TagStatus.CORRUPTED:
            return cls(
                status,
                decrypted=False,
                hint="AEAD verification failed (wrong key or tampered file)",
            )
        return cls(status, decrypted=True)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tag_status": self.tag_status.value,
            "decrypted": self.decrypted,
            "hint": self.hint,
        }

    def locked_error_dict(self) -> Dict[str, Any]:
        """Legacy 'encrypted-and-locked' diagnostic dict surfaced inline by the
        CLI/MCP inspect presenters (and the deprecated ``_tag_status_error``).
        Only meaningful when :attr:`decrypted` is ``False``.
        """
        return {"error": self.hint, "tag_status": self.tag_status.value}


@dataclass(frozen=True)
class StatusBlock:
    """The complete non-payload status attached to a :class:`ServiceResult`."""

    resolution: Resolution = Resolution.OK
    key: KeyStatus = field(default_factory=KeyStatus)
    diagnostics: Tuple[Diagnostic, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resolution": self.resolution.value,
            "key": self.key.to_dict(),
            "diagnostics": [d.to_dict() for d in self.diagnostics],
        }


@dataclass(frozen=True)
class ServiceResult(Generic[P]):
    """A payload plus its neutral, picklable status envelope."""

    payload: P
    status: StatusBlock = field(default_factory=StatusBlock)

    @classmethod
    def ok(cls, payload: P) -> "ServiceResult[P]":
        """Wrap ``payload`` with a default (OK / decrypted) status block."""
        return cls(payload, StatusBlock())

    def with_key(self, key: KeyStatus) -> "ServiceResult[P]":
        """Return a copy carrying ``key``, downgrading resolution if undecrypted.

        Existing diagnostics are preserved. Resolution becomes
        :attr:`Resolution.UNRESOLVED` when the key is not decrypted; otherwise
        the current resolution is kept.
        """
        resolution = Resolution.UNRESOLVED if not key.decrypted else self.status.resolution
        return ServiceResult(
            self.payload,
            StatusBlock(
                resolution=resolution,
                key=key,
                diagnostics=self.status.diagnostics,
            ),
        )
