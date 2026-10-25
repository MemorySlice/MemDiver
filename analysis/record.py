"""Analysis-record schema: one interpretation of a capture, versioned (plan T1.5, P1/D6/D9).

An :class:`AnalysisEntry` is anything concluded *about* a capture — a manual
annotation, a vol3 plugin row, a key hit, an ISF-draft entry, a structure
proposal, a table highlight rule, a fixture verdict. Entries are:

* **filed per capture** — ``capture_id`` is the capture's identity (a full
  image's sha256 or a ``.msl`` integrity hash); the record keeps one JSONL file
  per capture under ``<case_dir>/annotations/<capture_id>.jsonl``;
* **append-only** — nothing is edited or deleted. A correction is a new entry
  whose ``supersedes`` names the old one; withdrawing an entry is a
  :data:`RETRACTION` entry that supersedes it;
* **located** — every address is a :class:`~memdiver.core.location.Location`
  (P2), never a bare int;
* **supported and attributed** — ``support`` says what backs the claim,
  ``author`` says who made it (``human``, ``agent`` or ``tool:<name>``).

Never written into ``.msl`` capture-time blocks (memo §2). Stdlib only.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from memdiver.core.location import Location

#: Version of the on-disk line format; bump on any incompatible change.
SCHEMA_VERSION = 1

# Known entry kinds. ``kind`` is an open slug so producers can add their own,
# but these are the ones the plan's producers write.
ANNOTATION = "annotation"
PLUGIN_ROW = "plugin_row"
KEY_HIT = "key_hit"
ISF_DRAFT = "isf_draft"
STRUCTURE_PROPOSAL = "structure_proposal"
TABLE_RULE = "table_rule"
FIXTURE_VERDICT = "fixture_verdict"
#: Withdraws the entry it supersedes; never itself part of :meth:`latest` views.
RETRACTION = "retraction"

_SLUG = re.compile(r"^[a-z0-9][a-z0-9_.\-]{0,63}$")
_AUTHOR = re.compile(r"^(human|agent|tool:[A-Za-z0-9_.\-]{1,64})$")
_CAPTURE_ID = re.compile(r"^[A-Za-z0-9_.\-:]{1,128}$")


@dataclass(frozen=True)
class Support:
    """One piece of evidence behind an entry.

    ``kind`` is a slug naming the evidence type (e.g. ``vol3_run``, ``oracle``,
    ``pcap``, ``ground_truth``, ``entry``, ``observation``); ``ref`` points at
    it (a run id, an oracle name, another entry's id, a file path, ...).
    """

    kind: str
    ref: str

    def __post_init__(self) -> None:
        _require_slug("support kind", self.kind)
        if not isinstance(self.ref, str) or not self.ref:
            raise ValueError("support ref must be a non-empty string")

    def to_dict(self) -> Dict[str, str]:
        return {"kind": self.kind, "ref": self.ref}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Support":
        return cls(str(data["kind"]), str(data["ref"]))


@dataclass(frozen=True)
class AnalysisEntry:
    """One versioned interpretation of one capture."""

    capture_id: str
    kind: str
    author: str
    locations: Tuple[Location, ...] = ()
    length: Optional[int] = None
    label: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    support: Tuple[Support, ...] = ()
    supersedes: Optional[str] = None
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created: str = field(default_factory=lambda: utc_now())

    def __post_init__(self) -> None:
        if not _CAPTURE_ID.match(self.capture_id or ""):
            raise ValueError(f"invalid capture_id {self.capture_id!r}")
        _require_slug("kind", self.kind)
        if not _AUTHOR.match(self.author or ""):
            raise ValueError(f"author must be human, agent or tool:<name>, got {self.author!r}")
        if self.length is not None and self.length < 0:
            raise ValueError("length must be >= 0")
        if self.kind == RETRACTION and self.supersedes is None:
            raise ValueError("a retraction must name the entry it supersedes")
        if self.supersedes == self.id:
            raise ValueError("an entry cannot supersede itself")
        _require_json(self.payload)

    def to_dict(self) -> Dict[str, Any]:
        return {"v": SCHEMA_VERSION, "id": self.id, "capture_id": self.capture_id,
                "kind": self.kind, "author": self.author, "created": self.created,
                "supersedes": self.supersedes, "label": self.label,
                "locations": [loc.to_dict() for loc in self.locations],
                "length": self.length, "payload": self.payload,
                "support": [s.to_dict() for s in self.support]}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AnalysisEntry":
        if data.get("v") != SCHEMA_VERSION:
            raise ValueError(f"unsupported analysis-record version {data.get('v')!r}")
        return cls(
            capture_id=data["capture_id"], kind=data["kind"], author=data["author"],
            locations=tuple(Location.from_dict(d) for d in data.get("locations", ())),
            length=data.get("length"), label=data.get("label", ""),
            payload=dict(data.get("payload") or {}),
            support=tuple(Support.from_dict(d) for d in data.get("support", ())),
            supersedes=data.get("supersedes"), id=data["id"], created=data["created"])

    def to_json_line(self) -> str:
        """One JSONL line (no trailing newline), keys in a stable order."""
        return json.dumps(self.to_dict(), separators=(",", ":"), ensure_ascii=False)


def retraction_of(entry: AnalysisEntry, author: str, reason: str = "") -> AnalysisEntry:
    """The entry that withdraws ``entry`` (it stays in the log, flagged superseded)."""
    return AnalysisEntry(capture_id=entry.capture_id, kind=RETRACTION, author=author,
                         label=reason, supersedes=entry.id)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _require_slug(what: str, value: str) -> None:
    if not isinstance(value, str) or not _SLUG.match(value):
        raise ValueError(f"{what} must be a lowercase slug, got {value!r}")


def _require_json(payload: Dict[str, Any]) -> None:
    if not isinstance(payload, dict):
        raise TypeError("payload must be a dict")
    try:
        json.dumps(payload, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"payload is not JSON-serializable: {exc}") from exc
