"""Anchors from a TLS key log -- no per-dump hex typed by hand.

An NSS key log (``SSLKEYLOGFILE``, what friTap writes and Wireshark reads) is
ground truth for which secrets a capture's process held: lines of
``LABEL <client_random hex> <secret hex>``. This module turns one into the
inputs the object-model flow needs:

* :func:`parse_keylog_text` / :func:`parse_keylog_file` -- sessions (one per
  client_random), reusing the repository's line parser
  (:func:`memdiver.core.keylog.parse_keylog_line`). Accepted shapes: plain NSS
  lines, ``#`` comments, and the corpus ``keylog.csv`` form (a ``line`` /
  ``id,line`` header before the NSS lines). Wireshark's ``RSA`` and
  ``PMS_CLIENT_RANDOM`` lines are *ignored* (counted, never errors).
* :func:`resolve_keylog_anchors` -- per dump, which session belongs to it. A
  session's anchor secret is searched in the dump; the session whose secret is
  PRESENT is chosen. None present, or several present, leaves the dump
  unanchored with the reason spelled out -- the choice is never guessed.
  One shared key log for all dumps and one key log per dump both work: the
  caller just maps each dump to its session list.

Pure: no ``app`` imports. Sources must already be opened (see
:func:`memdiver.engine.anchor_consensus.search_needles`, which refuses an
unopened source rather than report "absent").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import (Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set,
                    Union)

from memdiver.core import keylog as _keylog
from memdiver.core.dump_search import present_needles
from memdiver.engine.anchor_consensus import _require_searchable, search_needles

#: Wireshark-only labels: a decryption aid, not a secret we can anchor on.
IGNORED_LABELS = frozenset({"RSA", "PMS_CLIENT_RANDOM"})
#: Standard NSS TLS 1.3 labels the protocol registry does not declare.
EXTRA_LABELS = frozenset({"EARLY_EXPORTER_SECRET", "CLIENT_EARLY_TRAFFIC_SECRET"})
#: Default anchor label; TLS 1.2 logs fall back to CLIENT_RANDOM (master secret).
PREFERRED_ANCHOR_LABEL = "CLIENT_TRAFFIC_SECRET_0"
TLS12_ANCHOR_LABEL = "CLIENT_RANDOM"
ANCHOR_FIELD = "anchor"
CLIENT_RANDOM_FIELD = "client_random"
#: Key-log text above this many bytes is refused by the app layer (upload cap).
MAX_KEYLOG_BYTES = 4 * 1024 * 1024
#: A key-log FILE (not inline text) may be this large.
MAX_KEYLOG_FILE_BYTES = 64 * 1024 * 1024
#: A needle shorter than this is never searched (it would match everywhere).
MIN_NEEDLE_BYTES = 16
CLIENT_RANDOM_BYTES = 32
TLS13_SECRET_BYTES = (32, 48)  # SHA-256 / SHA-384 hash length
TLS12_MASTER_SECRET_BYTES = 48
TLS13_LABELS = frozenset({
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0", "EXPORTER_SECRET",
    "EARLY_EXPORTER_SECRET", "CLIENT_EARLY_TRAFFIC_SECRET"})


@dataclass
class KeylogSession:
    """One TLS session: its client_random and every logged ``{label: secret}``."""

    client_random: bytes
    secrets: Dict[str, bytes] = field(default_factory=dict)


@dataclass
class KeylogParse:
    """Sessions in first-seen order plus an honest account of what was skipped."""

    sessions: List[KeylogSession] = field(default_factory=list)
    rows: int = 0
    ignored: Dict[str, int] = field(default_factory=dict)
    malformed: int = 0
    conflicts: int = 0  #: a label logged twice for one session with different secrets
    #: ``[{line, reason}]`` for every dropped malformed entry (1-based line numbers)
    malformed_details: List[Dict[str, Any]] = field(default_factory=list)
    #: sessions whose TLS 1.3 secrets do not share one hash length (kept, flagged)
    length_mismatches: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"sessions": len(self.sessions), "rows": self.rows,
                "ignored": dict(self.ignored), "malformed": self.malformed,
                "conflicts": self.conflicts,
                "malformed_details": [dict(d) for d in self.malformed_details],
                "length_mismatches": list(self.length_mismatches)}


def _length_problem(label: str, client_random: bytes, secret: bytes) -> Optional[str]:
    """Why a parsed entry is unusable (wrong lengths), or ``None`` when fine."""
    tls13 = (label in TLS13_LABELS or label.startswith("CLIENT_TRAFFIC_SECRET_")
             or label.startswith("SERVER_TRAFFIC_SECRET_"))
    # Custom (ground-truth / model) labels are not TLS: only TLS labels get TLS lengths.
    if (tls13 or label == TLS12_ANCHOR_LABEL) and len(client_random) != CLIENT_RANDOM_BYTES:
        return f"client_random is {len(client_random)} bytes, expected {CLIENT_RANDOM_BYTES}"
    if tls13:
        if len(secret) not in TLS13_SECRET_BYTES:
            return (f"{label} secret is {len(secret)} bytes, expected one of "
                    f"{list(TLS13_SECRET_BYTES)} (truncated line?)")
    elif label == TLS12_ANCHOR_LABEL and len(secret) != TLS12_MASTER_SECRET_BYTES:
        return (f"CLIENT_RANDOM master secret is {len(secret)} bytes, expected "
                f"{TLS12_MASTER_SECRET_BYTES} (truncated line?)")
    elif not secret:
        return "empty secret"
    return None


def field_name(label: str) -> str:
    """Field name a label's secret takes in a proposal (lower-case label).

    ``CLIENT_RANDOM`` carries the TLS 1.2 *master secret*, so it is named
    ``master_secret`` -- ``client_random`` is the session identifier field.
    """
    return "master_secret" if label == TLS12_ANCHOR_LABEL else label.lower()


def _normalise_row(raw: str) -> str:
    """Strip a CSV id column (``12,LABEL a b``) and quoting from one row."""
    line = raw.strip().strip('"')
    head, comma, tail = line.partition(",")
    if comma and " " not in head and tail.strip():
        return tail.strip().strip('"')
    return line


def _allowed_types(extra_labels: Iterable[str] = ()) -> SimpleNamespace:
    return SimpleNamespace(
        secret_types=set(_keylog.ALL_SECRET_TYPES) | EXTRA_LABELS | set(extra_labels))


def parse_keylog_text(text: str, extra_labels: Iterable[str] = ()) -> KeylogParse:
    """Parse NSS key-log text (or the corpus ``keylog.csv``) into sessions.

    *extra_labels* admits labels the registry does not know (a model's own
    ground-truth labels), so they are sessions' secrets, not malformed rows.
    """
    out = KeylogParse()
    allowed = _allowed_types(extra_labels)
    by_random: Dict[bytes, KeylogSession] = {}
    for lineno, raw in enumerate(text.lstrip("﻿").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#") or line.lower() in ("line", "id,line"):
            continue
        out.rows += 1
        row = _normalise_row(line)
        label = row.split(None, 1)[0] if row else ""
        if label in IGNORED_LABELS:
            out.ignored[label] = out.ignored.get(label, 0) + 1
            continue
        parsed = _keylog.parse_keylog_line(row, template=allowed)
        if parsed is None:
            out.malformed += 1
            out.malformed_details.append({"line": lineno, "reason": "not a valid key-log line"})
            continue
        problem = _length_problem(parsed.secret_type, parsed.identifier, parsed.secret_value)
        if problem:
            out.malformed += 1
            out.malformed_details.append({"line": lineno, "reason": problem})
            continue
        session = by_random.get(parsed.identifier)
        if session is None:
            session = by_random[parsed.identifier] = KeylogSession(parsed.identifier)
            out.sessions.append(session)
        known = session.secrets.get(parsed.secret_type)
        if known is None:
            session.secrets[parsed.secret_type] = parsed.secret_value
        elif known != parsed.secret_value:
            out.conflicts += 1
    for session in out.sessions:
        sizes = {len(v) for lb, v in session.secrets.items() if lb in TLS13_LABELS}
        if len(sizes) > 1:
            out.length_mismatches.append(session.client_random.hex())
    return out


def parse_keylog_file(path: Any, extra_labels: Iterable[str] = ()) -> KeylogParse:
    """:func:`parse_keylog_text` of a file (``FileNotFoundError`` if absent)."""
    from pathlib import Path

    return parse_keylog_text(
        Path(path).expanduser().read_text(encoding="utf-8-sig"), extra_labels)


def default_anchor_label(keylogs: Mapping[str, Sequence[KeylogSession]]) -> str:
    """``CLIENT_TRAFFIC_SECRET_0`` when any session logs it, else ``CLIENT_RANDOM``."""
    for sessions in keylogs.values():
        if any(PREFERRED_ANCHOR_LABEL in s.secrets for s in sessions):
            return PREFERRED_ANCHOR_LABEL
    return TLS12_ANCHOR_LABEL


@dataclass
class KeylogResolution:
    """Which key-log session a dump belongs to (or why none could be chosen)."""

    dump_path: str
    anchored: bool
    candidates: int = 0
    reason: str = ""
    client_random: Optional[bytes] = None
    needle: Optional[bytes] = None
    related: Dict[str, bytes] = field(default_factory=dict)
    labels: Dict[str, str] = field(default_factory=dict)  #: field name -> NSS label
    #: corroboration only: is the chosen session's client_random also in the dump?
    client_random_present: Optional[bool] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"dump_path": self.dump_path, "anchored": self.anchored,
                "client_random": None if self.client_random is None else self.client_random.hex(),
                "candidates": self.candidates, "reason": self.reason,
                "client_random_present": self.client_random_present,
                "labels": dict(self.labels)}


def _present(source: Any, path: str, secret: bytes,
             view: Union[str, Callable[[Any], str]]) -> bool:
    chosen_view = view(source) if callable(view) else view
    found = search_needles({path: source}, {path: secret}, view=chosen_view, max_hits=1)
    return bool(found[path].anchors)


def _present_set(source: Any, path: str, secrets: Sequence[bytes],
                 view: Union[str, Callable[[Any], str]]) -> Set[bytes]:
    """Which of *secrets* occur in the dump -- ONE pass, same answer as
    :func:`_present` per secret (which stays the fallback for sources the
    shared helper has no window strategy for)."""
    if not secrets:
        return set()
    chosen_view = view(source) if callable(view) else view
    _require_searchable(source, path, chosen_view)
    return present_needles(source, secrets, chosen_view,
                           lambda secret: _present(source, path, secret, chosen_view))


def _session_related(session: KeylogSession, anchor_label: str,
                     related_labels: Optional[Sequence[str]],
                     include_client_random: bool):
    wanted = [lb for lb in session.secrets if lb != anchor_label] \
        if related_labels is None else [lb for lb in related_labels if lb != anchor_label]
    related: Dict[str, bytes] = {}
    labels: Dict[str, str] = {ANCHOR_FIELD: anchor_label}
    if include_client_random:
        related[CLIENT_RANDOM_FIELD] = session.client_random
    for label in wanted:
        if label in session.secrets:
            related[field_name(label)] = session.secrets[label]
            labels[field_name(label)] = label
    return related, labels


def _resolve_one(path: str, source: Any, sessions: Sequence[KeylogSession], anchor_label: str,
                 related_labels: Optional[Sequence[str]], include_client_random: bool,
                 view: Union[str, Callable[[Any], str]]) -> KeylogResolution:
    candidates = [s for s in sessions if anchor_label in s.secrets
                  and len(s.secrets[anchor_label]) >= MIN_NEEDLE_BYTES]
    if not candidates:
        return KeylogResolution(path, False, 0,
                                f"no {anchor_label} secret in the key log (0 candidates searched)")
    found = _present_set(source, path, [s.secrets[anchor_label] for s in candidates], view)
    present = [s for s in candidates if s.secrets[anchor_label] in found]
    if not present:
        return KeylogResolution(path, False, len(candidates),
                                f"no {anchor_label} secret from the key log occurs in this dump "
                                f"({len(candidates)} candidates searched)")
    if len(present) > 1:
        return KeylogResolution(path, False, len(candidates),
                                f"ambiguous: {len(present)} key-log sessions occur in this dump")
    chosen = present[0]
    related, labels = _session_related(chosen, anchor_label, related_labels,
                                       include_client_random)
    cr_present = (len(chosen.client_random) >= MIN_NEEDLE_BYTES
                  and _present(source, path, chosen.client_random, view))
    return KeylogResolution(path, True, len(candidates),
                            f"session {chosen.client_random.hex()[:16]}... is the only one present",
                            chosen.client_random, chosen.secrets[anchor_label], related, labels,
                            cr_present)


def resolve_keylog_anchors(
    sources: Mapping[str, Any],
    keylogs: Mapping[str, Sequence[KeylogSession]],
    *,
    anchor_label: Optional[str] = None,
    related_labels: Optional[Sequence[str]] = None,
    include_client_random: bool = True,
    view: Union[str, Callable[[Any], str]] = "va",
) -> Dict[str, KeylogResolution]:
    """Resolve, per dump, the key-log session whose anchor secret it contains.

    *sources* maps dump path to an OPENED source; *keylogs* maps the same paths
    to their candidate sessions (share one list across dumps for one shared key
    log). *anchor_label* defaults to :func:`default_anchor_label`;
    *related_labels* ``None`` means every other label of the chosen session,
    ``()`` none. *view* is a view name or a ``source -> view`` callable.
    """
    label = anchor_label or default_anchor_label(keylogs)
    return {path: _resolve_one(path, source, keylogs.get(path, ()), label, related_labels,
                               include_client_random, view)
            for path, source in sources.items()}


def _meaning_for(label: str) -> str:
    prefix = "ssh" if label.startswith("SSH") else "tls"
    return f"{prefix}.{field_name(label)}"


def suggest_meanings(resolutions: Iterable[KeylogResolution]) -> List[Dict[str, str]]:
    """``[{field, meaning, label}]`` for the anchor, each related secret and the
    client_random (which carries no label), in first-seen order."""
    seen: Dict[str, Dict[str, str]] = {}
    has_random = False
    for res in resolutions:
        if not res.anchored:
            continue
        has_random = has_random or CLIENT_RANDOM_FIELD in res.related
        for name, label in res.labels.items():
            seen.setdefault(name, {"field": name, "meaning": _meaning_for(label),
                                   "label": label})
    out = list(seen.values())
    if has_random:
        out.append({"field": CLIENT_RANDOM_FIELD, "meaning": "tls.client_random",
                    "label": ""})
    return out
