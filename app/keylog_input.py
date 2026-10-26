"""Key-log driven anchoring: the ``keylog`` input of the object-model producers.

A ``keylog`` spec is exactly one of::

    {"path": "<shared NSS key log>"}           # one SSLKEYLOGFILE for all dumps
    {"text": "<shared key log content>"}       # same, uploaded (capped, 4 MiB)
    {"per_dump": {"<dump path>": "<key log path>"}}   # one key log per dump

``anchor_label`` is the NSS label whose secret anchors each dump. Default:
``CLIENT_TRAFFIC_SECRET_0`` when the key log holds it (TLS 1.3), else
``CLIENT_RANDOM`` -- for a TLS 1.2 log that line's secret is the master secret.
``related_labels`` defaults to every other label of the chosen session; the
session's client_random is always added as the ``client_random`` field.

The pure resolution lives in :mod:`memdiver.engine.keylog_anchors`; this module
owns the app-layer concerns: input validation, size caps, file reading, and the
mutable :class:`KeylogAnchoring` the anchor pipeline fills in.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from memdiver.core.service_errors import (
    CapabilityError, ErrorCategory, FileNotFoundServiceError)
from memdiver.engine import keylog_anchors as ka

_MAX_KEYLOG_FILE_BYTES = ka.MAX_KEYLOG_FILE_BYTES
_SPEC_KEYS = ("path", "text", "per_dump")


def _invalid(message: str, code: str) -> CapabilityError:
    return CapabilityError(message, category=ErrorCategory.INVALID_INPUT, code=code)


def _read_text(path: Any) -> str:
    target = Path(str(path)).expanduser()
    if not target.is_file():
        raise FileNotFoundServiceError(f"File not found: {path}")
    if target.stat().st_size > _MAX_KEYLOG_FILE_BYTES:
        raise _invalid(f"key log {path} exceeds {_MAX_KEYLOG_FILE_BYTES} bytes",
                       "keylog.too_large")
    try:
        return target.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise _invalid(f"key log {path} is not UTF-8 text (binary file?): {exc.reason}",
                       "keylog.not_text") from exc


def read_keylog_file(path: Any) -> str:
    """Public: a key log FILE's text under the shared 64 MiB file limit."""
    return _read_text(path)


def _parse_text(text: str, extra_labels: Sequence[str] = (), *,
                from_file: bool = False) -> ka.KeylogParse:
    limit = ka.MAX_KEYLOG_FILE_BYTES if from_file else ka.MAX_KEYLOG_BYTES
    if len(text.encode("utf-8")) > limit:
        what = "key log file" if from_file else "inline key log text"
        raise _invalid(f"{what} exceeds its {limit}-byte limit "
                       f"(inline text: {ka.MAX_KEYLOG_BYTES}, file: {ka.MAX_KEYLOG_FILE_BYTES})",
                       "keylog.too_large")
    return ka.parse_keylog_text(text, extra_labels)


def _validated_spec(spec: Any) -> Mapping[str, Any]:
    if not isinstance(spec, Mapping):
        raise _invalid("keylog must be an object: {path} | {text} | {per_dump}", "keylog.spec")
    unknown = sorted(set(spec) - set(_SPEC_KEYS))
    given = [k for k in _SPEC_KEYS if spec.get(k) not in (None, "", {})]
    if unknown or len(given) != 1:
        raise _invalid(f"keylog needs exactly one of {list(_SPEC_KEYS)} "
                       f"(got {given}, unknown {unknown})", "keylog.spec")
    return spec


def _resolved(path: str) -> str:
    return str(Path(path).expanduser().resolve(strict=False))


def load_keylogs(spec: Any, dump_paths: Sequence[str], extra_labels: Sequence[str] = ()):
    """``(keylogs, summary)``: ``{dump_path: [sessions]}`` and a per-file parse report.

    ``extra_labels`` are non-registry labels to accept (held-out validation)."""
    spec = _validated_spec(spec)
    if "per_dump" in spec:
        if not isinstance(spec["per_dump"], Mapping):
            raise _invalid("keylog.per_dump must be an object {dump path: key log path}",
                           "keylog.spec")
        by_dump = {_resolved(str(k)): str(v) for k, v in spec["per_dump"].items()}
        parsed = {p: _parse_text(_read_text(by_dump[_resolved(p)]), extra_labels, from_file=True)
                  for p in dump_paths if _resolved(p) in by_dump}
        summary = [{"dump_path": p, "path": by_dump[_resolved(p)], **r.to_dict()}
                   for p, r in parsed.items()]
        return {p: r.sessions for p, r in parsed.items()}, summary
    if "path" in spec:
        shared = _parse_text(_read_text(spec["path"]), extra_labels, from_file=True)
        origin = {"path": str(spec["path"])}
    else:
        if not isinstance(spec["text"], str):
            raise _invalid("keylog.text must be a string", "keylog.spec")
        shared, origin = _parse_text(spec["text"], extra_labels), {"text": "<uploaded>"}
    return ({p: shared.sessions for p in dump_paths}, [{**origin, **shared.to_dict()}])


def merge_related(keylog_related: Mapping[str, Mapping[str, str]],
                  explicit: Optional[Mapping[str, Mapping[str, str]]]) -> Dict[str, Dict[str, str]]:
    """Auto-built related values merged with the caller's; explicit wins per dump."""
    merged = {name: dict(by_path) for name, by_path in keylog_related.items()}
    for name, by_path in (explicit or {}).items():
        merged.setdefault(str(name), {}).update(by_path)
    return merged


@dataclass
class KeylogAnchoring:
    """Inputs (spec/labels) in, resolution out; filled by the anchor pipeline."""

    spec: Any
    dump_paths: Sequence[str]
    anchor_label: Optional[str] = None
    related_labels: Optional[Sequence[str]] = None
    resolutions: Dict[str, ka.KeylogResolution] = field(default_factory=dict)
    summary: List[Dict[str, Any]] = field(default_factory=list)
    resolved_label: str = ""

    def resolve(self, sources: Mapping[str, Any], view_of) -> None:
        keylogs, self.summary = load_keylogs(self.spec, list(self.dump_paths))
        self.resolved_label = self.anchor_label or ka.default_anchor_label(keylogs)
        self.resolutions = ka.resolve_keylog_anchors(
            sources, keylogs, anchor_label=self.resolved_label,
            related_labels=self.related_labels, view=view_of)
        for path in self.dump_paths:
            self.resolutions.setdefault(path, ka.KeylogResolution(
                path, False, 0, "no key log was given for this dump"))

    @property
    def needles(self) -> Dict[str, str]:
        return {p: r.needle.hex() for p, r in self.resolutions.items() if r.anchored}

    @property
    def related(self) -> Dict[str, Dict[str, str]]:
        out: Dict[str, Dict[str, str]] = {}
        for path, res in self.resolutions.items():
            for name, value in res.related.items():
                out.setdefault(name, {})[path] = value.hex()
        return out

    @property
    def unanchored(self) -> List[Dict[str, Any]]:
        return [{"dump_path": p, "occurrences": 0, "reason": r.reason}
                for p, r in self.resolutions.items() if not r.anchored]

    def payload(self) -> Dict[str, Any]:
        return {
            "keylog_resolution": [r.to_dict() for r in self.resolutions.values()],
            "keylog_anchor_label": self.resolved_label,
            "keylog_summary": self.summary,
            "suggested_meanings": ka.suggest_meanings(self.resolutions.values()),
        }
