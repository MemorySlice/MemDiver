"""Semantic producers: layout proposal and artifact-model build (``semantic.*``).

Productizes the learn-from-N-captures flow: anchor each capture on a verified
value (needle or explicit anchor), build the anchor-relative consensus, propose
field boundaries (``engine.layout_proposal``) and, on request, assemble a
validated artifact model (``engine.artifact_builder``) written to a NEW
``.json`` file.

* :func:`propose_layout_result` -- the proposal, plus (with ``case_dir``) one
  ``structure_proposal`` analysis-record entry per capture.
* :func:`artifact_model_build_result` -- the proposal plus the caller's
  meanings / relationships / applicability, built into a model that passes
  ``ArtifactModel.check()`` or is refused with ``INVALID_INPUT``.

Anchor resolution is shared with ``consensus.anchor``
(``tools_consensus._anchored_sources``): the same needles/anchors, occurrence
pick and cohort guard, so the two can never disagree about which instances
correspond.
"""

from __future__ import annotations

import hashlib
import logging
import re
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.core.service_result import Resolution, ServiceResult, StatusBlock

from .session import ToolSession

logger = logging.getLogger("memdiver.app.tools_semantic")

DEFAULT_AUTHOR = "tool:propose_layout"
_MODEL_SUFFIX = ".json"
_APPLICABILITY_KEYS = ("library", "library_version", "arch", "os", "states", "cohorts")


def _invalid(message: str, code: str) -> CapabilityError:
    return CapabilityError(message, category=ErrorCategory.INVALID_INPUT, code=code)


@dataclass
class _Learned:
    """Everything one learn pass produced; sources are live only inside the stack."""

    cohort: Optional[str]
    chosen: List[Any]
    unanchored: List[Dict[str, Any]]
    alternatives: Dict[str, int]
    consensus: Any
    proposal: Any
    anchor_length: int
    occurrence: int
    keylog: Any = None  # the filled KeylogAnchoring when anchored from a key log


# -- input resolution -------------------------------------------------------------

def _restrict(items: Any, dump_paths: Optional[Sequence[str]]) -> Any:
    """Keep only the entries naming one of ``dump_paths`` (no-op when None)."""
    if dump_paths is None or items is None:
        return items
    wanted = {str(p) for p in dump_paths}
    if isinstance(items, dict):
        return {p: v for p, v in items.items() if str(p) in wanted}
    return [a for a in items if str(a.get("dump_path", "")) in wanted]


def _resolve_anchor_length(anchor_length: Optional[int],
                           needles: Optional[Dict[str, str]]) -> int:
    """The anchor's byte length: explicit, else the (single) needle length."""
    if anchor_length is not None:
        if int(anchor_length) <= 0:
            raise _invalid("anchor_length must be >= 1", "semantic.anchor_length")
        return int(anchor_length)
    if not needles:
        raise _invalid("anchor_length is required when anchoring with explicit anchors",
                       "semantic.anchor_length")
    lengths = {len(h) // 2 for h in needles.values()}
    if len(lengths) != 1:
        raise _invalid(f"needles differ in length {sorted(lengths)}; pass anchor_length",
                       "semantic.anchor_length")
    return lengths.pop()


def _related_needles(related: Optional[Mapping[str, Mapping[str, str]]],
                     chosen: Sequence[Any]) -> Dict[str, List[Optional[bytes]]]:
    """``{name: {dump_path: hex}}`` -> per-instance bytes, in instance order."""
    out: Dict[str, List[Optional[bytes]]] = {}
    for name, by_path in (related or {}).items():
        try:
            parsed = {str(p): bytes.fromhex(h) for p, h in by_path.items()}
        except (ValueError, AttributeError) as exc:
            raise _invalid(f"related {name!r} is not {{dump_path: hex}}: {exc}",
                           "semantic.related") from exc
        out[str(name)] = [parsed.get(a.dump_path) for a in chosen]
    return out


def _no_va_view_message(dump_path: str, source: Any) -> str:
    """Actionable ``semantic.no_va_view`` text: names the dump + detected format
    and the exact ``memdiver import`` command that gives it a VA view."""
    from memdiver.core.dump_source import RawDumpSource

    kind = type(source).__name__
    is_flat_raw = isinstance(source, RawDumpSource) and "regioned" not in kind.lower()
    head = (f"{dump_path}: no VA view (detected format: {kind}); layout learning "
            "needs captured virtual-address runs, so ")
    if is_flat_raw:
        return (head + f"import it to .msl first: `memdiver import {dump_path} "
                "--maps <proc maps file> -o <out>.msl` (a /proc/<pid>/maps-style "
                "file gives it real virtual addresses; without maps the import keeps "
                "no VA map, so pointer and heap-chunk evidence stay unavailable - "
                "anchor consensus still works)")
    return (head + f"import it to .msl with `memdiver import {dump_path}` "
            "(its VA map is preserved)")


def _require_va_views(sources: Mapping[str, Any], chosen: Sequence[Any]) -> None:
    """Refuse a source with no VA view (raw dumps, regioned/gcore sources).

    Layout learning needs the captured VA runs (``captured_runs``), which only
    sources exposing a VA view provide; the others are refused rather than
    emulated, with the same code ``model-validate`` uses."""
    for anchor in chosen:
        source = sources[anchor.dump_path]
        span = getattr(source, "va_span_start", None)
        if not callable(span) or span() is None or not callable(
                getattr(source, "captured_runs", None)):
            raise CapabilityError(
                _no_va_view_message(anchor.dump_path, source),
                category=ErrorCategory.PRECONDITION, code="semantic.no_va_view")


def _runs_provider(sources: Mapping[str, Any], chosen: Sequence[Any]):
    def runs_of(i: int) -> List[Tuple[int, int]]:
        source = sources[chosen[i].dump_path]
        return [(va, n) for va, n, _ in source.captured_runs()]
    return runs_of


def _chunk_provider(sources: Mapping[str, Any], chosen: Sequence[Any]):
    from memdiver.heap.analyze import analyze_heap

    layouts: Dict[int, Any] = {}

    def chunk_of(i: int, va: int) -> Optional[Tuple[int, int]]:
        if i not in layouts:
            try:
                layouts[i] = analyze_heap(sources[chosen[i].dump_path])
            except Exception:  # heap parse is best effort; bounds stay unproposed
                layouts[i] = None
        chunk = None if layouts[i] is None else layouts[i].chunk_at(va)
        return None if chunk is None else (chunk.user_va, chunk.user_len)
    return chunk_of


def _learn(stack: ExitStack, *, dump_paths, needles, anchors, occurrence, delta_start,
           length, anchor_length, related, pointer_quorum, heap, mixed_ok,
           keylog=None, anchor_label=None, related_labels=None) -> _Learned:
    from memdiver.app.keylog_input import merge_related
    from memdiver.app.tools_consensus import _anchored_sources, _keylog_anchoring
    from memdiver.engine.anchor_consensus import MAX_WINDOW, anchor_consensus, read_instance
    from memdiver.engine.layout_proposal import propose_layout

    if not 0 < int(length) <= MAX_WINDOW:
        raise CapabilityError(f"length must be in [1, {MAX_WINDOW}], got {length}")
    needles, anchors = _restrict(needles, dump_paths), _restrict(anchors, dump_paths)
    anchoring = _keylog_anchoring(keylog, dump_paths, anchor_label, related_labels)
    cohort, sources, chosen, unanchored, alternatives = _anchored_sources(
        stack, anchors, needles, int(occurrence), mixed_ok, anchoring)
    size = _resolve_anchor_length(
        anchor_length, needles if anchoring is None else anchoring.needles)
    if anchoring is not None:
        related = merge_related(anchoring.related, related)
    _require_va_views(sources, chosen)
    try:
        windows = [read_instance(sources[a.dump_path], a, int(delta_start), int(length))
                   for a in chosen]
        consensus = anchor_consensus(windows, delta_start=int(delta_start))
        proposal = propose_layout(
            consensus, anchor_length=size,
            related=_related_needles(related, chosen),
            captured_runs_of=_runs_provider(sources, chosen),
            chunk_of=_chunk_provider(sources, chosen) if heap else None,
            pointer_quorum=pointer_quorum)
    except ValueError as exc:
        raise _invalid(str(exc), "semantic.layout_window") from exc
    return _Learned(cohort, chosen, unanchored, alternatives, consensus, proposal,
                    size, int(occurrence), anchoring)


# -- payload + record -------------------------------------------------------------

def _structure_payload(learned: _Learned, name: str) -> Dict[str, Any]:
    from memdiver.architect.artifact_model import structure_to_dict

    return structure_to_dict(learned.proposal.to_structure(name))


def _proposal_payload(learned: _Learned, name: str) -> Dict[str, Any]:
    from memdiver.app.tools_consensus import _anchor_instance_rows
    from memdiver.engine.anchor_consensus import CLASS_NAMES

    cons = learned.consensus
    counts = {label: int((cons.classes == code).sum()) for code, label in CLASS_NAMES.items()}
    keylog_part = {} if learned.keylog is None else learned.keylog.payload()
    return {
        **keylog_part,
        **learned.proposal.to_dict(),
        "structure": _structure_payload(learned, name),
        "cohort": learned.cohort, "anchor_length": learned.anchor_length,
        "delta_start": cons.delta_start, "length": cons.length,
        "occurrence": learned.occurrence,
        "instances": _anchor_instance_rows(cons), "unanchored": learned.unanchored,
        "alternatives": learned.alternatives, "class_counts": counts,
        "warnings": list(cons.warnings),
    }


DETAIL_LEVELS = ("summary", "full")
_OMITTED_HINT = ('summary payload: the keys in "omitted" were dropped; '
                 'pass detail="full" for the complete result')
_FIELD_SCALARS = ("name", "kind", "delta", "length")


def _checked_detail(detail: Any) -> str:
    if detail not in DETAIL_LEVELS:
        raise _invalid(f"detail must be one of {list(DETAIL_LEVELS)}, got {detail!r}",
                       "semantic.detail")
    return detail


def _summary_marks(omitted: List[str]) -> Dict[str, Any]:
    return {"detail": "summary", "omitted": omitted, "omitted_hint": _OMITTED_HINT}


def _summarize_proposal(payload: Dict[str, Any]) -> Dict[str, Any]:
    """The proposal minus its bulk: ``structure``, ``alternatives`` (kept as a
    count) and each field's ``evidence`` / ``alternatives`` (kept as a count)."""
    out = {k: v for k, v in payload.items()
           if k not in ("structure", "alternatives", "fields")}
    out["alternatives_count"] = len(payload.get("alternatives") or {})
    out["fields"] = [
        {**{k: f[k] for k in _FIELD_SCALARS if k in f},
         "alternatives_count": len(f.get("alternatives") or ())}
        for f in payload.get("fields", ())]
    omitted = ["structure", "alternatives", "fields[].evidence", "fields[].alternatives"]
    return {**out, **_summary_marks(omitted)}


def _model_summary(model_dict: Dict[str, Any], proposal_dict: Dict[str, Any]) -> Dict[str, Any]:
    locator = model_dict.get("locator") or {}
    pattern = locator.get("pattern") or {}

    def window(p: Dict[str, Any]) -> Dict[str, Any]:
        return {k: p.get(k) for k in ("key_offset", "key_length", "length", "static_ratio")}

    return {
        "name": model_dict.get("name"),
        "field_count": len(proposal_dict.get("fields", ())),
        "total_size": (model_dict.get("layout") or {}).get("total_size"),
        "proposal_total_size": proposal_dict.get("total_size"),
        "base_delta": proposal_dict.get("base_delta"),
        "locator": {"kind": locator.get("kind"), "primary": window(pattern),
                    "alternatives": [window(a) for a in locator.get("alternatives") or ()]},
        "warnings": list(model_dict.get("warnings") or ()),
    }


def _summarize_build(payload: Dict[str, Any], proposal_dict: Dict[str, Any],
                     keylog_part: Dict[str, Any]) -> Dict[str, Any]:
    """Build result minus ``model`` / ``proposal`` (the model is already at ``path``)."""
    out = {k: v for k, v in payload.items() if k not in ("model", "proposal")}
    out["model_summary"] = _model_summary(payload["model"], proposal_dict)
    out.update(keylog_part)
    return {**out, **_summary_marks(["model", "proposal"])}


def _anchor_location(anchor: Any, capture: str):
    from memdiver.core.location import AddressSpace, Location

    if anchor.va is not None:
        return Location(AddressSpace.MSL_VA, int(anchor.va), capture_id=capture)
    return Location(AddressSpace.FILE_OFFSET, int(anchor.offset), capture_id=capture)


def _record_entries(case_dir: str, learned: _Learned, proposal_dict: Dict[str, Any],
                    author: str) -> List[str]:
    """One ``structure_proposal`` entry per capture; returns the entry ids."""
    from memdiver.analysis.capture_id import capture_id_for
    from memdiver.analysis.record import STRUCTURE_PROPOSAL, AnalysisEntry, Support
    from memdiver.analysis.record_store import AnalysisRecord
    from memdiver.app.tools_isf import _case_root

    record = AnalysisRecord(_case_root(case_dir, create=True))
    n = len(learned.chosen)
    payload = {k: proposal_dict[k] for k in (
        "base_delta", "total_size", "bounds_evidence", "warnings", "fields",
        "anchor_length", "delta_start", "length", "occurrence", "alternatives")}
    ids: List[str] = []
    for anchor in learned.chosen:
        capture = capture_id_for(anchor.dump_path)
        try:
            entry = AnalysisEntry(
                capture_id=capture, kind=STRUCTURE_PROPOSAL, author=author,
                locations=(_anchor_location(anchor, capture),),
                length=learned.anchor_length,
                label=f"proposed layout around anchor ({n} instances)",
                payload=payload,
                support=(Support("observation", f"anchor_consensus {n} instances"),
                         Support("observation", anchor.basis or "anchor")))
        except ValueError as exc:
            raise _invalid(str(exc), "semantic.record_entry") from exc
        ids.append(record.append(entry).id)
    return ids


def _result(payload: Dict[str, Any], learned: _Learned) -> ServiceResult:
    resolution = Resolution.PARTIAL if learned.unanchored else Resolution.OK
    return ServiceResult(payload=payload, status=StatusBlock(resolution=resolution))


# -- producers --------------------------------------------------------------------

def propose_layout_result(
    session: ToolSession,
    *,
    dump_paths: Optional[Sequence[str]] = None,
    needles: Optional[Dict[str, str]] = None,
    anchors: Optional[Sequence[Dict[str, Any]]] = None,
    occurrence: int = 0,
    delta_start: int = -2048,
    length: int = 6144,
    anchor_length: Optional[int] = None,
    related: Optional[Mapping[str, Mapping[str, str]]] = None,
    pointer_quorum: Optional[int] = None,
    heap: bool = True,
    mixed_ok: bool = False,
    case_dir: Optional[str] = None,
    author: str = DEFAULT_AUTHOR,
    keylog: Optional[Mapping[str, Any]] = None,
    anchor_label: Optional[str] = None,
    related_labels: Optional[Sequence[str]] = None,
    detail: str = "summary",
) -> ServiceResult:
    """Field-boundary hypotheses around a verified anchor, learned from N captures.

    ``detail="summary"`` (default) drops ``structure``, the top-level
    ``alternatives`` and each field's ``evidence``/``alternatives`` (counts
    are kept) and says so in ``omitted``; ``detail="full"`` is the complete
    payload.

    Exactly one of ``needles`` (``{dump_path: hex}``), ``anchors``
    (``[{dump_path, va|offset}]``) or ``keylog`` (``{path} | {text} |
    {per_dump}``, see :mod:`memdiver.app.keylog_input`), resolved exactly as
    ``consensus.anchor``. With ``keylog`` the anchor is ``anchor_label``'s
    secret, ``related`` is auto-built from the same session (explicit
    ``related`` merges over it), ``anchor_length`` is the secret length, and the
    result adds ``keylog_resolution`` + ``suggested_meanings``.
    ``anchor_length`` defaults to the needle length (required with anchors).
    ``related`` is ``{name: {dump_path: hex}}``: other verified values expected
    at one constant delta. ``heap`` proposes object bounds from the allocator
    chunk. With ``case_dir`` one ``structure_proposal`` entry per capture is
    appended (ids under ``record_entries``).
    """
    detail = _checked_detail(detail)
    with ExitStack() as stack:
        learned = _learn(
            stack, dump_paths=dump_paths, needles=needles, anchors=anchors,
            occurrence=occurrence, delta_start=delta_start, length=length,
            anchor_length=anchor_length, related=related,
            pointer_quorum=pointer_quorum, heap=heap, mixed_ok=mixed_ok,
            keylog=keylog, anchor_label=anchor_label, related_labels=related_labels)
    payload = _proposal_payload(learned, "proposed_layout")
    if case_dir:
        payload["record_entries"] = _record_entries(case_dir, learned, payload, author)
    if detail == "summary":
        payload = _summarize_proposal(payload)
    return _result(payload, learned)


def _checked_model_target(out_path: Optional[str]) -> Path:
    """A fresh ``*.json`` target outside any case record; never overwrites."""
    if not out_path or not str(out_path).strip():
        raise _invalid("out_path is required", "out_path_required")
    target = Path(out_path).expanduser()
    if not target.name.endswith(_MODEL_SUFFIX) or target.name == _MODEL_SUFFIX:
        raise _invalid(f"out_path must end in {_MODEL_SUFFIX}: {target}", "model_out_target")
    if "annotations" in target.resolve(strict=False).parts:
        raise _invalid("out_path must not lie inside a case's annotations/", "model_out_target")
    if target.exists() or target.is_symlink():
        raise _invalid(f"out_path already exists (models never overwrite): {target}",
                       "model_out_exists")
    return target


def _evidence(items: Any) -> tuple:
    from memdiver.architect.artifact_model import Evidence

    try:
        return tuple(Evidence(str(e["kind"]), str(e["ref"])) for e in items or ())
    except (KeyError, TypeError) as exc:
        raise _invalid(f"support items need 'kind' and 'ref': {exc!r}",
                       "semantic.meanings") from exc


def _field_meanings(meanings: Sequence[Mapping[str, Any]]) -> List[Any]:
    from memdiver.engine.artifact_builder import FieldMeaning

    try:
        return [FieldMeaning(str(m["field"]), str(m["meaning"]), str(m.get("label", "")),
                             _evidence(m.get("support"))) for m in meanings]
    except (KeyError, TypeError) as exc:
        raise _invalid(f"each meaning needs 'field' and 'meaning': {exc!r}",
                       "semantic.meanings") from exc


def _relationship_tuples(relationships: Sequence[Mapping[str, Any]]) -> List[Tuple[str, str, str]]:
    try:
        return [(str(r["kind"]), str(r["source"]), str(r["target"])) for r in relationships]
    except (KeyError, TypeError) as exc:
        raise _invalid(f"each relationship needs 'kind', 'source', 'target': {exc!r}",
                       "semantic.relationships") from exc


def _applicability(spec: Optional[Mapping[str, Any]]) -> Any:
    from memdiver.architect.artifact_model import Applicability

    spec = dict(spec or {})
    unknown = sorted(set(spec) - set(_APPLICABILITY_KEYS))
    if unknown:
        raise _invalid(f"unknown applicability keys {unknown}; allowed {list(_APPLICABILITY_KEYS)}",
                       "semantic.applicability")
    for key in ("states", "cohorts"):
        if key in spec:
            spec[key] = tuple(str(v) for v in spec[key])
    return Applicability(**{k: (v if isinstance(v, tuple) else str(v)) for k, v in spec.items()})


def _write_model(target: Path, text: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(target, "x", encoding="utf-8") as handle:
            handle.write(text)
    except FileExistsError as exc:
        raise _invalid(f"out_path already exists (models never overwrite): {target}",
                       "model_out_exists") from exc


def _keylog_defaults(learned: _Learned, name: str, meanings: List[Any],
                     relationships: List[Tuple[str, str, str]], have_meanings: bool,
                     have_relationships: bool) -> Tuple[List[Any], List[Tuple[str, str, str]]]:
    """Fill omitted meanings / relationships from the key log (no-op otherwise).

    Only fields the proposal really contains are used: a related secret that was
    not found at a constant delta is simply not asserted."""
    if learned.keylog is None:
        return meanings, relationships
    from memdiver.engine.artifact_builder import FieldMeaning
    from memdiver.engine.keylog_anchors import CLIENT_RANDOM_FIELD, suggest_meanings

    present = {f.name for f in learned.proposal.to_structure(name).fields}
    suggested = [m for m in suggest_meanings(learned.keylog.resolutions.values())
                 if m["field"] in present]
    if not have_meanings:
        meanings = [FieldMeaning(m["field"], m["meaning"], m["label"]) for m in suggested]
    if not have_relationships and CLIENT_RANDOM_FIELD in present:
        relationships = [("owned_by", m["field"], CLIENT_RANDOM_FIELD) for m in suggested
                         if m["label"]]
    return meanings, relationships


def artifact_model_build_result(
    session: ToolSession,
    *,
    dump_paths: Optional[Sequence[str]] = None,
    needles: Optional[Dict[str, str]] = None,
    anchors: Optional[Sequence[Dict[str, Any]]] = None,
    occurrence: int = 0,
    delta_start: int = -2048,
    length: int = 6144,
    anchor_length: Optional[int] = None,
    related: Optional[Mapping[str, Mapping[str, str]]] = None,
    pointer_quorum: Optional[int] = None,
    heap: bool = True,
    mixed_ok: bool = False,
    case_dir: Optional[str] = None,
    author: str = DEFAULT_AUTHOR,
    name: str,
    meanings: Sequence[Mapping[str, Any]] = (),
    relationships: Sequence[Mapping[str, Any]] = (),
    applicability: Optional[Mapping[str, Any]] = None,
    prefilter_length: int = 64,
    out_path: Optional[str] = None,
    keylog: Optional[Mapping[str, Any]] = None,
    anchor_label: Optional[str] = None,
    related_labels: Optional[Sequence[str]] = None,
    detail: str = "summary",
) -> ServiceResult:
    """Learn a layout (as :func:`propose_layout_result`) and build the artifact model.

    ``detail="summary"`` (default) returns ``path``/``sha256``/``problems`` plus
    a ``model_summary`` and omits ``model`` and ``proposal`` (the model is in the
    file at ``path``); ``detail="full"`` returns both.

    Keylog-driven (``keylog``) with ``meanings`` omitted, meanings and labels
    default to the ``suggested_meanings`` that were actually found as fields
    (anchor + each related secret labelled, ``client_random`` unlabelled), and
    with ``relationships`` omitted each found secret is ``owned_by``
    ``client_random``.

    ``meanings`` is ``[{field, meaning, label, support:[{kind, ref}]}]``,
    ``relationships`` ``[{kind, source, target}]``; both name PROPOSED fields
    (a name the proposal lacks is ``INVALID_INPUT``, as is any model whose
    ``check()`` fails). The model JSON is written to ``out_path`` (a NEW
    ``.json`` file); the result carries the model, its path and sha256.
    """
    from memdiver.engine.artifact_builder import build_structure_model

    detail = _checked_detail(detail)
    if not name or not str(name).strip():
        raise _invalid("name is required", "semantic.name")
    target = _checked_model_target(out_path)
    parsed = (_field_meanings(meanings), _relationship_tuples(relationships),
              _applicability(applicability))
    with ExitStack() as stack:
        learned = _learn(
            stack, dump_paths=dump_paths, needles=needles, anchors=anchors,
            occurrence=occurrence, delta_start=delta_start, length=length,
            anchor_length=anchor_length, related=related,
            pointer_quorum=pointer_quorum, heap=heap, mixed_ok=mixed_ok,
            keylog=keylog, anchor_label=anchor_label, related_labels=related_labels)
    meanings_, relationships_ = _keylog_defaults(
        learned, str(name), parsed[0], parsed[1], bool(meanings), bool(relationships))
    try:
        model = build_structure_model(
            learned.consensus, learned.proposal, name=str(name),
            anchor_length=learned.anchor_length, meanings=meanings_,
            relationships=relationships_, applicability=parsed[2],
            prefilter_length=int(prefilter_length))
    except ValueError as exc:
        raise _invalid(str(exc), "semantic.model_invalid") from exc
    import json

    text = json.dumps(model.to_dict(), indent=1)
    _write_model(target, text)
    proposal_dict = _proposal_payload(learned, str(name))
    payload: Dict[str, Any] = {
        "model": model.to_dict(), "path": str(target),
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "problems": model.check(), "proposal": proposal_dict,
    }
    if case_dir:
        payload["record_entries"] = _record_entries(case_dir, learned, proposal_dict, author)
    if detail == "summary":
        keylog_part = {} if learned.keylog is None else learned.keylog.payload()
        payload = _summarize_build(payload, proposal_dict, keylog_part)
    return _result(payload, learned)


# -- model export + held-out validation -----------------------------------------------

_PLUGIN_SUFFIX = ".py"
_PLUGIN_CLASS = re.compile(r"^class (\w+)\(interfaces\.plugins\.PluginInterface\)", re.M)


def _checked_new_target(out_path: Optional[str], suffix: str, code: str) -> Path:
    """A fresh ``*<suffix>`` target outside any case record; never overwrites."""
    if not out_path or not str(out_path).strip():
        raise _invalid("out_path is required", "out_path_required")
    target = Path(out_path).expanduser()
    if not target.name.endswith(suffix) or target.name == suffix:
        raise _invalid(f"out_path must end in {suffix}: {target}", code)
    if "annotations" in target.resolve(strict=False).parts:
        raise _invalid("out_path must not lie inside a case's annotations/", code)
    if target.exists() or target.is_symlink():
        raise _invalid(f"out_path already exists (never overwritten): {target}",
                       "model_out_exists")
    return target


def _load_model(model_path: str) -> Any:
    """The artifact model at ``model_path``; unreadable/inconsistent is a refusal."""
    import json

    from memdiver.architect.artifact_model import ArtifactModel
    from memdiver.core.service_errors import FileNotFoundServiceError

    path = Path(model_path).expanduser()
    if not path.is_file():
        raise FileNotFoundServiceError(f"File not found: {model_path}")
    try:
        model = ArtifactModel.from_dict(json.loads(path.read_text(encoding="utf-8")))
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise _invalid(f"not an artifact model: {exc!r}", "semantic.model_invalid") from exc
    problems = model.check()
    if problems:
        raise _invalid("inconsistent artifact model: " + "; ".join(problems),
                       "semantic.model_invalid")
    return model


def _export_plugin(model: Any, plugin_name: Optional[str]) -> str:
    from memdiver.architect.volatility3_exporter import Volatility3Exporter

    try:
        return Volatility3Exporter.export_model(model, plugin_name)
    except ValueError as exc:
        raise _invalid(str(exc), "semantic.model_invalid") from exc


def artifact_model_export_result(
    session: ToolSession,
    *,
    model_path: str,
    out_path: str,
    plugin_name: Optional[str] = None,
) -> ServiceResult:
    """Export an artifact model as a Volatility3 plugin written to a NEW ``.py``.

    The model must load (``ArtifactModel.from_dict``) and pass ``check()``;
    otherwise ``INVALID_INPUT``. Volatility3 itself is not needed to export.
    Returns ``{path, sha256, locator_kind, class_name, bytes}``.
    """
    model = _load_model(model_path)
    target = _checked_new_target(out_path, _PLUGIN_SUFFIX, "plugin_out_target")
    source = _export_plugin(model, plugin_name)
    _write_model(target, source)
    found = _PLUGIN_CLASS.search(source)
    data = source.encode("utf-8")
    return ServiceResult(payload={
        "path": str(target), "sha256": hashlib.sha256(data).hexdigest(),
        "locator_kind": model.locator.kind,
        "class_name": found.group(1) if found else (plugin_name or ""),
        "bytes": len(data)})


def _parse_keylog_expected(text: str, labels: Optional[Sequence[str]] = None) -> set:
    """NSS keylog text -> ``{(label, client_random, secret)}`` (lower-case hex).

    Uses the SAME parser as the learning side (BOM, corpus ``line`` header,
    ``id,LABEL`` CSV rows, length validation); *labels* are admitted as labels
    even when the registry does not know them."""
    from memdiver.engine.keylog_anchors import parse_keylog_text

    wanted = set(labels) if labels is not None else None
    # No label filter: every upper-case first token is an admissible label.
    admitted = wanted if wanted is not None else {
        word for ln in text.splitlines() for word in ln.replace(",", " ").split()[:2]
        if word.isupper() and word.replace("_", "").isalnum()}
    parsed = parse_keylog_text(text, extra_labels=admitted)
    return {(lb, sess.client_random.hex(), secret.hex())
            for sess in parsed.sessions for lb, secret in sess.secrets.items()
            if wanted is None or lb in wanted}


def _present_in(opened: Any, view: str, needle: bytes) -> bool:
    from memdiver.engine.anchor_consensus import search_needles

    return bool(search_needles({"d": opened}, {"d": needle}, view=view, max_hits=1)["d"].anchors)


def _present_many(opened: Any, view: str, needles: Sequence[bytes]) -> set:
    """Which *needles* occur in *opened* -- one pass over the dump, the same
    answer as :func:`_present_in` per needle (its fallback for sources the
    shared helper has no window strategy for)."""
    from memdiver.core.dump_search import present_needles
    from memdiver.engine.anchor_consensus import _require_searchable

    if not needles:
        return set()
    _require_searchable(opened, "d", view)
    return present_needles(opened, needles, view,
                           lambda needle: _present_in(opened, view, needle))


def _shared_expected(sessions: Sequence[Any], opened: Any, labels: Sequence[str],
                     not_in_memory: Optional[List[str]] = None) -> set:
    """Triples of the shared-key-log sessions whose asserted SECRETS are in this capture.

    Same criterion as learning (secret presence): every candidate secret is
    searched exhaustively (exact, va view), independent of the plugin. A
    session whose client_random is present but none of whose asserted secrets
    are is appended to *not_in_memory* (informational, never a false negative).
    A capture with no expected triple is ``indeterminate``."""
    from memdiver.app.tools_consensus import _anchor_view_for
    from memdiver.engine.keylog_anchors import MIN_NEEDLE_BYTES

    view = _anchor_view_for(opened)
    secrets = [session.secrets[lb] for session in sessions for lb in labels
               if lb in session.secrets and len(session.secrets[lb]) >= MIN_NEEDLE_BYTES]
    # ONE presence pass: the client_randoms ride along with the secrets
    # (presence is per needle, so the union answers both questions).
    randoms = ([s.client_random for s in sessions
                if len(s.client_random) >= MIN_NEEDLE_BYTES]
               if not_in_memory is not None else [])
    found = _present_many(opened, view, secrets + randoms)
    out = set()
    absent_sessions = []
    for session in sessions:
        present = {lb for lb in labels if lb in session.secrets
                   and len(session.secrets[lb]) >= MIN_NEEDLE_BYTES
                   and session.secrets[lb] in found}
        if present:
            out |= {(lb, session.client_random.hex(), session.secrets[lb].hex())
                    for lb in present}
        elif not_in_memory is not None and len(session.client_random) >= MIN_NEEDLE_BYTES:
            absent_sessions.append(session)
    if not_in_memory is not None:
        not_in_memory.extend(s.client_random.hex() for s in absent_sessions
                             if s.client_random in found)
    return out


def _expected_triples(capture: Mapping[str, Any], labels: Sequence[str],
                      shared: Optional[Sequence[Any]] = None, opened: Any = None,
                      not_in_memory: Optional[List[str]] = None) -> set:
    keylog, expected = capture.get("keylog_path"), capture.get("expected")
    if shared is not None and not keylog and not expected:
        return _shared_expected(shared, opened, labels, not_in_memory)
    if bool(keylog) == bool(expected):
        raise _invalid("each held_out capture needs exactly one of keylog_path / expected",
                       "semantic.held_out")
    if keylog:
        from memdiver.app.keylog_input import read_keylog_file

        return _parse_keylog_expected(read_keylog_file(keylog), labels)
    try:
        return {(str(e["label"]), str(e["owner_hex"]).lower(), str(e["value_hex"]).lower())
                for e in expected or () if str(e["label"]) in labels}
    except (KeyError, TypeError) as exc:
        raise _invalid(f"expected items need label/owner_hex/value_hex: {exc!r}",
                       "semantic.held_out") from exc


def _refuse_learned(dump_path: str, learned_on: Sequence[str]) -> None:
    """Refuse a held-out dump the model was learned on, by RESOLVED path.

    Never by file name: capture tools reuse names across runs (every gocryptfs
    run is ``memslicer.msl``), so a name match would refuse every honest
    held-out capture of such a corpus."""
    resolved = str(Path(dump_path).expanduser().resolve(strict=False))
    paths = {str(Path(p).expanduser().resolve(strict=False)) for p in learned_on}
    if resolved in paths:
        raise _invalid(f"held-out dump was used for learning: {dump_path}",
                       "semantic.held_out_leak")


def _plugin_source(model: Any, plugin_path: Optional[str]) -> Tuple[str, str]:
    """``(source, sha256)``: the supplied plugin file, else the model's export."""
    if plugin_path:
        path = Path(plugin_path).expanduser()
        if not path.is_file():
            from memdiver.core.service_errors import FileNotFoundServiceError
            raise FileNotFoundServiceError(f"File not found: {plugin_path}")
        source = path.read_text(encoding="utf-8")
        logger.warning("memdiver: running UNSANDBOXED model plugin %s sha256=%s", path,
                       hashlib.sha256(source.encode("utf-8")).hexdigest())
    else:
        source = _export_plugin(model, None)
    return source, hashlib.sha256(source.encode("utf-8")).hexdigest()


def _owned_labels(model: Any) -> set:
    """Labels of the fields that are the SOURCE of an ``owned_by`` relationship."""
    owners = {r.source for r in model.relationships if r.kind == "owned_by"}
    return {a.label for a in model.assertions if a.label and a.field in owners}


def _score_one(stack: ExitStack, source: str, capture: Mapping[str, Any],
               labels: Sequence[str], min_run: int,
               owned_labels: Optional[set] = None,
               shared: Optional[Sequence[Any]] = None,
               not_in_memory: Optional[Dict[str, List[str]]] = None,
               window_hits: Optional[Dict[str, List[Dict[str, Any]]]] = None) -> Tuple[Any, int]:
    """``(HeldOutResult, scanned_runs)`` for one held-out capture.

    *not_in_memory* (when given) receives ``{capture: [client_random hex]}``;
    *window_hits* ``{capture: [{label, windows}]}`` (which prefilter windows found each TP)."""
    from memdiver.app.tools_consensus import _open_one
    from memdiver.engine.artifact_validation import (
        run_plugin_on_capture, score_capture, tp_windows)

    dump_path = str(capture["dump_path"])
    opened = _open_one(stack, dump_path, None)
    if opened.va_span_start() is None:  # before any presence scan of a refused capture
        raise CapabilityError(
            _no_va_view_message(dump_path, opened),
            category=ErrorCategory.PRECONDITION, code="semantic.no_va_view")
    absent: List[str] = []
    expected = _expected_triples(capture, labels, shared, opened, absent)
    if not_in_memory is not None:
        not_in_memory[str(Path(dump_path).expanduser().resolve(strict=False))] = absent
    run = run_plugin_on_capture(
        source, opened, str(Path(dump_path).expanduser().resolve(strict=False)),
        min_run=min_run)
    if window_hits is not None:
        window_hits[run.capture] = tp_windows(run, expected, labels)
    return score_capture(run, expected, labels, owned_labels), run.scanned_runs


def _shared_sessions(keylog: Optional[Mapping[str, Any]],
                     labels: Sequence[str] = ()) -> Optional[List[Any]]:
    """Sessions of the shared ``keylog`` ({path} | {text}); None when not given."""
    if keylog is None:
        return None
    from memdiver.app.keylog_input import load_keylogs

    if "per_dump" in keylog:
        raise _invalid("held-out 'keylog' is a shared {path} | {text}; use per-capture "
                       "keylog_path for one key log per dump", "keylog.spec")
    return load_keylogs(keylog, ["shared"], labels)[0]["shared"]


def _shared_keylog(keylog: Optional[Mapping[str, Any]], labels: Sequence[str] = ()
                   ) -> Tuple[Optional[List[Any]], Optional[List[Dict[str, Any]]]]:
    """``(sessions, parse summary)`` of the shared ``keylog``; ``(None, None)`` when not
    given. The summary (malformed lines with reasons, ignored lines) goes into the
    validate payload so a dropped held-out line is never silent."""
    if keylog is None:
        return None, None
    from memdiver.app.keylog_input import load_keylogs

    if "per_dump" in keylog:
        raise _invalid("held-out 'keylog' is a shared {path} | {text}; use per-capture "
                       "keylog_path for one key log per dump", "keylog.spec")
    sessions, summary = load_keylogs(keylog, ["shared"], labels)
    return sessions["shared"], list(summary)


def artifact_model_validate_result(
    session: ToolSession,
    *,
    model_path: str,
    held_out: Sequence[Mapping[str, Any]],
    labels: Optional[Sequence[str]] = None,
    plugin_path: Optional[str] = None,
    out_path: Optional[str] = None,
    min_run: int = 64,
    keylog: Optional[Mapping[str, Any]] = None,
) -> ServiceResult:
    """Run the model's plugin on held-out captures and score it against ground truth.

    ``keylog`` (``{path} | {text}``, one shared NSS key log) supplies the
    expected triples of every capture that names neither ``keylog_path`` nor
    ``expected``: a capture keeps only the sessions whose asserted secrets are
    PRESENT in it (exhaustive exact search); sessions whose client_random is
    present but whose secrets are not are listed as ``not_in_memory`` (never a
    false negative); no expected triple is ``indeterminate`` (never pass/fail).

    ``held_out`` is ``[{dump_path, keylog_path | expected}]``: ``keylog_path``
    is an NSS keylog file (expected = its ``(label, client_random, secret)``
    lines), ``expected`` is ``[{label, owner_hex, value_hex}]``; exactly one
    per capture. ``labels`` defaults to the model's non-empty assertion labels.
    A dump the model was learned on is refused (``semantic.held_out_leak``).
    Without ``plugin_path`` the plugin is exported in memory. ``out_path`` (a
    NEW ``.json``) receives the model with its validation replaced. Requires
    volatility3 (the ``vol`` extra).
    """
    import time
    from dataclasses import replace

    from memdiver.engine.artifact_validation import validation_record
    from memdiver.engine.vol3_verify import _require_volatility3

    model = _load_model(model_path)
    if not held_out:
        raise _invalid("held_out must list at least one capture", "semantic.held_out")
    use_labels = tuple(labels) if labels else tuple(sorted({a.label for a in model.assertions if a.label}))
    if not use_labels:
        raise _invalid("no labels: the model has no labelled assertions; pass labels",
                       "semantic.labels")
    target = _checked_new_target(out_path, _MODEL_SUFFIX, "model_out_target") if out_path else None
    for capture in held_out:
        _refuse_learned(str(capture.get("dump_path", "")), model.validation.learned_on)
    _require_volatility3()
    source, plugin_sha = _plugin_source(model, plugin_path)
    started, results, scanned = time.monotonic(), [], {}
    not_in_memory: Dict[str, List[str]] = {}
    window_hits: Dict[str, List[Dict[str, Any]]] = {}
    owned = _owned_labels(model)
    shared, keylog_summary = _shared_keylog(keylog, use_labels)
    with ExitStack() as stack:
        for capture in held_out:
            result, runs = _score_one(stack, source, capture, use_labels, int(min_run), owned,
                                      shared, not_in_memory, window_hits)
            results.append(result)
            scanned[result.capture] = runs
    try:
        record = validation_record(model.validation.learned_on, results, scanned)
    except ValueError as exc:
        raise _invalid(str(exc), "semantic.held_out_leak") from exc
    payload = _validation_payload(results, record, use_labels, plugin_sha,
                                  round(time.monotonic() - started, 3), scanned,
                                  not_in_memory, window_hits, model.warnings)
    if keylog_summary is not None:
        payload["keylog_summary"] = keylog_summary
    if target is not None:
        import json

        _write_model(target, json.dumps(replace(model, validation=record).to_dict(), indent=1))
        payload["model_path"] = str(target)
    return ServiceResult(payload=payload)


def _validation_payload(results: Sequence[Any], record: Any, labels: Sequence[str],
                        plugin_sha: str, seconds: float,
                        scanned: Mapping[str, int],
                        not_in_memory: Optional[Mapping[str, Sequence[str]]] = None,
                        window_hits: Optional[Mapping[str, Sequence[Mapping[str, Any]]]] = None,
                        warnings: Sequence[str] = ()) -> Dict[str, Any]:
    from dataclasses import asdict

    from memdiver.engine.artifact_validation import capture_verdict, window_redundancy

    def total(key: str) -> int:
        return sum(getattr(r, key) for r in results)

    return {
        "verdict": record.verdict, "labels": list(labels), "plugin_sha256": plugin_sha,
        "captures": [{**asdict(r), "verdict": capture_verdict(r, scanned.get(r.capture, 0)),
                      "scanned_runs": scanned.get(r.capture, 0),
                      "not_in_memory": list((not_in_memory or {}).get(r.capture, ())),
                      "tp_windows": list((window_hits or {}).get(r.capture, ()))}
                     for r in results],
        "seconds": seconds,
        "window_redundancy": window_redundancy(window_hits or {}),
        "warnings": list(warnings),
        "totals": {"expected": total("expected"), "tp": total("true_positives"),
                   "fp": total("false_positives"), "fn": total("false_negatives"),
                   "relationships_correct": total("relationships_correct"),
                   "relationships_checked": total("relationships_checked")},
    }
