"""ISF drafts with per-entry provenance, stored in the analysis record (plan T4.1, D6/D10).

A draft is a Volatility 3 ISF under construction for ONE capture (a full image,
``capture_id`` = its sha256). It is never stored as one big mutable document:
the analysis record holds an append-only log of **operations** (entries of kind
:data:`~memdiver.analysis.record.ISF_DRAFT`), and the draft is what replaying
that log produces. Consequences:

* **versioned** — every operation is a version; ``materialize(upto=entry_id)``
  rebuilds any earlier state and :meth:`IsfDraft.diff` compares two of them;
  ``version`` is the id of the last APPLIED entry and is NOT unique per state:
  after a retraction ``materialize()`` and ``materialize(upto=<that id>)`` can
  share a ``version`` yet differ in content. ``state_id`` (sha256/16 hex of the
  ordered applied entry ids) identifies the content; exports are named
  ``<version>-<state_id>.isf.json`` and never overwrite different bytes;
* **provenance per entry** — every symbol, type, field, base type and enum in a
  materialized draft knows the operation that set it and that operation's
  :class:`Provenance` (source, tier, evidence, author);
* **large imports stay out of the JSONL** — importing a whole ISF (a donor, a
  pakunoda extraction, 100k kallsyms symbols) writes the JSON once as a
  content-addressed blob under ``<case>/isf_drafts/blobs/<sha256>.json``; the
  log entry names the blob and its sha256 (a missing or altered blob is an
  error, never an empty import).

Replay semantics (``materialize``):

1. Entries of this draft (``payload["draft"] == name``) in file order.
2. An entry withdrawn by a RETRACTION (via :meth:`IsfDraftStore.retract`) is
   skipped. ``supersedes`` on a non-retraction entry is history only (rule 4):
   file order already makes the later write win, so it never removes an entry
   (in particular a single-key edit never drops the rest of an import).
3. Last writer wins per key. Keys: ``("symbol", name)``,
   ``("type", name)``, ``("field", struct, field)``, ``("base_type", name)``,
   ``("enum", name)``.
4. A single-key op whose key was last set by another single-key entry of the
   same draft sets ``supersedes`` to that entry's id, so the record's history
   chain shows the correction.

Tiers (``Provenance.tier``) are pakunoda's ``LayoutTier`` values (D10: no
parallel schema) plus three sources pakunoda's tiers do not cover:
``imported`` (copied from a whole ISF: donor, BTF or pakunoda extraction),
``probe`` (an address read by a probe: kallsyms, vmcoreinfo, ksymtab) and
``manual`` (a human or agent claim from an observation, e.g. a hex selection).
A ``bound`` claim (size upper bound) is recorded but never reaches
:meth:`IsfDraft.to_isf_dict` — it is not an offset or an exact size.

Addresses are ints in the log (Python JSON is lossless). Presenters that send a
draft to the browser MUST hex-encode symbol addresses (JS loses precision above
2**53).

Stdlib only; pakunoda (validation/readiness) is imported lazily by the tools layer.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import threading
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from memdiver.analysis.record import (
    _SLUG, ISF_DRAFT, RETRACTION, AnalysisEntry, Support, retraction_of)
from memdiver.analysis.record_store import AnalysisRecord
from memdiver.core.artifact_util import atomic_write_text
from memdiver.core.location import AddressSpace, Location
from memdiver.core.service_errors import CapabilityError, ErrorCategory

#: pakunoda ``LayoutTier`` values, strongest first, then MemDiver's own sources.
LAYOUT_TIERS: Tuple[str, ...] = (
    "exact", "ordinal", "population", "code", "crc_certified", "upstream_constant", "bound")
EXTRA_TIERS: Tuple[str, ...] = ("imported", "probe", "manual")
TIERS: Tuple[str, ...] = LAYOUT_TIERS + EXTRA_TIERS

#: ``payload["op"]`` values.
OP_CREATE = "create"            # {arch, banner?, base_metadata?}
OP_SET_SYMBOL = "set_symbol"    # {name, address, type?}            Location: KERNEL_VA
OP_SET_STRUCT = "set_struct"    # {name, kind: struct|union, size}
OP_SET_FIELD = "set_field"      # {struct, field, offset, type}     type = ISF type descriptor
OP_SET_BASE_TYPE = "set_base_type"  # {name, size, signed, kind, endian}
OP_SET_ENUM = "set_enum"        # {name, size, base, constants}
OP_SIZE_BOUND = "size_bound"    # {struct, bound}  (tier "bound"; never exported)
OP_REMOVE = "remove"            # {key: [section, name, field?]}    tombstone for one key
OP_IMPORT = "import"            # {blob, blob_sha256, sections, only?, counts}
OPS: Tuple[str, ...] = (OP_CREATE, OP_SET_SYMBOL, OP_SET_STRUCT, OP_SET_FIELD, OP_SET_BASE_TYPE,
                        OP_SET_ENUM, OP_SIZE_BOUND, OP_REMOVE, OP_IMPORT)

#: ISF sections an import may carry.
SECTIONS: Tuple[str, ...] = ("base_types", "user_types", "enums", "symbols")

#: OS blocks vol3's ISF schema allows next to ``format``/``producer`` (one at most).
_ISF_OS_BLOCKS = ("linux", "windows", "mac")

DRAFTS_DIR = "isf_drafts"
BLOBS_DIR = "blobs"
ISF_SUFFIX = ".isf.json"

Key = Tuple[str, ...]


ISF_FORMAT = "6.2.0"
_MAX_ADDRESS = 2 ** 64
#: ISF section -> key tag used in :data:`Key` tuples.
_SECTION_TAG: Dict[str, str] = {
    "base_types": "base_type", "user_types": "type", "enums": "enum", "symbols": "symbol"}
_TAG_SECTION: Dict[str, str] = {tag: section for section, tag in _SECTION_TAG.items()}
_TAGS = frozenset(_SECTION_TAG.values()) | {"field"}
_UNSIZED_EVIDENCE = "size_unknown"
_UNTYPED_EVIDENCE = "type_unknown"
_VOID_TYPE: Dict[str, Any] = {"kind": "base", "name": "void"}


def _invalid(message: str, code: str = "invalid_isf_draft") -> CapabilityError:
    return CapabilityError(message, category=ErrorCategory.INVALID_INPUT, code=code)


def _not_found(message: str, code: str = "isf_draft_not_found") -> CapabilityError:
    return CapabilityError(message, category=ErrorCategory.NOT_FOUND, code=code)


# -- validation ---------------------------------------------------------------

def _check_name(what: str, value: Any) -> str:
    if not isinstance(value, str) or not _SLUG.match(value):
        raise _invalid(f"{what} must be a lowercase slug, got {value!r}")
    return value


def _check_nonempty(what: str, value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise _invalid(f"{what} must be a non-empty string, got {value!r}")
    return value


def _check_int(what: str, value: Any, *, upper: Optional[int] = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _invalid(f"{what} must be an integer, got {value!r}")
    if value < 0 or (upper is not None and value >= upper):
        raise _invalid(f"{what} out of range: {value}")
    return value


def _check_address(value: Any) -> int:
    return _check_int("address", value, upper=_MAX_ADDRESS)


def _check_type(descriptor: Any) -> Dict[str, Any]:
    if not isinstance(descriptor, Mapping) or "kind" not in descriptor:
        raise _invalid(f"type descriptor must be a dict with a 'kind', got {descriptor!r}")
    return dict(descriptor)


def _check_provenance(provenance: Provenance) -> Provenance:
    _check_nonempty("provenance source", provenance.source)
    if provenance.tier not in TIERS:
        raise _invalid(f"unknown tier {provenance.tier!r}; expected one of {list(TIERS)}")
    if isinstance(provenance.witnesses, bool) or not isinstance(provenance.witnesses, int) \
            or provenance.witnesses < 1:
        raise _invalid("provenance witnesses must be an integer >= 1")
    return provenance


def _with_evidence(provenance: Provenance, extra: str) -> Provenance:
    return dataclasses.replace(provenance, evidence=tuple(provenance.evidence) + (extra,))


def _normalize_key(key: Sequence[str]) -> Key:
    parts = tuple(key)
    if not parts or any(not isinstance(p, str) or not p for p in parts):
        raise _invalid(f"invalid key {key!r}")
    tag = _SECTION_TAG.get(parts[0], parts[0])
    if tag not in _TAGS or len(parts) != (3 if tag == "field" else 2):
        raise _invalid(f"invalid key {key!r}: expected [section, name] or [field, struct, field]")
    return (tag,) + parts[1:]


# -- canonical blobs ----------------------------------------------------------

def _canonical_bytes(subset: Mapping[str, Any]) -> bytes:
    return json.dumps(subset, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _select(isf: Mapping[str, Any], sections: Sequence[str],
            only: Optional[Mapping[str, Sequence[str]]]) -> Dict[str, Dict[str, Any]]:
    """The imported subset of ``isf``; named-but-absent keys are an error."""
    for section in list(sections) + list(only or {}):
        if section not in SECTIONS:
            raise _invalid(f"unknown ISF section {section!r}; expected one of {list(SECTIONS)}")
    if only:
        chosen = [s for s in sections if s in only]
    else:
        chosen = list(sections)
    subset: Dict[str, Dict[str, Any]] = {}
    for section in chosen:
        available = isf.get(section) or {}
        names = list(only[section]) if only and section in only else list(available)
        missing = [n for n in names if n not in available]
        if missing:
            raise _invalid(f"{section}: not in the source ISF: {missing[:10]}", "isf_key_missing")
        subset[section] = {n: available[n] for n in names}
    if not any(subset.values()):
        raise _invalid("nothing to import: the selection is empty", "isf_import_empty")
    return subset


# -- replay -------------------------------------------------------------------

def _single_key(payload: Mapping[str, Any]) -> Optional[Key]:
    op = payload.get("op")
    if op == OP_SET_SYMBOL:
        return ("symbol", payload["name"])
    if op == OP_SET_STRUCT:
        return ("type", payload["name"])
    if op == OP_SET_FIELD:
        return ("field", payload["struct"], payload["field"])
    if op == OP_SET_BASE_TYPE:
        return ("base_type", payload["name"])
    if op == OP_SET_ENUM:
        return ("enum", payload["name"])
    if op == OP_SIZE_BOUND:
        return ("size_bound", payload["struct"])
    if op == OP_REMOVE:
        return tuple(payload["key"])
    return None


def _draft_entries(entries: Sequence[AnalysisEntry], name: str) -> List[AnalysisEntry]:
    return [e for e in entries if e.kind == ISF_DRAFT and e.payload.get("draft") == name]


def _is_draft_retraction(entry: AnalysisEntry, name: str) -> bool:
    return entry.kind == RETRACTION and entry.payload.get("draft") == name


def _retracted_ids(entries: Sequence[AnalysisEntry], name: str, cutoff: int) -> Set[str]:
    return {e.supersedes for e in entries[:cutoff + 1]
            if _is_draft_retraction(e, name) and e.supersedes}


#: Parsed import blobs, newest last: ``(path, size, mtime_ns, ctime_ns, inode, sha)`` ->
#: sections. A blob is content-addressed and never rewritten, so a key whose stat
#: identity is unchanged needs no re-read, re-hash or re-parse; any rewrite or removal
#: changes the stat identity and is re-verified (tamper / missing errors unchanged).
#: Cached dicts are SHARED and READ-ONLY: :meth:`_Replay._op_import` copies the
#: levels replay mutates (a struct body and its ``fields`` dict); leaf dicts (a
#: symbol, a field, an enum, a base type) are only ever replaced, never mutated in
#: place, by replay and by every caller of ``materialize`` / ``to_isf_dict``.
#: The cache is bounded twice: at most ``_BLOB_CACHE_MAX`` entries and at most
#: ``_BLOB_CACHE_MAX_BYTES`` of blob *file* bytes (the on-disk JSON size is the weight,
#: a rough proxy for the parsed dicts' footprint). Least-recently-used entries are
#: evicted first; a blob larger than the whole byte budget is never cached.
_BLOB_CACHE_MAX = 8
_BLOB_CACHE_MAX_BYTES = 256 * 1024 * 1024
_blob_cache: "OrderedDict[Tuple[Any, ...], Dict[str, Dict[str, Any]]]" = OrderedDict()
_blob_cache_lock = threading.Lock()


def _blob_cache_key(path: Path, sha: str) -> Optional[Tuple[Any, ...]]:
    try:
        st = path.stat()
    except FileNotFoundError:
        return None
    return (str(path), st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_ino, sha)


def _read_verified_blob(path: Path, sha: str) -> Dict[str, Dict[str, Any]]:
    if not path.is_file():
        raise CapabilityError(
            f"ISF draft blob {sha} is missing ({path})",
            category=ErrorCategory.NOT_FOUND, code="isf_blob_missing")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != sha:
        raise CapabilityError(
            f"ISF draft blob {path} does not match its sha256 {sha} (altered or corrupt)",
            category=ErrorCategory.INTERNAL, code="isf_blob_tampered")
    parsed: Dict[str, Dict[str, Any]] = json.loads(data.decode("utf-8"))
    return parsed


def _load_blob_cached(path: Path, sha: str) -> Dict[str, Dict[str, Any]]:
    """The parsed blob (shared, read-only); re-read only when the file's stat changed."""
    key = _blob_cache_key(path, sha)
    with _blob_cache_lock:
        if key is not None and key in _blob_cache:
            _blob_cache.move_to_end(key)
            return _blob_cache[key]
    parsed = _read_verified_blob(path, sha)
    if key is not None and key == _blob_cache_key(path, sha):
        _remember_blob(key, parsed)
    return parsed


def _blob_cache_weight(key: Tuple[Any, ...]) -> int:
    """The cache weight of an entry: its blob file size (``key[1]``)."""
    return int(key[1])


def _remember_blob(key: Tuple[Any, ...], parsed: Dict[str, Dict[str, Any]]) -> None:
    """Cache ``parsed`` under ``key``, evicting LRU entries past either bound."""
    if _blob_cache_weight(key) > _BLOB_CACHE_MAX_BYTES:
        return
    with _blob_cache_lock:
        _blob_cache[key] = parsed
        _blob_cache.move_to_end(key)
        total = sum(_blob_cache_weight(k) for k in _blob_cache)
        while len(_blob_cache) > _BLOB_CACHE_MAX or total > _BLOB_CACHE_MAX_BYTES:
            evicted, _ = _blob_cache.popitem(last=False)
            total -= _blob_cache_weight(evicted)


def _struct_copy(struct: Mapping[str, Any]) -> Dict[str, Any]:
    """A struct body replay may mutate: own dict and own ``fields`` dict, shared leaves."""
    copied = dict(struct)
    if isinstance(copied.get("fields"), dict):
        copied["fields"] = dict(copied["fields"])
    return copied


class _Replay:
    """Applies operations to an :class:`IsfDraft`, tracking per-key origins."""

    def __init__(self, draft: IsfDraft, entries_dir: Path) -> None:
        self.draft = draft
        self.blob_dir = entries_dir

    def apply(self, entry: AnalysisEntry) -> None:
        payload = entry.payload
        op = payload["op"]
        provenance = Provenance.from_dict(payload["provenance"])
        origin = EntryOrigin(entry.id, entry.created, op, provenance)
        handler = getattr(self, f"_op_{op}", None)
        if handler is None:
            raise _invalid(f"unknown draft operation {op!r} in entry {entry.id}")
        handler(payload, origin)
        self.draft.version = entry.id
        self.draft.applied_ids.append(entry.id)
        self.draft.applied += 1

    def _op_create(self, payload: Mapping[str, Any], origin: EntryOrigin) -> None:
        meta = dict(payload.get("base_metadata") or {})
        meta["arch"] = payload["arch"]
        if payload.get("banner") is not None:
            meta["banner"] = payload["banner"]
        self.draft.metadata = meta

    def _op_set_symbol(self, payload: Mapping[str, Any], origin: EntryOrigin) -> None:
        symbol: Dict[str, Any] = {"address": payload["address"]}
        if payload.get("type") is not None:
            symbol["type"] = payload["type"]
        self.draft.symbols[payload["name"]] = symbol
        self.draft.origins[("symbol", payload["name"])] = origin

    def _op_set_struct(self, payload: Mapping[str, Any], origin: EntryOrigin) -> None:
        struct = self.draft.user_types.setdefault(
            payload["name"], {"kind": payload["kind"], "size": payload["size"], "fields": {}})
        struct["kind"], struct["size"] = payload["kind"], payload["size"]
        self.draft.origins[("type", payload["name"])] = origin

    def _op_set_field(self, payload: Mapping[str, Any], origin: EntryOrigin) -> None:
        struct_name = payload["struct"]
        if struct_name not in self.draft.user_types:
            self.draft.user_types[struct_name] = {"kind": "struct", "size": 0, "fields": {}}
            unsized = dataclasses.replace(
                origin, provenance=_with_evidence(origin.provenance, _UNSIZED_EVIDENCE))
            self.draft.origins[("type", struct_name)] = unsized
        fields = self.draft.user_types[struct_name].setdefault("fields", {})
        fields[payload["field"]] = {"offset": payload["offset"], "type": payload["type"]}
        self.draft.origins[("field", struct_name, payload["field"])] = origin

    def _op_set_base_type(self, payload: Mapping[str, Any], origin: EntryOrigin) -> None:
        self.draft.base_types[payload["name"]] = {
            "size": payload["size"], "signed": payload["signed"],
            "kind": payload["kind"], "endian": payload["endian"]}
        self.draft.origins[("base_type", payload["name"])] = origin

    def _op_set_enum(self, payload: Mapping[str, Any], origin: EntryOrigin) -> None:
        self.draft.enums[payload["name"]] = {
            "size": payload["size"], "base": payload["base"],
            "constants": dict(payload["constants"])}
        self.draft.origins[("enum", payload["name"])] = origin

    def _op_size_bound(self, payload: Mapping[str, Any], origin: EntryOrigin) -> None:
        self.draft.size_bounds[payload["struct"]] = payload["bound"]

    def _op_remove(self, payload: Mapping[str, Any], origin: EntryOrigin) -> None:
        key = tuple(payload["key"])
        tag, name = key[0], key[1]
        if tag == "type":
            self._drop_struct(name)
        elif tag == "field":
            struct = self.draft.user_types.get(name)
            if struct is not None:
                struct.get("fields", {}).pop(key[2], None)
        elif tag in _TAG_SECTION:
            getattr(self.draft, _TAG_SECTION[tag]).pop(name, None)
        self.draft.origins.pop(key, None)

    def _drop_struct(self, name: str) -> None:
        struct = self.draft.user_types.pop(name, None)
        for field_name in (struct or {}).get("fields", {}):
            self.draft.origins.pop(("field", name, field_name), None)

    def _op_import(self, payload: Mapping[str, Any], origin: EntryOrigin) -> None:
        subset = self._load_blob(payload)
        for section, items in subset.items():
            tag = _SECTION_TAG[section]
            target = getattr(self.draft, section)
            for key_name, value in items.items():
                if section == "user_types":
                    self._drop_struct(key_name)
                    self._import_struct_origins(key_name, value, origin)
                    value = _struct_copy(value)     # the cached blob stays untouched
                target[key_name] = value
                self.draft.origins[(tag, key_name)] = origin

    def _import_struct_origins(self, name: str, struct: Mapping[str, Any],
                               origin: EntryOrigin) -> None:
        for field_name in struct.get("fields", {}):
            self.draft.origins[("field", name, field_name)] = origin

    def _load_blob(self, payload: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
        sha = payload["blob_sha256"]
        return _load_blob_cached(self.blob_dir / f"{sha}.json", sha)


def _origin_dict(origin: Optional[EntryOrigin]) -> Optional[Dict[str, Any]]:
    if origin is None:
        return None
    return {"entry_id": origin.entry_id, "created": origin.created, "op": origin.op,
            "provenance": origin.provenance.to_dict()}


# -- diff ---------------------------------------------------------------------

def _selected_names(section: str, mine: Mapping[str, Any], theirs: Mapping[str, Any],
                    only: Optional[Mapping[str, Sequence[str]]]) -> List[str]:
    if only is not None and section in only:
        wanted = set(only[section])
        return sorted(n for n in wanted if n in mine or n in theirs)
    return sorted(set(mine) | set(theirs))


def _symbols_differ(a: Mapping[str, Any], b: Mapping[str, Any]) -> bool:
    if a.get("address") != b.get("address"):
        return True
    return "type" in a and "type" in b and a["type"] != b["type"]


def _item(key: Key, change: str, before: Any, after: Any,
          mine: "IsfDraft", theirs: "IsfDraft") -> DiffItem:
    return DiffItem(key, change, before, after,
                    mine.origins.get(key) if change != "added" else None,
                    theirs.origins.get(key) if change != "removed" else None)


def _diff_whole(section: str, name: str, a: Optional[Any], b: Optional[Any],
                mine: "IsfDraft", theirs: "IsfDraft") -> List[DiffItem]:
    key = (_SECTION_TAG[section], name)
    if a is None:
        return [_item(key, "added", None, b, mine, theirs)]
    if b is None:
        return [_item(key, "removed", a, None, mine, theirs)]
    differs = _symbols_differ(a, b) if section == "symbols" else a != b
    return [_item(key, "changed", a, b, mine, theirs)] if differs else []


def _diff_struct(name: str, a: Optional[Mapping[str, Any]], b: Optional[Mapping[str, Any]],
                 mine: "IsfDraft", theirs: "IsfDraft") -> List[DiffItem]:
    key = ("type", name)
    if a is None:
        return [_item(key, "added", None, b, mine, theirs)]
    if b is None:
        return [_item(key, "removed", a, None, mine, theirs)]
    items: List[DiffItem] = []
    if (a.get("kind"), a.get("size")) != (b.get("kind"), b.get("size")):
        items.append(_item(key, "changed", {"kind": a.get("kind"), "size": a.get("size")},
                           {"kind": b.get("kind"), "size": b.get("size")}, mine, theirs))
    fa, fb = a.get("fields", {}), b.get("fields", {})
    for field_name in sorted(set(fa) | set(fb)):
        items.extend(_diff_field(name, field_name, fa.get(field_name), fb.get(field_name),
                                 mine, theirs))
    return items


def _diff_field(struct: str, field_name: str, a: Optional[Any], b: Optional[Any],
                mine: "IsfDraft", theirs: "IsfDraft") -> List[DiffItem]:
    key = ("field", struct, field_name)
    if a is None:
        return [_item(key, "added", None, b, mine, theirs)]
    if b is None:
        return [_item(key, "removed", a, None, mine, theirs)]
    same = a.get("offset") == b.get("offset") and a.get("type") == b.get("type")
    return [] if same else [_item(key, "changed", a, b, mine, theirs)]


@dataclass(frozen=True)
class Provenance:
    """Who/what established one draft entry, and how strongly (D10 ``LayoutClaim`` shape).

    ``source`` is a slug naming the producer (``kallsyms``, ``vmcoreinfo``,
    ``btf``, ``layout_leg:anchor``, ``pakunoda_extract``, ``isf_import``,
    ``manual``, ...); ``tier`` one of :data:`TIERS`; ``evidence`` replayable
    strings (``init_task+0x9b8 == &init_mm``, ``hex selection 0x…``, a file
    sha256); ``witnesses`` independent observations behind it.
    """

    source: str
    tier: str
    evidence: Tuple[str, ...] = ()
    author: str = "human"
    witnesses: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {"source": self.source, "tier": self.tier, "evidence": list(self.evidence),
                "author": self.author, "witnesses": self.witnesses}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Provenance":
        return cls(source=str(data["source"]), tier=str(data["tier"]),
                   evidence=tuple(str(e) for e in data.get("evidence", ())),
                   author=str(data.get("author", "human")),
                   witnesses=int(data.get("witnesses", 1)))


@dataclass(frozen=True)
class EntryOrigin:
    """Where a materialized key came from: the operation entry and its provenance."""

    entry_id: str
    created: str
    op: str
    provenance: Provenance


@dataclass
class IsfDraft:
    """A materialized draft: ``TypeStore``-shaped sections + per-key origin.

    ``version`` is the id of the last applied entry (``None`` for an empty
    draft); ``applied`` counts the operations replayed. ``state_id`` identifies
    the exact materialized content (see the module docstring).
    """

    name: str
    capture_id: str
    base_types: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    user_types: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    enums: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    symbols: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    origins: Dict[Key, EntryOrigin] = field(default_factory=dict)
    size_bounds: Dict[str, int] = field(default_factory=dict)
    version: Optional[str] = None
    applied: int = 0
    applied_ids: List[str] = field(default_factory=list)

    @classmethod
    def from_isf_dict(cls, isf: Mapping[str, Any], *, name: str = "reference",
                      capture_id: str = "reference") -> "IsfDraft":
        """Wrap a plain ISF (e.g. a shipped ``.isf.json``) so it can be diffed; no origins."""
        return cls(name=name, capture_id=capture_id,
                   base_types=dict(isf.get("base_types") or {}),
                   user_types=dict(isf.get("user_types") or {}),
                   enums=dict(isf.get("enums") or {}),
                   symbols=dict(isf.get("symbols") or {}),
                   metadata=dict(isf.get("metadata") or {}))

    @property
    def state_id(self) -> str:
        """Short sha256 (16 hex) over the ordered ids of the APPLIED entries."""
        return hashlib.sha256("\n".join(self.applied_ids).encode("utf-8")).hexdigest()[:16]

    def to_isf_dict(self) -> Dict[str, Any]:
        """A Volatility 3 ISF 6.2.0 dict (pakunoda ``TypeStore.to_isf_dict`` shape).

        ``metadata`` is limited to what vol3's ISF schema allows (its
        ``element_metadata`` forbids extra keys, so an ISF carrying the draft's own
        ``arch``/``banner`` would not load at all): ``format`` (``6.2.0``), an OS
        block (``linux``/``windows``/``mac``) when the draft has one, and
        ``producer`` = memdiver + version + ``memdiver_draft = {name, capture_id,
        version, state_id, applied}`` (the producer object allows extra keys).
        ``arch``/``banner`` stay draft metadata; size bounds are omitted.

        Fields whose type is still an untyped placeholder (a layout claim without
        a type: ``void`` + ``type_unknown``) are NOT exported: vol3 code checks
        ``has_member(...)`` and then dereferences the member, so an exported
        ``void`` member breaks plugins that would work without it (arista gate:
        ``task_struct.signal``/``nsproxy`` from the layout legs made
        ``task_struct.is_valid`` raise). They stay in the draft and are counted
        in ``memdiver_draft.untyped_fields_omitted``.
        """
        from memdiver import __version__

        untyped = set(self.untyped_fields())
        metadata: Dict[str, Any] = {k: v for k, v in self.metadata.items()
                                    if k in _ISF_OS_BLOCKS}
        metadata["format"] = ISF_FORMAT
        metadata["producer"] = {"name": "memdiver", "version": __version__,
                                "memdiver_draft": {"name": self.name,
                                                   "capture_id": self.capture_id,
                                                   "version": self.version,
                                                   "state_id": self.state_id,
                                                   "applied": self.applied,
                                                   "untyped_fields_omitted": len(untyped)}}
        return {"metadata": metadata, "base_types": dict(self.base_types),
                "user_types": _without_fields(self.user_types, untyped),
                "enums": dict(self.enums), "symbols": dict(self.symbols)}

    def untyped_fields(self) -> List[Tuple[str, str]]:
        """``(struct, field)`` pairs still carrying an untyped placeholder, sorted."""
        found = []
        for key, origin in self.origins.items():
            if key[0] == "field" and _UNTYPED_EVIDENCE in origin.provenance.evidence:
                found.append((key[1], key[2]))
        return sorted(found)

    def provenance_of(self, key: Key) -> Optional[EntryOrigin]:
        return self.origins.get(key)

    def diff(self, other: "IsfDraft", *, sections: Sequence[str] = SECTIONS,
             only: Optional[Mapping[str, Sequence[str]]] = None) -> "DraftDiff":
        """Key-level differences ``self`` → ``other``.

        Symbols compare by address (and type when both have one); user types by
        kind/size and per field by offset and type descriptor; base types and
        enums by their whole dict. ``only`` restricts the comparison (e.g. to the
        symbols/structs a plugin needs: ``{"symbols": [...], "user_types": [...]}``).
        """
        items: List[DiffItem] = []
        compared: Dict[str, int] = {}
        for section in sections:
            if section not in SECTIONS:
                raise _invalid(f"unknown ISF section {section!r}")
            mine, theirs = getattr(self, section), getattr(other, section)
            names = _selected_names(section, mine, theirs, only)
            compared[section] = len(names)
            for name in names:
                if section == "user_types":
                    items.extend(_diff_struct(name, mine.get(name), theirs.get(name), self, other))
                else:
                    items.extend(_diff_whole(section, name, mine.get(name), theirs.get(name),
                                             self, other))
        return DraftDiff(items=tuple(items), compared=compared)


@dataclass(frozen=True)
class DiffItem:
    key: Key
    change: str                      # "added" | "removed" | "changed"
    before: Any = None
    after: Any = None
    origin_before: Optional[EntryOrigin] = None
    origin_after: Optional[EntryOrigin] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"key": list(self.key), "change": self.change,
                "before": self.before, "after": self.after,
                "origin_before": _origin_dict(self.origin_before),
                "origin_after": _origin_dict(self.origin_after)}


@dataclass(frozen=True)
class DraftDiff:
    items: Tuple[DiffItem, ...]
    compared: Dict[str, int]          # section -> number of keys compared

    @property
    def equal(self) -> bool:
        return not self.items

    def counts(self) -> Dict[str, int]:
        """``{"added": n, "removed": n, "changed": n}``."""
        counts = {"added": 0, "removed": 0, "changed": 0}
        for item in self.items:
            counts[item.change] += 1
        return counts

    def to_dict(self, *, limit: Optional[int] = None) -> Dict[str, Any]:
        """JSON form; ``truncated`` set when ``limit`` cut the item list (never silent)."""
        shown = self.items if limit is None else self.items[:max(limit, 0)]
        return {"equal": self.equal, "counts": self.counts(), "compared": dict(self.compared),
                "total": len(self.items), "truncated": len(shown) < len(self.items),
                "items": [item.to_dict() for item in shown]}


def _without_fields(user_types: Mapping[str, Dict[str, Any]],
                    drop: "set[Tuple[str, str]]") -> Dict[str, Dict[str, Any]]:
    if not drop:
        return dict(user_types)
    out: Dict[str, Dict[str, Any]] = {}
    for name, body in user_types.items():
        fields = body.get("fields") or {}
        if any((name, f) in drop for f in fields):
            body = {**body, "fields": {f: v for f, v in fields.items() if (name, f) not in drop}}
        out[name] = body
    return out


def _struct_body(struct: str, size: int, kind: str) -> Dict[str, Any]:
    _check_nonempty("struct name", struct)
    _check_int("size", size)
    if kind not in ("struct", "union"):
        raise _invalid(f"kind must be 'struct' or 'union', got {kind!r}")
    return {"name": struct, "kind": kind, "size": size}


def _field_body(struct: str, field_name: str, offset: int,
                type_descriptor: Mapping[str, Any]) -> Dict[str, Any]:
    _check_nonempty("struct name", struct)
    _check_nonempty("field name", field_name)
    _check_int("offset", offset)
    return {"struct": struct, "field": field_name, "offset": offset,
            "type": _check_type(type_descriptor)}


class IsfDraftStore:
    """Drafts of one case directory, persisted through :class:`AnalysisRecord`.

    Every mutating method appends exactly one entry (``kind=isf_draft``,
    ``author=provenance.author``, ``support`` = one ``Support("evidence", e)`` per
    evidence string, symbols located as ``Location(KERNEL_VA, address, capture_id)``)
    and returns it. Draft names are slugs; ``create`` refuses an existing name,
    every other op refuses an unknown one (CapabilityError, NOT_FOUND / INVALID_INPUT).
    """

    def __init__(self, case_dir: Path) -> None:
        self.case_dir = Path(case_dir)
        self._record = AnalysisRecord(self.case_dir)

    # -- internals -----------------------------------------------------------
    def _all(self, capture_id: str) -> List[AnalysisEntry]:
        return self._record.entries(capture_id)

    def _require_draft(self, capture_id: str, name: str) -> List[AnalysisEntry]:
        _check_name("draft name", name)
        entries = self._all(capture_id)
        if not any(e.payload.get("op") == OP_CREATE for e in _draft_entries(entries, name)):
            raise _not_found(f"no ISF draft {name!r} for capture {capture_id!r}")
        return entries

    def _last_writers(self, entries: Sequence[AnalysisEntry], name: str) -> Dict[Key, str]:
        retracted = _retracted_ids(entries, name, len(entries))
        writers: Dict[Key, str] = {}
        for entry in _draft_entries(entries, name):
            key = _single_key(entry.payload)
            if key is not None and entry.id not in retracted:
                writers[key] = entry.id
        return writers

    def _append(self, capture_id: str, name: str, op: str, provenance: Provenance,
                body: Mapping[str, Any], *, label: str, entries: Optional[Sequence[AnalysisEntry]] = None,
                locations: Tuple[Location, ...] = ()) -> AnalysisEntry:
        writers = self._last_writers(entries, name) if entries is not None else None
        return self._record.append(self._build(capture_id, name, op, provenance, body,
                                               label=label, writers=writers, locations=locations))

    @staticmethod
    def _build(capture_id: str, name: str, op: str, provenance: Provenance,
               body: Mapping[str, Any], *, label: str, writers: Optional[Mapping[Key, str]] = None,
               locations: Tuple[Location, ...] = ()) -> AnalysisEntry:
        """The entry ``_append`` files; ``writers`` (key -> last single-key writer) sets supersedes."""
        _check_provenance(provenance)
        payload: Dict[str, Any] = {"draft": name, "op": op, **body,
                                   "provenance": provenance.to_dict()}
        supersedes = None
        key = _single_key(payload) if op not in (OP_CREATE, OP_IMPORT) else None
        if key is not None and writers is not None:
            supersedes = writers.get(key)
        try:
            entry = AnalysisEntry(
                capture_id=capture_id, kind=ISF_DRAFT, author=provenance.author,
                locations=locations, label=label, payload=payload,
                support=tuple(Support("evidence", e) for e in provenance.evidence),
                supersedes=supersedes)
        except (ValueError, TypeError) as exc:
            raise _invalid(str(exc)) from exc
        return entry

    # -- lifecycle -----------------------------------------------------------
    def create(self, capture_id: str, name: str, *, arch: str, author: str = "human",
               banner: Optional[str] = None, base_metadata: Optional[Mapping[str, Any]] = None
               ) -> AnalysisEntry:
        _check_name("draft name", name)
        _check_nonempty("arch", arch)
        entries = self._all(capture_id)
        if any(e.payload.get("op") == OP_CREATE for e in _draft_entries(entries, name)):
            raise _invalid(f"ISF draft {name!r} already exists for capture {capture_id!r}",
                           "isf_draft_exists")
        body = {"arch": arch, "banner": banner, "base_metadata": dict(base_metadata or {})}
        return self._append(capture_id, name, OP_CREATE,
                            Provenance("create", "manual", author=author), body,
                            label=f"create ISF draft {name}")

    def list_drafts(self, capture_id: str) -> List[Dict[str, Any]]:
        entries = self._all(capture_id)
        out: List[Dict[str, Any]] = []
        for entry in entries:
            if entry.kind != ISF_DRAFT or entry.payload.get("op") != OP_CREATE:
                continue
            name = entry.payload["draft"]
            draft = self._replay(capture_id, name, entries, None)
            out.append({"name": name, "arch": entry.payload["arch"], "created": entry.created,
                        "version": draft.version, "state_id": draft.state_id,
                        "applied": draft.applied,
                        "counts": {s: len(getattr(draft, s)) for s in SECTIONS}})
        return out

    def versions(self, capture_id: str, name: str) -> List[Dict[str, Any]]:
        entries = self._require_draft(capture_id, name)
        retracted = _retracted_ids(entries, name, len(entries))
        out: List[Dict[str, Any]] = []
        for entry in _draft_entries(entries, name):
            payload = entry.payload
            key = _single_key(payload)
            out.append({"entry_id": entry.id, "created": entry.created, "op": payload["op"],
                        "key": list(key) if key is not None else None,
                        "blob": payload.get("blob_sha256"),
                        "provenance": payload["provenance"],
                        "retracted": entry.id in retracted})
        return out

    def materialize(self, capture_id: str, name: str, *, upto: Optional[str] = None) -> IsfDraft:
        """Replay the draft (module docstring rules); ``upto`` stops after that entry id."""
        entries = self._require_draft(capture_id, name)
        return self._replay(capture_id, name, entries, upto)

    def _replay(self, capture_id: str, name: str, entries: Sequence[AnalysisEntry],
                upto: Optional[str]) -> IsfDraft:
        cutoff = len(entries) - 1
        if upto is not None:
            cutoff = next((i for i, e in enumerate(entries) if e.id == upto
                           and (e.payload.get("draft") == name)), -1)
            if cutoff < 0:
                raise _not_found(f"entry {upto!r} is not part of ISF draft {name!r}",
                                 "isf_entry_not_found")
        retracted = _retracted_ids(entries, name, cutoff)
        draft = IsfDraft(name=name, capture_id=capture_id)
        replay = _Replay(draft, self.case_dir / DRAFTS_DIR / BLOBS_DIR)
        for entry in entries[:cutoff + 1]:
            if entry.kind == ISF_DRAFT and entry.payload.get("draft") == name \
                    and entry.id not in retracted:
                replay.apply(entry)
        return draft

    def retract(self, capture_id: str, name: str, entry_id: str, *, author: str = "human",
                reason: str = "") -> AnalysisEntry:
        entries = self._require_draft(capture_id, name)
        target = next((e for e in _draft_entries(entries, name) if e.id == entry_id), None)
        if target is None:
            raise _not_found(f"entry {entry_id!r} is not an operation of ISF draft {name!r}",
                             "isf_entry_not_found")
        if target.payload["op"] == OP_CREATE:
            raise _invalid("the create operation cannot be retracted", "isf_retract_create")
        if entry_id in _retracted_ids(entries, name, len(entries)):
            raise _invalid(f"entry {entry_id!r} is already retracted", "isf_already_retracted")
        try:
            base = retraction_of(target, author, reason)
            retraction = dataclasses.replace(
                base, payload={"draft": name, "op": "retract", "entry_id": entry_id})
        except (ValueError, TypeError) as exc:
            raise _invalid(str(exc)) from exc
        return self._record.append(retraction)

    # -- single-key ops ------------------------------------------------------
    def set_symbol(self, capture_id: str, name: str, symbol: str, address: int,
                   provenance: Provenance, *, type_descriptor: Optional[Mapping[str, Any]] = None
                   ) -> AnalysisEntry:
        entries = self._require_draft(capture_id, name)
        _check_nonempty("symbol name", symbol)
        _check_address(address)
        body: Dict[str, Any] = {"name": symbol, "address": address}
        if type_descriptor is not None:
            body["type"] = _check_type(type_descriptor)
        location = Location(AddressSpace.KERNEL_VA, address, capture_id=capture_id)
        return self._append(capture_id, name, OP_SET_SYMBOL, provenance, body,
                            label=f"symbol {symbol}", entries=entries, locations=(location,))

    def set_struct(self, capture_id: str, name: str, struct: str, size: int,
                   provenance: Provenance, *, kind: str = "struct") -> AnalysisEntry:
        entries = self._require_draft(capture_id, name)
        return self._append(capture_id, name, OP_SET_STRUCT, provenance,
                            _struct_body(struct, size, kind),
                            label=f"sizeof({struct})", entries=entries)

    def set_field(self, capture_id: str, name: str, struct: str, field_name: str, offset: int,
                  type_descriptor: Mapping[str, Any], provenance: Provenance) -> AnalysisEntry:
        """Also creates the struct (size 0, flagged ``size_unknown`` in its origin) if absent."""
        entries = self._require_draft(capture_id, name)
        body = _field_body(struct, field_name, offset, type_descriptor)
        return self._append(capture_id, name, OP_SET_FIELD, provenance, body,
                            label=f"{struct}.{field_name}", entries=entries)

    def set_base_type(self, capture_id: str, name: str, base_type: str, *, size: int,
                      signed: bool, kind: str, endian: str, provenance: Provenance) -> AnalysisEntry:
        entries = self._require_draft(capture_id, name)
        _check_nonempty("base type name", base_type)
        _check_int("size", size)
        _check_nonempty("kind", kind)
        _check_nonempty("endian", endian)
        body = {"name": base_type, "size": size, "signed": bool(signed),
                "kind": kind, "endian": endian}
        return self._append(capture_id, name, OP_SET_BASE_TYPE, provenance, body,
                            label=f"base type {base_type}", entries=entries)

    def set_enum(self, capture_id: str, name: str, enum: str, *, size: int, base: str,
                 constants: Mapping[str, int], provenance: Provenance) -> AnalysisEntry:
        entries = self._require_draft(capture_id, name)
        _check_nonempty("enum name", enum)
        _check_int("size", size)
        _check_nonempty("base", base)
        body = {"name": enum, "size": size, "base": base, "constants": dict(constants)}
        return self._append(capture_id, name, OP_SET_ENUM, provenance, body,
                            label=f"enum {enum}", entries=entries)

    def remove(self, capture_id: str, name: str, key: Key, provenance: Provenance) -> AnalysisEntry:
        entries = self._require_draft(capture_id, name)
        normalized = _normalize_key(key)
        return self._append(capture_id, name, OP_REMOVE, provenance,
                            {"key": list(normalized)},
                            label="remove " + "/".join(normalized), entries=entries)

    # -- bulk imports --------------------------------------------------------
    def import_isf(self, capture_id: str, name: str, isf: Mapping[str, Any],
                   provenance: Provenance, *, sections: Sequence[str] = SECTIONS,
                   only: Optional[Mapping[str, Sequence[str]]] = None) -> AnalysisEntry:
        """Import (a subset of) a whole ISF via a content-addressed blob.

        ``only`` = ``{"symbols": [...], "user_types": [...], ...}`` imports just
        those keys (e.g. "take ``task_struct`` from a donor"); named keys absent
        from ``isf`` are an error, never a silent partial import.
        """
        self._require_draft(capture_id, name)
        subset = _select(isf, sections, only)
        return self._append_import(capture_id, name, subset, provenance, only)

    def _append_import(self, capture_id: str, name: str, subset: Mapping[str, Any],
                       provenance: Provenance,
                       only: Optional[Mapping[str, Sequence[str]]]) -> AnalysisEntry:
        _check_provenance(provenance)
        sha = self._write_blob(_canonical_bytes(subset))
        counts = {section: len(items) for section, items in subset.items()}
        body = {"blob": f"{BLOBS_DIR}/{sha}.json", "blob_sha256": sha,
                "sections": list(subset), "counts": counts,
                "only": {k: list(v) for k, v in only.items()} if only else None}
        return self._append(capture_id, name, OP_IMPORT, provenance, body,
                            label=f"import {sum(counts.values())} ISF keys")

    def import_pakunoda_result(self, capture_id: str, name: str, result: Any,
                               provenance: Provenance) -> AnalysisEntry:
        """``result`` = a pakunoda ``PipelineResult`` (its TypeStore) or its ISF dict."""
        if isinstance(result, Mapping):
            isf: Mapping[str, Any] = result
        elif getattr(result, "type_store", None) is not None:
            isf = result.type_store.to_isf_dict()
        elif getattr(result, "isf_json", None) is not None:
            isf = result.isf_json
        elif hasattr(result, "to_isf_dict"):
            isf = result.to_isf_dict()
        else:
            raise _invalid("result has no type store or ISF dict to import",
                           "isf_import_no_store")
        return self.import_isf(capture_id, name, isf, provenance)

    def import_symbols(self, capture_id: str, name: str, addresses: Mapping[str, int],
                       provenance: Provenance) -> AnalysisEntry:
        """Bulk symbol addresses from a probe (kallsyms, ksymtab, vmcoreinfo) via a blob."""
        self._require_draft(capture_id, name)
        symbols: Dict[str, Any] = {}
        for symbol, address in addresses.items():
            _check_nonempty("symbol name", symbol)
            symbols[symbol] = {"address": _check_address(address)}
        if not symbols:
            raise _invalid("nothing to import: no symbols given", "isf_import_empty")
        return self._append_import(capture_id, name, {"symbols": symbols}, provenance, None)

    def import_layout_claims(self, capture_id: str, name: str, claims: Sequence[Any], *,
                             type_hints: Optional[Mapping[Tuple[str, str], Mapping[str, Any]]] = None,
                             author: str = "tool:pakunoda") -> List[AnalysisEntry]:
        """pakunoda ``LayoutClaim``s → one entry each (D10 1:1).

        Member claim → ``set_field`` (type from ``type_hints[(struct, member)]``,
        else an unsized placeholder ``{"kind": "base", "name": "void"}`` flagged in
        the origin); exact size claim → ``set_struct`` size; ``bound`` tier →
        ``size_bound``. Provenance = ``(claim.source, claim.tier.value,
        claim.evidence, author, claim.witnesses)``.

        One read of the record and ONE batched append (all-or-nothing: an invalid
        claim files none of them); a later claim on the same key supersedes the
        earlier one of the batch, exactly as one ``set_field``/``set_struct`` call
        per claim would.
        """
        entries = self._require_draft(capture_id, name)
        hints = type_hints or {}
        known = self._replay(capture_id, name, entries, None).user_types
        writers = self._last_writers(entries, name)
        built: List[AnalysisEntry] = []
        for claim in claims:
            entry = self._claim_entry(capture_id, name, claim, hints, known, author, writers)
            key = _single_key(entry.payload)
            if key is not None:
                writers[key] = entry.id
            built.append(entry)
        return self._record.append_many(built)

    def _claim_entry(self, capture_id: str, name: str, claim: Any,
                     hints: Mapping[Tuple[str, str], Mapping[str, Any]],
                     known: Mapping[str, Mapping[str, Any]], author: str,
                     writers: Mapping[Key, str]) -> AnalysisEntry:
        provenance = Provenance(claim.source, claim.tier.value, tuple(claim.evidence),
                                author, claim.witnesses)
        if claim.member is not None:
            hint = hints.get((claim.struct, claim.member))
            if hint is None:
                provenance = _with_evidence(provenance, _UNTYPED_EVIDENCE)
            body = _field_body(claim.struct, claim.member, claim.offset,
                               hint if hint is not None else dict(_VOID_TYPE))
            return self._build(capture_id, name, OP_SET_FIELD, provenance, body,
                               label=f"{claim.struct}.{claim.member}", writers=writers)
        if claim.tier.value == "bound":
            return self._build(capture_id, name, OP_SIZE_BOUND, provenance,
                               {"struct": claim.struct, "bound": _check_int("bound", claim.width)},
                               label=f"sizeof({claim.struct}) <= {claim.width}", writers=writers)
        kind = known.get(claim.struct, {}).get("kind", "struct")
        return self._build(capture_id, name, OP_SET_STRUCT, provenance,
                           _struct_body(claim.struct, claim.width, kind),
                           label=f"sizeof({claim.struct})", writers=writers)

    # -- blobs ---------------------------------------------------------------
    def blob_path(self, sha256: str) -> Path:
        return self.case_dir / DRAFTS_DIR / BLOBS_DIR / f"{sha256}.json"

    def _write_blob(self, data: bytes) -> str:
        sha = hashlib.sha256(data).hexdigest()
        path = self.blob_path(sha)
        if path.is_file():
            return sha
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{sha}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
        try:
            tmp.write_bytes(data)
            os.replace(tmp, path)
        finally:
            tmp.unlink(missing_ok=True)
        return sha

    def export_isf(self, capture_id: str, name: str, *, upto: Optional[str] = None,
                   out_path: Optional[Path] = None) -> Path:
        """Materialize + write the draft as an ISF file; return its path.

        See :meth:`export_draft` for the target rules.
        """
        return self.export_draft(self.materialize(capture_id, name, upto=upto), out_path=out_path)

    def export_draft(self, draft: IsfDraft, *, out_path: Optional[Path] = None) -> Path:
        """Write an already materialized draft as an ISF file; return its path.

        Default target ``<case>/isf_drafts/<capture>/<name>/<version>-<state_id>-<sha8>.isf.json``:
        content-addressed, so a file is never overwritten with different bytes
        (a recorded ``.mdview`` sha or ``isf_try`` support stays true) even when
        the same draft state exports differently (e.g. a newer MemDiver writes
        different metadata). ``out_path`` writes exactly there, but only to a NEW
        ``*.isf.json`` file outside the case's record/blob directories: an export
        never overwrites anything (``isf_export_exists``) and never lands in the
        append-only analysis record (``isf_export_target``).
        """
        data = json.dumps(draft.to_isf_dict(), sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False)
        digest = hashlib.sha256(data.encode("utf-8")).hexdigest()[:8]
        if out_path is not None:
            target = self._checked_export_target(Path(out_path))
        else:
            target = (self.case_dir / DRAFTS_DIR / draft.capture_id / draft.name
                      / f"{draft.version}-{draft.state_id}-{digest}.isf.json")
        target.parent.mkdir(parents=True, exist_ok=True)
        if out_path is None and target.exists() and target.read_text(encoding="utf-8") == data:
            return target
        self._write_atomic(target, data, exclusive=out_path is not None)
        return target

    def _checked_export_target(self, target: Path) -> Path:
        """Refuse a target that is not a fresh ``*.isf.json`` outside protected case dirs."""
        resolved = target.expanduser().resolve(strict=False)
        if not resolved.name.endswith(ISF_SUFFIX) or resolved.name == ISF_SUFFIX:
            raise _invalid(f"export out_path must end in {ISF_SUFFIX}: {target}",
                           "isf_export_target")
        if resolved.exists() or resolved.is_symlink() or target.is_symlink():
            raise _invalid(f"export target already exists (exports never overwrite): {target}",
                           "isf_export_exists")
        for case_root in self._protected_case_roots(resolved):
            for protected in (case_root / "annotations", case_root / DRAFTS_DIR / BLOBS_DIR):
                if resolved.is_relative_to(protected):
                    raise _invalid(f"export target lies inside the case record: {protected}",
                                   "isf_export_target")
        return resolved

    def _protected_case_roots(self, resolved: Path) -> List[Path]:
        """This store's case plus any case directory (has ``case.json``) above the target."""
        roots = [self.case_dir.resolve()]
        roots += [p for p in resolved.parents if (p / "case.json").is_file()]
        return roots

    @staticmethod
    def _write_atomic(target: Path, data: str, *, exclusive: bool) -> None:
        if not exclusive:
            atomic_write_text(target, data)
            return
        tmp = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
        try:
            tmp.write_text(data, encoding="utf-8")
            try:
                os.link(tmp, target)  # fails if the target appeared meanwhile
            except FileExistsError as exc:
                raise _invalid(f"export target already exists: {target}",
                               "isf_export_exists") from exc
        finally:
            tmp.unlink(missing_ok=True)
