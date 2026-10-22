"""Region categories and import-time region selection.

A *category* is a selection-only classification of a memory region. It is
derived from the stored ``RegionType`` / ``Protection`` plus side information
(thread stack ranges, module paths) and is never written back as such.

One exception keeps the stored type truthful: an ANONYMOUS region the
importer identified as a thread stack (ELF core thread SP / minidump
ThreadList) is written as ``RegionType.STACK``, so a converted ``.msl``
still knows its stacks; :class:`RegionInfo` built by the importers and the
preview already carries that stored type (:func:`stored_region_type`).
Alignment keys (``core/region_align.py``) depend on the stored
``region_type``; :func:`alignment_region_type` folds such derived STACK
regions back into the ANONYMOUS key class, so keys stay byte-identical to
``.msl`` files imported before stacks were recorded.

Why private anonymous memory counts as HEAP: no importer can see the
allocator's bookkeeping, so it never emits ``RegionType.HEAP``. On Linux the
glibc main arena lives in ``[heap]`` (anonymous in a core), and both
secondary malloc arenas and large (``mmap``-threshold) chunks are plain
anonymous mappings; on Windows every heap segment is ``MEM_PRIVATE``.
Treating ANONYMOUS as HEAP therefore captures where secrets actually live,
at the cost of also sweeping in other private anonymous mappings (JIT
buffers, thread-local arenas) — acceptable for a "where are the keys" filter.

Mapping names: when a region's name is known (``RegionInfo.name``: the maps
path column, an NT_FILE path or a trusted VAS_MAP ``mapped_path``),
:func:`memdiver.msl.region_names.classify_mapping_name` may override the
category — Android heaps (``[anon:scudo:*]``) become HEAP, thread stacks
(``[anon:stack_and_tls:*]``) STACK, and the zygote / boot-image ART runtime,
GC metadata, JIT caches and kernel / device mappings RUNTIME. RUNTIME is not
part of the default interactive selection. The stored ``region_type`` never
changes, so alignment keys do not either. Precedence: the name override
wins, except that a HEAP name on a stored SHARED_MEM region stays SHARED.
"""

from __future__ import annotations

import fnmatch
import posixpath
from dataclasses import dataclass, field
from enum import Enum
from typing import FrozenSet, Iterable, Optional, Sequence, Tuple

from .enums import Protection, RegionType, SourceFormat


class RegionCategory(str, Enum):
    """Selection category of a memory region (never stored in the file)."""

    HEAP = "heap"
    STACK = "stack"
    IMAGE_CODE = "image_code"
    IMAGE_DATA = "image_data"
    MAPPED_FILE = "mapped_file"
    SHARED = "shared"
    UNCLASSIFIED = "unclassified"
    # Appended last: zygote / boot-image ART runtime, GC metadata, JIT
    # caches, kernel / device mappings (only ever assigned by mapping name).
    RUNTIME = "runtime"


ALL_CATEGORIES: FrozenSet[RegionCategory] = frozenset(RegionCategory)
DEFAULT_INTERACTIVE_CATEGORIES: FrozenSet[RegionCategory] = frozenset({
    RegionCategory.HEAP, RegionCategory.STACK, RegionCategory.UNCLASSIFIED,
})

# Group aliases accepted by parse_selection (kept deliberately small).
_ALIASES = {
    "image": frozenset({RegionCategory.IMAGE_CODE, RegionCategory.IMAGE_DATA}),
}
_ALL_KEYWORD = "all"

StackRange = Tuple[int, int]  # (base, size)


@dataclass(frozen=True)
class RegionInfo:
    """Metadata-only view of one region, as an import would emit it."""

    base_addr: int
    size: int
    protection: int
    region_type: int
    category: RegionCategory
    module_path: Optional[str] = None
    captured_bytes: int = 0
    # Full mapping name ("[anon:scudo:primary]", "/system/lib64/libc.so");
    # None when unknown (e.g. an .msl whose names are not trusted).
    name: Optional[str] = None

    @property
    def is_writable(self) -> bool:
        return bool(self.protection & Protection.WRITE)


    def to_dict(self) -> dict:
        return {
            "base_addr": self.base_addr,
            "size": self.size,
            "protection": self.protection,
            "region_type": self.region_type,
            "category": self.category.value,
            "module_path": self.module_path,
            "captured_bytes": self.captured_bytes,
            "name": self.name,
        }


# -- classification -----------------------------------------------------------


def _overlaps(base: int, size: int, ranges: Iterable[StackRange]) -> bool:
    end = base + size
    return any(lo < end and base < lo + length for lo, length in ranges)


def _file_backed_category(region_type: int, writable: bool) -> RegionCategory:
    if writable:
        return RegionCategory.IMAGE_DATA
    if region_type == RegionType.IMAGE:
        return RegionCategory.IMAGE_CODE
    return RegionCategory.MAPPED_FILE


_STACK_CAPABLE_TYPES = frozenset({
    int(RegionType.ANONYMOUS), int(RegionType.HEAP), int(RegionType.UNKNOWN),
})


def classify(region_type: int, protection: int, base: int, size: int,
             stack_ranges: Sequence[StackRange] = (),
             module_path: Optional[str] = None,
             name: Optional[str] = None) -> RegionCategory:
    """Derive the selection category of one region (see module docstring).

    *module_path* is accepted for API symmetry; module membership is applied
    by :meth:`RegionSelection.includes` (globs), not by the category.
    *name* (full mapping name) may override the type-derived category
    (:func:`apply_name_override`).
    """
    category = _type_category(region_type, protection, base, size,
                              stack_ranges)
    return apply_name_override(category, region_type, name)


def apply_name_override(category: RegionCategory, region_type: int,
                        name: Optional[str]) -> RegionCategory:
    """*category* overridden by the mapping *name*, if the name implies one.

    A HEAP name on a stored SHARED_MEM region stays SHARED (shared memory
    is reported as such even when an allocator labelled it).
    """
    from .region_names import classify_mapping_name

    override = classify_mapping_name(name)
    if override is None:
        return category
    if override is RegionCategory.HEAP and \
            region_type == RegionType.SHARED_MEM:
        return category
    return override


def _type_category(region_type: int, protection: int, base: int, size: int,
                   stack_ranges: Sequence[StackRange]) -> RegionCategory:
    """Category from the stored type / protection / thread stacks only."""
    if region_type == RegionType.SHARED_MEM:
        return RegionCategory.SHARED
    if region_type == RegionType.STACK:
        return RegionCategory.STACK
    # A thread SP only marks private memory as a stack; file-backed
    # mappings are never stacks even if a (bogus) SP points into them.
    if (region_type in _STACK_CAPABLE_TYPES
            and _overlaps(base, size, stack_ranges)):
        return RegionCategory.STACK
    if region_type in (RegionType.HEAP, RegionType.ANONYMOUS):
        return RegionCategory.HEAP
    if region_type in (RegionType.IMAGE, RegionType.MAPPED_FILE):
        return _file_backed_category(
            region_type, bool(protection & Protection.WRITE))
    return RegionCategory.UNCLASSIFIED


def stored_region_type(region_type: int, category: RegionCategory) -> int:
    """``region_type`` an importer writes for a region of *category*.

    An ANONYMOUS region classified STACK (thread SP / ThreadList) is stored
    as STACK. Only ANONYMOUS is promoted, so :func:`alignment_region_type`
    recovers the pre-promotion key class exactly.
    """
    if (category is RegionCategory.STACK
            and region_type == RegionType.ANONYMOUS):
        return int(RegionType.STACK)
    return region_type


# Import sources whose stored region type is a writer default rather than an
# observation (a raw dump has no layout metadata at all).
_UNCLASSIFIED_SOURCE_FORMATS = frozenset({int(SourceFormat.RAW_DUMP)})


def classify_stored(region_type: int, protection: int, base: int, size: int,
                    stack_ranges: Sequence[StackRange] = (),
                    module_path: Optional[str] = None,
                    source_format: Optional[int] = None,
                    name: Optional[str] = None) -> RegionCategory:
    """Category of a region already stored in an ``.msl``.

    Like :func:`classify`, except that regions imported from a raw dump
    (IMPORT_PROVENANCE ``source_format`` == RAW_DUMP) are UNCLASSIFIED: the
    raw importer stores the writer-default ANONYMOUS type (alignment keys
    depend on it), which would otherwise read as HEAP. Used by the import
    preview and the analysis-time view filter so both agree. *name* is a
    TRUSTED mapping name (see
    :func:`memdiver.msl.import_preview.msl_classification_context`).
    """
    if source_format is not None and int(source_format) in \
            _UNCLASSIFIED_SOURCE_FORMATS:
        return RegionCategory.UNCLASSIFIED
    return classify(region_type, protection, base, size, stack_ranges,
                    module_path, name=name)


# Import sources whose STACK regions were promoted from ANONYMOUS by the
# importer (stored_region_type), not recorded by a live producer.
_DERIVED_STACK_SOURCE_FORMATS = frozenset({
    int(SourceFormat.ELF_CORE), int(SourceFormat.MINIDUMP)})


def alignment_region_type(region_type: int,
                          source_format: Optional[int]) -> int:
    """Stored type as the alignment-key class (``anon:{TYPE}:...``).

    A STACK region in an ELF-core / minidump import was ANONYMOUS before the
    importer recorded stacks, so it keys as ANONYMOUS: old and new imports of
    the same dump get identical keys and ordinals. A STACK region recorded
    by a live producer (no such provenance) keeps its own key class.
    """
    if (region_type == RegionType.STACK and source_format is not None
            and int(source_format) in _DERIVED_STACK_SOURCE_FORMATS):
        return int(RegionType.ANONYMOUS)
    return region_type


# Provenance-note keys appended after RegionSelection.to_note().
_EXCLUDED_REGIONS_KEY = "excluded_regions"
_EXCLUDED_BYTES_KEY = "excluded_bytes"
_PROVENANCE_SEPARATOR = "; "


# -- selection ----------------------------------------------------------------


def _glob_matches(path: Optional[str], globs: Sequence[str]) -> bool:
    if not path or not globs:
        return False
    name = posixpath.basename(path.replace("\\", "/"))
    return any(fnmatch.fnmatch(path, g) or fnmatch.fnmatch(name, g)
               for g in globs)


def _passes_writable(info: RegionInfo) -> bool:
    """WRITE required, except unknown-protection (0) UNCLASSIFIED regions."""
    if info.is_writable:
        return True
    return info.category is RegionCategory.UNCLASSIFIED and info.protection == 0


@dataclass(frozen=True)
class RegionSelection:
    """Which regions an import keeps.

    A region is kept when its category is selected OR its module path matches
    one of *module_globs* (fnmatch on the full path and on the basename);
    *writable_only* then drops regions without WRITE in either case, except
    UNCLASSIFIED regions with unknown (zero) protection.
    """

    categories: FrozenSet[RegionCategory]
    writable_only: bool = False
    module_globs: Tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def all(cls) -> "RegionSelection":
        return cls(ALL_CATEGORIES)

    @classmethod
    def default_interactive(cls) -> "RegionSelection":
        return cls(DEFAULT_INTERACTIVE_CATEGORIES)

    @property
    def is_all(self) -> bool:
        return (self.categories == ALL_CATEGORIES and not self.writable_only)

    def includes(self, info: RegionInfo) -> bool:
        selected = (info.category in self.categories
                    or _glob_matches(info.module_path, self.module_globs))
        if not selected:
            return False
        return _passes_writable(info) if self.writable_only else True

    def to_note(self) -> str:
        """Stable, machine-parseable form, e.g. ``regions=heap,stack``."""
        names = (_ALL_KEYWORD if self.categories == ALL_CATEGORIES
                 else ",".join(sorted(c.value for c in self.categories)))
        parts = [f"regions={names}"]
        if self.writable_only:
            parts.append("writable=1")
        if self.module_globs:
            parts.append("modules=" + "|".join(self.module_globs))
        return ";".join(parts)

    @classmethod
    def from_note(cls, note: str) -> "RegionSelection":
        """Inverse of :meth:`to_note`; raises ``ValueError`` if malformed."""
        fields = _split_note(note)
        if "regions" not in fields:
            raise ValueError(f"not a region-selection note: {note!r}")
        modules = fields.get("modules", "")
        return cls(
            categories=_parse_names(fields["regions"]),
            writable_only=fields.get("writable") == "1",
            module_globs=tuple(g for g in modules.split("|") if g),
        )


def selection_provenance_note(selection: "RegionSelection",
                              excluded_regions: int, excluded_bytes: int,
                              fallback: bool = False) -> str:
    """``to_note()`` plus exclusion totals, as stored in IMPORT_PROVENANCE."""
    parts = [selection.to_note(),
             f"{_EXCLUDED_REGIONS_KEY}={excluded_regions}",
             f"{_EXCLUDED_BYTES_KEY}={excluded_bytes}"]
    if fallback:
        parts.append(f"{_FALLBACK_KEY}=all")
    return ";".join(parts)


def join_provenance_note(base_note: str, selection_note: str) -> str:
    """Append a selection note to an importer's human-readable note."""
    if not base_note:
        return selection_note
    return f"{base_note}{_PROVENANCE_SEPARATOR}{selection_note}"


def split_provenance_note(note: str) -> Tuple[str, Optional[str]]:
    """Inverse of :func:`join_provenance_note`: (base note, selection note).

    The selection part is the LAST ``"; regions="`` segment (or the whole
    note when it starts with ``regions=``); ``(note, None)`` when absent.
    """
    if note.startswith("regions="):
        return "", note
    idx = note.rfind(_PROVENANCE_SEPARATOR + "regions=")
    if idx < 0:
        return note, None
    return note[:idx], note[idx + len(_PROVENANCE_SEPARATOR):]


def selection_from_provenance_note(note: str) -> Optional["RegionSelection"]:
    """The :class:`RegionSelection` recorded in a provenance note, if any."""
    _, selection_note = split_provenance_note(note)
    return None if selection_note is None else \
        RegionSelection.from_note(selection_note)


def _split_note(note: str) -> dict:
    fields = {}
    for part in note.strip().split(";"):
        key, sep, value = part.partition("=")
        if not sep:
            raise ValueError(f"malformed region-selection note: {note!r}")
        fields[key.strip()] = value.strip()
    return fields


def _valid_names() -> str:
    names = [c.value for c in RegionCategory] + sorted(_ALIASES) + [_ALL_KEYWORD]
    return ", ".join(names)


def _parse_name(token: str) -> FrozenSet[RegionCategory]:
    key = token.strip().lower().replace("-", "_")
    if key == _ALL_KEYWORD:
        return ALL_CATEGORIES
    if key in _ALIASES:
        return _ALIASES[key]
    try:
        return frozenset({RegionCategory(key)})
    except ValueError:
        raise ValueError(
            f"unknown region category {token.strip()!r}; "
            f"valid names: {_valid_names()}") from None


def _parse_names(spec: str) -> FrozenSet[RegionCategory]:
    tokens = [t for t in spec.split(",") if t.strip()]
    if not tokens:
        raise ValueError(f"empty region list; valid names: {_valid_names()}")
    result: FrozenSet[RegionCategory] = frozenset()
    for token in tokens:
        result |= _parse_name(token)
    return result


def parse_selection(spec: Optional[str],
                    exclude: Optional[str] = None) -> Optional[RegionSelection]:
    """Parse ``"heap,stack"`` / ``"all"`` (+ optional exclusions).

    Returns ``None`` when neither *spec* nor *exclude* is given (meaning "no
    selection requested"; callers decide the default). *exclude* alone means
    "everything except". Raises ``ValueError`` on unknown names or when the
    result selects nothing.
    """
    if spec is None and exclude is None:
        return None
    categories = ALL_CATEGORIES if spec is None else _parse_names(spec)
    if exclude is not None:
        categories = categories - _parse_names(exclude)
    if not categories:
        raise ValueError("region selection excludes every category")
    return RegionSelection(frozenset(categories))


# -- provenance-note parsing --------------------------------------------------

# Keys a materialized ``.msl`` copy appends (msl/materialize.py writes them).
MATERIALIZED_KEY = "materialized"
ORIG_EOC_HASH_KEY = "orig_eoc_hash"
DROPPED_KEY_HINTS_KEY = "dropped_key_hints"
_FALLBACK_KEY = "fallback"
# Marker segment importers append to their base note when every region's
# full mapping name is stored in the VAS_MAP (``mapped_path``): readers only
# classify by those names when this marker is present.
REGION_NAMES_KEY = "region_names"
REGION_NAMES_NOTE = f"{REGION_NAMES_KEY}=1"


@dataclass(frozen=True)
class ProvenanceNoteFields:
    """Structured view of an IMPORT_PROVENANCE ``note``.

    Every field is optional: notes written before region selection existed
    (or by other tools) simply leave them unset. ``selection`` is ``None``
    when the note records no (or an unparseable) region selection.
    """

    base_note: str = ""
    selection: Optional[RegionSelection] = None
    excluded_regions: Optional[int] = None
    excluded_bytes: Optional[int] = None
    fallback_all: bool = False
    materialized: bool = False
    orig_eoc_hash: Optional[str] = None
    dropped_key_hints: Optional[int] = None
    region_names: bool = False

    def to_dict(self) -> dict:
        """JSON-ready form shared by the CLI, REST, MCP and library surfaces."""
        sel = self.selection
        return {
            "base_note": self.base_note,
            "selected_categories": (None if sel is None else
                                    sorted(c.value for c in sel.categories)),
            "selection_all": bool(sel is not None and sel.is_all),
            "writable_only": bool(sel is not None and sel.writable_only),
            "module_globs": [] if sel is None else list(sel.module_globs),
            "excluded_regions": self.excluded_regions,
            "excluded_bytes": self.excluded_bytes,
            "fallback_all": self.fallback_all,
            "materialized": self.materialized,
            "orig_eoc_hash": self.orig_eoc_hash,
            "dropped_key_hints": self.dropped_key_hints,
            "region_names": self.region_names,
        }


def _lenient_fields(text: str) -> dict:
    """``key=value`` pairs of a ``;``-joined note; free text is ignored."""
    fields = {}
    for part in text.split(";"):
        key, sep, value = part.partition("=")
        if sep and key.strip():
            fields[key.strip()] = value.strip()
    return fields


def _optional_int(value: Optional[str]) -> Optional[int]:
    try:
        return None if value is None else int(value)
    except ValueError:
        return None


def _materialize_fields(base_note: str) -> dict:
    """Fields of the LAST ``materialized=1`` segment (the immediate source)."""
    for segment in reversed(base_note.split(_PROVENANCE_SEPARATOR)):
        fields = _lenient_fields(segment)
        if fields.get(MATERIALIZED_KEY) == "1":
            return fields
    return {}


def _has_region_names_marker(base_note: str) -> bool:
    """True when any base-note segment carries ``region_names=1``."""
    return any(_lenient_fields(segment).get(REGION_NAMES_KEY) == "1"
               for segment in base_note.split(_PROVENANCE_SEPARATOR))


def _selection_or_none(selection_note: Optional[str]) -> Optional[RegionSelection]:
    if selection_note is None:
        return None
    try:
        return RegionSelection.from_note(selection_note)
    except ValueError:
        return None


def parse_provenance_note(note: Optional[str]) -> ProvenanceNoteFields:
    """Parse an IMPORT_PROVENANCE note into :class:`ProvenanceNoteFields`.

    Never raises: an empty, foreign or malformed note yields the defaults
    (with the unparsed text kept in ``base_note``).
    """
    base_note, selection_note = split_provenance_note(note or "")
    sel_fields = _lenient_fields(selection_note or "")
    mat_fields = _materialize_fields(base_note)
    return ProvenanceNoteFields(
        base_note=base_note,
        selection=_selection_or_none(selection_note),
        excluded_regions=_optional_int(sel_fields.get(_EXCLUDED_REGIONS_KEY)),
        excluded_bytes=_optional_int(sel_fields.get(_EXCLUDED_BYTES_KEY)),
        fallback_all=sel_fields.get(_FALLBACK_KEY) == "all",
        materialized=bool(mat_fields),
        orig_eoc_hash=mat_fields.get(ORIG_EOC_HASH_KEY) or None,
        dropped_key_hints=_optional_int(mat_fields.get(DROPPED_KEY_HINTS_KEY)),
        region_names=_has_region_names_marker(base_note),
    )
