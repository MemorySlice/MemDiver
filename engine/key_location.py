"""Key location — where ONE known secret sits across N dumps, and what a
missing answer is allowed to mean.

This is the compute behind the "locate this key in my dumps" workflow: the
caller already holds the secret bytes (from a key log, a verified brute-force
hit, or a paste into the key-log composer) and wants the per-dump census of
where those bytes occur, plus one honest cross-dump verdict.

The whole point of this module is the THREE-VALUED per-dump answer:

``status == "searched"``
    The dump was opened and its whole view was searched, so ``present`` is a
    real ``True``/``False``.

``status == "unreadable"`` / ``status == "too_small"``
    Nothing was searched, so ``present`` stays ``None``. It is NOT ``False``.

A two-valued model collapses "we looked and it is not there" into "we could not
look", and a UI then paints a red absent cell over bytes nobody ever read. That
is the silent zero this module exists to prevent, which is why
:class:`DumpKeyLocation` refuses at construction time to hold a non-NULL
``present`` on a non-searched row, and why :attr:`KeyLocationResult.verdict`
has a third value :data:`VERDICT_NOT_SEARCHED` that claims NOTHING.

Why this does not import ``engine.survival_scan.DumpObservation``
-----------------------------------------------------------------
That class encodes exactly this discipline and it was tempting to reuse. Reuse
is structurally blocked, not merely inelegant:

* :data:`engine.survival_scan.MAX_HIT_COUNT` is ``1`` and its
  ``__post_init__`` *raises* for a larger ``hit_count`` — it is a presence
  probe built on ``find_first``. This module needs the full occurrence census
  (a TLS library keeps copies of one secret in its key-schedule and
  record-layer structs), so it would raise for the ordinary case here.
* Its ~20 fields *are* the ``survival`` DuckDB row (``sweep_id``, ``library``,
  ``protocol_version``, ``scenario``, ``phase``, ``run_number``…). None of that
  exists in an interactive N-dump session, and widening the row to make it fit
  would change a persisted schema.

So this module reuses the *discipline* — the invariant style of
``survival_scan.py`` — and not the class.
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

from memdiver.core.dump_source import open_dump

logger = logging.getLogger("memdiver.engine.key_location")

PathLike = Union[str, Path]

# -- per-dump status vocabulary --------------------------------------------- #

#: Opened and fully searched — ``present`` is non-NULL and may be believed.
KEY_LOCATION_SEARCHED = "searched"
#: Open/read raised — ``present`` is NULL; nothing may be claimed.
KEY_LOCATION_UNREADABLE = "unreadable"
#: The searched view is shorter than the needle — ``present`` is NULL.
KEY_LOCATION_TOO_SMALL = "too_small"

#: Every per-dump status. A caller may compare against this tuple but must
#: never invent a status of its own.
KEY_LOCATION_STATUSES = (
    KEY_LOCATION_SEARCHED,
    KEY_LOCATION_UNREADABLE,
    KEY_LOCATION_TOO_SMALL,
)

# -- cross-dump verdict vocabulary ------------------------------------------ #

#: Present in at least one searched dump.
VERDICT_FOUND = "found"
#: At least one dump was searched, and the secret was present in none of them.
VERDICT_ABSENT = "absent"
#: Zero dumps were searched. This verdict claims NOTHING — it is neither a
#: presence nor an absence, and a consumer must render it as "unknown".
VERDICT_NOT_SEARCHED = "not_searched"

#: Every cross-dump verdict.
KEY_LOCATION_VERDICTS = (VERDICT_FOUND, VERDICT_ABSENT, VERDICT_NOT_SEARCHED)

#: Context bytes per side for the located-key window a caller renders around a
#: hit (the key itself sits between the two halves).
DEFAULT_KEY_CONTEXT = 64

#: Offsets RETURNED per dump. ``hit_count`` remains the TRUE total, so a
#: truncated list never understates the census the verdict was computed from.
DEFAULT_MAX_KEY_OFFSETS = 64

#: Decimal places :attr:`KeyLocationResult.elapsed_s` is rounded to.
ELAPSED_PRECISION = 6


@dataclass(frozen=True)
class DumpKeyLocation:
    """One ``(dump, secret)`` cell: where the secret occurs in ONE dump.

    Frozen, because the row is an identity key in the result map and in the
    caller's per-dump UI and must not mutate underneath either.

    Validation raises :class:`ValueError`, not
    :class:`core.service_errors.CapabilityError`: every guard below catches a
    WRITER BUG, not user input — the same justification as
    :class:`engine.survival_scan.DumpObservation`.
    """

    dump_path: str = ""
    name: str = ""
    format_name: str = ""
    size_for_view: int = 0
    status: str = KEY_LOCATION_SEARCHED
    present: Optional[bool] = None
    first_offset: Optional[int] = None
    hit_count: int = 0
    offsets: Tuple[int, ...] = ()
    offsets_truncated: bool = False
    detail: str = ""

    def __post_init__(self) -> None:
        """Enforce the ``status`` / ``present`` / offsets invariants.

        ``present`` is non-NULL if and ONLY IF ``status == 'searched'``. That
        one biconditional is the whole capability: a non-NULL ``present`` on an
        unreadable dump is an absence claim over bytes that were never read,
        and a NULL on a searched dump is an attempt that contributes to neither
        ``=== true`` nor ``=== false`` in the consumer that renders the cell.
        """
        if self.status not in KEY_LOCATION_STATUSES:
            raise ValueError(
                "unknown key-location status " + repr(self.status)
                + "; expected one of "
                + ", ".join(repr(s) for s in KEY_LOCATION_STATUSES))
        if self.status == KEY_LOCATION_SEARCHED:
            if self.present is None:
                raise ValueError(
                    "status 'searched' requires a non-NULL present for "
                    + repr(self.dump_path)
                    + "; use status 'unreadable' or 'too_small' when the dump"
                    " could not be searched")
        elif self.present is not None:
            raise ValueError(
                "status " + repr(self.status) + " must leave present NULL for "
                + repr(self.dump_path) + "; only a searched dump may claim"
                " presence or absence")
        if bool(self.present) != (self.first_offset is not None):
            raise ValueError(
                "present " + repr(self.present) + " contradicts first_offset "
                + repr(self.first_offset) + " for " + repr(self.dump_path))
        if bool(self.present) != bool(self.hit_count):
            raise ValueError(
                "present " + repr(self.present) + " contradicts hit_count "
                + repr(self.hit_count) + " for " + repr(self.dump_path))
        if len(self.offsets) > self.hit_count:
            raise ValueError(
                "returned " + str(len(self.offsets)) + " offsets but hit_count"
                " is " + str(self.hit_count) + " for " + repr(self.dump_path)
                + "; hit_count is the TRUE total and can never be the smaller"
                " of the two")
        if self.offsets_truncated != (len(self.offsets) < self.hit_count):
            raise ValueError(
                "offsets_truncated " + repr(self.offsets_truncated)
                + " contradicts " + str(len(self.offsets)) + " of "
                + str(self.hit_count) + " offsets for " + repr(self.dump_path))
        if self.offsets:
            if self.offsets[0] != self.first_offset:
                raise ValueError(
                    "offsets[0] " + repr(self.offsets[0]) + " contradicts"
                    " first_offset " + repr(self.first_offset) + " for "
                    + repr(self.dump_path))
            if tuple(sorted(self.offsets)) != self.offsets:
                raise ValueError(
                    "offsets must be ascending for " + repr(self.dump_path)
                    + "; got " + repr(self.offsets))
        if not self.present and self.offsets:
            raise ValueError(
                "present " + repr(self.present) + " must carry no offsets for "
                + repr(self.dump_path) + "; got " + repr(self.offsets))

    @property
    def searched(self) -> bool:
        """True when this dump's ``present`` may be believed."""
        return self.status == KEY_LOCATION_SEARCHED

    def to_dict(self) -> Dict[str, Any]:
        """JSON-serialisable view. ``present`` stays ``None`` when NULL."""
        return {
            "dump_path": self.dump_path,
            "name": self.name,
            "format_name": self.format_name,
            "size_for_view": self.size_for_view,
            "status": self.status,
            "present": self.present,
            "first_offset": self.first_offset,
            "hit_count": self.hit_count,
            "offsets": list(self.offsets),
            "offsets_truncated": self.offsets_truncated,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class KeyLocationResult:
    """The cross-dump answer for ONE secret.

    Only :attr:`dumps` is stored. Every aggregate below is a ``@property``
    derived from it, so no summary can ever disagree with the rows it summarises
    — in particular ``verdict == 'absent'`` implies ``dumps_searched >= 1`` BY
    CONSTRUCTION, because the derivation cannot reach ``absent`` with an empty
    ``searched`` tuple. ``__post_init__`` re-asserts that so a hand-built
    result cannot smuggle the claim in either.

    ``dumps`` is in the caller's SUPPLIED ORDER — not sorted, not filtered — so
    a caller may zip it against its own ``dump_paths``.
    """

    needle_length: int = 0
    needle_sha256: str = ""
    view: Optional[str] = None
    dumps: Tuple[DumpKeyLocation, ...] = ()
    elapsed_s: float = 0.0

    def __post_init__(self) -> None:
        """Re-assert the verdict invariant.

        Both branches are UNREACHABLE while :attr:`verdict` stays derived — that
        is the point of deriving it. They are kept (and marked) as defence in
        depth against a future refactor that caches or stores an aggregate: the
        day ``verdict`` becomes a field, this is the guard that stops an
        ``absent`` claim over zero searched dumps from being persisted.
        """
        if self.verdict == VERDICT_ABSENT and not self.searched:  # pragma: no cover - unreachable while verdict is derived
            raise ValueError(
                "verdict 'absent' with zero searched dumps; absence may only"
                " be claimed from bytes that were actually read")
        if self.verdict not in KEY_LOCATION_VERDICTS:  # pragma: no cover - unreachable while verdict is derived
            raise ValueError("unknown verdict " + repr(self.verdict))

    # -- row partitions ----------------------------------------------------- #

    @property
    def searched(self) -> Tuple[DumpKeyLocation, ...]:
        """Rows whose ``present`` may be believed."""
        return tuple(d for d in self.dumps if d.status == KEY_LOCATION_SEARCHED)

    @property
    def present(self) -> Tuple[DumpKeyLocation, ...]:
        """Searched rows that contain the secret."""
        return tuple(d for d in self.dumps if d.present is True)

    @property
    def absent(self) -> Tuple[DumpKeyLocation, ...]:
        """Searched rows that provably do NOT contain the secret."""
        return tuple(d for d in self.dumps if d.present is False)

    @property
    def unreadable(self) -> Tuple[DumpKeyLocation, ...]:
        """Rows whose open/read raised."""
        return tuple(
            d for d in self.dumps if d.status == KEY_LOCATION_UNREADABLE)

    @property
    def too_small(self) -> Tuple[DumpKeyLocation, ...]:
        """Rows whose view is shorter than the needle."""
        return tuple(
            d for d in self.dumps if d.status == KEY_LOCATION_TOO_SMALL)

    # -- counts ------------------------------------------------------------- #

    @property
    def dumps_total(self) -> int:
        return len(self.dumps)

    @property
    def dumps_searched(self) -> int:
        return len(self.searched)

    @property
    def dumps_present(self) -> int:
        return len(self.present)

    @property
    def dumps_absent(self) -> int:
        return len(self.absent)

    @property
    def dumps_unreadable(self) -> int:
        return len(self.unreadable)

    @property
    def dumps_too_small(self) -> int:
        return len(self.too_small)

    # -- verdict ------------------------------------------------------------ #

    @property
    def verdict(self) -> str:
        """One of :data:`KEY_LOCATION_VERDICTS`.

        :data:`VERDICT_NOT_SEARCHED` if and only if nothing was searched — an
        all-unreadable set must never read as ``absent``.
        """
        if not self.searched:
            return VERDICT_NOT_SEARCHED
        return VERDICT_FOUND if self.present else VERDICT_ABSENT

    @property
    def unanimous(self) -> bool:
        """True when EVERY searched dump agrees, and at least one was searched.

        ``False`` for a mixed result and ``False`` when nothing was searched,
        so no caller can read unanimity out of silence.
        """
        searched = self.searched
        if not searched:
            return False
        return len(self.present) in (0, len(searched))

    # -- offsets ------------------------------------------------------------ #

    @property
    def anchor_offsets(self) -> Dict[str, int]:
        """``{dump_path: first_offset}`` over the present dumps only.

        This is what a caller anchors its per-dump hex window on, which is why
        it deliberately omits every row with a NULL ``present``.
        """
        return {
            d.dump_path: int(d.first_offset)
            for d in self.present
            if d.first_offset is not None
        }

    @property
    def offsets_agree(self) -> bool:
        """True when every present dump found the secret at the SAME offset.

        ``False`` when nothing is present: there is no shared offset to agree
        on, and reporting agreement over an empty set is the same silent-zero
        mistake as an absent verdict over nothing searched.
        """
        anchors = set(self.anchor_offsets.values())
        return len(anchors) == 1

    @property
    def common_offset(self) -> Optional[int]:
        """The one shared offset, or ``None`` — non-None iff offsets agree."""
        anchors = set(self.anchor_offsets.values())
        return anchors.pop() if len(anchors) == 1 else None

    @property
    def first_offset(self) -> Optional[int]:
        """Lowest offset any present dump reported, or ``None``."""
        anchors = self.anchor_offsets.values()
        return min(anchors) if anchors else None

    @property
    def total_hits(self) -> int:
        """Sum of the TRUE occurrence counts over the present dumps."""
        return sum(d.hit_count for d in self.present)

    def to_dict(self) -> Dict[str, Any]:
        """JSON-serialisable view carrying the derived summary explicitly."""
        return {
            "needle_length": self.needle_length,
            "needle_sha256": self.needle_sha256,
            "view": self.view,
            "verdict": self.verdict,
            "unanimous": self.unanimous,
            "dumps_total": self.dumps_total,
            "dumps_searched": self.dumps_searched,
            "dumps_present": self.dumps_present,
            "dumps_absent": self.dumps_absent,
            "dumps_unreadable": self.dumps_unreadable,
            "dumps_too_small": self.dumps_too_small,
            "offsets_agree": self.offsets_agree,
            "common_offset": self.common_offset,
            "first_offset": self.first_offset,
            "total_hits": self.total_hits,
            "anchor_offsets": self.anchor_offsets,
            "elapsed_s": self.elapsed_s,
            "dumps": [d.to_dict() for d in self.dumps],
        }


def _size_of_view(source: Any, view: Optional[str]) -> int:
    """Size of the view that will actually be searched.

    ``size_for`` is a :class:`core.dump_source.DumpSource` Protocol member, but
    a duck-typed source registered via ``register_dump_source`` predating it
    would only have ``size``; fall back rather than raise.

    *view* is forwarded ONLY when supplied, so ``RawDumpSource`` keeps its
    ``"raw"`` default and ``MslDumpSource`` keeps ``"vas"`` — the same contract
    as :func:`core.dump_source.find_first_in`.
    """
    size_for = getattr(source, "size_for", None)
    if callable(size_for):
        return int(size_for() if view is None else size_for(view=view))
    return int(source.size)


def locate_key_across_dumps(
    dump_paths: Sequence[PathLike],
    needle: bytes,
    *,
    view: Optional[str] = None,
    key_material: Optional[Dict[str, Any]] = None,
    max_offsets: int = DEFAULT_MAX_KEY_OFFSETS,
    on_source: Optional[Callable[[Any], None]] = None,
) -> KeyLocationResult:
    """Locate *needle* in every dump in *dump_paths*, honestly.

    Args:
        dump_paths: The dumps to search. Result rows come back in THIS order.
        needle: The secret bytes. Must be non-empty (see Raises).
        view: Byte view to search. Forwarded to the source ONLY when supplied,
            so each format keeps its own default (``"raw"`` for
            :class:`~core.dump_source.RawDumpSource` and the region-table
            sources, ``"vas"`` for :class:`~core.dump_source.MslDumpSource`).
        key_material: ``key`` / ``passphrase`` / ``kem_private_key`` kwargs
            forwarded to :func:`core.dump_source.open_dump` so encrypted
            ``.msl`` containers decrypt.
        max_offsets: How many offsets to RETURN per dump. ``hit_count`` stays
            the true total, so truncation never weakens the verdict.
        on_source: Called with each freshly opened source BEFORE anything is
            read from it. The app layer hooks its encrypted-container lock
            check in here; anything this raises propagates (see below).

    Returns:
        A :class:`KeyLocationResult` whose per-dump rows distinguish "searched
        and absent" from "never searched".

    Raises:
        ValueError: for an empty needle — unsearchable, and no absence may be
            claimed for it.
        core.service_errors.EncryptedDumpLockedError: when a locked encrypted
            container is supplied (raised by *on_source*), because then EVERY
            answer in the set is garbage.
    """
    # An empty needle is a caller error, not a query with a degenerate answer.
    # ``core.dump_io``'s find_first_offset/find_all_offsets deliberately AGREE
    # that an empty needle is a non-hit, so without this guard an empty secret
    # would come back "searched, present=False" for every dump — a fully
    # green-looking absent verdict for a secret nobody ever searched for.
    # Mirrors :func:`engine.corpus_proof.locate_secret`.
    if not needle:
        raise ValueError(
            "cannot locate an empty secret; no absence may be claimed for it")

    started = time.perf_counter()
    rows: List[DumpKeyLocation] = []
    needle_len = len(needle)
    view_kwargs: Dict[str, Any] = {} if view is None else {"view": view}

    for raw_path in dump_paths:
        path = Path(raw_path)
        dump_path = str(raw_path)
        name = path.name
        format_name = ""
        size = 0
        try:
            with open_dump(path, **(key_material or {})) as source:
                # FIRST, before any read: the caller's gate (e.g. the app
                # layer's encrypted-container lock check) must run before this
                # function can produce any row at all for this dump.
                if on_source is not None:
                    on_source(source)
                name = str(getattr(source, "name", name))
                format_name = str(getattr(source, "format_name", ""))
                size = _size_of_view(source, view)
                if size < needle_len:
                    # NOT "absent", even though absence is logically provable
                    # for a view too short to contain the needle: such a view is
                    # almost always truncated, mis-projected or half-decrypted,
                    # and painting a confident red cell from it is exactly the
                    # silent zero this model exists to prevent. Report the two
                    # sizes and claim nothing.
                    rows.append(DumpKeyLocation(
                        dump_path=dump_path,
                        name=name,
                        format_name=format_name,
                        size_for_view=size,
                        status=KEY_LOCATION_TOO_SMALL,
                        present=None,
                        detail=(
                            "the searched view exposes " + str(size)
                            + " bytes; the needle is " + str(needle_len)),
                    ))
                    continue
                # ``find_all``, NOT ``find_first``: it IS a DumpSource Protocol
                # member, and every occurrence is real — a TLS library keeps
                # copies of one secret in its key-schedule and record-layer
                # structs (see engine.truth_labels). The census feeds the
                # verdict (hit_count) AND the window anchor (offsets).
                # Never ``read_all().find()``: ``read_all`` is not a Protocol
                # member (gcore/regioned sources omit it deliberately) and
                # ``mmap.find`` defaults its start to the CURRENT file
                # position, which has already reported a real secret absent
                # (see core.dump_io.find_first_offset).
                offsets = list(source.find_all(needle, **view_kwargs))
        except (OSError, ValueError) as exc:
            # NARROW ON PURPOSE. ``EncryptedDumpLockedError`` subclasses
            # ``CapabilityError(Exception)`` and NOT ``ValueError``, so it
            # propagates straight through this handler — a locked container
            # means the caller forgot the key and every answer in the set is
            # garbage, whereas an unreadable file is one bad dump among many.
            # Same posture as engine.corpus_proof.locate_secret. This is
            # fragile: widening the tuple to ``Exception`` would silently
            # convert a forgotten key into N confident absences.
            logger.warning(
                "%s: unreadable while locating a secret (%s); claiming nothing"
                " about this dump.", dump_path, exc)
            rows.append(DumpKeyLocation(
                dump_path=dump_path,
                name=name,
                format_name=format_name,
                size_for_view=size,
                status=KEY_LOCATION_UNREADABLE,
                present=None,
                detail=str(exc),
            ))
            continue

        hit_count = len(offsets)
        kept = tuple(offsets[:max_offsets]) if offsets else ()
        rows.append(DumpKeyLocation(
            dump_path=dump_path,
            name=name,
            format_name=format_name,
            size_for_view=size,
            status=KEY_LOCATION_SEARCHED,
            present=bool(offsets),
            first_offset=offsets[0] if offsets else None,
            hit_count=hit_count,
            offsets=kept,
            offsets_truncated=hit_count > len(kept),
        ))

    return KeyLocationResult(
        needle_length=needle_len,
        needle_sha256=hashlib.sha256(needle).hexdigest(),
        view=view,
        dumps=tuple(rows),
        elapsed_s=round(time.perf_counter() - started, ELAPSED_PRECISION),
    )
