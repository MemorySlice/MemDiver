"""Truth-label locators — where the real keys actually are in a dump.

A detector report is only as trustworthy as the truth set it is scored
against, so this module keeps the two available truth sources explicit and
visibly distinct via :attr:`TruthInterval.source`:

``"keylog"`` (:func:`locate_keylog_truth`) — **the authoritative truth set.**
    Every corpus run ships a ``keylog.csv`` listing every secret that existed
    in that TLS session (see :meth:`core.keylog.KeylogParser.parse`). Because
    the secret *bytes* are known, the true byte offsets are computable exactly
    by substring search over the dump — the truth set is therefore complete by
    construction, and a detector that misses a key is genuinely charged a false
    negative.

``"ledger"`` (:func:`ledger_truth`) — **corroboration only.**
    The DuckDB ``ground_truth`` table (written by
    :meth:`engine.project_db.ProjectDB.persist_ground_truth`) records the hits
    a *previous run of the tooling* confirmed. It is opt-in
    (``persist_ground_truth=False`` by default), therefore sparse, and it only
    ever contains offsets some earlier sweep already visited — so it is
    stride-dependent. Recall measured against it is silently **inflated**: a
    truth nobody ever recorded can never be counted as a miss. Use it to
    cross-check keylog truth, never as the denominator of a recall claim.

Both *locators* are pure compute: no file IO, no database access. Reading the
keylog and opening the dump are the caller's job — except through the one
convenience entry point below.

:func:`corroborate` is how the ledger is meant to be used: it intersects a
ledger set with the keylog set, reports :attr:`CorroboratedTruth.
ledger_corroborated_truths`, and stamps a set-level ``truth_source`` tri-state
(``"keylog"`` / ``"ledger"`` / ``"both"``) alongside the per-interval
:attr:`TruthInterval.source`. Ledger-only intervals are *counted*, never merged
into the returned set, so corroboration can never grow a recall denominator.

:func:`truth_for_dump` (and :func:`keylog_secrets_for_run`) is the one place
that does touch the filesystem: it wires ``keylog.csv`` -> secrets -> open dump
-> intervals for a single ``(run, dump)`` pair, and — the point of it — carries
the keylog's parse status (:data:`core.keylog.KEYLOG_STATUSES`) out with the
result. A keylog that failed to parse yields zero secrets, which a survival
sweep would otherwise render exactly like a genuine post-KeyUpdate gap; the
status is what keeps a parse failure and a real absence distinguishable.

Why not :func:`core.dump_search.DumpSearcher.search_secrets`? That existing
helper does find every occurrence of every secret, but it is ``DumpReader``-
based, so it only ever sees the *raw* byte view — it cannot address the
``"vas"``/``"va"`` projections that :class:`core.dump_source.MslDumpSource`
exposes and that scanners actually run against, which would silently mis-locate
truth for ``.msl`` inputs. It also materialises ``ctx``-byte context windows
(0x100 bytes before *and* after every hit) into :class:`core.models.KeyOccurrence`
objects; nothing in a precision/recall computation reads those bytes, and at
corpus scale they are pure allocation. :func:`locate_keylog_truth` goes through
the ``DumpSource`` ``find_all`` contract instead and keeps only the interval.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from memdiver.core.keylog import (
    KEYLOG_STATUS_OK,
    KeylogParseResult,
    parse_keylog_with_status,
)
from memdiver.core.models import CryptoSecret

logger = logging.getLogger("memdiver.engine.truth_labels")

#: Accepted spellings of the ledger's key-bytes column, in precedence order.
#: The ``ground_truth`` table declares the column ``key_hex``
#: (``engine/project_db.py`` schema), but
#: :meth:`~engine.project_db.ProjectDB.persist_ground_truth` populates that same
#: column from each hit's ``value_hex`` key, and
#: :meth:`~engine.project_db.ProjectDB.record_ground_truth_run` normalises
#: brute-force hits (which carry ``key_hex``) onto ``value_hex`` on the way in.
#: So depending on whether a row came straight out of the table or out of one of
#: the in-flight hit dicts, the key bytes live under a different name. Rather
#: than guess which layer a caller is handing us, accept either and document the
#: confusion.
LEDGER_KEY_HEX_FIELDS = ("key_hex", "value_hex")

SOURCE_KEYLOG = "keylog"
SOURCE_LEDGER = "ledger"

#: Set-level truth provenance, used only by :class:`CorroboratedTruth`. A single
#: :class:`TruthInterval` is always ``"keylog"`` or ``"ledger"``; ``"both"``
#: describes a *set* that carries keylog truth corroborated by ledger rows —
#: at least one row that actually agreed, never the mere presence of rows.
SOURCE_BOTH = "both"

#: The exact tri-state, in the order a set degrades from authoritative to
#: corroboration-only. Callers compare against these; nothing invents a fourth.
TRUTH_SOURCES = (SOURCE_KEYLOG, SOURCE_LEDGER, SOURCE_BOTH)

#: Filename every corpus run uses for its session key log.
DEFAULT_KEYLOG_FILENAME = "keylog.csv"


@dataclass(frozen=True)
class TruthInterval:
    """One known-true key location: ``[start, start + length)`` bytes.

    ``source`` is either ``"keylog"`` (computed from the session key log — the
    complete truth set) or ``"ledger"`` (read back from the opt-in DuckDB
    ``ground_truth`` table — corroboration only). It is carried on every
    interval so a mixed truth set can never launder ledger corroboration into a
    recall denominator; see the module docstring.
    """

    start: int
    length: int
    secret_type: str
    key_hex: str
    client_random: str
    source: str

    def to_dict(self) -> dict:
        """JSON-serialisable view of this interval."""
        return {
            "start": self.start,
            "length": self.length,
            "secret_type": self.secret_type,
            "key_hex": self.key_hex,
            "client_random": self.client_random,
            "source": self.source,
        }


def _as_hex(value: Any) -> str:
    """Render ``bytes``/``bytearray`` as hex; pass strings through."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    return "" if value is None else str(value)


def _sort_key(interval: TruthInterval) -> tuple:
    return (interval.start, interval.secret_type)


def locate_keylog_truth(
    source: Any,
    secrets: Iterable[Any],
    *,
    view: Optional[str] = None,
) -> List[TruthInterval]:
    """Locate every occurrence of every keylog *secret* inside *source*.

    Args:
        source: An open :class:`core.dump_source.DumpSource` (anything with a
            ``find_all(needle, view=...)`` method).
        secrets: :class:`core.models.CryptoSecret` objects, e.g. from
            :meth:`core.keylog.KeylogParser.parse`.
        view: Byte view to search. Forwarded **only when supplied**, so each
            source keeps its own default view (``"raw"`` for
            :class:`~core.dump_source.RawDumpSource` and the region-table
            sources, ``"vas"`` for :class:`~core.dump_source.MslDumpSource`) —
            same contract as :func:`core.dump_source.find_first_in`.

    Returns:
        Every occurrence, as ``source="keylog"`` intervals sorted by
        ``(start, secret_type)`` for determinism.

    This uses ``find_all``, **not** ``find_first``: a secret legitimately
    appears more than once in a live process (TLS libraries keep copies of the
    same secret inside their own key-schedule and record-layer structs), and
    **every one of those occurrences is a real truth** a detector could
    legitimately fire on. Keeping only the first would understate recall for
    every detector that happens to find a later copy.

    Secrets with an empty ``secret_value`` are skipped: an empty needle matches
    at every offset, which would flood the truth set and drive recall to
    nonsense.
    """
    kwargs = {} if view is None else {"view": view}
    intervals: List[TruthInterval] = []

    for secret in secrets:
        needle = getattr(secret, "secret_value", b"") or b""
        if not needle:
            logger.debug(
                "Skipping secret with empty secret_value: %s",
                getattr(secret, "secret_type", "?"),
            )
            continue
        offsets = source.find_all(needle, **kwargs)
        secret_type = getattr(secret, "secret_type", "") or ""
        key_hex = _as_hex(needle)
        client_random = _as_hex(getattr(secret, "identifier", b""))
        for offset in offsets:
            intervals.append(TruthInterval(
                start=int(offset),
                length=len(needle),
                secret_type=secret_type,
                key_hex=key_hex,
                client_random=client_random,
                source=SOURCE_KEYLOG,
            ))

    intervals.sort(key=_sort_key)
    return intervals


def _ledger_key_hex(row: Mapping[str, Any]) -> str:
    """Read the key bytes out of a ledger row under either accepted spelling."""
    for column in LEDGER_KEY_HEX_FIELDS:
        value = row.get(column)
        if value:
            return _as_hex(value)
    return ""


def _ledger_length(row: Mapping[str, Any], key_hex: str) -> Tuple[int, bool]:
    """Resolve a ledger row's byte extent as ``(length, overridden)``.

    The key bytes win. A row's ``length`` is bookkeeping; the key it carries is
    evidence, so the width implied by *key_hex* is used whenever the row's own
    ``length`` is **absent or disagrees with that key**, and ``overridden`` says
    which happened (only a disagreement counts as an override).

    A disagreement is not cosmetic. :func:`corroborate` keys on
    ``(start, length)``, so a row recorded as ``length=48`` around a 32-byte key
    can never match the keylog interval ``(start, 32)`` describing those same
    bytes: the corroboration is silently lost and ``ledger_only_truths`` — which
    is supposed to mean "the ledger saw something keylog truth didn't" — is
    inflated by a row that saw exactly what keylog truth saw. In the ledger-only
    fallback the same row is scored as a 48-byte truth over a 32-byte key.

    ``length=0`` beside a real key is the same class of disagreement and is
    likewise recovered as the key width rather than dropped — the key implies a
    perfectly good extent. Only a row whose extent *nothing* attests (no key
    bytes, and a ``length`` that is absent or non-positive) is left ``<= 0``
    for :func:`ledger_truth` to drop.
    """
    key_width = len(key_hex) // 2
    length = row.get("length")
    if length is None:
        return key_width, False
    length = int(length)
    if key_width and length != key_width:
        return key_width, True
    return length, False


def ledger_truth(rows: Sequence[Mapping[str, Any]]) -> List[TruthInterval]:
    """Normalise DuckDB ``ground_truth`` rows into ``source="ledger"`` intervals.

    Args:
        rows: Mappings as returned by
            :meth:`engine.project_db.ProjectDB.list_ground_truth` (or the hit
            dicts fed to ``persist_ground_truth``).

    Accepts the key bytes under **either** ``key_hex`` or ``value_hex`` — see
    :data:`LEDGER_KEY_HEX_FIELDS` for why both spellings occur in practice.
    Rows without an ``offset`` are dropped: an interval with no start cannot be
    scored. ``length`` falls back to the width implied by the key hex whenever
    the row's own value is absent **or contradicted by that key** — the key
    bytes are the evidence and always win, including over an explicit ``0``,
    which is why such a row is recovered rather than dropped (see
    :func:`_ledger_length` for why a contradicted length silently destroys the
    corroboration it should have produced).

    Rows that resolve to a **non-positive length are dropped for the identical
    reason**: an interval with no extent cannot be scored either. A row carrying
    neither key field and no explicit ``length`` lands on ``length == 0``, and a
    zero-length truth is not merely useless — it is actively corrupting.
    :func:`engine.detector_metrics._containment_pairs` tests
    ``start <= t_start and t_start + length <= end``, which for ``length == 0``
    is satisfied by *any* match window covering the start: the junk row counts
    as a covered truth **and** promotes the match to a true positive, inflating
    recall and precision at once.

    Output is sorted by ``(start, secret_type)``. Remember these intervals are
    corroboration, not a recall denominator (module docstring).
    """
    intervals: List[TruthInterval] = []
    dropped_zero_length = 0
    overridden_lengths = 0
    for row in rows:
        offset = row.get("offset")
        if offset is None:
            logger.debug("Skipping ledger row without an offset: %r", row)
            continue
        key_hex = _ledger_key_hex(row)
        length, overridden = _ledger_length(row, key_hex)
        if overridden:
            overridden_lengths += 1
            logger.debug(
                "Ledger row length %r contradicts its %d-byte key; using the "
                "key width: %r", row.get("length"), length, row)
        if length <= 0:
            dropped_zero_length += 1
            logger.debug("Skipping ledger row with non-positive length: %r", row)
            continue
        intervals.append(TruthInterval(
            start=int(offset),
            length=length,
            secret_type=str(row.get("secret_type") or ""),
            key_hex=key_hex,
            client_random=_as_hex(row.get("client_random")),
            source=SOURCE_LEDGER,
        ))
    if dropped_zero_length:
        logger.warning(
            "Dropped %d ledger row(s) with a non-positive length; a zero-length "
            "truth is trivially 'contained' by any match window and would "
            "inflate both recall and precision.",
            dropped_zero_length,
        )
    if overridden_lengths:
        logger.warning(
            "Overrode %d ledger row length(s) that contradicted the row's own "
            "key bytes; the key width wins, because a span that disagrees with "
            "the key can never corroborate the keylog interval covering the "
            "same bytes.",
            overridden_lengths,
        )
    intervals.sort(key=_sort_key)
    return intervals


# --------------------------------------------------------------------------- #
# Corroboration — the documented use for ledger truth
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class CorroboratedTruth:
    """A truth set plus how much of it the ledger independently confirms.

    ``intervals`` is what a scorer should use as its truth set, and it is
    **never** keylog truth widened by ledger rows: when keylog truth exists it is
    returned verbatim, and ledger rows only ever contribute the
    ``ledger_corroborated_truths`` / ``ledger_only_truths`` counts. Only when
    there is no keylog truth at all does the set fall back to the ledger — and
    then ``truth_source`` says ``"ledger"``, which is a caller's cue that no
    recall claim may be made from it (module docstring).
    """

    intervals: List[TruthInterval] = field(default_factory=list)
    truth_source: str = SOURCE_KEYLOG
    keylog_truths: int = 0
    ledger_truths: int = 0
    ledger_corroborated_truths: int = 0
    ledger_only_truths: int = 0

    @property
    def corroboration_rate(self) -> float:
        """Fraction of keylog truths the ledger confirms; ``0.0`` when vacuous."""
        return (self.ledger_corroborated_truths / self.keylog_truths
                if self.keylog_truths else 0.0)

    @property
    def is_scorable(self) -> bool:
        """True only when the set rests on keylog truth (a real denominator)."""
        return self.truth_source in (SOURCE_KEYLOG, SOURCE_BOTH) and bool(self.intervals)

    def to_dict(self) -> dict:
        """JSON-serialisable view; ``intervals`` become interval dicts."""
        return {
            "intervals": [i.to_dict() for i in self.intervals],
            "truth_source": self.truth_source,
            "keylog_truths": self.keylog_truths,
            "ledger_truths": self.ledger_truths,
            "ledger_corroborated_truths": self.ledger_corroborated_truths,
            "ledger_only_truths": self.ledger_only_truths,
            "corroboration_rate": self.corroboration_rate,
        }


def _span(interval: TruthInterval) -> Tuple[int, int]:
    """The byte extent that identifies an interval across the two sources."""
    return (interval.start, interval.length)


def _keys_agree(a: TruthInterval, b: TruthInterval) -> bool:
    """Whether two intervals' key bytes are compatible.

    A ledger row may carry no key bytes at all (the column is nullable), so an
    empty ``key_hex`` on either side abstains rather than vetoing the match;
    two *present* and *different* keys at the same span are a genuine conflict.
    """
    if not a.key_hex or not b.key_hex:
        return True
    return a.key_hex.lower() == b.key_hex.lower()


def corroborate(
    keylog_intervals: Sequence[TruthInterval],
    ledger_intervals: Sequence[TruthInterval],
) -> CorroboratedTruth:
    """Intersect keylog truth with ledger truth; report the agreement.

    Args:
        keylog_intervals: Output of :func:`locate_keylog_truth` — the
            authoritative, complete-by-construction truth set.
        ledger_intervals: Output of :func:`ledger_truth` — sparse,
            stride-dependent corroboration.

    Returns:
        A :class:`CorroboratedTruth` whose ``truth_source`` is exactly one of
        ``"keylog"`` (no ledger rows, **or** ledger rows that corroborated
        nothing), ``"ledger"`` (ledger rows only — not a recall denominator),
        or ``"both"`` (at least one keylog truth the ledger actually confirms).
        ``"both"`` therefore means what the module docstring says it means —
        keylog truth *corroborated by* ledger rows — and never merely "ledger
        rows were also supplied": a consumer branching on it must not be told a
        set was cross-checked when the ledger disagreed with all of it. With
        neither source present the result is an empty ``"keylog"`` set: an empty
        truth set is a vacuous keylog set, never an attribution to the ledger.

    Two intervals corroborate when they cover the **same byte span**
    ``(start, length)`` and their key bytes do not conflict (see
    :func:`_keys_agree`). Span equality rather than overlap is deliberate: the
    ledger records offsets an earlier sweep confirmed, so a real corroboration
    is byte-identical, and accepting overlap would let a stride artifact one byte
    away launder itself into agreement.
    """
    keylog = list(keylog_intervals)
    ledger = list(ledger_intervals)

    by_span: Dict[Tuple[int, int], List[int]] = {}
    for j, interval in enumerate(ledger):
        by_span.setdefault(_span(interval), []).append(j)

    matched: Set[int] = set()
    corroborated = 0
    for truth in keylog:
        agreeing = [j for j in by_span.get(_span(truth), ())
                    if _keys_agree(truth, ledger[j])]
        if agreeing:
            corroborated += 1
            matched.update(agreeing)

    if keylog:
        # ``both`` is an agreement claim, not a "two inputs were supplied"
        # claim: it is what tells a consumer the set was independently
        # cross-checked. Ledger rows that corroborate nothing — a stride
        # artifact one byte off, or a row whose key actively conflicts at the
        # same span — leave the set exactly as authoritative, and no more, than
        # keylog truth alone, so it stays ``keylog``.
        truth_source = SOURCE_BOTH if corroborated else SOURCE_KEYLOG
    elif ledger:
        truth_source = SOURCE_LEDGER
    else:
        truth_source = SOURCE_KEYLOG

    intervals = keylog if keylog else sorted(ledger, key=_sort_key)
    return CorroboratedTruth(
        intervals=intervals,
        truth_source=truth_source,
        keylog_truths=len(keylog),
        ledger_truths=len(ledger),
        ledger_corroborated_truths=corroborated,
        ledger_only_truths=len(ledger) - len(matched),
    )


# --------------------------------------------------------------------------- #
# Per-(run, dump) entry point — the one place that touches the filesystem
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class DumpTruth:
    """Truth for one ``(run, dump)`` pair, with the keylog's parse status.

    ``keylog_status`` is one of :data:`core.keylog.KEYLOG_STATUSES`. It must be
    consulted before reading anything into ``secrets_available == 0``: only
    ``"ok"`` (and, with a caveat, ``"partial"``) means "this session really did
    log this many secrets". ``"missing"`` / ``"unreadable"`` mean the denominator
    is unknown, which is a different cell from a genuine absence.

    ``keylog_rows_read`` / ``keylog_rows_malformed`` carry the parser's own
    counters through, because the status is a verdict and these are the
    evidence behind it. ``keylog_rows_read`` in particular is the *only*
    surviving signal that separates "the file held nothing" from "the file held
    rows this build could make nothing of": both land on
    ``secrets_available == 0``, and only ``keylog_rows_read > 0`` says content
    was there. ``keylog_rows_malformed`` then says how much of it was lost.
    """

    dump_path: str = ""
    keylog_path: str = ""
    keylog_status: str = KEYLOG_STATUS_OK
    keylog_detail: str = ""
    keylog_rows_read: int = 0
    keylog_rows_malformed: int = 0
    secrets: List[CryptoSecret] = field(default_factory=list)
    intervals: List[TruthInterval] = field(default_factory=list)

    @property
    def secrets_available(self) -> int:
        """How many distinct secrets the keylog offered as truth."""
        return len(self.secrets)

    @property
    def truth_is_known(self) -> bool:
        """True when the keylog parsed cleanly, so a zero really means zero."""
        return self.keylog_status == KEYLOG_STATUS_OK

    def to_dict(self) -> dict:
        """JSON-serialisable view; ``secrets`` are summarised by type."""
        return {
            "dump_path": self.dump_path,
            "keylog_path": self.keylog_path,
            "keylog_status": self.keylog_status,
            "keylog_detail": self.keylog_detail,
            "keylog_rows_read": self.keylog_rows_read,
            "keylog_rows_malformed": self.keylog_rows_malformed,
            "secrets_available": self.secrets_available,
            "secret_types": sorted({s.secret_type for s in self.secrets}),
            "truth_is_known": self.truth_is_known,
            "intervals": [i.to_dict() for i in self.intervals],
        }


def _parse_run_keylog(
    run_dir: Any, keylog_filename: str, template: Any,
) -> KeylogParseResult:
    """Parse ``<run_dir>/<keylog_filename>``, logging anything short of ``ok``."""
    keylog_path = Path(run_dir) / keylog_filename
    result = parse_keylog_with_status(keylog_path, template=template)
    if result.status != KEYLOG_STATUS_OK:
        logger.warning(
            "Keylog %s parsed as %r (%s): %d secret(s) recovered.",
            keylog_path, result.status, result.detail or "no detail",
            len(result.secrets),
        )
    return result


def keylog_secrets_for_run(
    run_dir: Any,
    *,
    keylog_filename: str = DEFAULT_KEYLOG_FILENAME,
    template: Any = None,
) -> Tuple[List[CryptoSecret], str]:
    """Read one run directory's key log as ``(secrets, parse_status)``.

    Args:
        run_dir: The run directory holding *keylog_filename*.
        keylog_filename: Overridable for non-default corpora.
        template: Optional protocol template restricting the accepted secret
            types, forwarded to :func:`core.keylog.parse_keylog_with_status`.

    Returns:
        The parsed secrets and the typed status. ``([], "missing")`` and
        ``([], "unreadable")`` are **not** the same fact as ``([], "ok")``: the
        first two mean the denominator is unknown, the last means the session
        genuinely logged nothing. Collapsing them is exactly the bug this
        function exists to prevent.

        The tuple shape is deliberately unchanged. A caller that also needs the
        parser's counters — ``rows_read`` is what separates "the file held
        nothing" from "the file held rows nothing could be made of" — should
        read :attr:`DumpTruth.keylog_rows_read` from :func:`truth_for_dump`, or
        call :func:`core.keylog.parse_keylog_with_status` directly.
    """
    result = _parse_run_keylog(run_dir, keylog_filename, template)
    return list(result.secrets), result.status


def truth_for_dump(
    run_dir: Any,
    dump_path: Any,
    *,
    view: Optional[str] = None,
    keylog_filename: str = DEFAULT_KEYLOG_FILENAME,
    template: Any = None,
) -> DumpTruth:
    """Locate one dump's truth intervals from its own run's key log.

    Wires the three steps every caller was hand-assembling — parse the keylog,
    open the dump, :func:`locate_keylog_truth` — and carries the keylog parse
    status out with the result so a parse failure never reads as an absence.

    Args:
        run_dir: The run directory (supplies ``keylog.csv``).
        dump_path: The dump to search. Opened and closed here.
        view: Byte view, forwarded only when supplied — same contract as
            :func:`locate_keylog_truth`.
        keylog_filename: Overridable for non-default corpora.
        template: Optional protocol template restricting the secret types.

    Returns:
        A :class:`DumpTruth`. When the keylog yields no secrets the dump is not
        opened at all (there is nothing to search for) and ``intervals`` is
        empty — read ``keylog_status`` to learn whether that is a real zero.

    Raises:
        OSError: If *dump_path* cannot be opened. A missing dump is the
            caller's enumeration bug, not a truth-set outcome, so it is not
            flattened into an empty result the way a missing keylog is.
    """
    parsed = _parse_run_keylog(run_dir, keylog_filename, template)
    secrets = list(parsed.secrets)
    result = DumpTruth(
        dump_path=str(dump_path),
        keylog_path=str(Path(run_dir) / keylog_filename),
        keylog_status=parsed.status,
        keylog_detail=parsed.detail,
        keylog_rows_read=parsed.rows_read,
        keylog_rows_malformed=parsed.rows_malformed,
        secrets=secrets,
    )
    if not secrets:
        return result

    # Imported lazily: everything above this line is pure compute, and callers
    # that only score pre-located intervals should not pay for the dump-source
    # registry (and its optional format backends) at import time.
    from memdiver.core.dump_source import open_dump

    with open_dump(Path(dump_path)) as source:
        intervals = locate_keylog_truth(source, secrets, view=view)

    return DumpTruth(
        dump_path=result.dump_path,
        keylog_path=result.keylog_path,
        keylog_status=result.keylog_status,
        keylog_detail=result.keylog_detail,
        keylog_rows_read=result.keylog_rows_read,
        keylog_rows_malformed=result.keylog_rows_malformed,
        secrets=secrets,
        intervals=intervals,
    )

