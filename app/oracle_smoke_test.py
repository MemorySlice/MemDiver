"""Compose MEANINGFUL samples for the web UI's oracle smoke test.

A smoke test exists to answer one question before a sweep of millions of
candidates is launched: *does this oracle actually work?* The previous
implementation graded sixteen hard-coded synthetic byte strings, which answers
nothing — a correct oracle rejects all sixteen (they are not its key) and a
totally broken one rejects all sixteen too (it rejects everything). Both score
0 pass / 16 fail, so the grade carries no information at all.

A test only discriminates when it contains samples whose CORRECT verdict is
known in advance, and in both directions:

* one **positive control** — the run's real master key, taken from the corpus
  ``meta.json`` that owns the first selected dump. A working oracle must accept
  it. A rejection here means the oracle, its config, or the run pairing is
  wrong, and it means that *before* the sweep rather than after it returns zero
  hits with no explanation.
* N **negative controls** — real bytes read out of the dump itself at random
  offsets. A working oracle must reject every one. Acceptance here means the
  oracle says yes to arbitrary memory, so every "hit" a sweep produces would be
  noise.

Three facts shape how the negatives are drawn, and each of them is the
difference between a meaningful grade and a fabricated one:

1. **The view is load-bearing.** ``view="va"`` is a synthesized projection:
   gaps, FAILED and UNMAPPED pages and truncated run tails are all zero-filled
   by ``MslDumpSource._read_range_va``, so a "negative control" drawn there can
   be bytes the dump never captured — invented evidence, the worst answer a
   forensics tool can give. Symmetrically, raw-view offsets on an ``.msl``
   address the CONTAINER (file and block headers, the hash chain — see
   ``app/tools_consensus.py:68-89``), not process memory, so a raw draw there
   grades the oracle against file metadata. ``"vas"`` — the flattened
   captured-memory projection — is the one view whose offsets name real
   captured process bytes, so it is resolved explicitly and passed to BOTH
   ``size_for`` and ``read_range``. That is not belt and braces: the per-class
   defaults genuinely disagree (``GCoreDumpSource.size_for`` defaults to
   ``"vas"`` while its ``read_range`` defaults to ``"raw"``), so omitting the
   argument draws offsets sized against one stream and reads them out of
   another.

2. **The real key genuinely occurs in these dumps.** That is the entire premise
   of the tool. An unguarded random draw can therefore land on the key itself,
   and an oracle that correctly accepts it would be recorded as "accepts
   arbitrary noise" — a false accusation against a working oracle. Every draw is
   compared against the positive control and resampled on a match.

3. **Real memory is mostly zeroes.** A 32-byte window drawn from a live process
   image is very often a run of a single byte value, and fifteen zero-blocks
   prove nothing about an oracle's discrimination. Low-variety draws are
   resampled; they are only admitted as a last-resort top-up when the dump
   cannot supply enough varied windows, and the count is reported so the caller
   can disclose it rather than present a weakened test as a full one.

Nothing here raises. A dump outside the corpus, a run with no ``meta.json``, a
malformed key, an unreadable file or a dump smaller than the key all mean
"fewer samples to offer", reported as a named reason or caveat — exactly the
degradation contract the sibling :mod:`app.oracle_autoconfig` follows. A smoke
test that cannot compose a positive control is still a useful negative-only
test; a smoke test that 500s is not.
"""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional, Sequence, Tuple

from memdiver.app.oracle_autoconfig import _run_label, cipher_mismatch_reason
from memdiver.core.dataset_metadata import DatasetMeta
from memdiver.core.discovery import RunDiscovery
from memdiver.core.dump_source import open_dump, supported_views

logger = logging.getLogger("memdiver.app.oracle_smoke_test")

#: Views a negative control may be drawn from, most preferred first.
#: ``"va"`` is deliberately absent — it pads with synthesized ``0x00`` (fact 1
#: in the module docstring), so a sample drawn there may be invented bytes.
_NEGATIVE_VIEW_PREFERENCE: Tuple[str, ...] = ("vas", "raw")

#: A draw with fewer than this many DISTINCT byte values is treated as
#: low-entropy filler (fact 3). Eight is deliberately generous: it rejects zero
#: runs, ``0xff`` runs and small repeating patterns while keeping anything that
#: plausibly looks like data an oracle has to reason about.
_MIN_DISTINCT_BYTES = 8

#: Resampling budget per requested negative. Generous because the rejection
#: loop discards duplicates, short reads, key aliases and zero runs, and a
#: mostly-zero dump can burn a lot of draws before it yields a varied window.
_ATTEMPTS_PER_NEGATIVE = 40


@dataclass(frozen=True)
class PositiveControl:
    """The one sample a working oracle MUST accept, and where it came from."""

    sample: bytes
    source: str
    provenance_label: str


@dataclass(frozen=True)
class SmokeSamples:
    """Everything a presenter needs to run and to explain a smoke test.

    ``positive is None`` with a ``no_positive_reason`` is the ordinary outcome
    for a dump outside the corpus: the test degrades to negatives only, which
    still catches an oracle that accepts everything. ``caveats`` are the things
    that do not stop the test but change what its result means, and every one
    of them is meant to reach the analyst.
    """

    positive: Optional[PositiveControl] = None
    no_positive_reason: Optional[str] = None
    negatives: Tuple[bytes, ...] = ()
    negative_offsets: Tuple[int, ...] = ()
    key_size: int = 32
    view: str = ""
    dump_path: Optional[str] = None
    dump_format: Optional[str] = None
    dump_size: int = 0
    low_entropy_included: int = 0
    caveats: Tuple[str, ...] = ()


def compose_smoke_samples(
    source_paths: Sequence[str],
    *,
    key_size: int = 32,
    negatives: int = 15,
    include_positive_control: bool = True,
    requires_cipher: Optional[str] = None,
    seed: Optional[int] = None,
) -> SmokeSamples:
    """Build the positive and negative controls for one oracle smoke test.

    Only ``source_paths[0]`` is ever used — the same rule
    :mod:`app.oracle_autoconfig` follows, and for the same reason: the sweep
    verifies against the first source alone, each corpus run has its own
    password and therefore its own master key, so a key or a byte taken from
    any other run would be graded against an oracle that was never configured
    for it.

    ``seed`` makes the offset draw reproducible, which is what a test (and a
    "run it again" button) needs; without it the draw is unpredictable.

    Never raises: every failure mode collapses to fewer samples plus a caveat.
    """
    try:
        return _compose(
            source_paths,
            key_size=key_size,
            negatives=negatives,
            include_positive_control=include_positive_control,
            requires_cipher=requires_cipher,
            seed=seed,
        )
    except Exception:  # pragma: no cover - defence, not a code path
        logger.debug("Smoke-sample composition failed", exc_info=True)
        return SmokeSamples(
            key_size=key_size,
            caveats=("Sample composition failed, so no controls were prepared.",),
        )


# -- Internals ----------------------------------------------------------------


@dataclass(frozen=True)
class _NegativeDraw:
    """The outcome of reading negative controls out of one dump."""

    samples: Tuple[bytes, ...] = ()
    offsets: Tuple[int, ...] = ()
    view: str = ""
    dump_format: Optional[str] = None
    dump_size: int = 0
    low_entropy_included: int = 0
    caveats: Tuple[str, ...] = ()


def _compose(
    source_paths: Sequence[str],
    *,
    key_size: int,
    negatives: int,
    include_positive_control: bool,
    requires_cipher: Optional[str],
    seed: Optional[int],
) -> SmokeSamples:
    """The body of :func:`compose_smoke_samples`, free to raise."""
    if not source_paths:
        return SmokeSamples(
            key_size=key_size,
            no_positive_reason="no dump was selected",
            caveats=("No dump was selected, so no samples could be composed.",),
        )

    reference_dump = str(source_paths[0])
    caveats: List[str] = []

    positive: Optional[PositiveControl] = None
    reason: Optional[str] = None
    if include_positive_control:
        positive, reason, positive_caveats = _positive_control(
            reference_dump, key_size=key_size, requires_cipher=requires_cipher,
        )
        caveats.extend(positive_caveats)

    draw = _draw_negatives(
        reference_dump,
        key_size=key_size,
        quota=max(0, negatives),
        positive=positive,
        rng=_rng(seed),
    )
    caveats.extend(draw.caveats)

    return SmokeSamples(
        positive=positive,
        no_positive_reason=reason,
        negatives=draw.samples,
        negative_offsets=draw.offsets,
        key_size=key_size,
        view=draw.view,
        dump_path=reference_dump,
        dump_format=draw.dump_format,
        dump_size=draw.dump_size,
        low_entropy_included=draw.low_entropy_included,
        caveats=tuple(caveats),
    )


def _rng(seed: Optional[int]) -> random.Random:
    """A seeded PRNG when reproducibility was asked for, else a system one.

    ``random.Random`` is chosen deliberately and only when the caller supplies a
    seed: these numbers select OFFSETS to sample, never key material, and a
    repeatable smoke test is the whole point of the seed.
    """
    if seed is None:
        return random.SystemRandom()
    # B311 rationale (suppressed on the line below): a seeded Mersenne Twister
    # is exactly what a REPRODUCIBLE smoke test needs, and the numbers it
    # produces only choose where in the dump to read. No key, nonce, IV or
    # other security material is ever derived from them.
    #
    # The word "nosec" is deliberately kept OUT of this block: bandit scans
    # every comment for it and then treats each following word as a test id,
    # emitting one WARNING per word into `make security` output.
    return random.Random(seed)  # nosec B311


# -- Positive control ---------------------------------------------------------


def _positive_control(
    reference_dump: str, *, key_size: int, requires_cipher: Optional[str],
) -> Tuple[Optional[PositiveControl], Optional[str], List[str]]:
    """The run's real master key, or a reason there is none to offer."""
    meta = RunDiscovery.meta_for_dump(reference_dump)
    if meta is None:
        logger.debug("No meta.json owns %s; no positive control", reference_dump)
        return None, f"no meta.json owns {Path(reference_dump).name}", []

    if not meta.master_key:
        # Empty covers BOTH "the key is absent" and "the hex was malformed":
        # `core.dataset_metadata._decode_hex` returns b"" for odd-length and
        # non-hex values rather than front-padding them, because a
        # nibble-misaligned key is a WRONG key, and a wrong positive control
        # manufactures a failing grade for a working oracle.
        return None, (
            f"{_run_label(meta)}/meta.json declares no usable master key "
            f"(master_key_hex is absent or malformed)"
        ), []

    positive = PositiveControl(
        sample=meta.master_key,
        source="meta.json",
        provenance_label=_provenance_label(meta),
    )
    return positive, None, _positive_caveats(meta, key_size, requires_cipher)


def _provenance_label(meta: DatasetMeta) -> str:
    """The one-line answer to "where did this key come from?".

    Named by run DIRECTORY, like every message in :mod:`app.oracle_autoconfig`,
    so a label can be matched against the file picker without arithmetic.
    """
    return (
        f"{_run_label(meta)}/meta.json master_key_hex — "
        f"{len(meta.master_key)} bytes, cipher={meta.cipher or 'unknown'}"
    )


def _positive_caveats(
    meta: DatasetMeta, key_size: int, requires_cipher: Optional[str],
) -> List[str]:
    """What does not stop the positive control but changes what it proves."""
    caveats: List[str] = []
    if len(meta.master_key) != key_size:
        # The FULL key is kept. Truncating it to `key_size` would submit bytes
        # that are not the key, the oracle would rightly reject them, and the
        # smoke test would report a working oracle as broken.
        caveats.append(
            f"{_run_label(meta)}'s master key is {len(meta.master_key)} bytes, "
            f"not the {key_size} bytes this sweep searches for. The full key is "
            f"submitted unchanged, so the oracle is tested against the real key, "
            f"but a sweep for {key_size}-byte candidates cannot find it."
        )
    mismatch = cipher_mismatch_reason(requires_cipher, meta)
    if mismatch is not None:
        caveats.append(mismatch)
    return caveats


# -- Negative controls --------------------------------------------------------


def _draw_negatives(
    reference_dump: str,
    *,
    key_size: int,
    quota: int,
    positive: Optional[PositiveControl],
    rng: random.Random,
) -> _NegativeDraw:
    """Read *quota* real byte windows out of the dump. Never raises."""
    try:
        with open_dump(Path(reference_dump)) as source:
            return _draw_from_source(
                source,
                key_size=key_size,
                quota=quota,
                positive=positive,
                rng=rng,
            )
    except Exception as exc:  # unreadable, unparsable, or an unsupported view
        logger.debug("Cannot draw negatives from %s: %s", reference_dump, exc)
        return _NegativeDraw(caveats=(
            f"{Path(reference_dump).name} could not be read, so no negative "
            f"controls were drawn and the oracle was not tested against real "
            f"memory.",
        ))


def _draw_from_source(
    source: Any,
    *,
    key_size: int,
    quota: int,
    positive: Optional[PositiveControl],
    rng: random.Random,
) -> _NegativeDraw:
    """:func:`_draw_negatives` with the dump already open."""
    view = _negative_view(source)
    size = int(source.size_for(view))
    dump_format = str(getattr(source, "format_name", "") or "") or None
    name = Path(str(source.path)).name

    if size < key_size:
        return _NegativeDraw(
            view=view,
            dump_format=dump_format,
            dump_size=size,
            caveats=(
                f"{name} exposes {size} bytes in its {view!r} view, fewer than "
                f"the {key_size}-byte sample size, so no negative controls were "
                f"drawn.",
            ),
        )

    samples, offsets, low_entropy_included = _sample_offsets(
        source, view=view, size=size, key_size=key_size, quota=quota,
        positive=positive, rng=rng,
    )
    return _NegativeDraw(
        samples=samples,
        offsets=offsets,
        view=view,
        dump_format=dump_format,
        dump_size=size,
        low_entropy_included=low_entropy_included,
        caveats=_negative_caveats(name, len(samples), quota, low_entropy_included),
    )


def _negative_view(source: Any) -> str:
    """The ONE view every negative control is sized and read in (fact 1).

    ``"vas"`` — the flattened captured-memory projection — is preferred because
    it is the only view whose offsets name real captured process bytes on every
    format that has a region table. ``"raw"`` is the fallback for a flat dump,
    where the two views coincide anyway. ``"va"`` is never chosen: it pads
    unmapped space with synthesized ``0x00``, so a sample drawn there could be
    bytes the dump never captured.

    Asked through the module-level :func:`core.dump_source.supported_views`
    helper rather than off the ``DumpSource`` Protocol, which is
    ``runtime_checkable`` and must not grow members.
    """
    views = supported_views(source)
    for candidate in _NEGATIVE_VIEW_PREFERENCE:
        if candidate in views:
            return candidate
    return _NEGATIVE_VIEW_PREFERENCE[-1]


def _sample_offsets(
    source: Any,
    *,
    view: str,
    size: int,
    key_size: int,
    quota: int,
    positive: Optional[PositiveControl],
    rng: random.Random,
) -> Tuple[Tuple[bytes, ...], Tuple[int, ...], int]:
    """Draw distinct, varied, non-aliasing windows; top up if the dump is thin.

    Returns ``(samples, offsets, low_entropy_included)``. The three rejection
    rules are applied in a fixed order — length, then key aliasing, then variety
    — so that anything parked in the low-entropy reserve has ALREADY passed the
    first two, and the top-up pass can admit it without re-checking.
    """
    samples: List[bytes] = []
    offsets: List[int] = []
    reserve: List[Tuple[int, bytes]] = []
    seen: set[int] = set()
    # Inclusive upper bound: `size - key_size` is the last offset at which a
    # full sample still fits, so a draw can never run off the tail.
    highest = size - key_size
    attempts = 0
    max_attempts = quota * _ATTEMPTS_PER_NEGATIVE

    while len(samples) < quota and attempts < max_attempts:
        attempts += 1
        offset = rng.randrange(0, highest + 1)
        if offset in seen:
            continue
        seen.add(offset)
        data = source.read_range(offset, key_size, view=view)
        if len(data) != key_size:
            continue  # short read at a captured-run boundary: not a full sample
        if positive is not None and data == positive.sample:
            continue  # the real key really is in here (fact 2)
        if len(set(data)) < _MIN_DISTINCT_BYTES:
            reserve.append((offset, data))  # fact 3: a zero run proves nothing
            continue
        samples.append(data)
        offsets.append(offset)

    low_entropy_included = 0
    for offset, data in reserve:
        if len(samples) >= quota:
            break
        samples.append(data)
        offsets.append(offset)
        low_entropy_included += 1

    return tuple(samples), tuple(offsets), low_entropy_included


def _negative_caveats(
    name: str, drawn: int, quota: int, low_entropy_included: int,
) -> Tuple[str, ...]:
    """Disclose a weakened negative set; empty when the draw was clean."""
    caveats: List[str] = []
    if low_entropy_included:
        caveats.append(
            f"{low_entropy_included} of the {drawn} negative controls are "
            f"low-variety byte runs (mostly repeated values) because {name} "
            f"could not supply enough varied windows. Rejecting those proves "
            f"less about the oracle than rejecting real-looking data does."
        )
    if drawn < quota:
        caveats.append(
            f"Only {drawn} of the {quota} requested negative controls could be "
            f"drawn from {name}."
        )
    return tuple(caveats)
