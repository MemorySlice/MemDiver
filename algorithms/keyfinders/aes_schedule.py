"""AES-128/192/256 expanded key-schedule finder (Halderman et al., 2008).

A software AES key lives in memory as its expanded schedule, and every derived
word is a fixed function of the words before it, so a schedule is recognisable
without ground truth. For each candidate offset the first derived word
``w[Nk] = w[0] ^ SubWord(RotWord(w[Nk-1])) ^ Rcon[1]`` is checked, vectorised over
a slab of offsets one byte at a time (byte 0 over every offset, bytes 1-3 over the
1/256 survivors); the rare offsets passing all four bytes are expanded in full and
scored by the fraction of derived words that match.

Two orientations are searched: ``forward`` (the FIPS-197 encryption schedule; also the
only one an AES-GCM/CTR context holds) and ``inverse`` (the OpenSSL / AES-NI
decryption schedule: round keys reversed, InvMixColumns on the middle rounds).
Each is searched in two byte orders: ``natural`` (AES-NI, ARMv8, most libraries)
and ``swapped32`` (each 32-bit word byte-reversed: OpenSSL's C ``AES_KEY``, which
stores host-endian ``u32`` round keys, on a little-endian machine; checked against
libcrypto's ``AES_set_encrypt_key``/``AES_set_decrypt_key``).
The S-box term rejects zero and constant-byte fill, so blank pages yield nothing.
The default stride is 1: keys sit at offsets that are not multiples of 4 or 8.
"""

from typing import Any, Callable, Dict, Iterable, List, NamedTuple, Optional, Sequence, Tuple

import numpy as np

from memdiver.algorithms.base import AlgorithmResult, AnalysisContext, BaseAlgorithm, Match
from memdiver.algorithms.keyfinders.aes_tables import (
    RCON, ROUNDS, SBOX_NP, XTIME_NP, expand_key, mix_column, schedule_words,
)
from memdiver.core.constants import UNKNOWN_KEY

FORWARD, INVERSE = "forward", "inverse"
ORIENTATIONS = (FORWARD, INVERSE)
NATURAL, SWAPPED32 = "natural", "swapped32"
BYTE_ORDERS = (NATURAL, SWAPPED32)
#: Key size in bits -> key length in 32-bit words (Nk).
KEY_WORDS = {128: 4, 192: 6, 256: 8}
DEFAULT_MIN_CONFIDENCE = 0.5
#: Candidate offsets per slab; temporaries are ~a dozen bytes per offset.
_SLAB = 1 << 22
_MAX_SPAN = 4 * schedule_words(8)

# A byte accessor: offset into the slab buffer -> one value per candidate offset.
Accessor = Callable[[np.ndarray, int], np.ndarray]


class Layout(NamedTuple):
    """How a schedule sits in memory: round-key order and per-word byte order."""
    orientation: str
    byte_order: str

    def byte(self, base: int, b: int) -> int:
        """Offset of byte *b* of the word stored at *base*."""
        return base + (3 - b if self.byte_order == SWAPPED32 else b)

    def word(self, raw: bytes) -> bytes:
        """A stored word in AES (natural) byte order."""
        return raw[::-1] if self.byte_order == SWAPPED32 else raw


def _word_location(layout: Layout, nk: int, k: int) -> Tuple[int, bool]:
    """(byte offset of forward word *k* inside the layout, stored mix-columned?)."""
    if layout.orientation == FORWARD:
        return 4 * k, False
    nr = ROUNDS[nk]
    r, c = divmod(k, 4)
    return 16 * (nr - r) + 4 * c, 0 < r < nr


def _prefilter_span(layout: Layout, nk: int) -> int:
    """Bytes after a candidate offset that the first-word check reads."""
    words = (0, nk - 1, nk)
    return max(_word_location(layout, nk, k)[0] for k in words) + 4


class _Slab:
    """One slab of the input with its S-box and xtime images, read by accessor."""

    def __init__(self, raw: np.ndarray) -> None:
        self.raw, self.sub, self.xtime = raw, SBOX_NP[raw], XTIME_NP[raw]

    def word_byte(self, at: Accessor, layout: Layout, nk: int, k: int, b: int) -> np.ndarray:
        base, mixed = _word_location(layout, nk, k)
        if not mixed:
            return at(self.raw, layout.byte(base, b))
        a0, a1, a2, a3 = (layout.byte(base, (b + i) % 4) for i in range(4))
        return (at(self.xtime, a0) ^ at(self.xtime, a1)
                ^ at(self.raw, a1) ^ at(self.raw, a2) ^ at(self.raw, a3))

    def sub_word_byte(self, at: Accessor, layout: Layout, nk: int, k: int,
                      b: int) -> np.ndarray:
        base, mixed = _word_location(layout, nk, k)
        if not mixed:
            return at(self.sub, layout.byte(base, b))
        return SBOX_NP[self.word_byte(at, layout, nk, k, b)]

    def first_word_byte_ok(self, at: Accessor, layout: Layout, nk: int,
                           b: int) -> np.ndarray:
        """Byte *b* of ``w[Nk] == w[0] ^ SubWord(RotWord(w[Nk-1])) ^ Rcon[1]``."""
        rhs = (self.word_byte(at, layout, nk, 0, b)
               ^ self.sub_word_byte(at, layout, nk, nk - 1, (b + 1) % 4))
        if b == 0:
            rhs = rhs ^ np.uint8(RCON[1])
        return self.word_byte(at, layout, nk, nk, b) == rhs


def _candidates(slab: _Slab, first: int, count: int, stride: int,
                layout: Layout, nk: int) -> np.ndarray:
    """Slab-relative offsets (from *first*, step *stride*) passing the first-word check."""
    def strided(arr: np.ndarray, off: int) -> np.ndarray:
        start = first + off
        return arr[start:start + (count - 1) * stride + 1:stride]

    rel = first + stride * np.flatnonzero(slab.first_word_byte_ok(strided, layout, nk, 0))
    for b in (1, 2, 3):
        if rel.size == 0:
            break
        def gathered(arr: np.ndarray, off: int, _rel: np.ndarray = rel) -> np.ndarray:
            return arr[_rel + off]
        rel = rel[slab.first_word_byte_ok(gathered, layout, nk, b)]
    return rel


def _forward_words(data: Any, offset: int, layout: Layout, nk: int) -> List[Optional[bytes]]:
    """Forward schedule words read back from *layout* (None past the end of *data*)."""
    words: List[Optional[bytes]] = []
    for k in range(schedule_words(nk)):
        base, mixed = _word_location(layout, nk, k)
        start = offset + base
        if start + 4 > len(data):
            words.append(None)
            continue
        word = layout.word(bytes(data[start:start + 4]))
        words.append(mix_column(word) if mixed else word)
    return words


def _score(data: Any, offset: int, layout: Layout, nk: int,
           min_confidence: float) -> Optional[Match]:
    words = _forward_words(data, offset, layout, nk)
    if any(w is None for w in words[:nk]):
        return None
    key = b"".join(w for w in words[:nk] if w is not None)
    expected = expand_key(key)
    derived = range(nk, len(words))
    matched = sum(1 for k in derived if words[k] == expected[4 * k:4 * k + 4])
    confidence = matched / len(derived)
    if confidence < min_confidence:
        return None
    return _match(data, offset, layout, nk, key, matched, len(derived), confidence)


def _match(data: Any, offset: int, layout: Layout, nk: int, key: bytes,
           matched: int, derived: int, confidence: float) -> Match:
    bits = nk * 32
    length = min(4 * schedule_words(nk), len(data) - offset)
    metadata: Dict[str, Any] = {
        "key_hex": key.hex(), "key_bits": bits, "orientation": layout.orientation,
        "byte_order": layout.byte_order, "matched_words": matched, "derived_words": derived,
        "key_distinct_bytes": len(set(key)),
    }
    literal = _literal_key_offset(layout, nk)
    if literal is not None:
        metadata["key_offset"] = offset + literal
    return Match(offset=offset, length=length, confidence=confidence,
                 label=f"aes{bits}_schedule", data=bytes(data[offset:offset + length]),
                 metadata=metadata)


def _literal_key_offset(layout: Layout, nk: int) -> Optional[int]:
    """Where the raw key bytes sit inside the layout, if they sit there verbatim."""
    if layout.byte_order != NATURAL:
        return None
    locations = [_word_location(layout, nk, k) for k in range(nk)]
    if any(mixed for _, mixed in locations):
        return None
    starts = [base for base, _ in locations]
    contiguous = starts == list(range(starts[0], starts[0] + 4 * nk, 4))
    return starts[0] if contiguous else None


def _slab_starts(n: int, stride: int) -> Iterable[int]:
    step = (_SLAB // stride) * stride
    return range(0, n, step)


def find_aes_schedules(data: Any, key_bits: Sequence[int] = (128, 192, 256),
                       orientations: Sequence[str] = ORIENTATIONS,
                       byte_orders: Sequence[str] = BYTE_ORDERS, stride: int = 1,
                       min_confidence: float = DEFAULT_MIN_CONFIDENCE) -> List[Match]:
    """Every AES key schedule in *data* (any buffer), sorted by offset."""
    _validate(key_bits, orientations, byte_orders, stride)
    layouts = [Layout(o, b) for o in orientations for b in byte_orders]
    buf = np.frombuffer(memoryview(data).cast("B"), dtype=np.uint8)
    n = len(buf)
    matches: List[Match] = []
    for start in _slab_starts(n, stride):
        slab = _Slab(buf[start:min(n, start + _SLAB + _MAX_SPAN)])
        for bits in key_bits:
            for layout in layouts:
                matches.extend(_slab_matches(data, slab, start, n, stride,
                                             layout, KEY_WORDS[bits], min_confidence))
    return sorted(matches, key=lambda m: (m.offset, m.label, m.metadata["orientation"],
                                          m.metadata["byte_order"]))


def _slab_matches(data: Any, slab: _Slab, start: int, n: int, stride: int,
                  layout: Layout, nk: int, min_confidence: float) -> List[Match]:
    last = min(start + _SLAB, n - _prefilter_span(layout, nk) + 1)
    if last <= start:
        return []
    count = (last - start + stride - 1) // stride
    found = []
    for rel in _candidates(slab, 0, count, stride, layout, nk).tolist():
        match = _score(data, start + rel, layout, nk, min_confidence)
        if match is not None:
            found.append(match)
    return found


def _validate(key_bits: Sequence[int], orientations: Sequence[str],
              byte_orders: Sequence[str], stride: int) -> None:
    for kind, given, allowed in (("AES key size", key_bits, tuple(KEY_WORDS)),
                                 ("orientation", orientations, ORIENTATIONS),
                                 ("byte order", byte_orders, BYTE_ORDERS)):
        unknown = [v for v in given if v not in allowed]
        if unknown or not given:
            raise ValueError(f"unsupported {kind}(s): {unknown or 'none given'}; "
                             f"choose from {list(allowed)}")
    if stride < 1:
        raise ValueError("stride must be >= 1")


class AesScheduleAlgorithm(BaseAlgorithm):
    """Find expanded AES key schedules (forward/inverse, natural/word-swapped)."""

    name = "aes_schedule"
    description = "AES-128/192/256 expanded key-schedule finder"
    mode = UNKNOWN_KEY

    def run(self, dump_data: bytes, context: AnalysisContext) -> AlgorithmResult:
        extra = context.extra
        matches = find_aes_schedules(
            dump_data,
            key_bits=extra.get("aes_key_bits", (128, 192, 256)),
            orientations=extra.get("aes_orientations", ORIENTATIONS),
            byte_orders=extra.get("aes_byte_orders", BYTE_ORDERS),
            stride=extra.get("stride", 1),
            min_confidence=extra.get("aes_min_confidence", DEFAULT_MIN_CONFIDENCE))
        best = max((m.confidence for m in matches), default=0.0)
        return AlgorithmResult(algorithm_name=self.name, confidence=best, matches=matches,
                               metadata={"schedules": len(matches)})

    def estimate_working_set(self, size: int, context: Optional[AnalysisContext] = None,
                             sample: Optional[Sequence[bytes]] = None) -> int:
        """Per-slab temporaries (raw/S-box/xtime images + check arrays), independent of size."""
        return 16 * min(size, _SLAB + _MAX_SPAN)
