"""Turning what an analyst TYPED into the bytes to search for.

One search box, several ways of spelling a needle. An analyst hunting a secret
does not always hold it as hex: it may be a literal string (``-----BEGIN``), a
wide string the process stored as UTF-16LE, a base64 blob pasted out of a
key-log or a JSON config, or a pointer value they read off another pane. Every
one of those is the same question — "where does this byte sequence live?" — and
:meth:`DumpSource.find_all` has always taken plain ``bytes``, so the only thing
that was ever hex-specific is this parse step.

WHY ONE MODULE. The hex normalisation used to be copy-pasted: ``tools_inspect``
had it, ``tools_pipeline._needle_from_key_hex`` had a VERBATIM copy whose
docstring said so, and ``region_analysis.parse_hex_pattern`` had a third. They
agreed only because a test
(``test_api_locate_key.test_hex_normalisation_matches_the_byte_search_box``)
held them together by hand. Adding five more formats to three copies is how
"the same string" starts meaning different bytes in different panes.

WHY ``auto`` RESOLVES TO HEX. ``dead``, ``cafe``, ``face`` and ``added`` are
all valid hex AND valid words. There is no reading of the input that is right
every time, so ``auto`` keeps the behaviour the box has always had — pure-hex
input is hex — and the ambiguity is surfaced instead of guessed at:
:func:`plausible_alternatives` names the other readings so a caller can offer a
one-click switch, and the web UI shows the resolved bytes before the search
runs. A wrong guess you can SEE costs one click; a wrong guess you cannot see
costs an analyst their afternoon.

WHY ``base64`` AND THE INTEGERS ARE NEVER AUTO-DETECTED. Their character sets
overlap plain text completely — ``Set-Cookie`` is as good a base64 charset run
as a real blob, and ``1234`` is as good a number as a string. Auto-detecting
them would make ``auto`` unpredictable, which is the one thing it must not be.
They are explicit-only, and reachable in one click through
:func:`plausible_alternatives`.
"""

import base64
import binascii
import re
from typing import List, Tuple

from .service_errors import CapabilityError, ErrorCategory

#: Every spelling the search box understands.
#:
#: Integer width and endianness live IN the format name rather than in extra
#: parameters, so the needle stays one ``(text, format)`` pair on all four
#: surfaces instead of growing width/endian fields on each of them.
NEEDLE_FORMATS: Tuple[str, ...] = (
    "auto",
    "hex",
    "text",
    "utf16le",
    "base64",
    "u32le",
    "u32be",
    "u64le",
    "u64be",
)

#: The concrete formats — everything :func:`detect_needle_format` may return.
CONCRETE_FORMATS: Tuple[str, ...] = tuple(
    f for f in NEEDLE_FORMATS if f != "auto"
)

#: ``{format: (byte width, byteorder)}`` for the fixed-width integer formats.
_INT_FORMATS = {
    "u32le": (4, "little"),
    "u32be": (4, "big"),
    "u64le": (8, "little"),
    "u64be": (8, "big"),
}

_HEX_RE = re.compile(r"\A[0-9a-fA-F]+\Z")
_BASE64_RE = re.compile(r"\A[A-Za-z0-9+/]+={0,2}\Z")

#: Shortest input worth offering as a base64 alternative.
#:
#: Short words are far too easy to read as base64 by accident (``dead`` decodes
#: to three bytes), so the hint would fire constantly and mean nothing.
_BASE64_HINT_MIN_CHARS = 16


def _invalid(message: str) -> CapabilityError:
    return CapabilityError(message, category=ErrorCategory.INVALID_INPUT)


def normalize_hex(text: str) -> str:
    """Strip whitespace and an optional leading ``0x``/``0X``.

    The spelling the byte-search box has always accepted: ``deadbeef``,
    ``0xdeadbeef``, ``de ad be ef`` and ``0XDEADBEEF`` all normalise to the
    same digits, because an analyst pastes the same string out of the hex
    viewer, a key-log line and a paper.
    """
    return "".join(text.split()).removeprefix("0x").removeprefix("0X")


def looks_like_hex(text: str) -> bool:
    """Is *text* an unambiguous, whole-byte hex string?

    Requires an EVEN digit count: an odd run is half a byte, and silently
    dropping or padding a nibble would search for something the analyst never
    typed.
    """
    cleaned = normalize_hex(text)
    return (
        len(cleaned) >= 2
        and len(cleaned) % 2 == 0
        and bool(_HEX_RE.match(cleaned))
    )


def looks_like_base64(text: str) -> bool:
    """Could *text* be a base64 blob worth OFFERING as an alternative?

    Deliberately conservative — see the module doc: this only ever feeds a
    hint, never a decision.
    """
    cleaned = "".join(text.split())
    return (
        len(cleaned) >= _BASE64_HINT_MIN_CHARS
        and len(cleaned) % 4 == 0
        and bool(_BASE64_RE.match(cleaned))
    )


def detect_needle_format(text: str) -> str:
    """Resolve ``auto`` to a concrete format.

    Hex when the input is unambiguously whole-byte hex, text otherwise. Never
    returns ``base64`` or an integer format — see the module doc.
    """
    if not text.strip():
        raise _invalid("Empty byte pattern")
    return "hex" if looks_like_hex(text) else "text"


def plausible_alternatives(text: str) -> List[str]:
    """Other formats *text* could sensibly be read as, best first.

    Powers the "also valid as …" hint beside the search box. Excludes whatever
    :func:`detect_needle_format` already chose, so the hint only ever offers a
    reading the user is NOT currently getting.
    """
    if not text.strip():
        return []
    resolved = detect_needle_format(text)
    out: List[str] = []
    if resolved != "hex" and looks_like_hex(text):
        out.append("hex")
    if resolved != "text":
        out.append("text")
    if looks_like_base64(text):
        out.append("base64")
    return out


def parse_needle(text: str, fmt: str = "hex") -> bytes:
    """Turn typed *text* into the bytes to search for.

    :param fmt: One of :data:`NEEDLE_FORMATS`; ``"auto"`` is resolved with
        :func:`detect_needle_format`.
    :raises CapabilityError: on an unknown format, an unparseable value, or an
        input that resolves to zero bytes.
    """
    if fmt not in NEEDLE_FORMATS:
        raise _invalid(
            f"Unknown pattern format: {fmt!r} "
            f"(expected one of {', '.join(NEEDLE_FORMATS)})")
    if not text.strip():
        raise _invalid("Empty byte pattern")
    if fmt == "auto":
        fmt = detect_needle_format(text)

    needle = _decode(text, fmt)
    if not needle:
        # An empty needle is not a query. `find_all_offsets` already returns []
        # for one (it must -- `mmap.find(b"", ...)` clamps and loops forever),
        # so without this the user would get a confident "0 hits" for an input
        # that was never searchable in the first place.
        raise _invalid(f"Empty byte pattern after decoding as {fmt}")
    return needle


def _decode(text: str, fmt: str) -> bytes:
    """Format-specific decode, assuming *fmt* is concrete and *text* non-blank."""
    if fmt == "hex":
        cleaned = normalize_hex(text)
        if not cleaned:
            raise _invalid("Empty byte pattern")
        try:
            return bytes.fromhex(cleaned)
        except ValueError as exc:
            # Name the likeliest cause rather than echoing binascii's wording:
            # an odd digit count is by far the most common way to get here, and
            # "non-hexadecimal number found" does not tell anyone that.
            hint = (
                " (odd number of hex digits — a byte needs two)"
                if len(cleaned) % 2 else ""
            )
            raise _invalid(
                f"Invalid hex byte pattern: {text!r}{hint}") from exc

    if fmt == "text":
        return text.encode("utf-8")

    if fmt == "utf16le":
        # No BOM: a needle is a fragment to find INSIDE a buffer, and a BOM
        # would only ever match at the start of a string the process stored
        # with one -- i.e. it would make the common case fail.
        return text.encode("utf-16-le")

    if fmt == "base64":
        cleaned = "".join(text.split())
        try:
            return base64.b64decode(cleaned, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise _invalid(f"Invalid base64 pattern: {text!r}") from exc

    width, byteorder = _INT_FORMATS[fmt]
    stripped = text.strip()
    try:
        # base=0 so 0x/0o/0b prefixes work and a bare string stays decimal --
        # the same spelling `--offset` already accepts elsewhere in the CLI.
        value = int(stripped, 0)
    except ValueError as exc:
        raise _invalid(f"Invalid integer pattern: {text!r}") from exc
    if value < 0:
        raise _invalid(f"Integer pattern must not be negative: {text!r}")
    try:
        return value.to_bytes(width, byteorder)  # type: ignore[arg-type]
    except OverflowError as exc:
        raise _invalid(
            f"Integer pattern {stripped} does not fit in {width} bytes "
            f"({fmt})") from exc
