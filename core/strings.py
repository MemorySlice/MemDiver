"""String extraction from raw byte buffers.

Scans binary data for contiguous runs of printable characters and returns
them as StringMatch objects. Supports ASCII and UTF-8 modes.

All functions are stdlib-only with no external dependencies.
"""

import logging
from dataclasses import dataclass
from typing import List

logger = logging.getLogger("memdiver.core.strings")


@dataclass(frozen=True)
class StringMatch:
    """A printable string found in a byte buffer."""
    offset: int
    value: str
    encoding: str  # "ascii" or "utf-8"
    length: int

    def __hash__(self):
        return hash((self.offset, self.value))

    def __eq__(self, other):
        if not isinstance(other, StringMatch):
            return NotImplemented
        return self.offset == other.offset and self.value == other.value


# ASCII printable range: 0x20-0x7E plus tab, newline, carriage return
_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def extract_strings(
    data: bytes,
    min_length: int = 4,
    encoding: str = "ascii",
) -> List[StringMatch]:
    """Extract printable strings from a byte buffer.

    Scans for contiguous runs of printable characters at or above min_length.
    ASCII mode: bytes in 0x20-0x7E plus tab/newline/CR.
    UTF-8 mode: attempts decode on runs containing bytes > 0x7F.

    Args:
        data: Raw byte buffer to scan.
        min_length: Minimum string length to report (default 4).
        encoding: "ascii" or "utf-8" (default "ascii").

    Returns:
        List of StringMatch sorted by offset.
    """
    if not data:
        return []

    matches: List[StringMatch] = []

    if encoding == "utf-8":
        _extract_utf8(data, min_length, matches)
    else:
        _extract_ascii(data, min_length, matches)

    return matches


def _extract_ascii(
    data: bytes, min_length: int, matches: List[StringMatch]
) -> None:
    """Single-pass ASCII string extraction."""
    run_start = -1
    for i, byte in enumerate(data):
        if byte in _PRINTABLE:
            if run_start < 0:
                run_start = i
        else:
            if run_start >= 0:
                length = i - run_start
                if length >= min_length:
                    value = data[run_start:i].decode("ascii")
                    matches.append(StringMatch(
                        offset=run_start, value=value,
                        encoding="ascii", length=length,
                    ))
                run_start = -1

    # Handle run extending to end of data.
    if run_start >= 0:
        length = len(data) - run_start
        if length >= min_length:
            value = data[run_start:].decode("ascii")
            matches.append(StringMatch(
                offset=run_start, value=value,
                encoding="ascii", length=length,
            ))


def _extract_utf8(
    data: bytes, min_length: int, matches: List[StringMatch]
) -> None:
    """Single-pass UTF-8 string extraction.

    Extends runs to include bytes > 0x7F. When a run ends, attempts
    UTF-8 decode; on failure falls back to ASCII-only portions.
    """
    run_start = -1
    for i, byte in enumerate(data):
        if byte in _PRINTABLE or byte > 0x7F:
            if run_start < 0:
                run_start = i
        else:
            if run_start >= 0:
                _emit_utf8_run(data, run_start, i, min_length, matches)
                run_start = -1

    if run_start >= 0:
        _emit_utf8_run(data, run_start, len(data), min_length, matches)


def _emit_utf8_run(
    data: bytes, start: int, end: int,
    min_length: int, matches: List[StringMatch],
) -> None:
    """Try to decode a byte run as UTF-8; fall back to ASCII portions."""
    chunk = data[start:end]
    try:
        value = chunk.decode("utf-8", errors="strict")
        if len(value) >= min_length:
            matches.append(StringMatch(
                offset=start, value=value,
                encoding="utf-8", length=len(chunk),
            ))
    except UnicodeDecodeError:
        # Fall back: extract ASCII-only portions from the run.
        ascii_matches: List[StringMatch] = []
        _extract_ascii(chunk, min_length, ascii_matches)
        for m in ascii_matches:
            matches.append(StringMatch(
                offset=start + m.offset, value=m.value,
                encoding="ascii", length=m.length,
            ))
