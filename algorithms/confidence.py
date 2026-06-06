"""Confidence calibration helpers for analysis algorithms.

What "confidence" means here
----------------------------
Confidence is an *advisory* signal in the range 0.0 to 1.0 used to rank and
optionally suppress algorithm results. It is **not** a calibrated probability
that a result is correct -- it is a relative ordering hint so that more
specific, more discriminating findings float above broad, noisy ones.

Two scales coexist in this codebase:

* The modern specificity/density based signal produced by ``regex_specificity``
  and ``density_penalty`` (and combined at the call site).
* The legacy count-based scale, preserved verbatim via ``count_confidence`` for
  callers that have not yet migrated. ``count_confidence(n)`` with the default
  ``saturation=10`` reproduces the historical ``min(total / 10.0, 1.0)`` numbers
  exactly, so existing behavior is unchanged for those callers.

All functions are pure (no I/O, no global state, no external dependencies).
"""

# Number of literal (non-metacharacter) bytes at or above which a pattern is
# treated as "fully specific" (specificity contribution saturates at 1.0).
LITERAL_SATURATION = 8

# Extra specificity granted when an anchor (^, $, or \b) is present, reflecting
# that anchored patterns are more discriminating than free-floating ones.
ANCHOR_BONUS = 0.15

# Match-coverage fraction at which ``density_penalty`` reaches 0.0. A pattern
# whose matches cover this fraction (or more) of the dump is considered too
# broad to be useful and is fully penalized.
DENSITY_CEILING = 0.5

# Regex metacharacters that do not contribute to literal specificity.
_META = set(". ^ $ * + ? { } [ ] ( ) | \\".split())


def count_confidence(n: int, *, saturation: int = 10) -> float:
    """Legacy count-based confidence: ``min(n / saturation, 1.0)``.

    The default ``saturation=10`` reproduces the historical
    ``min(total / 10.0, 1.0)`` numbers exactly. Negative counts clamp to 0.0.
    """
    if n <= 0:
        return 0.0
    return round(min(n / saturation, 1.0), 4)


def regex_specificity(pattern: str) -> float:
    """Return the 0..1 specificity of a regex string.

    Counts literal (non-metacharacter) bytes, saturating at
    ``LITERAL_SATURATION``; adds ``ANCHOR_BONUS`` if any of ``^``, ``$`` or
    ``\\b`` appear. So ``"."`` -> ~0.0 and an 8+ character literal -> ~1.0.
    An empty pattern returns 0.0.
    """
    if not pattern:
        return 0.0

    literals = sum(1 for ch in pattern if ch not in _META)
    spec = min(literals / LITERAL_SATURATION, 1.0)

    if "^" in pattern or "$" in pattern or "\\b" in pattern:
        spec = min(spec + ANCHOR_BONUS, 1.0)

    return round(spec, 4)


def density_penalty(matched_bytes: int, total_bytes: int, *, ceiling: float = DENSITY_CEILING) -> float:
    """Return ``max(0.0, 1.0 - density / ceiling)``.

    ``density = matched_bytes / total_bytes``. Returns 0.0 when
    ``total_bytes <= 0``. Patterns covering a large fraction of the dump are
    penalized toward 0.0; patterns covering at or above ``ceiling`` get 0.0.
    """
    if total_bytes <= 0:
        return 0.0

    density = matched_bytes / total_bytes
    penalty = max(0.0, 1.0 - density / ceiling)
    return round(penalty, 4)
