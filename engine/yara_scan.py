"""Compile MemDiver-emitted YARA rules and scan dump sources with them.

MemDiver has been able to *emit* YARA rules since the architect layer landed
(:class:`architect.yara_exporter.YaraExporter`), but never to *scan* with them:
the only ``yara.compile`` call in the tree lived inside the generated
Volatility3 plugin template and was never executed in-process. An emitted
detector you cannot run is a detector you cannot evaluate, so this module
closes the loop.

Two things are worth knowing before reading further.

**What a match means.** ``architect.pattern_generator.PatternGenerator`` builds
``wildcard_pattern`` as one flat byte string in which volatile bytes are ``??``
and static bytes are literal hex. The rule therefore matches the *window that
contains* the key, and libyara reports the window's start offset -- not the
key's. The optional ``key_offset`` / ``key_length`` metas that
:meth:`YaraExporter.export` now emits carry the key's position *within* that
window; they are lifted onto every :class:`RuleMatch` so a later containment
metric can score "did the window actually cover the key?" without re-parsing
the rule. This module deliberately does no scoring of its own.

**Two scan strategies, chosen by dump format.** A plain raw dump is scanned by
handing libyara the file path, because for a raw dump the file offset *is* the
default view offset, so libyara's own zero-copy mapping is both correct and the
fastest thing available. Every other format (``.msl``, gcore, regioned raw) is
scanned chunk-by-chunk through :meth:`DumpSource.read_range`, because those
bytes have to be decrypted and/or VAS-projected first: for a gcore core the
file offset is *not* the VAS offset, and for an encrypted ``.msl`` the on-disk
bytes are not the plaintext at all. See :func:`scan_source`.

Layering: this module is pure compute over ``core.*``. It may import ``core``
and must never import ``app`` or ``presentation`` (AST-enforced by
``tests/test_architecture_invariants.py``), and it carries no CLI flag strings.
"""

from __future__ import annotations

import inspect
import logging
import random
import re
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from memdiver.core.install_hints import missing_package_message
from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.core.variance import CHUNK_BYTES  # 16 MiB; one constant, one owner

logger = logging.getLogger("memdiver.engine.yara_scan")

try:
    import yara

    HAS_YARA = True
    # libyara surfaces *everything* through its own hierarchy rooted at
    # ``yara.Error``: ``yara.SyntaxError`` for a bad rule, ``yara.TimeoutError``
    # for an exhausted scan budget, ``yara.WarningError`` for a promoted
    # warning. None of them derive from OSError/ValueError, so the funnel below
    # has to catch this base explicitly.
    _YaraError: tuple = (yara.Error,)
except ImportError:
    HAS_YARA = False
    _YaraError = ()  # empty tuple -> an ``except`` that matches nothing

# ``yara-python`` is a BASE dependency (see pyproject.toml), not an extra, so
# its absence means a broken environment rather than a forgotten install
# option. ``missing_package_message`` is therefore called WITHOUT ``extra=``,
# which makes it degrade to the base-reinstall hint (class 2 in
# ``core.install_hints``). Do not add an ``extra=`` here and do not add "yara"
# to ``OPTIONAL_EXTRAS``.
_YARA_MISSING = missing_package_message("yara-python (rule scanning)")

#: Hard ceiling on the rule text handed to libyara. A rule set is authored by a
#: human or emitted by the architect layer; either way a megabyte is orders of
#: magnitude past anything legitimate, and libyara's compiler happily spends
#: unbounded time and memory on a pathological source.
MAX_RULE_SOURCE_BYTES = 1 << 20

#: Bytes of the *next* chunk stitched onto the end of each chunk so a match
#: straddling a chunk boundary is still seen whole. Only a floor -- see
#: :func:`_resolve_overlap`.
DEFAULT_OVERLAP_BYTES = 4096

#: Cap on reported matches. A wildcard-heavy pattern on a multi-GB dump can
#: match tens of thousands of times; the cap keeps a corpus sweep bounded and
#: is *reported* (``ScanResult.truncated``) rather than hidden.
DEFAULT_MAX_MATCHES = 10_000

#: Per-scan libyara budget, in seconds. Applied per chunk in the chunked
#: strategy and once for the whole file in the filepath strategy.
DEFAULT_TIMEOUT_S = 60

#: How many compiled rule sets the in-process cache keeps (FIFO).
_RULE_CACHE_CAPACITY = 8

#: Compiled rule sets keyed by BLAKE3 of their normalized source. A corpus
#: sweep compiles ONE rule set and scans thousands of dumps; recompiling per
#: dump dominates the runtime. Never persisted -- a compiled ``.yarc`` on disk
#: is a code-loading surface (see :func:`compile_rules`), so the cache lives
#: and dies with the process.
_RULE_CACHE: "OrderedDict[str, Any]" = OrderedDict()

_STRATEGY_FILEPATH = "filepath"
_STRATEGY_CHUNKED = "chunked"


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RuleMatch:
    """One string instance of one rule, at one absolute offset in a view.

    ``offset``/``length`` describe the *matched window*, in the coordinate
    space of :attr:`ScanResult.view`. ``key_offset``/``key_length`` are lifted
    verbatim from the rule's meta block when the emitter supplied them and are
    relative to the start of the pattern, i.e. the key is expected at
    ``offset + key_offset``. Both are ``None`` for a rule that carries no such
    meta; this module does not guess them.

    ``matched_hex`` is libyara's ``matched_data``, which libyara itself caps at
    its ``max_match_data`` configuration value (512 bytes by default). For a
    pattern longer than that cap, ``len(bytes.fromhex(matched_hex))`` is
    therefore SHORTER than ``length``; ``length`` is always the true match
    width. MemDiver's emitted key-window patterns are far below the cap, so the
    two agree in practice, but a caller reconstructing bytes from
    ``matched_hex`` must compare against ``length`` rather than assume.
    """

    rule: str
    tags: Tuple[str, ...]
    string_id: str
    offset: int
    length: int
    matched_hex: str
    key_offset: Optional[int]
    key_length: Optional[int]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule,
            "tags": list(self.tags),
            "string_id": self.string_id,
            "offset": self.offset,
            "length": self.length,
            "matched_hex": self.matched_hex,
            "key_offset": self.key_offset,
            "key_length": self.key_length,
        }


@dataclass(frozen=True)
class ScanResult:
    """Everything one scan of one dump produced, including what it could not do.

    The three "bad news" fields are the point of this type. ``truncated`` says
    the match list stops at ``max_matches`` and is not the whole truth;
    ``timed_out`` says at least one chunk hit the libyara budget and its bytes
    are unscanned; ``errors`` carries the per-chunk failures. None of the three
    raises, because a corpus sweep must not die on one bad dump -- but none of
    them is swallowed either, so a caller that ignores them is doing so
    knowingly.
    """

    dump_path: str
    view: str
    scanned_bytes: int
    rule_names: Tuple[str, ...]
    matches: Tuple[RuleMatch, ...]
    truncated: bool
    timed_out: bool
    chunks: int
    strategy: str
    errors: Tuple[str, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dump_path": self.dump_path,
            "view": self.view,
            "scanned_bytes": self.scanned_bytes,
            "rule_names": list(self.rule_names),
            "matches": [m.to_dict() for m in self.matches],
            "match_count": len(self.matches),
            "truncated": self.truncated,
            "timed_out": self.timed_out,
            "chunks": self.chunks,
            "strategy": self.strategy,
            "errors": list(self.errors),
        }


# ---------------------------------------------------------------------------
# Rule compilation
# ---------------------------------------------------------------------------


def _require_yara() -> None:
    """Raise the class-2 install hint when yara-python is absent.

    The module itself imports cleanly without yara so that merely importing an
    engine package never explodes; only actually compiling or scanning needs
    the dependency.
    """
    if not HAS_YARA:
        raise CapabilityError(
            _YARA_MISSING,
            category=ErrorCategory.PRECONDITION,
            code="yara.missing",
        )


def _normalize_source(source: str) -> str:
    """Canonicalise rule text for cache keying.

    Trailing whitespace and the presence or absence of a final newline change
    the bytes without changing the compiled rules, and both differ routinely
    between a heredoc, a file read and a generated string. Normalising them
    away means the same logical rule set hits the cache.
    """
    return "\n".join(line.rstrip() for line in source.strip().splitlines())


def _cache_get(key: str) -> Optional[Any]:
    return _RULE_CACHE.get(key)


def _cache_put(key: str, rules: Any) -> None:
    """Insert *rules*, evicting the oldest entry once the cap is exceeded.

    FIFO, not LRU: a sweep reuses one rule set for its whole run, so recency
    carries no signal worth the bookkeeping, and FIFO cannot be starved by a
    long tail of one-off compiles.
    """
    _RULE_CACHE[key] = rules
    while len(_RULE_CACHE) > _RULE_CACHE_CAPACITY:
        evicted, _ = _RULE_CACHE.popitem(last=False)
        logger.debug("yara rule cache evicted %s", evicted[:16])


def clear_rule_cache() -> None:
    """Drop every cached rule set. For tests and long-lived processes."""
    _RULE_CACHE.clear()


def _guard_source_size(byte_len: int, what: str) -> None:
    if byte_len > MAX_RULE_SOURCE_BYTES:
        raise CapabilityError(
            f"{what} is {byte_len} bytes, over the {MAX_RULE_SOURCE_BYTES}-byte "
            f"limit for YARA rule text",
            category=ErrorCategory.INVALID_INPUT,
            code="yara.rules_too_large",
        )


def _namespaced_paths(paths: Sequence[Path]) -> Tuple[Dict[str, str], str]:
    """Build libyara's ``filepaths`` mapping and a cache key for *paths*.

    The dict form of ``yara.compile`` puts each file in its own namespace,
    which is what keeps two rule files that happen to define the same rule
    name from colliding at compile time. A namespace is derived from the file
    stem, so two paths with the same stem would silently collapse into one
    dict entry and one of the two files would never be compiled -- that is
    rejected rather than swallowed.

    The cache key folds in each file's *content*, not its path or mtime, so an
    edited rule file recompiles and an unchanged one does not.
    """
    if not paths:
        raise CapabilityError(
            "compile_rules(paths=...) needs at least one path",
            category=ErrorCategory.INVALID_INPUT,
            code="yara.no_rules",
        )
    filepaths: Dict[str, str] = {}
    key_parts: List[str] = []
    total = 0
    for raw in paths:
        path = Path(raw)
        namespace = path.stem
        if namespace in filepaths:
            raise CapabilityError(
                f"two rule files share the namespace {namespace!r} "
                f"({filepaths[namespace]} and {path}); rename one so each file "
                f"gets its own YARA namespace",
                category=ErrorCategory.INVALID_INPUT,
                code="yara.namespace_collision",
            )
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise CapabilityError(
                f"cannot read YARA rule file {path}: {exc}",
                category=ErrorCategory.NOT_FOUND,
                code="yara.rules_unreadable",
            ) from exc
        total += len(text.encode("utf-8"))
        _guard_source_size(total, "the combined YARA rule files")
        filepaths[namespace] = str(path)
        key_parts.append(f"{namespace}\x00{_normalize_source(text)}")
    return filepaths, "\x01".join(key_parts)


def _blake3_key(material: str) -> str:
    """BLAKE3 digest of *material*.

    BLAKE3 (a base dependency, and already the MSL container's integrity hash)
    rather than MD5/SHA-1: this is a content-addressed cache key, and a hash
    with known collisions could hand back the wrong compiled rule set.
    """
    from blake3 import blake3

    return blake3(material.encode("utf-8")).hexdigest()


def compile_rules(
    *,
    source: Optional[str] = None,
    paths: Optional[Sequence[Path]] = None,
) -> "yara.Rules":
    """Compile a YARA rule set from inline text or from rule files.

    Exactly one of *source* / *paths* must be given; passing both or neither is
    an error rather than a silent precedence rule. Results are memoised in a
    small in-process cache (:data:`_RULE_CACHE_CAPACITY` entries, FIFO) keyed
    on the BLAKE3 digest of the normalized rule text, so a corpus sweep pays
    the compile cost once.

    Note:
        ``yara.load()`` on a precompiled ``.yarc`` is deliberately NOT offered.
        A compiled rule file is executable libyara bytecode, so loading one is
        a code-loading operation with the trust properties of importing a
        module -- accepting a ``.yarc`` from a dump corpus, an upload or a CLI
        argument would be a straightforward arbitrary-behaviour surface. Rules
        reach this function as *text*, which the compiler validates.

    Raises:
        CapabilityError: yara-python absent, argument misuse, rule text over
            :data:`MAX_RULE_SOURCE_BYTES`, an unreadable rule file, or a
            libyara compile error (its message is preserved).
    """
    _require_yara()
    if (source is None) == (paths is None):
        raise CapabilityError(
            "compile_rules() takes exactly one of source= or paths=",
            category=ErrorCategory.INVALID_INPUT,
            code="yara.bad_rule_intake",
        )

    if source is not None:
        _guard_source_size(len(source.encode("utf-8")), "the YARA rule source")
        cache_key = _blake3_key("source\x01" + _normalize_source(source))
        compile_kwargs: Dict[str, Any] = {"source": source}
        described = "inline source"
    else:
        # ``paths`` is not None here: the exactly-one check above rejects the
        # both-None and both-set cases, so this branch always has paths.
        filepaths, key_material = _namespaced_paths(paths or ())
        cache_key = _blake3_key("filepaths\x01" + key_material)
        compile_kwargs = {"filepaths": filepaths}
        described = f"{len(filepaths)} rule file(s)"

    cached = _cache_get(cache_key)
    if cached is not None:
        logger.debug("yara rule cache hit for %s (%s)", cache_key[:16], described)
        return cached

    try:
        rules = yara.compile(**compile_kwargs)
    except _YaraError as exc:
        raise CapabilityError(
            f"YARA rule compilation failed ({described}): {exc}",
            category=ErrorCategory.INVALID_INPUT,
            code="yara.compile_failed",
        ) from exc

    _cache_put(cache_key, rules)
    logger.info("compiled YARA rules from %s (%d rule(s))", described, len(rule_names(rules)))
    return rules


def rule_names(rules: "yara.Rules") -> Tuple[str, ...]:
    """Identifiers of every rule in a compiled set, in declaration order."""
    return tuple(rule.identifier for rule in rules)


def max_pattern_length(rules: "yara.Rules") -> Optional[int]:
    """Largest ``pattern_length`` meta across *rules*, or ``None`` if absent.

    ``pattern_length`` is emitted by :meth:`YaraExporter.export` and is the
    byte length of the wildcard pattern, i.e. exactly the width a chunk overlap
    has to cover for a straddling match to be seen whole.
    """
    lengths = [
        value
        for rule in rules
        for key, value in rule.meta.items()
        if key == "pattern_length" and isinstance(value, int) and value > 0
    ]
    return max(lengths) if lengths else None


# ---------------------------------------------------------------------------
# libyara's regexp verification limit
# ---------------------------------------------------------------------------
#
# A hex string containing a ``??`` wildcard is not a literal to libyara: it is
# compiled to a regexp. libyara matches a regexp by picking ONE literal atom
# out of it, finding that atom with Aho-Corasick, and then *verifying* the rest
# of the pattern backward and forward from the atom with its own RE VM. That
# verification is bounded by a compile-time constant, ``YR_RE_SCAN_LIMIT``, and
# when a pattern is wider than the bound the verification simply stops -- so
# libyara reports NO MATCH for a pattern that is present in the data, byte for
# byte, with no error, no warning and no diagnostic of any kind.
#
# That constant regressed from 4096 to 1024 in yara 4.5.3/4.5.4 (upstream PR
# #2144). It is reverted upstream but UNRELEASED: 4.5.4 is the newest wheel on
# PyPI, so no dependency floor can route around it. See the module-level
# discussion in ``tests/test_libyara_scan_limit.py``.
#
# We probe for the limit instead of hardcoding 1024, for the same reason
# ``tests/test_yara_exporter_compiles.py`` asks libyara for its reserved-word
# set rather than trusting a literal list: a number baked in here is silently
# WRONG the day a fixed libyara lands, and wrong in the dangerous direction --
# we would keep calling perfectly good 2 KiB rules dead. A probe self-corrects.

#: Wildcard placements, as a fraction of the pattern, used by one probe round.
#: Which atom libyara picks depends on the byte content, and therefore so does
#: how far it has to verify in each direction -- so a single placement measures
#: that placement's luck, not the limit. Probing several and requiring ALL of
#: them to match is what makes the answer a property of libyara.
_PROBE_WILDCARD_FRACTIONS = (0.0, 0.25, 0.5, 0.75, 1.0)

#: Two fixed seeds, so the probe is deterministic (a cached number must not
#: depend on which random bytes a process happened to draw) and so a single
#: unlucky byte draw cannot decide the result.
_PROBE_SEEDS = (0xC0FFEE, 0x5EED)

#: Bracket for the search. The floor is small enough that any sane libyara
#: clears it; the ceiling is far past any limit libyara has ever shipped.
_PROBE_MIN_BYTES = 64
_PROBE_MAX_BYTES = 1 << 16

#: Memoized probe result. ``None`` means "not probed yet"; the probe itself
#: stores an ``Optional[int]``, so the sentinel has to be distinct from a
#: legitimately-unknown ``None`` outcome. Never computed at import -- see
#: :func:`regexp_scan_limit`.
_SCAN_LIMIT_PROBED = False
_SCAN_LIMIT: Optional[int] = None


def _probe_matches_at(length: int) -> bool:
    """Does libyara match a wildcarded *length*-byte pattern planted verbatim?

    Builds a pattern of exactly *length* bytes from deterministic pseudorandom
    data, plants those same bytes in a buffer, wildcards one token so the
    string compiles as a regexp rather than a literal, and asks libyara. True
    only when EVERY (seed, wildcard placement) combination matches; one miss is
    enough to call the length unsafe, because a rule a user emits will have its
    wildcards wherever the volatile bytes happened to fall.
    """
    for seed in _PROBE_SEEDS:
        # nosec B311 - a DETERMINISTIC PRNG is the requirement here, not a
        # weakness: the probe's answer is memoized and must not depend on which
        # bytes a process happened to draw, so a seeded Mersenne Twister is
        # correct and ``secrets``/``os.urandom`` would be wrong. These bytes are
        # haystack filler for a capability probe and are never a key, a nonce,
        # an IV or any other security material.
        rng = random.Random(seed ^ length)  # nosec B311
        body = bytes(rng.randrange(256) for _ in range(length))
        # Pad both sides so the pattern is genuinely interior to the buffer and
        # libyara cannot match it by running off either end.
        pad = bytes(rng.randrange(256) for _ in range(64))
        data = pad + body + pad
        for fraction in _PROBE_WILDCARD_FRACTIONS:
            position = min(length - 1, max(0, int(fraction * (length - 1))))
            tokens = ["%02x" % b for b in body]
            tokens[position] = "??"
            source = "rule memdiver_probe { strings: $a = { %s } condition: $a }" % (
                " ".join(tokens),
            )
            try:
                if not yara.compile(source=source).match(data=data):
                    return False
            except _YaraError as exc:  # pragma: no cover - defensive
                # A compiler that refuses the probe rule tells us nothing about
                # the verification limit, so treat the length as unsafe rather
                # than let an exception escape a capability probe.
                logger.debug("scan-limit probe failed to compile at %d: %s", length, exc)
                return False
    return True


def _probe_regexp_scan_limit() -> Optional[int]:
    """Measure libyara's regexp verification limit, in bytes.

    Geometric bracket, then bisect, then floor to a power of two. The floor is
    the part worth explaining: right above the true limit libyara's behaviour
    is *flaky* rather than cleanly monotone -- a lucky atom placement can carry
    a pattern a few bytes past the cliff -- so a bisect can land slightly high.
    ``YR_RE_SCAN_LIMIT`` has only ever been a power of two (4096, then 1024),
    and rounding down is the conservative direction: it can only ever make us
    warn about a rule that would in fact have worked, never stay silent about
    one that is dead.

    Returns ``None`` when the limit cannot be established -- yara-python
    absent, or a libyara so broken that even the 64-byte floor does not match.
    ``None`` means "unknown", and every caller treats it as "cannot prove this
    rule is dead", never as "the rule is fine".
    """
    if not HAS_YARA:
        return None
    if not _probe_matches_at(_PROBE_MIN_BYTES):
        # Not a limit we can characterise: if a 64-byte wildcard pattern does
        # not match bytes planted verbatim, something far more basic is wrong.
        logger.warning(
            "yara scan: libyara did not match a %d-byte wildcard pattern planted "
            "verbatim; cannot establish its regexp verification limit",
            _PROBE_MIN_BYTES,
        )
        return None
    low = _PROBE_MIN_BYTES
    while low * 2 <= _PROBE_MAX_BYTES and _probe_matches_at(low * 2):
        low *= 2
    if low * 2 > _PROBE_MAX_BYTES:
        # Cleared the whole bracket; report the ceiling rather than pretend to
        # a precision we did not measure.
        return low
    high = low * 2
    while high - low > 8:
        mid = (low + high) // 2
        if _probe_matches_at(mid):
            low = mid
        else:
            high = mid
    return 1 << (low.bit_length() - 1)


def regexp_scan_limit() -> Optional[int]:
    """Widest wildcard pattern the installed libyara will actually verify.

    A pattern longer than this compiles and scans without complaint and
    matches NOTHING, so every caller that is about to emit or trust such a
    pattern has to consult this first. ``None`` means the limit could not be
    established; see :func:`_probe_regexp_scan_limit`.

    Lazy and memoized: the probe costs a few dozen small ``yara.compile``
    calls (~20 ms here), which is nothing once but is not something to spend at
    import time, in every process, whether or not any rule is ever scanned.
    """
    global _SCAN_LIMIT_PROBED, _SCAN_LIMIT
    if not _SCAN_LIMIT_PROBED:
        _SCAN_LIMIT = _probe_regexp_scan_limit()
        _SCAN_LIMIT_PROBED = True
        logger.debug("libyara regexp verification limit probed as %r", _SCAN_LIMIT)
    return _SCAN_LIMIT


def clear_scan_limit_cache() -> None:
    """Forget the memoized probe result. For tests; harmless in production."""
    global _SCAN_LIMIT_PROBED, _SCAN_LIMIT
    _SCAN_LIMIT_PROBED = False
    _SCAN_LIMIT = None


#: Tokens that put a hex string outside :func:`measure_hex_string_widths`'s
#: competence: jumps (``[4-6]``), alternation (``( 41 | 42 )``) and negation
#: (``~41``) all make the width variable or the parse non-trivial. A block
#: holding any of them is reported as UNMEASURED rather than guessed at.
_HEX_BLOCK_UNSUPPORTED = set("[]()|~")

#: A YARA hex string is brace-delimited and introduced by ``=``. Text strings
#: and regexps are quote/slash-delimited, and a rule body's own brace is not
#: preceded by ``=``, so this does not collide with either.
_HEX_BLOCK_RE = re.compile(r"=\s*\{(.*?)\}", re.S)

#: ``//`` to end of line, or ``/* ... */``. Stripped before looking for hex
#: blocks so a commented-out string cannot be measured as a live one.
_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)


def measure_hex_string_widths(text: str) -> Tuple[Tuple[int, ...], int]:
    """Measure the WILDCARDED hex strings in *text*, from the rule source.

    Returns ``(widths, unmeasured)``: the byte width of every brace-delimited
    hex string that contains a wildcard (``??`` or a nibble like ``4?``), plus
    a count of the wildcarded blocks whose syntax this function declines to
    parse. A block with no wildcard at all is neither measured nor counted --
    it compiles to a literal, and the regexp verification limit does not apply
    to literals (verified: an 8 KiB pure-literal hex string matches fine).

    Why this exists alongside :func:`max_pattern_length`. That function reads
    the ``pattern_length`` meta, which only rules MemDiver emitted carry. A
    third-party ``.yar`` has no such meta, so the meta route cannot tell a
    harmless rule from one that is silently dead -- and answering "fine"
    because we did not know would be the same false all-clear this whole
    mechanism exists to prevent. The rule TEXT is available at every call site
    that compiles one, so for the common shape (a flat run of hex pairs and
    wildcards, which is exactly what a memory signature looks like) the width
    can simply be measured instead of asked for.

    Deliberately CONSERVATIVE, not clever: anything carrying a jump,
    alternation or negation is counted as unmeasured and reported as such,
    rather than parsed with a half-right grammar whose mistakes would be
    invisible. A wrong width here would produce exactly the confident-wrong
    answer the function is meant to replace.
    """
    widths: List[int] = []
    unmeasured = 0
    for block in _HEX_BLOCK_RE.findall(_COMMENT_RE.sub(" ", text)):
        compact = "".join(block.split())
        if "?" not in compact:
            continue  # a literal; the regexp limit does not apply
        if set(compact) & _HEX_BLOCK_UNSUPPORTED or len(compact) % 2:
            unmeasured += 1
            continue
        if any(c not in "0123456789abcdefABCDEF?" for c in compact):
            unmeasured += 1
            continue
        widths.append(len(compact) // 2)
    return tuple(widths), unmeasured


def pattern_exceeds_scan_limit(pattern_length: Optional[int]) -> bool:
    """Is a *pattern_length*-byte wildcard pattern too wide for this libyara?

    ``False`` for an unknown length (``None``) and for an unknown limit: a
    warning nobody can substantiate is worse than none. The callers that must
    NOT conclude "fine" from an unknown length say so themselves, with their
    own diagnostic -- this predicate answers only the question it can answer.
    """
    limit = regexp_scan_limit()
    if pattern_length is None or limit is None:
        return False
    return pattern_length > limit


# ---------------------------------------------------------------------------
# Match extraction
# ---------------------------------------------------------------------------


def _meta_int(meta: Dict[str, Any], key: str) -> Optional[int]:
    """Read *key* from a rule's meta as an int, or ``None``.

    libyara types an unquoted meta value as an int and a quoted one as a str,
    and the emitter has used both spellings over time, so a numeric string is
    accepted too. Anything else is reported as absent rather than coerced.
    """
    value = meta.get(key)
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.lstrip("-").isdigit():
            return int(text)
    return None


def _extract_matches(
    yara_matches: Any,
    *,
    chunk_start: int,
    own_len: Optional[int],
) -> List[RuleMatch]:
    """Flatten libyara's match objects into :class:`RuleMatch`, rebased.

    ``chunk_start`` is added to every instance offset so results are in the
    view's absolute coordinates rather than the chunk's.

    ``own_len`` implements the chunk-ownership rule copied from
    ``core.dump_sources.gcore.GCoreDumpSource._find_all_vas``: a chunk is
    scanned together with a short overlap stitched from the bytes that follow
    it, so an instance whose *local* offset is ``>= own_len`` began inside that
    overlap and belongs to the chunk that owns those bytes. Dropping it here is
    what keeps the global match list unique and ascending instead of
    double-reporting every boundary-straddling hit. ``None`` disables the rule
    (the filepath strategy scans the file exactly once, so nothing is shared).
    """
    out: List[RuleMatch] = []
    for match in yara_matches:
        tags = tuple(match.tags)
        key_offset = _meta_int(match.meta, "key_offset")
        key_length = _meta_int(match.meta, "key_length")
        for string_match in match.strings:
            for instance in string_match.instances:
                local = instance.offset
                if own_len is not None and local >= own_len:
                    continue
                data = bytes(instance.matched_data)
                out.append(
                    RuleMatch(
                        rule=match.rule,
                        tags=tags,
                        string_id=string_match.identifier,
                        offset=chunk_start + local,
                        length=instance.matched_length,
                        matched_hex=data.hex(),
                        key_offset=key_offset,
                        key_length=key_length,
                    )
                )
    out.sort(key=lambda m: (m.offset, m.rule, m.string_id))
    return out


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


def _default_view(source: Any) -> str:
    """The view a source uses when a caller names none.

    Each :class:`~core.dump_source.DumpSource` implementation keeps its own
    default (``"raw"`` for :class:`RawDumpSource`, ``"vas"`` for ``.msl``,
    gcore and the regioned-raw sources), declared as the default of the
    ``view`` parameter. Reading it from the signature keeps that single
    declaration authoritative instead of restating the mapping here, where it
    would drift the first time a new format is registered.
    """
    try:
        default = inspect.signature(source.size_for).parameters["view"].default
    except (TypeError, ValueError, KeyError) as exc:
        logger.debug("cannot read default view from %r: %s", source, exc)
        return "raw"
    return default if isinstance(default, str) else "raw"


def _resolve_overlap(
    overlap_bytes: int,
    chunk_bytes: int,
    rules: "yara.Rules",
) -> Tuple[int, List[str]]:
    """Decide the chunk overlap, returning it plus any warnings to report.

    ``overlap_bytes=0`` means "choose for me": start from
    :data:`DEFAULT_OVERLAP_BYTES` and raise it to ``max(pattern_length) - 1``
    when the rules carry that meta, because that is the widest a straddling
    match can reach. The automatic value is capped at half the chunk so the
    sweep always makes forward progress; when the cap actually bites, the
    caller is told, because from then on a long enough pattern CAN be missed
    at a boundary.

    A non-zero *overlap_bytes* is honoured verbatim. That is deliberate: it
    lets a caller trade recall for speed knowingly, and it keeps the
    limitation testable.

    The auto path has a SECOND degraded state, and it is the quiet one: rules
    that carry no usable ``pattern_length`` meta at all. There is then nothing
    to size the overlap from, so it stays at the flat
    :data:`DEFAULT_OVERLAP_BYTES` floor -- and a pattern wider than that floor
    becomes missable at a chunk boundary. That used to happen with no signal
    whatsoever; it is now reported the same way the ceiling case is, because
    "we do not know how wide your patterns are" is exactly as consequential
    for recall as "we could not make the overlap that wide".
    """
    notes: List[str] = []
    if chunk_bytes <= 0:
        raise CapabilityError(
            f"chunk_bytes must be positive, got {chunk_bytes}",
            category=ErrorCategory.INVALID_INPUT,
            code="yara.bad_chunk_size",
        )
    if overlap_bytes < 0:
        raise CapabilityError(
            f"overlap_bytes must not be negative, got {overlap_bytes}",
            category=ErrorCategory.INVALID_INPUT,
            code="yara.bad_overlap",
        )
    if overlap_bytes > 0:
        if overlap_bytes >= chunk_bytes:
            raise CapabilityError(
                f"overlap_bytes ({overlap_bytes}) must be smaller than "
                f"chunk_bytes ({chunk_bytes}); an overlap at or past the chunk "
                f"size would re-read the same bytes forever",
                category=ErrorCategory.INVALID_INPUT,
                code="yara.bad_overlap",
            )
        return overlap_bytes, notes

    wanted = DEFAULT_OVERLAP_BYTES
    longest = max_pattern_length(rules)
    if longest is not None and longest - 1 > wanted:
        wanted = longest - 1
    elif longest is None:
        notes.append(
            f"no usable pattern_length meta on any of "
            f"{len(rule_names(rules))} rule(s), so the auto overlap fell back "
            f"to the default {DEFAULT_OVERLAP_BYTES}-byte floor; boundary "
            f"recall is only guaranteed for matches up to "
            f"{DEFAULT_OVERLAP_BYTES} bytes wide. Emit the rules through "
            f"YaraExporter (which sets pattern_length) or pass an explicit "
            f"overlap_bytes at least as wide as the widest pattern."
        )
        logger.warning("yara scan: %s", notes[-1])
    ceiling = max(1, chunk_bytes // 2)
    if wanted > ceiling:
        notes.append(
            f"overlap capped at {ceiling} bytes (wanted {wanted}) because "
            f"chunk_bytes is {chunk_bytes}; a match longer than {ceiling} bytes "
            f"can be missed at a chunk boundary"
        )
        logger.warning("yara scan: %s", notes[-1])
        wanted = ceiling
    return wanted, notes


def _validate_max_matches(max_matches: Optional[int]) -> None:
    """Reject a non-positive match cap; ``None`` is the way to say "no cap".

    Every other numeric knob on this module's entry points is validated
    up front and raises (``yara.bad_chunk_size``, ``yara.bad_overlap``,
    ``yara.rules_too_large``, ...). ``max_matches`` was the one that was not,
    and ``0`` or a negative meant *unlimited* -- with :attr:`ScanResult.truncated`
    left ``False``, which is technically true and practically a trap: a
    ``max_matches`` computed as ``limit - already_seen`` that reaches ``0``
    means "stop", and being handed the entire multi-GB match list instead is
    the opposite of what the caller asked for. A typo'd or arithmetic zero is
    therefore an error, exactly like a zero ``chunk_bytes``.

    "No cap" is still available, because a recall measurement legitimately
    wants every match -- it just has to be *said*, as ``max_matches=None``,
    rather than arrived at by accident. That keeps the unlimited branch of
    :func:`_apply_cap` reachable under an unambiguous spelling.
    """
    if max_matches is None:
        return
    if max_matches <= 0:
        raise CapabilityError(
            f"max_matches must be positive, got {max_matches}; pass "
            f"max_matches=None to scan without a cap",
            category=ErrorCategory.INVALID_INPUT,
            code="yara.bad_max_matches",
        )


def scan_source(
    source: Any,
    rules: "yara.Rules",
    *,
    view: Optional[str] = None,
    chunk_bytes: int = CHUNK_BYTES,
    overlap_bytes: int = 0,
    max_matches: Optional[int] = DEFAULT_MAX_MATCHES,
    timeout_s: int = DEFAULT_TIMEOUT_S,
) -> ScanResult:
    """Scan one :class:`~core.dump_source.DumpSource` with compiled *rules*.

    The strategy is picked from the dump format:

    * ``format_name == "raw"`` and the raw view -> ``strategy="filepath"``.
      libyara maps the file itself, which is both correct (for a raw dump the
      file offset *is* the view offset) and the only genuinely streaming option
      available: :meth:`RawDumpSource.iter_ranges` is implemented on top of
      ``read_all()`` (``core/dump_source.py:181-183``), so it materialises the
      whole dump and is NOT a streaming seam.
    * everything else -> ``strategy="chunked"`` via :func:`scan_chunked`,
      because those bytes must be decrypted and/or VAS-projected before a
      pattern means anything.

    Args:
        source: An OPEN dump source. The chunked strategy reads through it, so
            an unopened source yields a zero-size, zero-match result.
        rules: Output of :func:`compile_rules`.
        view: View to scan. Defaults to the source's own default view.
        chunk_bytes: Chunked strategy only; bytes scanned per libyara call.
        overlap_bytes: Chunked strategy only; ``0`` means auto (see
            :func:`_resolve_overlap`).
        max_matches: Stop after this many matches and set ``truncated``. Must
            be positive; ``None`` means "no cap" (see
            :func:`_validate_max_matches`).
        timeout_s: libyara budget, per chunk (chunked) or per file (filepath).

    Returns:
        A :class:`ScanResult`. Failures that concern one chunk are recorded in
        ``errors``/``timed_out`` instead of propagating, so one bad dump cannot
        abort a corpus sweep; argument and rule errors still raise.
    """
    _require_yara()
    _validate_max_matches(max_matches)
    resolved_view = view if view is not None else _default_view(source)
    if getattr(source, "format_name", None) == "raw" and resolved_view == "raw":
        return _scan_filepath(
            source,
            rules,
            view=resolved_view,
            max_matches=max_matches,
            timeout_s=timeout_s,
        )
    return scan_chunked(
        source,
        rules,
        view=resolved_view,
        chunk_bytes=chunk_bytes,
        overlap_bytes=overlap_bytes,
        max_matches=max_matches,
        timeout_s=timeout_s,
    )


def _scan_filepath(
    source: Any,
    rules: "yara.Rules",
    *,
    view: str,
    max_matches: Optional[int],
    timeout_s: int,
) -> ScanResult:
    """Hand the file to libyara and let it do its own zero-copy mapping."""
    _validate_max_matches(max_matches)
    path = Path(source.path)
    errors: List[str] = []
    matches: List[RuleMatch] = []
    truncated = False
    timed_out = False
    chunks = 0
    try:
        scanned = path.stat().st_size
    except OSError as exc:
        scanned = 0
        errors.append(f"cannot stat {path}: {exc}")
        logger.warning("yara scan: cannot stat %s: %s", path, exc)

    if not errors:
        chunks = 1
        try:
            raw_matches = rules.match(filepath=str(path), timeout=timeout_s)
        except _YaraError as exc:
            if HAS_YARA and isinstance(exc, yara.TimeoutError):
                timed_out = True
                message = f"scan of {path.name} timed out after {timeout_s}s"
            else:
                message = f"scan of {path.name} failed: {exc}"
            errors.append(message)
            logger.warning("yara scan: %s", message)
            raw_matches = []
        extracted = _extract_matches(raw_matches, chunk_start=0, own_len=None)
        matches, truncated = _apply_cap(extracted, [], max_matches)

    return ScanResult(
        dump_path=str(path),
        view=view,
        scanned_bytes=scanned,
        rule_names=rule_names(rules),
        matches=tuple(matches),
        truncated=truncated,
        timed_out=timed_out,
        chunks=chunks,
        strategy=_STRATEGY_FILEPATH,
        errors=tuple(errors),
    )


def _apply_cap(
    new_matches: List[RuleMatch],
    kept: List[RuleMatch],
    max_matches: Optional[int],
) -> Tuple[List[RuleMatch], bool]:
    """Append *new_matches* to *kept* up to *max_matches*.

    Returns the (possibly unchanged) list plus whether the cap bit. The cap is
    a reporting decision, not a silent one -- the boolean travels out to
    :attr:`ScanResult.truncated`.

    ``max_matches=None`` is the uncapped path and reports ``truncated=False``,
    which is the truth: nothing was dropped. A non-positive *max_matches*
    cannot reach here from a public entry point -- all three validate it via
    :func:`_validate_max_matches` -- but it is still handled the same way, so
    this helper stays total rather than dividing by a cap of zero.
    """
    if max_matches is None or max_matches <= 0:
        kept.extend(new_matches)
        return kept, False
    room = max_matches - len(kept)
    if room <= 0:
        return kept, True
    if len(new_matches) <= room:
        kept.extend(new_matches)
        return kept, False
    kept.extend(new_matches[:room])
    return kept, True


def scan_chunked(
    source: Any,
    rules: "yara.Rules",
    *,
    view: Optional[str] = None,
    chunk_bytes: int = CHUNK_BYTES,
    overlap_bytes: int = 0,
    max_matches: Optional[int] = DEFAULT_MAX_MATCHES,
    timeout_s: int = DEFAULT_TIMEOUT_S,
) -> ScanResult:
    """Scan any dump source chunk-by-chunk through :meth:`read_range`.

    :func:`scan_source` routes here for every format whose bytes need work
    before a pattern means anything. It is public in its own right for two
    reasons: a caller may want the projected-view coordinates even for a raw
    dump, and a differential check ("do the chunked offsets equal the filepath
    offsets for this same file?") is the cheapest available proof that the
    rebase arithmetic is correct.

    Limitation, stated rather than hidden: a rule string longer than the
    effective overlap can straddle a chunk boundary with neither chunk holding
    it whole, and such a match is simply not found. The automatic overlap sizes
    itself from the rules' ``pattern_length`` meta precisely to avoid this, but
    a rule set without that meta, or an explicit undersized *overlap_bytes*,
    reopens the gap. Both of those now land in :attr:`ScanResult.errors` rather
    than passing unremarked.

    *max_matches* must be positive; ``None`` asks for no cap at all (see
    :func:`_validate_max_matches`).
    """
    _require_yara()
    _validate_max_matches(max_matches)
    resolved_view = view if view is not None else _default_view(source)
    overlap, errors = _resolve_overlap(overlap_bytes, chunk_bytes, rules)

    # Genuine I/O failure degrades into ``errors`` (consistent with the
    # empty-read handling in the loop below, and with this module's rule that
    # one bad dump must not abort a corpus sweep) -- but ONLY OSError does.
    #
    # ``CapabilityError`` is deliberately not caught, and that is load-bearing
    # rather than incidental: ``EncryptedDumpLockedError`` is a
    # ``CapabilityError``, and a locked ``.msl`` reads back EMPTY instead of
    # failing, so degrading it here would report a locked dump as an honest
    # zero-match scan -- the exact false negative
    # ``test_g9_producers_surface_locked_dump`` exists to prevent. It is not an
    # ``OSError``, so the narrow ``except`` already lets it through; the
    # explicit re-raise says so out loud and keeps that true if the hierarchy
    # ever moves.
    try:
        size = int(source.size_for(resolved_view) or 0)
    except CapabilityError:
        raise
    except OSError as exc:
        size = 0
        message = f"cannot size view {resolved_view!r}: {exc}"
        errors.append(message)
        logger.warning("yara scan: %s", message)

    matches: List[RuleMatch] = []
    seen: set = set()
    truncated = False
    timed_out = False
    chunks = 0
    scanned = 0

    for chunk_start in range(0, size, chunk_bytes):
        own_len = min(chunk_bytes, size - chunk_start)
        read_len = min(own_len + overlap, size - chunk_start)
        # Same narrow funnel as the sizing call above: an unreadable region is
        # one chunk's bad news, a CapabilityError is the whole scan's.
        try:
            data = source.read_range(chunk_start, read_len, resolved_view)
        except CapabilityError:
            raise
        except OSError as exc:
            message = (
                f"failed read of {read_len} bytes at offset {chunk_start} "
                f"(view {resolved_view!r}): {exc}"
            )
            errors.append(message)
            logger.warning("yara scan: %s", message)
            continue
        if not data:
            message = (
                f"empty read of {read_len} bytes at offset {chunk_start} "
                f"(view {resolved_view!r})"
            )
            errors.append(message)
            logger.warning("yara scan: %s", message)
            continue
        # A source may clamp a read; the chunk can never own more bytes than
        # it actually got back.
        own_len = min(own_len, len(data))
        chunks += 1
        scanned += own_len
        try:
            raw_matches = rules.match(data=bytes(data), timeout=timeout_s)
        except _YaraError as exc:
            if HAS_YARA and isinstance(exc, yara.TimeoutError):
                timed_out = True
                message = (
                    f"chunk at offset {chunk_start} timed out after {timeout_s}s; "
                    f"its {own_len} bytes are unscanned"
                )
            else:
                message = f"chunk at offset {chunk_start} failed: {exc}"
            errors.append(message)
            logger.warning("yara scan: %s", message)
            continue

        fresh = [
            m
            for m in _extract_matches(
                raw_matches, chunk_start=chunk_start, own_len=own_len
            )
            if (m.rule, m.string_id, m.offset, m.length) not in seen
        ]
        for m in fresh:
            seen.add((m.rule, m.string_id, m.offset, m.length))
        matches, hit_cap = _apply_cap(fresh, matches, max_matches)
        if hit_cap:
            truncated = True
            logger.warning(
                "yara scan: match cap %d reached at offset %d; results truncated",
                max_matches, chunk_start,
            )
            break

    return ScanResult(
        dump_path=str(getattr(source, "path", "")),
        view=resolved_view,
        scanned_bytes=scanned,
        rule_names=rule_names(rules),
        matches=tuple(matches),
        truncated=truncated,
        timed_out=timed_out,
        chunks=chunks,
        strategy=_STRATEGY_CHUNKED,
        errors=tuple(errors),
    )
