"""YaraExporter - export patterns as YARA rules."""

import logging
import re
import unicodedata
from typing import Any, List, Optional, Tuple

logger = logging.getLogger("memdiver.architect.yara_exporter")

#: Words libyara's grammar reserves, so they cannot stand where an
#: *identifier* is expected -- which is exactly where a rule name and every
#: rule tag go. Verified against yara-python 4.5.4: each of these produces
#: "syntax error, unexpected <kw>, expecting identifier" in both positions.
#: ``include`` currently parses in the name position but is reserved by the
#: grammar elsewhere, so it is listed too rather than relying on that.
_YARA_KEYWORDS = frozenset({
    "rule", "meta", "strings", "condition", "and", "or", "not", "all", "any",
    "them", "for", "of", "at", "in", "filesize", "entrypoint", "import",
    "include", "private", "global", "true", "false", "ascii", "wide",
    "nocase", "fullword", "xor", "base64", "base64wide",
    # The quantifier/operator and integer-reader words below were MISSING, so
    # ``_sanitize_identifier`` passed them through and the exporter emitted an
    # uncompilable ``rule none { ... }``. libyara rejects each of these as an
    # identifier; ``none`` is merely the one a hypothesis draw happened to find
    # (``tests/test_yara_exporter_compiles.py``), and the other 21 were the same
    # latent bug waiting for a differently-named pattern. Over-listing is safe --
    # a false positive here only prefixes a name that did not need it, which is
    # why ``include`` stays even though this libyara accepts it. Under-listing
    # emits a rule that will not compile. The gap cannot silently reopen:
    # ``test_no_reserved_word_is_missing_from_the_keyword_set`` asks the INSTALLED
    # libyara which words it rejects rather than trusting this literal.
    "none", "defined", "matches", "contains",
    "startswith", "endswith", "icontains", "istartswith", "iendswith",
    "iequals",
    "int8", "int16", "int32", "uint8", "uint16", "uint32",
    "int8be", "int16be", "int32be", "uint8be", "uint16be", "uint32be",
})

#: libyara caps an identifier at 128 characters; a longer one is truncated by
#: the lexer mid-token and the rule fails to parse.
_MAX_IDENTIFIER_LENGTH = 128

#: Prefix that rescues a name the grammar would otherwise reject outright: a
#: leading digit, or a reserved word.
_IDENTIFIER_RESCUE_PREFIX = "r_"

#: What an all-unmappable (or empty) name degrades to.
_FALLBACK_IDENTIFIER = "unnamed_rule"


class YaraExporter:
    """Export byte patterns as YARA detection rules."""

    @staticmethod
    def export(
        pattern: dict,
        rule_name: Optional[str] = None,
        description: Optional[str] = None,
        tags: Optional[list] = None,
        key_offset: Optional[int] = None,
        key_length: Optional[int] = None,
    ) -> str:
        """Export a pattern dict as a YARA rule string.

        Every caller-supplied value reaches a position where YARA's grammar is
        strict, so each is normalised here rather than trusted: *rule_name* and
        *tags* become identifiers (see :func:`_sanitize_identifier`),
        *description* is escaped for a double-quoted meta string (see
        :func:`_escape_meta`), and the integer metas are coerced and clamped
        (see :func:`_meta_int`). An unknown ``pattern['length']`` omits the
        ``pattern_length`` meta line entirely rather than emitting ``0``, for
        the reason spelled out at the meta block below.

        The hex byte string is the one input that cannot be *normalised* into
        something meaningful -- a malformed token stream has no correct
        interpretation -- so it is VALIDATED instead and a bad one raises
        ``ValueError`` (see :func:`_normalize_wildcard_pattern`). That is
        deliberate: silently repairing it would ship a detector matching bytes
        the caller never asked for.

        Args:
            pattern: Pattern dict from PatternGenerator.generate().
            rule_name: YARA rule name (defaults to the pattern name).
                Sanitized either way -- HTTP and CLI callers pass user text
                straight through.
            description: Rule description. Escaped, not trusted.
            tags: Optional YARA tags. Each is sanitized to an identifier;
                blank entries, reserved words and duplicates are dropped.
            key_offset: Offset of the key bytes *within* the pattern, emitted
                as a ``key_offset`` meta line when supplied. Omitted entirely
                when None so an existing rule's meta block is unchanged.
            key_length: Length of the key bytes, emitted as a ``key_length``
                meta line when supplied.

        Returns:
            YARA rule as a string.

        Raises:
            ValueError: ``wildcard_pattern`` is missing, is not a string, or
                holds a token that is neither a hex byte pair nor ``??``. A
                malformed byte string has no valid interpretation, so it is
                rejected rather than repaired. An all-``??`` pattern is NOT
                rejected -- it is a legitimate (if degenerate) request via a
                zero minimum-static-ratio, and is warned about instead; see
                :func:`_normalize_wildcard_pattern`.

        Note:
            libyara's lexer bounds a string literal at a few kilobytes, so a
            description longer than that cannot be represented at all; this
            function escapes but deliberately does not truncate, so an
            extreme description surfaces as a compile error rather than as
            silently lost text.
        """
        name = _sanitize_identifier(rule_name or pattern.get("name", "memdiver_pattern"))
        desc = description or f"MemDiver pattern: {pattern.get('name', 'unknown')}"
        clean_tags = _sanitize_tags(tags)
        tag_str = " : " + " ".join(clean_tags) if clean_tags else ""

        # Validated, not trusted: this dict is caller-supplied and untyped, so a
        # missing/None value used to raise AttributeError out of a public static
        # method, and odd-length or non-hex tokens emitted a rule that only
        # failed to compile later, on the analyst's machine.
        yara_hex = _normalize_wildcard_pattern(pattern.get("wildcard_pattern"))

        # Every META VALUE is normalised, not just the string-typed ones. The
        # integer metas are emitted UNQUOTED, so YARA's grammar requires a bare
        # integer literal there: a non-numeric or None ``length`` (this dict is
        # caller-supplied and untyped) previously interpolated verbatim and
        # produced an uncompilable rule -- and nothing caught it, because the
        # export surface never compiles what it emits. ``_meta_int`` coerces and
        # clamps to a YARA-representable signed-64-bit range instead.
        #
        # ``pattern_length`` is OMITTED rather than emitted as ``0`` when the
        # length is absent or unparseable. A zero-byte pattern is not a thing
        # that exists, so ``pattern_length = 0`` is a false claim about the
        # rule -- and a load-bearing one: ``engine.yara_scan.max_pattern_length``
        # reads exactly this meta to size the chunk overlap of a chunked scan,
        # and treats a non-positive value as absent anyway. Emitting the lie
        # bought nothing and cost the reader the ability to tell "the emitter
        # did not know" apart from "the emitter measured zero". Absent is
        # honest, and every consumer already tolerates absence: ``yara_scan``
        # falls back (and now says so), while ``Volatility3Exporter``'s
        # ``$pattern_length`` template slot is fed from the pattern dict
        # directly, never from this meta.
        pattern_length = _meta_int(pattern.get("length", 0))
        meta_lines = [
            f'        description = "{_escape_meta(desc)}"',
        ]
        if pattern_length > 0:
            meta_lines.append(f'        pattern_length = {pattern_length}')
        meta_lines.append(
            f'        static_ratio = "{_escape_meta(str(pattern.get("static_ratio", 0)))}"'
        )
        if key_offset is not None:
            meta_lines.append(f'        key_offset = {_meta_int(key_offset)}')
        if key_length is not None:
            meta_lines.append(f'        key_length = {_meta_int(key_length)}')
        meta_lines.append('        generated_by = "MemDiver"')

        lines = [
            f'rule {name}{tag_str}',
            '{',
            '    meta:',
            *meta_lines,
            '',
            '    strings:',
            f'        $key = {{ {yara_hex} }}',
            '',
            '    condition:',
            '        $key',
            '}',
        ]
        rule = "\n".join(lines)

        # ``pattern_length``, not the raw ``pattern["length"]``: the dict is
        # caller-supplied, so the raw value can be None or a string, and ``%d``
        # against one of those raises inside logging -- silently under the
        # stdlib's handleError, but as a hard TypeError under any handler that
        # re-raises formatting failures (pytest's log capture does). The
        # coerced int is the same number in every case that used to work.
        # A pattern wider than libyara's regexp verification limit compiles
        # cleanly and matches NOTHING -- see
        # ``engine.yara_scan.regexp_scan_limit``. This exporter returns a bare
        # string and has no diagnostics channel of its own (its callers in
        # ``app.tools_pipeline`` attach ``export.pattern.over_scan_limit``), so
        # the log is the only voice it has; it is still worth having, because
        # ``export`` is a public static method that other code paths and tests
        # call directly. Imported lazily and guarded so this module keeps its
        # zero-import-cost, yara-optional character.
        if pattern_length > 0 and "?" in yara_hex:
            try:
                from memdiver.engine.yara_scan import (
                    pattern_exceeds_scan_limit,
                    regexp_scan_limit,
                )
            except ImportError:  # pragma: no cover - defensive
                pass
            else:
                if pattern_exceeds_scan_limit(pattern_length):
                    logger.warning(
                        "Exported YARA rule %s has a %d-byte wildcard pattern, "
                        "over the %s-byte limit the installed libyara will "
                        "verify: this rule will match NOTHING, not even the "
                        "dump its bytes came from. Re-emit with a smaller "
                        "context window.",
                        name, pattern_length, regexp_scan_limit(),
                    )
        logger.info("Exported YARA rule: %s (%d bytes)", name, pattern_length)
        return rule


def key_locator_from_pattern(
    pattern: dict,
) -> Tuple[Optional[int], Optional[int]]:
    """Read the key locator a *pattern* dict may already carry.

    ``engine.vol3_emit`` enriches the dict produced by
    :meth:`PatternGenerator.generate` with ``key_offset`` (relative to the
    pattern window start, exactly as :meth:`YaraExporter.export` wants it)
    and ``key_length``. Callers that hold only such a dict -- the HTTP
    ``/architect/export`` endpoint and
    :meth:`Volatility3Exporter.export`'s own YARA fallback -- recover the
    locator here rather than re-deriving or inventing it.

    A missing, ``None``, or non-integral value yields ``None`` so the meta
    line is omitted instead of emitted wrong: the dict can arrive verbatim
    from an HTTP request body, where any JSON value is possible.

    Returns:
        ``(key_offset, key_length)``, either element possibly ``None``.
    """
    return (_coerce_meta_int(pattern.get("key_offset")),
            _coerce_meta_int(pattern.get("key_length")))


def _coerce_meta_int(value: Any) -> Optional[int]:
    """Return *value* as an ``int``, or ``None`` if it is not integral.

    The INPUT-side counterpart of :func:`_meta_int`, and deliberately a
    different function rather than a shared one: the two answer different
    questions and so have different return types. This one decides *whether* a
    meta line should exist at all (``None`` => omit it, because a locator we
    cannot read is better left unstated than guessed), while
    :func:`_meta_int` makes a line that IS being emitted syntactically safe
    (always an ``int``, clamped to YARA's signed-64-bit meta range). A value
    read here therefore still passes through :func:`_meta_int` on emission.

    ``bool`` is excluded explicitly because ``isinstance(True, int)`` holds in
    Python, and ``key_offset = true`` in a JSON body is a caller error rather
    than the offset 1.
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _sanitize_identifier(name: str) -> str:
    """Convert a string to a valid YARA identifier.

    YARA identifiers are ASCII ``[A-Za-z0-9_]`` only, may not start with a
    digit, may not be a reserved word, and may not exceed 128 characters.
    """
    sanitized = ""
    for c in name:
        if c == "_" or (c.isascii() and c.isalnum()):
            sanitized += c
        else:
            sanitized += "_"
    if not sanitized:
        return _FALLBACK_IDENTIFIER
    if sanitized[0].isdigit() or sanitized in _YARA_KEYWORDS:
        budget = _MAX_IDENTIFIER_LENGTH - len(_IDENTIFIER_RESCUE_PREFIX)
        sanitized = _IDENTIFIER_RESCUE_PREFIX + sanitized[:budget]
    return sanitized[:_MAX_IDENTIFIER_LENGTH]


def _sanitize_tags(tags: Optional[list]) -> List[str]:
    """Normalise *tags* into usable YARA tag identifiers.

    A tag sits in the same identifier position as the rule name, so the same
    character rules apply. Blank entries carry no information and are
    dropped rather than emitted as ``unnamed_rule``; a reserved word is
    dropped too, because a tag is decorative and silently renaming it to
    ``r_ascii`` would be more surprising than losing it.
    """
    clean: List[str] = []
    for raw in tags or []:
        text = str(raw)
        if not text or text in _YARA_KEYWORDS:
            continue
        ident = _sanitize_identifier(text)
        if ident not in clean:
            clean.append(ident)
    return clean


#: A ``wildcard_pattern`` token: either a hex byte pair or the ``??`` wildcard.
#: ``PatternGenerator`` emits exactly these, space separated.
_WILDCARD_TOKEN = re.compile(r"\A(?:[0-9A-Fa-f]{2}|\?\?)\Z")


def _normalize_wildcard_pattern(wildcard: object) -> str:
    """Validate a space-separated hex/``??`` token stream; return it uppercased.

    Unlike every other input to :meth:`YaraExporter.export`, a malformed byte
    string has no correct normalisation -- guessing at one would emit a detector
    that matches bytes the caller never asked for -- so this raises instead.

    An all-``??`` pattern is WARNED about but allowed. It compiles and matches
    every buffer of its length -- a 100%-false-positive detector -- but a caller
    only reaches that state by explicitly asking for it: the CLI's
    ``min-static-ratio`` knob accepts ``0.0`` precisely to permit a
    fully-volatile region, and ``tests/test_aes_e2e.py`` exercises that path on
    a real dump whose key bytes differ in every capture. Refusing here would
    override an explicit operator decision and break a shipped workflow, so the
    honest behaviour is to make the degeneracy loud rather than fatal. Genuinely
    MALFORMED input still raises, because a bad token stream has no valid
    interpretation and no flag authorises it.
    """
    if not isinstance(wildcard, str) or not wildcard.strip():
        raise ValueError(
            "pattern['wildcard_pattern'] must be a non-empty string of "
            f"space-separated hex byte pairs and '??' wildcards, got {wildcard!r}"
        )
    tokens = wildcard.split()
    bad = [t for t in tokens if not _WILDCARD_TOKEN.match(t)]
    if bad:
        raise ValueError(
            "pattern['wildcard_pattern'] holds token(s) that are neither a hex "
            f"byte pair nor '??': {bad[:5]!r}"
            + (f" (and {len(bad) - 5} more)" if len(bad) > 5 else "")
        )
    if all(t == "??" for t in tokens):
        logger.warning(
            "pattern has NO fixed bytes (%d wildcard tokens): the emitted rule "
            "will match every buffer of that length, i.e. it is a "
            "100%%-false-positive detector. Raise the minimum static ratio so "
            "the pattern keeps at least one static anchor.",
            len(tokens),
        )
    return " ".join(t.upper() for t in tokens)


_META_INT_MAX = 2 ** 63 - 1


def _meta_int(value: object) -> int:
    """Coerce *value* to a YARA-emittable integer meta, never raising.

    The EMISSION-side counterpart of :func:`_coerce_meta_int` -- see that
    function for why the two are separate and how they compose.

    The integer metas (``pattern_length``, ``key_offset``, ``key_length``) are
    emitted unquoted, so YARA needs a bare integer literal. ``export`` takes an
    untyped, caller-supplied ``pattern`` dict, so a value can legitimately be a
    string, ``None``, a float, or wider than YARA's signed 64-bit meta range --
    each of which used to emit a rule that fails to compile on the analyst's
    machine rather than here. Unparseable values become ``0`` (an honest "not
    known" for a length/offset) and out-of-range values clamp.
    """
    try:
        parsed = int(value)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return 0
    if parsed > _META_INT_MAX:
        return _META_INT_MAX
    if parsed < -_META_INT_MAX:
        return -_META_INT_MAX
    return parsed


def _escape_meta(text: str) -> str:
    """Escape *text* for use inside a double-quoted YARA meta string.

    A raw ``"`` closes the literal early and a raw newline is a syntax
    error, so both are neutralised: backslashes are doubled *first* (so the
    escapes added next are not themselves re-escaped), quotes are escaped,
    and every control or line-breaking character -- ``\\r``, ``\\n``,
    ``\\t``, and anything else in a Unicode ``C*`` category -- collapses to
    a single space. Printable non-ASCII text is left alone; libyara accepts
    UTF-8 inside string literals.
    """
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return "".join(
        " " if (c.isspace() or unicodedata.category(c).startswith("C")) else c
        for c in escaped
    )
