"""Emitted YARA rules must COMPILE -- and must match what generated them.

Every pre-existing assertion about the YARA exporter is a substring check
(``assert "rule test_pattern" in rule``). A substring check cannot see a rule
that libyara refuses to parse, so two latent bugs survived: a caller-supplied
``rule_name`` was interpolated unsanitized (``my-rule.v2`` is not an
identifier), and ``description`` was interpolated unescaped into a
double-quoted meta string (one ``"`` ends the literal; a raw newline is a
syntax error). Both reach the exporter straight from user input via
``api/routers/architect.py`` and the CLI.

So this module asserts against the real compiler. ``import yara`` is a hard
import, deliberately NOT ``pytest.importorskip``: yara-python is a declared
base dependency (see ``tests/test_install_contract.py``), so its absence is a
broken environment that must fail loudly rather than quietly skip -- quiet
skipping is how the dependency went undeclared in the first place.

"Compiles" is still strictly weaker than "matches what generated it", so the
closure test below exports a pattern built from known bytes, compiles it, and
scans those same bytes with it.
"""

from __future__ import annotations

import ast
import random
import sys
from pathlib import Path

import yara
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.architect.pattern_generator import PatternGenerator  # noqa: E402
from memdiver.architect.volatility3_exporter import Volatility3Exporter  # noqa: E402
from memdiver.architect.yara_exporter import (  # noqa: E402
    _escape_meta,
    _sanitize_identifier,
    YaraExporter,
)

BASIC_PATTERN = {
    "name": "test_pattern",
    "wildcard_pattern": "AA ?? BB CC ?? DD",
    "length": 6,
    "static_ratio": 0.6667,
}


def _compile(rule_source: str) -> yara.Rules:
    """Compile *rule_source*, failing with the source on a syntax error."""
    try:
        return yara.compile(source=rule_source)
    except yara.SyntaxError as exc:  # pragma: no cover - only on regression
        raise AssertionError(
            f"emitted rule does not compile: {exc}\n--- source ---\n{rule_source}"
        ) from exc


def _only_rule(rules: yara.Rules):
    """The single compiled rule object, for meta/tag/identifier assertions."""
    listed = list(rules)
    assert len(listed) == 1, f"expected exactly one rule, got {len(listed)}"
    return listed[0]


# ---------------------------------------------------------------------------
# Compilation round-trips
# ---------------------------------------------------------------------------


def test_default_name_compiles():
    """The no-arguments export path produces a compilable rule."""
    rule = _only_rule(_compile(YaraExporter.export(BASIC_PATTERN)))
    assert rule.identifier == "test_pattern"


def test_caller_supplied_name_with_punctuation_compiles():
    """A rule_name with '-', '.' and spaces is sanitized, not passed through."""
    source = YaraExporter.export(BASIC_PATTERN, rule_name="my-rule.v2 name")
    rule = _only_rule(_compile(source))
    assert rule.identifier == "my_rule_v2_name"


def test_caller_supplied_name_that_is_a_yara_keyword_compiles():
    """A name colliding with a reserved word gets the r_ rescue prefix."""
    source = YaraExporter.export(BASIC_PATTERN, rule_name="filesize")
    rule = _only_rule(_compile(source))
    assert rule.identifier == "r_filesize"


def test_caller_supplied_name_with_leading_digit_compiles():
    """A leading digit is illegal in an identifier and gets the same prefix."""
    source = YaraExporter.export(BASIC_PATTERN, rule_name="123abc")
    rule = _only_rule(_compile(source))
    assert rule.identifier == "r_123abc"


def test_over_long_name_is_truncated_to_the_libyara_identifier_limit():
    """libyara caps an identifier at 128 chars; a longer one must be cut."""
    source = YaraExporter.export(BASIC_PATTERN, rule_name="n" * 400)
    rule = _only_rule(_compile(source))
    assert len(rule.identifier) == 128


def test_description_with_quote_newline_and_backslash_compiles():
    """The escaping bug: a quote closed the literal, a newline broke parsing."""
    source = YaraExporter.export(
        BASIC_PATTERN, description='he said "hi"\nline2\\x',
    )
    rule = _only_rule(_compile(source))
    meta = dict(rule.meta)
    # The quote survives as data, the newline collapses to a single space,
    # and the backslash is preserved rather than eating the next character.
    assert meta["description"] == 'he said "hi" line2\\x'


def test_tags_are_sanitized_deduped_and_keyword_filtered():
    """Tags sit in identifier position too: 1.3-beta and 'rule' are illegal."""
    source = YaraExporter.export(
        BASIC_PATTERN, tags=["tls", "1.3-beta", "rule", "", "tls"],
    )
    rule = _only_rule(_compile(source))
    assert rule.tags == ["tls", "r_1_3_beta"]


def test_all_wildcard_pattern_compiles():
    """A fully-volatile region still emits a parseable (if broad) rule."""
    pattern = {
        "name": "all_wild",
        "wildcard_pattern": " ".join(["??"] * 16),
        "length": 16,
        "static_ratio": 0.0,
    }
    _compile(YaraExporter.export(pattern))


def test_four_kilobyte_pattern_compiles():
    """A realistically large pattern (4 KB of hex tokens) still compiles."""
    rng = random.Random(1234)
    tokens = [
        "??" if i % 4 == 3 else f"{rng.randrange(256):02X}"
        for i in range(4096)
    ]
    pattern = {
        "name": "big_pattern",
        "wildcard_pattern": " ".join(tokens),
        "length": 4096,
        "static_ratio": 0.75,
    }
    _compile(YaraExporter.export(pattern))


def test_non_numeric_static_ratio_is_escaped_not_interpolated_raw():
    """static_ratio is emitted as a QUOTED meta value, so it needs escaping."""
    pattern = dict(BASIC_PATTERN, static_ratio='0.5" evil')
    rule = _only_rule(_compile(YaraExporter.export(pattern)))
    assert dict(rule.meta)["static_ratio"] == '0.5" evil'


# ---------------------------------------------------------------------------
# Emit <-> scan closure: the rule must match the bytes it was built from
# ---------------------------------------------------------------------------


def _closure_fixture() -> tuple[bytes, list[bool], dict]:
    """Known bytes + mask + the pattern PatternGenerator derives from them."""
    reference_bytes = bytes((i * 7 + 3) % 256 for i in range(64))
    # Volatile every 5th byte -> 80% static, comfortably over min_static_ratio.
    static_mask = [i % 5 != 0 for i in range(64)]
    pattern = PatternGenerator.generate(
        reference_bytes, static_mask, name="closure_pattern",
    )
    assert pattern is not None
    return reference_bytes, static_mask, pattern


def test_exported_rule_matches_the_bytes_it_was_generated_from():
    """The whole point of emitting a detector: it detects its own input."""
    reference_bytes, _, pattern = _closure_fixture()
    rules = _compile(YaraExporter.export(pattern))
    matches = rules.match(data=reference_bytes)
    assert len(matches) >= 1, "emitted rule does not match its own reference bytes"
    assert matches[0].rule == "closure_pattern"


def test_exported_rule_matches_when_volatile_bytes_differ():
    """Wildcards must actually be wildcards: flip every volatile byte."""
    reference_bytes, static_mask, pattern = _closure_fixture()
    mutated = bytes(
        b if static_mask[i] else (b ^ 0xFF)
        for i, b in enumerate(reference_bytes)
    )
    rules = _compile(YaraExporter.export(pattern))
    assert len(rules.match(data=mutated)) >= 1


def test_exported_rule_does_not_match_when_a_static_byte_differs():
    """A static byte is an anchor; changing one must break the match."""
    reference_bytes, static_mask, pattern = _closure_fixture()
    idx = static_mask.index(True)
    mutated = bytearray(reference_bytes)
    mutated[idx] ^= 0xFF
    rules = _compile(YaraExporter.export(pattern))
    assert rules.match(data=bytes(mutated)) == []


def test_key_offset_and_key_length_metas_round_trip():
    """The optional key-location metas survive compilation as integers."""
    _, _, pattern = _closure_fixture()
    source = YaraExporter.export(pattern, key_offset=32, key_length=16)
    meta = dict(_only_rule(_compile(source)).meta)
    assert meta["key_offset"] == 32
    assert meta["key_length"] == 16


def test_key_metas_are_absent_when_not_supplied():
    """Omitting them must leave an existing rule's meta block unchanged."""
    _, _, pattern = _closure_fixture()
    meta = dict(_only_rule(_compile(YaraExporter.export(pattern))).meta)
    assert "key_offset" not in meta
    assert "key_length" not in meta


# ---------------------------------------------------------------------------
# Property test: arbitrary user text must never emit an uncompilable rule
# ---------------------------------------------------------------------------

# Bounded because libyara itself is bounded: an identifier may not exceed 128
# characters and a string literal is capped by the lexer's buffer at a few
# kilobytes. The sizes below stay well inside both while still covering
# control characters, quotes, backslashes and non-ASCII text.
_TEXT = st.text(max_size=64)


@settings(
    max_examples=150,
    deadline=None,  # yara.compile() timing is machine-dependent
    suppress_health_check=[HealthCheck.too_slow],
)
@given(name=_TEXT, description=_TEXT, tags=st.lists(_TEXT, max_size=4))
def test_arbitrary_text_always_produces_a_compilable_rule(name, description, tags):
    """No string a user can type may produce a rule libyara rejects."""
    source = YaraExporter.export(
        BASIC_PATTERN, rule_name=name, description=description, tags=tags,
    )
    yara.compile(source=source)


@given(text=_TEXT)
@settings(max_examples=100, deadline=None)
def test_sanitize_identifier_always_yields_a_legal_identifier(text):
    """The identifier contract, checked directly rather than via a rule."""
    ident = _sanitize_identifier(text)
    assert ident
    assert len(ident) <= 128
    assert ident.isascii()
    assert all(c == "_" or c.isalnum() for c in ident)
    assert not ident[0].isdigit()
    from memdiver.architect.yara_exporter import _YARA_KEYWORDS

    assert ident not in _YARA_KEYWORDS


@given(text=_TEXT)
@settings(max_examples=100, deadline=None)
def test_escape_meta_never_leaves_a_bare_quote_or_control_character(text):
    """Escaped meta text can neither close the literal nor break the line."""
    escaped = _escape_meta(text)
    assert "\n" not in escaped and "\r" not in escaped and "\t" not in escaped
    # Every remaining quote is backslash-escaped, and every escaping
    # backslash is itself doubled -- check by compiling a literal with it.
    yara.compile(source=f'rule ok {{ meta: d = "{escaped}" condition: true }}')


# ---------------------------------------------------------------------------
# Volatility3 plugin: the source must import AND its embedded rule must compile
# ---------------------------------------------------------------------------


def _embedded_yara_rule(plugin_source: str) -> str:
    """Pull the YARA_RULE literal out of a generated plugin via the AST.

    Read from the parsed tree rather than by regex so the extraction cannot
    drift from what Python itself would see in the generated module.
    """
    tree = ast.parse(plugin_source)
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if "YARA_RULE" in targets and isinstance(node.value, ast.Constant):
            return node.value.value
    raise AssertionError("generated plugin has no YARA_RULE string assignment")


def test_volatility3_plugin_parses_and_its_embedded_rule_compiles():
    """The plugin ships its rule inside `try/except Exception: pass`.

    That swallow means an uncompilable embedded rule degrades silently to the
    unverified BytesScanner path at runtime, so nothing downstream would ever
    report it. Compile it here instead.
    """
    _, _, pattern = _closure_fixture()
    source = Volatility3Exporter.export(pattern)
    ast.parse(source)  # the plugin must be importable Python
    _compile(_embedded_yara_rule(source))


def test_volatility3_plugin_with_hostile_name_and_description():
    """The same punctuation/quote/newline hostility, through the vol3 path."""
    _, _, pattern = _closure_fixture()
    yara_rule = YaraExporter.export(
        pattern, rule_name="my-rule.v2 name", description='q"uote\nnewline',
    )
    source = Volatility3Exporter.export(
        pattern, description='q"uote\nnewline', yara_rule=yara_rule,
    )
    ast.parse(source)
    rule = _only_rule(_compile(_embedded_yara_rule(source)))
    assert rule.identifier == "my_rule_v2_name"
