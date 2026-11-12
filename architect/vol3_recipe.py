"""Recipe v2: a declarative description of a synthesized Volatility 3 plugin.

A :class:`PluginRecipe` says HOW to find a secret (``locators``), how to cut a
candidate key out of what was found (``decoder``), how to PROVE a candidate
(``oracle``: a format oracle from :mod:`memdiver.oracles` plus its evidence
sample) and what to export. :func:`render` turns a recipe into the source of a
standalone single-file plugin (template ``templates/vol3_plugin_v2.py.tmpl``)
that imports only the standard library and ``volatility3`` and carries the
oracle source inlined verbatim by :mod:`memdiver.oracles.embed`.
:func:`emit` writes the plugin plus its ``.recipe.json`` (and ``.yar`` when
there is an anchor) and self-tests it in-process with
:func:`memdiver.engine.vol3_verify.run_over_buffer`.

:func:`recipe_from_located_key` builds a recipe from real data: it locates a
known key in one or more captures (``engine.key_location``), wildcards the key
bytes, measures the static mask of the neighbourhood across every occurrence
(``StaticChecker``) and packs the oracle sample with the format module.

Design rule: the ANCHOR only proposes candidates; the ORACLE alone decides
``Proven``. A weak anchor therefore costs time (extra, capped candidates),
never a false proof. Degenerate anchors (filler such as zero padding) are
still refused by :func:`emit` unless ``strict_anchors=False``.

Adjacent-secret rule: a static anchor byte is copied verbatim into the plugin,
so a HIGH-ENTROPY static run (>= 16 bytes, >= 3.5 bits/byte over 16 bytes)
next to the key may be another secret of the same session (an IV, a second
key). :func:`recipe_from_located_key` therefore refuses such an anchor unless
``allow_high_entropy_context=True`` -- EXCEPT when the mask was measured over
captures holding at least two DIFFERENT keys: a run that stays byte-identical
across independent sessions is a program constant (e.g. the 32-byte constant
gocryptfs keeps in front of its master key), not a per-session secret.

Layering: ``architect`` imports ``engine``/``core``/``oracles`` only inside
functions (``engine.vol3_emit`` imports ``architect`` at module level).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import math
import re
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from os import path as os_path
from os import stat as os_stat
from os import walk as os_walk
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from .pattern_generator import PatternGenerator

logger = logging.getLogger("memdiver.architect.vol3_recipe")

SCHEMA_ID = "memdiver-vol3-recipe/2"
TEMPLATE_PATH = Path(__file__).resolve().parent / "templates" / "vol3_plugin_v2.py.tmpl"

IMPLEMENTED_LOCATORS = ("anchor_regex", "entropy")
RESERVED_LOCATORS = ("yara", "artifact_window", "aes_schedule", "pubkey_adjacency",
                     "kernel_struct")
CANDIDATE_LAYOUTS = ("single",)
SAMPLE_INLINE_MAX = 8 * 1024

#: Degenerate-anchor thresholds, the values ``export_key_pattern`` uses
#: (``app.tools_pipeline.KEY_PATTERN_MIN_ANCHOR_BYTES`` / ``..._BITS``): fewer
#: than 3 distinct anchor byte values, or zero bits/byte, is filler.
MIN_ANCHOR_DISTINCT_BYTES = 3
MIN_ANCHOR_SHANNON_BITS = 0.0

DEFAULT_CONTEXT = 64
DEFAULT_ENTROPY_THRESHOLD = 4.5
DEFAULT_MAX_ANCHOR_HITS = 4096
DEFAULT_MAX_ENTROPY_CANDIDATES = 500_000
#: Largest entropy-scan step inferred from observed key alignment.
MAX_INFERRED_STEP = 8
#: Adjacent-secret guard: a static run of at least this many bytes with a
#: window of that size at or above HIGH_ENTROPY_BITS bits/byte is "high entropy".
HIGH_ENTROPY_RUN = 16
HIGH_ENTROPY_BITS = 3.5
SAMPLE_DIR_MAX_DEPTH = 3
SAMPLE_DIR_MAX_FILES = 10000
_TOKEN = re.compile(r"^(?:[0-9a-fA-F]{2}|\?\?)$")


class RecipeError(ValueError):
    """A recipe is malformed or cannot be rendered."""


class UnimplementedLocatorError(NotImplementedError):
    """A recognised, reserved locator kind that no template implements yet."""


class DegenerateAnchorError(RecipeError):
    """An anchor's static bytes are filler and would match almost anywhere."""


class HighEntropyContextError(RecipeError):
    """A static anchor run looks like a neighbouring secret (see the module docstring)."""


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Locator:
    """How candidates are found: ``kind`` plus its JSON-able ``params``."""

    kind: str
    params: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.kind not in IMPLEMENTED_LOCATORS + RESERVED_LOCATORS:
            raise RecipeError(f"unknown locator kind {self.kind!r}; known: "
                              f"{IMPLEMENTED_LOCATORS + RESERVED_LOCATORS}")
        object.__setattr__(self, "params", dict(self.params))

    @property
    def implemented(self) -> bool:
        return self.kind in IMPLEMENTED_LOCATORS

    def to_dict(self) -> dict:
        return {"kind": self.kind, "params": dict(self.params)}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Locator":
        return cls(str(data["kind"]), dict(data.get("params") or {}))


@dataclass(frozen=True)
class Decoder:
    """Cuts a candidate key out of a located window."""

    key_offset: int
    key_length: int
    candidate_layout: str = "single"
    cipher: Optional[str] = None
    fields: Tuple[Mapping[str, Any], ...] = ()

    def __post_init__(self) -> None:
        if self.key_length <= 0 or self.key_offset < 0:
            raise RecipeError("decoder needs key_offset >= 0 and key_length > 0")
        if self.candidate_layout not in CANDIDATE_LAYOUTS:
            raise RecipeError(f"candidate_layout {self.candidate_layout!r} is not "
                              f"implemented; known: {CANDIDATE_LAYOUTS}")
        object.__setattr__(self, "fields", tuple(dict(f) for f in self.fields))

    def to_dict(self) -> dict:
        return {"key_offset": self.key_offset, "key_length": self.key_length,
                "candidate_layout": self.candidate_layout, "cipher": self.cipher,
                "fields": [dict(f) for f in self.fields]}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Decoder":
        return cls(int(data["key_offset"]), int(data["key_length"]),
                   str(data.get("candidate_layout") or "single"), data.get("cipher"),
                   tuple(data.get("fields") or ()))


@dataclass(frozen=True)
class OracleSample:
    """The oracle's evidence: inline (base64, <= 8 KiB) or a path, plus sha256."""

    inline_b64: Optional[str] = None
    path: Optional[str] = None
    sha256: Optional[str] = None

    def __post_init__(self) -> None:
        if (self.inline_b64 is None) == (self.path is None):
            raise RecipeError("an oracle sample is inline_b64 XOR path")
        if self.inline_b64 is not None:
            blob = base64.b64decode(self.inline_b64, validate=True)
            if len(blob) > SAMPLE_INLINE_MAX:
                raise RecipeError(f"inline sample is {len(blob)} bytes "
                                  f"(cap {SAMPLE_INLINE_MAX})")
            digest = hashlib.sha256(blob).hexdigest()
            if self.sha256 is None:
                object.__setattr__(self, "sha256", digest)
            elif self.sha256 != digest:
                raise RecipeError("inline sample does not match its sha256")

    @classmethod
    def from_bytes(cls, blob: bytes) -> "OracleSample":
        return cls(inline_b64=base64.b64encode(bytes(blob)).decode("ascii"))

    def blob(self) -> bytes:
        """The sample bytes (read from ``path`` when not inline; sha256-checked)."""
        data = (base64.b64decode(self.inline_b64) if self.inline_b64 is not None
                else Path(str(self.path)).read_bytes())
        if self.sha256 and hashlib.sha256(data).hexdigest() != self.sha256:
            raise RecipeError("oracle sample does not match its sha256")
        return data

    def to_dict(self) -> dict:
        return {"inline_b64": self.inline_b64, "path": self.path, "sha256": self.sha256}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "OracleSample":
        return cls(data.get("inline_b64"), data.get("path"), data.get("sha256"))


#: ctx keys the generated plugin fills at run time; a recipe's static ctx may not set them.
RUNTIME_ORACLE_CTX_KEYS = ("found", "layer", "read", "offset", "locators")


@dataclass(frozen=True)
class OracleSpec:
    """Which format oracle proves candidates, its params, its sample and its static ctx.

    ``ctx`` (JSON values only, default empty) is merged UNDER the ctx the plugin
    builds at run time (:data:`RUNTIME_ORACLE_CTX_KEYS`) for every ``verify``.
    """

    kind: str
    params: Mapping[str, Any] = field(default_factory=dict)
    sample: Optional[OracleSample] = None
    ctx: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "params", dict(self.params))
        object.__setattr__(self, "ctx", _checked_oracle_ctx(self.ctx))

    def to_dict(self) -> dict:
        data = {"kind": self.kind, "params": dict(self.params),
                "sample": self.sample.to_dict() if self.sample else None}
        if self.ctx:  # omitted when empty: recipes without a ctx stay byte-identical
            data["ctx"] = dict(self.ctx)
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "OracleSpec":
        sample = data.get("sample")
        return cls(str(data["kind"]), dict(data.get("params") or {}),
                   OracleSample.from_dict(sample) if sample else None,
                   dict(data.get("ctx") or {}))


def _checked_oracle_ctx(ctx: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """A static oracle ctx: a JSON-serialisable dict without run-time keys."""
    ctx = dict(ctx or {})
    reserved = sorted(set(ctx) & set(RUNTIME_ORACLE_CTX_KEYS))
    if reserved:
        raise RecipeError(f"oracle ctx keys {reserved} are filled by the plugin at run time")
    try:
        json.dumps(ctx, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise RecipeError(f"oracle ctx must be JSON-serialisable: {exc}") from exc
    return ctx


@dataclass(frozen=True)
class Exporter:
    """Report formats the plugin can write with ``--export``."""

    formats: Tuple[str, ...] = ("json",)

    def __post_init__(self) -> None:
        unknown = [f for f in self.formats if f != "json"]
        if unknown:
            raise RecipeError(f"unsupported export formats {unknown}; known: ['json']")
        object.__setattr__(self, "formats", tuple(self.formats))

    def to_dict(self) -> dict:
        return {"formats": list(self.formats)}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Exporter":
        return cls(tuple(data.get("formats") or ("json",)))


_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class PluginRecipe:
    """Everything needed to render one synthesized plugin."""

    name: str
    class_name: str
    description: str
    locators: Tuple[Locator, ...]
    decoder: Decoder
    oracle: Optional[OracleSpec] = None
    exporter: Exporter = field(default_factory=Exporter)
    provenance: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for label, value in (("name", self.name), ("class_name", self.class_name)):
            if not _IDENT.match(value):
                raise RecipeError(f"{label} {value!r} is not a Python identifier")
        if not self.locators:
            raise RecipeError("a recipe needs at least one locator")
        object.__setattr__(self, "locators", tuple(self.locators))
        object.__setattr__(self, "provenance", dict(self.provenance))

    def to_dict(self) -> dict:
        return {"schema": SCHEMA_ID, "name": self.name, "class_name": self.class_name,
                "description": self.description,
                "locators": [loc.to_dict() for loc in self.locators],
                "decoder": self.decoder.to_dict(),
                "oracle": self.oracle.to_dict() if self.oracle else None,
                "exporter": self.exporter.to_dict(),
                "provenance": dict(self.provenance)}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=1, sort_keys=True)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "PluginRecipe":
        if data.get("schema") != SCHEMA_ID:
            raise RecipeError(f"schema {data.get('schema')!r} is not {SCHEMA_ID!r}")
        oracle = data.get("oracle")
        return cls(
            name=str(data["name"]), class_name=str(data["class_name"]),
            description=str(data.get("description") or ""),
            locators=tuple(Locator.from_dict(loc) for loc in data["locators"]),
            decoder=Decoder.from_dict(data["decoder"]),
            oracle=OracleSpec.from_dict(oracle) if oracle else None,
            exporter=Exporter.from_dict(data.get("exporter") or {}),
            provenance=dict(data.get("provenance") or {}),
        )

    @classmethod
    def from_json(cls, text: str) -> "PluginRecipe":
        return cls.from_dict(json.loads(text))

    def anchor_locators(self) -> List[Locator]:
        return [loc for loc in self.locators if loc.kind == "anchor_regex"]


# --------------------------------------------------------------------------
# Anchor quality
# --------------------------------------------------------------------------

def _anchor_parts(tokens: str) -> Tuple[bytes, List[bool]]:
    """``(reference bytes, static mask)`` of a wildcard token string."""
    values, mask = [], []
    for token in tokens.split():
        mask.append(token != "??")  # nosec B105 -- "??" is a YARA-style wildcard byte, not a password
        values.append(0 if token == "??" else int(token, 16))  # nosec B105 -- wildcard byte
    return bytes(values), mask


def anchor_quality(locator: Locator) -> Dict[str, Any]:
    """``PatternGenerator.anchor_distinctiveness`` of an anchor + a ``degenerate`` flag."""
    reference, mask = _anchor_parts(str(locator.params.get("pattern", "")))
    quality: Dict[str, Any] = dict(PatternGenerator.anchor_distinctiveness(reference, mask))
    quality["degenerate"] = bool(
        quality["distinct_bytes"] < MIN_ANCHOR_DISTINCT_BYTES
        or quality["shannon_bits"] <= MIN_ANCHOR_SHANNON_BITS)
    return quality


def check_anchors(recipe: PluginRecipe, strict: bool = True) -> List[Dict[str, Any]]:
    """Diagnostics for every anchor; raises :class:`DegenerateAnchorError` if strict."""
    diagnostics = []
    for index, locator in enumerate(recipe.anchor_locators()):
        quality = anchor_quality(locator)
        if not quality["degenerate"]:
            continue
        message = (f"anchor {index} is degenerate: {quality['distinct_bytes']} distinct "
                   f"byte value(s), {quality['shannon_bits']} bits/byte over "
                   f"{quality['static_bytes']} static bytes; it pins filler, not "
                   f"structure. Widen the context or add captures.")
        if strict:
            raise DegenerateAnchorError(message)
        diagnostics.append({"code": "vol3_recipe.degenerate_anchor", "severity": "warning",
                            "message": message, "details": quality})
    return diagnostics


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

_PLACEHOLDER = re.compile(r"@@([A-Z_]+)@@")
_NO_ORACLE_BUNDLE = "# (no oracle inlined)\nMEMDIVER_INLINED_SOURCES = ''\n"


def _check_renderable(recipe: PluginRecipe) -> None:
    for locator in recipe.locators:
        if not locator.implemented:
            raise UnimplementedLocatorError(
                f"locator kind {locator.kind!r} is reserved but not implemented by the "
                f"v2 template yet; implemented: {IMPLEMENTED_LOCATORS}")
    for locator in recipe.anchor_locators():
        _check_anchor_tokens(locator, recipe.decoder)


def _check_anchor_tokens(locator: Locator, decoder: Decoder) -> None:
    """An anchor pattern is hex byte tokens / ``??``, holds the key, has a static byte."""
    tokens = str(locator.params.get("pattern", "")).split()
    bad = [t for t in tokens if not _TOKEN.match(t)]
    if not tokens or bad:
        raise RecipeError(f"anchor pattern has invalid tokens {bad[:5]} (want 'aa' or '??')")
    if all(t == "??" for t in tokens):
        raise RecipeError("anchor pattern has no static byte")
    key_offset = int(locator.params.get("key_offset", decoder.key_offset))
    if key_offset + decoder.key_length > len(tokens):
        raise RecipeError(f"key [{key_offset}, +{decoder.key_length}) lies outside the "
                          f"{len(tokens)}-byte anchor pattern")


def _docstring_safe(text: str) -> str:
    return text.replace("\\", "/").replace('"""', "'''")


def _raw_literal_safe(text: str, what: str) -> str:
    if "'''" in text or text.endswith("\\"):
        raise RecipeError(f"{what} cannot be embedded in a raw ''' string")
    return text


def _yara_rule(recipe: PluginRecipe) -> str:
    anchors = recipe.anchor_locators()
    if not anchors:
        return ""
    from .yara_exporter import YaraExporter

    params = anchors[0].params
    tokens = str(params["pattern"])
    pattern = {"name": recipe.name, "length": len(tokens.split()),
               "wildcard_pattern": tokens,
               "static_ratio": float(params.get("static_ratio", 0.0))}
    key_offset = int(params.get("key_offset", recipe.decoder.key_offset))
    return YaraExporter.export(pattern, rule_name=recipe.name,
                               description=recipe.description[:200] or None,
                               key_offset=key_offset, key_length=recipe.decoder.key_length)


def _pattern_length(recipe: PluginRecipe) -> int:
    anchors = recipe.anchor_locators()
    if anchors:
        return len(str(anchors[0].params["pattern"]).split())
    return recipe.decoder.key_length


def oracle_bundle(recipe: PluginRecipe) -> str:
    """The inlined-oracle bundle text for ``recipe`` (``oracles.embed.render_bundle``)."""
    if recipe.oracle is None:
        return _NO_ORACLE_BUNDLE
    from memdiver.oracles.embed import render_bundle

    return render_bundle([recipe.oracle.kind])


def render(recipe: PluginRecipe, *, bundle: Optional[str] = None) -> str:
    """Plugin source for ``recipe``; deterministic for a given recipe + oracle sources.

    ``bundle`` replaces the inlined-oracle bundle (tests pin the template part
    with a placeholder so a change to an oracle module does not churn the pin).
    """
    _check_renderable(recipe)
    values = {
        "NAME": recipe.name,
        "CLASS_NAME": recipe.class_name,
        "DESCRIPTION": _docstring_safe(recipe.description or recipe.name),
        "PATTERN_LENGTH": str(_pattern_length(recipe)),
        "YARA_RULE": _raw_literal_safe(_yara_rule(recipe), "YARA rule"),
        "RECIPE_JSON": _raw_literal_safe(recipe.to_json(), "recipe JSON"),
        "BUNDLE": oracle_bundle(recipe) if bundle is None else bundle,
    }
    template = TEMPLATE_PATH.read_text(encoding="utf-8")
    source = _PLACEHOLDER.sub(lambda m: values[m.group(1)], template)
    compile(source, f"<vol3 recipe {recipe.name}>", "exec")
    return source


# --------------------------------------------------------------------------
# Emission + self-test
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class SelfTestHits:
    """What the emitted plugin reported over the reference data."""

    found: bool
    proven: int
    rows: int
    expected_offset: Optional[int] = None
    expected_offset_reported: Optional[bool] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass(frozen=True)
class EmitResult:
    source: str
    path: Path
    yara_path: Optional[Path]
    recipe: PluginRecipe
    self_test: Optional[SelfTestHits]
    diagnostics: Tuple[Dict[str, Any], ...] = ()


def _plugin_path(recipe: PluginRecipe, output_path: Union[str, Path]) -> Path:
    path = Path(output_path)
    if path.suffix != ".py":
        path = path / f"{recipe.name}.py"
    if not _IDENT.match(path.stem):
        raise RecipeError(f"plugin file stem {path.stem!r} must be a Python identifier "
                          f"(vol loads it as volatility3.plugins.<stem>)")
    return path


def self_test(source: str, reference_data: bytes,
              expected_offset: Optional[int] = None) -> SelfTestHits:
    """Run ``source`` in-process over ``reference_data`` (``vol3_verify.run_over_buffer``)."""
    from memdiver.engine.vol3_verify import run_over_buffer

    report = run_over_buffer(source, reference_data, expected_offset=expected_offset)
    return SelfTestHits(
        found=report.match_count > 0, proven=report.proven_count, rows=report.match_count,
        expected_offset=expected_offset,
        expected_offset_reported=(report.expected_offset_reported
                                  if expected_offset is not None else None))


def emit(recipe: PluginRecipe, reference_data: Optional[bytes],
         output_path: Union[str, Path], strict_anchors: bool = True, *,
         expected_offset: Optional[int] = None,
         before_self_test: Optional[Callable[[], None]] = None) -> EmitResult:
    """Write ``<name>.py`` + ``<name>.recipe.json`` (+ ``<name>.yar``) and self-test.

    ``output_path`` is the plugin file or a directory to write it into.
    ``reference_data`` (skipped when ``None``) is scanned in-process; a failed
    self-test is reported in ``self_test.error``, not raised.
    *before_self_test* runs after the files are written and before the
    self-test (a background job's cancel check); what it raises propagates.
    """
    diagnostics = check_anchors(recipe, strict=strict_anchors)
    source = render(recipe)
    path = _plugin_path(recipe, output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    path.with_name(f"{path.stem}.recipe.json").write_text(recipe.to_json() + "\n",
                                                          encoding="utf-8")
    yara_path = None
    rule = _yara_rule(recipe)
    if rule:
        yara_path = path.with_name(f"{path.stem}.yar")
        yara_path.write_text(rule.rstrip("\n") + "\n", encoding="utf-8")
    result_test = None
    if reference_data is not None:
        if before_self_test is not None:
            before_self_test()
        try:
            result_test = self_test(source, reference_data, expected_offset)
        except Exception as exc:  # reported, not raised: the files are written
            logger.warning("self-test of %s failed: %s", path, exc)
            result_test = SelfTestHits(False, 0, 0, expected_offset, None, repr(exc))
    logger.info("wrote vol3 v2 plugin %s (%d bytes)", path, len(source))
    return EmitResult(source, path, yara_path, recipe, result_test, tuple(diagnostics))


# --------------------------------------------------------------------------
# Builder from real data
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class _Occurrence:
    dump_path: str
    offset: int


def _parse_key(key_hex: str) -> bytes:
    text = re.sub(r"[\s:]", "", str(key_hex)).lower()
    if text.startswith("0x"):
        text = text[2:]
    try:
        key = bytes.fromhex(text)
    except ValueError as exc:
        raise RecipeError(f"key is not hex: {exc}") from exc
    if not key:
        raise RecipeError("empty key")
    return key


def _keys_per_dump(dump_paths: Sequence[str], key_hex: Union[str, Sequence[str]]) -> List[bytes]:
    if isinstance(key_hex, str):
        return [_parse_key(key_hex)] * len(dump_paths)
    keys = [_parse_key(k) for k in key_hex]
    if len(keys) != len(dump_paths):
        raise RecipeError(f"{len(keys)} keys for {len(dump_paths)} dumps")
    if len({len(k) for k in keys}) != 1:
        raise RecipeError("all keys must have the same length")
    return keys


def locate_occurrences(dump_paths: Sequence[str], keys: Sequence[bytes], *,
                       view: Optional[str] = None,
                       key_material: Optional[Dict[str, Any]] = None,
                       max_offsets: int = 64,
                       is_cancelled: Optional[Callable[[], bool]] = None,
                       opener: Optional[Callable[..., Any]] = None) -> List[_Occurrence]:
    """Every occurrence of each dump's key (``engine.key_location``).

    *is_cancelled* (a background job's) is checked before each dump; true raises
    ``engine.progress.Cancelled``. ``None`` (every other caller) checks nothing.
    *opener* replaces ``open_dump`` (see :func:`recipe_from_located_key`).
    """
    from memdiver.engine.key_location import locate_key_across_dumps
    from memdiver.engine.progress import Cancelled

    found: List[_Occurrence] = []
    for path, key in zip(dump_paths, keys):
        if is_cancelled is not None and is_cancelled():
            raise Cancelled()
        result = locate_key_across_dumps([path], key, view=view, key_material=key_material,
                                         max_offsets=max_offsets, allocator="off",
                                         opener=opener)
        for row in result.present:
            found.extend(_Occurrence(row.dump_path, int(o)) for o in row.offsets)
    if not found:
        raise RecipeError("the key is in none of the supplied dumps")
    return found


def _read_windows(occurrences: Sequence[_Occurrence], key_length: int, context: int, *,
                  view: Optional[str], key_material: Optional[Dict[str, Any]],
                  opener: Optional[Callable[..., Any]] = None
                  ) -> Tuple[List[bytes], int]:
    """Equal-length windows (common padding) around every occurrence; ``(windows, pad_left)``."""
    from memdiver.core.dump_source import open_dump

    opener = opener or open_dump

    view_kw = {} if view is None else {"view": view}
    pad_left = min(context, min(o.offset for o in occurrences))
    by_dump: Dict[str, List[int]] = {}
    for index, occ in enumerate(occurrences):
        by_dump.setdefault(occ.dump_path, []).append(index)
    sizes: Dict[str, int] = {}
    raw: List[bytes] = [b""] * len(occurrences)
    for dump_path, indices in by_dump.items():  # one open (and decrypt) per dump
        with opener(Path(dump_path), **(key_material or {})) as source:
            sizes[dump_path] = int(source.size_for(**view_kw))
            for index in indices:
                start = occurrences[index].offset - pad_left
                raw[index] = bytes(source.read_range(
                    start, pad_left + key_length + context, **view_kw))
    pad_right = max(0, min(min(context, sizes[o.dump_path] - o.offset - key_length)
                           for o in occurrences))
    length = pad_left + key_length + pad_right
    return [data[:length] for data in raw], pad_left


def _static_mask(windows: Sequence[bytes], key_offset: int, key_length: int) -> List[bool]:
    from .static_checker import StaticChecker

    mask, _reference = StaticChecker.check_regions(list(windows))
    mask = list(mask)
    for index in range(key_offset, key_offset + key_length):
        mask[index] = False  # the key is never an anchor
    return mask


def _inferred_step(occurrences: Sequence[_Occurrence]) -> int:
    """Largest power of two <= MAX_INFERRED_STEP dividing every observed key offset."""
    step = MAX_INFERRED_STEP
    while step > 1 and any(o.offset % step for o in occurrences):
        step //= 2
    return step


def build_oracle_sample(oracle_kind: str, sample_path: Union[str, Path]) -> bytes:
    """Pack the oracle evidence at ``sample_path`` with the format module.

    A directory goes through the module's ``sample_from_vault`` when it has
    one; a file is used as-is when the module accepts it as a packed sample,
    else packed with ``make_sample``.
    """
    from memdiver.oracles import get_format

    module = get_format(oracle_kind)
    path = Path(sample_path)
    if path.is_dir():
        reader = getattr(module, "sample_from_vault", None)
        if reader is None:
            raise RecipeError(f"oracle {oracle_kind} cannot read a directory sample")
        _check_sample_dir(path)
        return reader(str(path))
    raw = path.read_bytes()
    try:
        module.build_oracle({}, raw)
        return raw
    except ValueError:
        return module.make_sample(raw)


def _check_sample_dir(path: Path) -> None:
    """Same bounds as the plugin's ``check_sample_dir``: depth <= 3, <= 10000 files."""
    files = 0
    for root, _dirs, names in os_walk(path):
        depth = len(Path(root).relative_to(path).parts)
        if depth > SAMPLE_DIR_MAX_DEPTH:
            raise RecipeError(f"sample directory {path} is deeper than "
                              f"{SAMPLE_DIR_MAX_DEPTH} levels")
        files += len(names)
        if files > SAMPLE_DIR_MAX_FILES:
            raise RecipeError(f"sample directory {path} holds over "
                              f"{SAMPLE_DIR_MAX_FILES} files")


def _verify_sample(oracle_kind: str, params: Mapping[str, Any], blob: bytes,
                   key: bytes, ctx: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    from memdiver.oracles import get_format, verdict_from

    oracle = get_format(oracle_kind).build_oracle(dict(params), blob)
    verdict = verdict_from(oracle.verify(key, dict(ctx or {})), oracle_kind)
    return {"status": verdict.status, "detail": verdict.detail}


def _class_name_for(name: str) -> str:
    words = [w for w in re.split(r"[^A-Za-z0-9]+", name) if w]
    words = [w for w in words if w.lower() != "memdiver"] or ["Secret"]
    return "MemDiverSynth" + "".join(w[:1].upper() + w[1:] for w in words)


def recipe_from_located_key(
    dump_paths: Sequence[Union[str, Path]],
    key_hex: Union[str, Sequence[str]],
    *,
    oracle_kind: Optional[str],
    oracle_sample_path: Optional[Union[str, Path]] = None,
    oracle_params: Optional[Mapping[str, Any]] = None,
    oracle_ctx: Optional[Mapping[str, Any]] = None,
    context: int = DEFAULT_CONTEXT,
    name: str = "memdiver_secret",
    class_name: Optional[str] = None,
    description: str = "",
    view: Optional[str] = None,
    key_material: Optional[Dict[str, Any]] = None,
    min_static_ratio: float = 0.3,
    entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
    entropy_mode: str = "fallback",
    max_anchor_hits: int = DEFAULT_MAX_ANCHOR_HITS,
    max_entropy_candidates: int = DEFAULT_MAX_ENTROPY_CANDIDATES,
    allow_high_entropy_context: bool = False,
    is_cancelled: Optional[Callable[[], bool]] = None,
    opener: Optional[Callable[..., Any]] = None,
) -> Tuple[PluginRecipe, Dict[str, Any]]:
    """Build a recipe from a key located in real captures.

    *is_cancelled* is checked once per dump while the key is located
    (see :func:`locate_occurrences`); ``None`` checks nothing.

    *opener* is called as ``opener(path, **key_material)`` wherever a dump is
    opened (locating, the windows, the reference slice) and used as a context
    manager; the default is ``core.dump_source.open_dump``, one open per step.
    A caller that already holds the dumps open passes its pool's opener
    (``app.key_material.KeyedSources.opener``): an encrypted dump is then
    decrypted once for the whole build.

    ``key_hex`` is one key for every dump, or one key per dump (e.g. several
    runs of the same program, each with its own key). Every occurrence of the
    key becomes a window of ``context`` bytes either side; bytes equal across
    all windows are anchors, the key span is always wildcarded. The entropy
    locator's step is inferred from the observed key alignment. The
    adjacent-secret rule (module docstring) refuses a high-entropy static run
    unless ``allow_high_entropy_context`` or two different keys agree on it.

    Returns ``(recipe, extras)`` where ``extras`` carries what a caller needs
    for :func:`emit`: ``reference_data`` (a slice of the first capture around
    the key), ``expected_offset`` in it, and ``diagnostics``.
    """
    paths = [str(Path(p).expanduser()) for p in dump_paths]
    if not paths:
        raise RecipeError("need at least one dump")
    if context < 0:
        raise RecipeError("context must be non-negative")
    keys = _keys_per_dump(paths, key_hex)
    key_length = len(keys[0])
    occurrences = locate_occurrences(paths, keys, view=view, key_material=key_material,
                                     is_cancelled=is_cancelled, opener=opener)
    windows, pad_left = _read_windows(occurrences, key_length, context, view=view,
                                      key_material=key_material, opener=opener)
    mask = _static_mask(windows, pad_left, key_length)
    pattern = PatternGenerator.generate(windows[0], mask, name=name,
                                        min_static_ratio=min_static_ratio)
    if pattern is None:
        raise RecipeError(f"too few static bytes around the key for an anchor "
                          f"({sum(mask)}/{len(mask)}); widen the context")
    diagnostics = _builder_diagnostics(occurrences, windows)
    diagnostics.extend(_high_entropy_context_diagnostics(
        windows[0], mask, distinct_keys=len(set(keys)),
        allow=allow_high_entropy_context))
    locators = (
        Locator("anchor_regex", {"pattern": pattern["wildcard_pattern"],
                                 "static_ratio": pattern["static_ratio"],
                                 "max_hits": int(max_anchor_hits), "alignment": 1}),
        Locator("entropy", {"threshold": float(entropy_threshold), "mode": entropy_mode,
                            "step": _inferred_step(occurrences),
                            "max_candidates": int(max_entropy_candidates)}),
    )
    oracle = _oracle_spec(oracle_kind, oracle_sample_path, oracle_params, keys[0], diagnostics,
                          ctx=oracle_ctx)
    provenance = _provenance(paths, keys, occurrences, context, pad_left, windows, view)
    recipe = PluginRecipe(
        name=name, class_name=class_name or _class_name_for(name),
        description=description or f"Secret located by MemDiver ({key_length}-byte key)",
        locators=locators, decoder=Decoder(pad_left, key_length),
        oracle=oracle, provenance=provenance)
    reference, expected = _reference_slice(occurrences[0], key_length, view, key_material,
                                           opener=opener)
    return recipe, {"reference_data": reference, "expected_offset": expected,
                    "diagnostics": diagnostics, "pattern": pattern}


def _oracle_spec(kind: Optional[str], sample_path: Optional[Union[str, Path]],
                 params: Optional[Mapping[str, Any]], key: bytes,
                 diagnostics: List[Dict[str, Any]], *,
                 ctx: Optional[Mapping[str, Any]] = None) -> Optional[OracleSpec]:
    if not kind:
        return None
    ctx = _checked_oracle_ctx(ctx)
    sample = None
    if sample_path is not None:
        blob = build_oracle_sample(kind, sample_path)
        verdict = _verify_sample(kind, params or {}, blob, key, ctx)
        if verdict["status"] != "proven":
            diagnostics.append({"code": "vol3_recipe.sample_does_not_prove_key",
                                "severity": "warning", "message":
                                f"the oracle sample does not prove the located key: "
                                f"{verdict['status']} ({verdict['detail']})"})
        sample = OracleSample.from_bytes(blob)
    return OracleSpec(kind, dict(params or {}), sample, ctx)


def high_entropy_static_runs(reference: bytes, mask: Sequence[bool]) -> List[Tuple[int, int]]:
    """``(start, length)`` of static runs holding a 16-byte window of >= 3.5 bits/byte."""
    from memdiver.core.entropy import shannon_entropy

    found = []
    for start, length in PatternGenerator.find_anchors(list(mask), HIGH_ENTROPY_RUN):
        for index in range(start, start + length - HIGH_ENTROPY_RUN + 1):
            if shannon_entropy(reference[index:index + HIGH_ENTROPY_RUN]) >= HIGH_ENTROPY_BITS:
                found.append((start, length))
                break
    return found


def _high_entropy_context_diagnostics(reference: bytes, mask: Sequence[bool], *,
                                      distinct_keys: int, allow: bool
                                      ) -> List[Dict[str, Any]]:
    runs = high_entropy_static_runs(reference, mask)
    if not runs:
        return []
    details = {"runs": [{"offset": o, "length": n} for o, n in runs],
               "distinct_keys": distinct_keys}
    if distinct_keys >= 2:
        return [{"code": "vol3_recipe.high_entropy_constant", "severity": "info",
                 "message": f"{len(runs)} high-entropy static run(s) in the anchor are "
                            f"identical across {distinct_keys} captures with different "
                            f"keys, so they are program constants, not session secrets",
                 "details": details}]
    message = (f"{len(runs)} high-entropy static run(s) next to the key would be copied "
               f"verbatim into the plugin and may be ANOTHER secret of this session; "
               f"build from >= 2 captures with different keys (a constant survives, a "
               f"secret is wildcarded) or pass allow_high_entropy_context=True")
    if not allow:
        raise HighEntropyContextError(message)
    return [{"code": "vol3_recipe.high_entropy_context", "severity": "warning",
             "message": message, "details": details}]


def _builder_diagnostics(occurrences: Sequence[_Occurrence],
                         windows: Sequence[bytes]) -> List[Dict[str, Any]]:
    diagnostics: List[Dict[str, Any]] = []
    if len(windows) < 2:
        diagnostics.append({
            "code": "vol3_recipe.single_window", "severity": "warning",
            "message": "the static mask comes from ONE window, so every neighbouring "
                       "byte counts as static; add captures (or a dump holding the key "
                       "twice) to wildcard volatile bytes"})
    if len({o.dump_path for o in occurrences}) < 2:
        diagnostics.append({
            "code": "vol3_recipe.single_dump", "severity": "warning",
            "message": "the mask was measured within one capture; anchors may include "
                       "bytes that differ between runs"})
    return diagnostics


def _provenance(paths: Sequence[str], keys: Sequence[bytes],
                occurrences: Sequence[_Occurrence], context: int, pad_left: int,
                windows: Sequence[bytes], view: Optional[str]) -> Dict[str, Any]:
    per_dump: Dict[str, List[int]] = {}
    for occ in occurrences:
        per_dump.setdefault(occ.dump_path, []).append(occ.offset)
    # No absolute paths in a shareable artefact: basename + content digest.
    return {
        "generator": "memdiver.architect.vol3_recipe.recipe_from_located_key",
        "view": view or "default",
        "context": int(context),
        "pad_left": int(pad_left),
        "mask_windows": len(windows),
        "key_length": len(keys[0]),
        # The keys themselves are never written out; their digests correlate.
        "key_sha256": sorted({hashlib.sha256(k).hexdigest() for k in keys}),
        "dumps": [{"name": Path(p).name, "sha256": digest, "offsets": per_dump.get(p, [])}
                  for p, digest in zip(paths, _dump_digests(paths))],
    }


#: sha256 per (realpath, size, mtime_ns, inode): a re-synthesis over the same
#: multi-GB dumps does not stream them again. Bounded; oldest entry evicted first.
_DIGEST_CACHE: "OrderedDict[Tuple[str, int, int, int], str]" = OrderedDict()
_DIGEST_CACHE_MAX = 256
_DIGEST_CACHE_LOCK = threading.Lock()


def _dump_digests(paths: Sequence[str]) -> List[str]:
    """sha256 of every dump, hashed concurrently (``hashlib`` releases the GIL)
    and memoized per file identity (see :data:`_DIGEST_CACHE`)."""
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=min(4, max(1, len(paths)))) as pool:
        return list(pool.map(_dump_digest, paths))


def _dump_digest(path: Union[str, Path]) -> str:
    from memdiver.core.artifact_util import sha256_streamed

    real = os_path.realpath(str(path))
    stat = os_stat(real)
    identity = (real, stat.st_size, stat.st_mtime_ns, stat.st_ino)
    with _DIGEST_CACHE_LOCK:
        cached = _DIGEST_CACHE.get(identity)
        if cached is not None:
            _DIGEST_CACHE.move_to_end(identity)
            return cached
    digest = sha256_streamed(Path(real))
    with _DIGEST_CACHE_LOCK:
        _DIGEST_CACHE[identity] = digest
        while len(_DIGEST_CACHE) > _DIGEST_CACHE_MAX:
            _DIGEST_CACHE.popitem(last=False)
    return digest


def _reference_slice(occ: _Occurrence, key_length: int, view: Optional[str],
                     key_material: Optional[Dict[str, Any]], span: int = 32 * 1024,
                     opener: Optional[Callable[..., Any]] = None) -> Tuple[bytes, int]:
    """A slice of the first capture around the key, and the key's offset in it."""
    from memdiver.core.dump_source import open_dump

    view_kw = {} if view is None else {"view": view}
    start = max(0, occ.offset - span)
    with (opener or open_dump)(Path(occ.dump_path), **(key_material or {})) as source:
        end = min(int(source.size_for(**view_kw)), occ.offset + key_length + span)
        data = bytes(source.read_range(start, end - start, **view_kw))
    return data, occ.offset - start

