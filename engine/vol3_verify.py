"""Load a MemDiver-emitted Volatility3 plugin and RUN it, in this process.

The ``engine/yara_scan.py`` analogue, one layer up. That module was written
because MemDiver could *emit* YARA rules but never *scan* with them, so an
emitted detector was a detector nobody could evaluate
(``tests/test_yara_scan.py`` says exactly that). The Volatility3 side had the
same hole and a worse one: the emitted plugin was only ever checked by
``ast.parse`` and substring assertions over the generated text, so a plugin
that could not even be *imported* -- let alone find a key -- still passed every
test in the suite. This module closes that loop: it execs the emitted source,
constructs the plugin through Volatility3's own ``PluginInterface.__init__``
(which runs the real ``unsatisfied()`` requirement gate), calls ``run()``, and
walks the returned ``TreeGrid`` into typed hits.

**Why the probe is soft here and hard in yara_scan.** ``yara-python`` is a BASE
dependency: its absence means a broken environment, so ``yara_scan`` imports it
unguarded and fails loudly. ``volatility3`` is an *extra* (``memdiver[vol]``):
its absence means a forgotten install option, so it is probed softly and the
absence is reported with the ``pip install "memdiver[vol]"`` hint that
``core.install_hints`` exists to produce. Wiring those two conditions to the
same behaviour would destroy the distinction that module is built on.

**The format_hints import is load-bearing.** ``from
volatility3.framework.renderers import format_hints`` below is not decoration:
binding that submodule on its parent package is what makes
``renderers.format_hints`` resolvable, and 111 of Volatility3's own bundled
plugins do the same import. The emitted template as of B5.0 reached for
``renderers.format_hints`` at module level *without* importing the submodule,
so it only worked once somebody else had bound it -- see
``tests/test_vol3_verify.py`` for the guard that deletes the attribute to prove
the bug was real. **Fixed in B5.1**: the template now does the explicit submodule
import itself, and that guard is green with its ``xfail`` removed. The import
below stays regardless -- this module needs ``format_hints`` in its own right,
and the guard's control test asserts it is bound here.

**Coordinates.** The emitted plugin's ``PatternOffset`` is the start of the
*wildcarded window* that contains the key, and ``KeyOffset`` is the key's
absolute position. Both come out of the TreeGrid as absolutes;
:class:`Vol3Hit` stores the window start in ``offset`` and the key's position
*relative to that window* in ``key_offset``, which is the convention
``engine.detector_metrics`` duck-types on.

Layering: ``engine`` may import ``core`` and ``architect`` (``engine/vol3_emit.py``
already does) and must never import ``app`` or ``presentation`` (AST-enforced
by ``tests/test_architecture_invariants.py``). No ``print``/stdout here --
``logger`` only.
"""

from __future__ import annotations

import logging
import re
import sys
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from memdiver.core.install_hints import missing_package_message
from memdiver.core.service_errors import CapabilityError, ErrorCategory

logger = logging.getLogger("memdiver.engine.vol3_verify")

try:
    # The bare package import is what tests/test_install_contract.py's probe
    # scanner reads to learn that this module depends on the `volatility3`
    # distribution; keep it even though the aliased imports below do the work.
    import volatility3  # noqa: F401
    from volatility3 import framework as vol3_framework
    from volatility3.framework import constants as vol3_constants
    from volatility3.framework import contexts as vol3_contexts
    from volatility3.framework import interfaces as vol3_interfaces
    from volatility3.framework.layers import physical as vol3_physical

    # Binds ``format_hints`` onto ``volatility3.framework.renderers``. Keep it,
    # and keep the ``noqa`` -- see the module docstring.
    from volatility3.framework.renderers import format_hints as vol3_format_hints  # noqa: F401

    HAS_VOLATILITY3 = True
except ImportError:  # pragma: no cover - exercised only on a machine without the extra
    HAS_VOLATILITY3 = False

#: The one message every entry point raises when the extra is absent. Built via
#: ``missing_package_message(..., extra="vol")``, so it renders the
#: ``pip install "memdiver[vol]"`` form -- which requires ``"vol"`` to be in
#: ``core.install_hints.OPTIONAL_EXTRAS`` and NOT in ``NO_OP_EXTRAS``.
VOL3_MISSING = missing_package_message(
    "volatility3 (emitted-plugin verification)", extra="vol",
)

#: Ceiling on retained hits. ``match_count`` always reports the true total, so a
#: pathological pattern on a multi-GB dump is *counted* honestly rather than
#: materialised as millions of dataclasses.
DEFAULT_MAX_HITS = 50_000

#: Name of the layer this module registers. Deliberately not "primary": the
#: plugin's ``primary`` *requirement* is a config value that POINTS at a layer,
#: and conflating the two is how a layer-name bug hides.
FLAT_LAYER_NAME = "flat"

#: The TreeGrid columns the emitted template declares, by name. Read by name
#: (never by position) so a reordered ``_COLUMNS`` cannot silently swap
#: ``KeyOffset`` for ``PatternOffset``.
_COL_KEY_OFFSET = "KeyOffset"
_COL_KEY_HEX = "KeyHex"
_COL_KEY_ENTROPY = "KeyEntropy"
_COL_KEY_LENGTH = "KeyLength"
_COL_PATTERN_OFFSET = "PatternOffset"
_COL_STATIC_RATIO = "StaticRatio"

_MIB = 1024 * 1024

#: Pulls the hex-string body out of an emitted plugin's ``YARA_RULE`` block.
#: Used only for anchor statistics; a rule it cannot parse yields zeroes rather
#: than an exception, because anchor stats are diagnostics, not correctness.
_YARA_HEX_BODY = re.compile(r"\$\w+\s*=\s*\{([^}]*)\}", re.S)


@dataclass(frozen=True)
class Vol3Hit:
    """One row of the emitted plugin's TreeGrid, in MemDiver coordinates.

    **The field names are load-bearing. Do not rename them.**
    ``engine.detector_metrics`` scores detector firings by *duck-typing* on
    ``offset`` / ``length`` / ``key_offset`` (see its "Duck-typed accessors"
    block) and deliberately does not import any scanner's match class. A
    well-meant rename to e.g. ``pattern_offset`` would not break an import --
    ``getattr(match, "offset", None)`` would simply return ``None``, every
    containment pair would vanish, and every metric would silently read 0.0.
    """

    offset: int          # PatternOffset -- the start of the wildcarded WINDOW
    length: int          # PATTERN_LENGTH -- the window's size
    key_offset: int      # KeyOffset - PatternOffset: RELATIVE to the match start
    key_length: int
    key_hex: str
    key_entropy: float
    static_ratio: float

    @property
    def key_absolute_offset(self) -> int:
        """The key's absolute position in the scanned layer."""
        return self.offset + self.key_offset


@dataclass(frozen=True)
class Vol3VerifyReport:
    """Everything one run of an emitted plugin observed.

    ``match_count`` is a field rather than ``len(hits)`` because ``hits`` is
    capped at :data:`DEFAULT_MAX_HITS`; a test that wants the selectivity of a
    pattern must be able to read the honest total.

    ``expected_offset_reported`` is EXACT membership with no tolerance, on
    purpose. The failure this instrument exists to catch is "the plugin
    reported a hit 64 bytes away from the real key"; a tolerance would score
    that as a near-miss instead of the miss it is.
    """

    framework_version: Tuple[int, int, int]
    plugin_class_name: str
    layer_scanned: str
    layer_bytes: int
    match_count: int
    hits: Tuple[Vol3Hit, ...]
    expected_offset: Optional[int]
    expected_offset_reported: bool
    anchor_bytes: int
    anchor_distinct_bytes: int
    matches_per_mib: float

    def to_dict(self) -> dict:
        return {
            "framework_version": list(self.framework_version),
            "plugin_class_name": self.plugin_class_name,
            "layer_scanned": self.layer_scanned,
            "layer_bytes": self.layer_bytes,
            "match_count": self.match_count,
            "hits_retained": len(self.hits),
            "expected_offset": self.expected_offset,
            "expected_offset_reported": self.expected_offset_reported,
            "anchor_bytes": self.anchor_bytes,
            "anchor_distinct_bytes": self.anchor_distinct_bytes,
            "matches_per_mib": self.matches_per_mib,
        }


def _require_volatility3() -> None:
    """Raise the one capability error for "the ``vol`` extra is not installed"."""
    if not HAS_VOLATILITY3:
        raise CapabilityError(VOL3_MISSING, category=ErrorCategory.UNSUPPORTED)


def framework_version() -> Tuple[int, int, int]:
    """The running framework's ``(major, minor, patch)``.

    Three Volatility3 trees commonly coexist on one machine and they disagree,
    so every report carries the version it was produced under rather than
    leaving the reader to guess.
    """
    _require_volatility3()
    return (
        int(vol3_constants.VERSION_MAJOR),
        int(vol3_constants.VERSION_MINOR),
        int(vol3_constants.VERSION_PATCH),
    )


def anchor_stats(source: str) -> Tuple[int, int]:
    """``(anchor_bytes, anchor_distinct_bytes)`` for an emitted plugin's pattern.

    Read off the embedded YARA rule's hex string, where a static byte is a hex
    token and a volatile byte is ``??``. ``anchor_distinct_bytes`` is the number
    of distinct *values* among the static bytes, and it is the single most
    predictive number for selectivity: an anchor made of 128 zero bytes has
    ``anchor_distinct_bytes == 1`` and matches anywhere a long zero run exists,
    no matter how high its static ratio looks.
    """
    match = _YARA_HEX_BODY.search(source)
    if match is None:
        logger.warning("no YARA hex body found in plugin source; anchor stats unavailable")
        return (0, 0)
    values: List[int] = []
    for token in match.group(1).split():
        if "?" in token:
            continue
        try:
            values.append(int(token, 16))
        except ValueError:
            continue
    return (len(values), len(set(values)))


def load_plugin_class(source: str, module_name: str) -> type:
    """Exec *source* as a fresh module and return its PluginInterface subclass.

    The module is registered in ``sys.modules`` under *module_name* so
    tracebacks and ``inspect`` resolve the same way they would for a real
    import; callers should pass a unique name per emission.

    ``framework.require_interface_version`` is called with the plugin's own
    ``_required_framework_version``, which is exactly the gate Volatility3's
    own loader applies -- so a plugin declaring an incompatible framework
    version fails here rather than half-running.
    """
    _require_volatility3()
    module = types.ModuleType(module_name)
    module.__file__ = f"<emitted:{module_name}>"
    sys.modules[module_name] = module
    try:
        exec(compile(source, module.__file__, "exec"), module.__dict__)  # nosec B102
    except BaseException:
        # A half-executed module left in ``sys.modules`` would make the NEXT
        # load of the same name silently succeed against a broken object. The
        # bug-(a) guard in tests/test_vol3_verify.py depends on this.
        sys.modules.pop(module_name, None)
        raise

    base = vol3_interfaces.plugins.PluginInterface
    found: List[type] = [
        value for value in vars(module).values()
        if isinstance(value, type) and issubclass(value, base) and value is not base
    ]
    if not found:
        raise CapabilityError(
            f"emitted plugin {module_name!r} declares no "
            f"interfaces.plugins.PluginInterface subclass",
            category=ErrorCategory.INVALID_INPUT,
        )
    if len(found) > 1:
        raise CapabilityError(
            f"emitted plugin {module_name!r} declares {len(found)} plugin classes "
            f"({', '.join(c.__name__ for c in found)}); expected exactly one",
            category=ErrorCategory.INVALID_INPUT,
        )
    plugin_cls = found[0]
    # ``_required_framework_version`` is declared on the plugin CLASS, not on
    # ``type``; the annotation is ``type`` because callers treat the result as a
    # plain class, so read the attribute defensively rather than widening the
    # signature to ``Any``.
    required = getattr(plugin_cls, "_required_framework_version", None)
    if required is None:
        raise CapabilityError(
            f"emitted plugin {module_name!r} declares no "
            f"_required_framework_version",
            category=ErrorCategory.INVALID_INPUT,
        )
    vol3_framework.require_interface_version(*required)
    return plugin_cls


def _column_index(grid: Any) -> Dict[str, int]:
    return {column.name: index for index, column in enumerate(grid.columns)}


def _rows(grid: Any) -> List[Sequence[Any]]:
    collected: List[Sequence[Any]] = []

    def visitor(node: Any, accumulator: None) -> None:
        collected.append(node.values)
        return accumulator

    grid.populate(visitor, None)
    return collected


def _hit_from_row(row: Sequence[Any], index: Mapping[str, int], window_length: int) -> Vol3Hit:
    pattern_offset = int(row[index[_COL_PATTERN_OFFSET]])
    key_absolute = int(row[index[_COL_KEY_OFFSET]])
    return Vol3Hit(
        offset=pattern_offset,
        length=window_length,
        key_offset=key_absolute - pattern_offset,
        key_length=int(row[index[_COL_KEY_LENGTH]]),
        key_hex=str(row[index[_COL_KEY_HEX]]),
        key_entropy=float(row[index[_COL_KEY_ENTROPY]]),
        static_ratio=float(row[index[_COL_STATIC_RATIO]]),
    )


def _pattern_length(plugin_cls: type) -> int:
    """``PATTERN_LENGTH`` from the plugin's own module, not re-derived."""
    module = sys.modules.get(plugin_cls.__module__)
    return int(getattr(module, "PATTERN_LENGTH", 0) or 0)


def _run_plugin(
    plugin_cls: type,
    context: Any,
    layer_name: str,
    *,
    extra_config: Optional[Mapping[str, Any]] = None,
) -> Any:
    """Construct and run *plugin_cls* against *layer_name*.

    Construction is where Volatility3 runs ``unsatisfied()``, so a requirement
    the emitted template gets wrong raises here -- which is the point.
    """
    config_path = f"plugins.{plugin_cls.__name__}"
    context.config[f"{config_path}.primary"] = layer_name
    context.config[f"{config_path}.full_scan"] = True
    for key, value in (extra_config or {}).items():
        context.config[f"{config_path}.{key}"] = value
    plugin = plugin_cls(context, config_path)
    return plugin.run()


def _build_report(
    *,
    source: str,
    plugin_cls: type,
    grid: Any,
    layer_name: str,
    layer_bytes: int,
    expected_offset: Optional[int],
    max_hits: int,
) -> Vol3VerifyReport:
    index = _column_index(grid)
    missing = [
        name for name in (
            _COL_KEY_OFFSET, _COL_KEY_HEX, _COL_KEY_ENTROPY,
            _COL_KEY_LENGTH, _COL_PATTERN_OFFSET, _COL_STATIC_RATIO,
        )
        if name not in index
    ]
    if missing:
        raise CapabilityError(
            f"emitted plugin's TreeGrid is missing columns {missing}",
            category=ErrorCategory.INVALID_INPUT,
        )

    window_length = _pattern_length(plugin_cls)
    rows = _rows(grid)
    hits: List[Vol3Hit] = []
    reported = False
    for row in rows:
        hit = _hit_from_row(row, index, window_length)
        if expected_offset is not None and hit.key_absolute_offset == expected_offset:
            reported = True
        if len(hits) < max_hits:
            hits.append(hit)

    anchor_bytes, anchor_distinct = anchor_stats(source)
    per_mib = len(rows) / (layer_bytes / _MIB) if layer_bytes else 0.0
    report = Vol3VerifyReport(
        framework_version=framework_version(),
        plugin_class_name=plugin_cls.__name__,
        layer_scanned=layer_name,
        layer_bytes=layer_bytes,
        match_count=len(rows),
        hits=tuple(hits),
        expected_offset=expected_offset,
        expected_offset_reported=reported,
        anchor_bytes=anchor_bytes,
        anchor_distinct_bytes=anchor_distinct,
        matches_per_mib=per_mib,
    )
    logger.info(
        "vol3 %s scanned %d bytes of layer %r: %d matches (%.1f/MiB), "
        "anchor %d bytes / %d distinct values, expected_offset_reported=%s",
        report.plugin_class_name, report.layer_bytes, report.layer_scanned,
        report.match_count, report.matches_per_mib, report.anchor_bytes,
        report.anchor_distinct_bytes, report.expected_offset_reported,
    )
    return report


def run_over_buffer(
    source: str,
    data: bytes,
    *,
    expected_offset: Optional[int] = None,
    module_name: Optional[str] = None,
    extra_config: Optional[Mapping[str, Any]] = None,
    max_hits: int = DEFAULT_MAX_HITS,
) -> Vol3VerifyReport:
    """Run the emitted plugin in *source* over *data* held in memory."""
    _require_volatility3()
    plugin_cls = load_plugin_class(source, module_name or _default_module_name(source))
    context = vol3_contexts.Context()
    layer = vol3_physical.BufferDataLayer(
        context, "base", FLAT_LAYER_NAME, bytes(data),
    )
    context.add_layer(layer)
    grid = _run_plugin(plugin_cls, context, FLAT_LAYER_NAME, extra_config=extra_config)
    return _build_report(
        source=source, plugin_cls=plugin_cls, grid=grid,
        layer_name=FLAT_LAYER_NAME, layer_bytes=len(data),
        expected_offset=expected_offset, max_hits=max_hits,
    )


def run_over_file(
    source: str,
    path: Path,
    *,
    expected_offset: Optional[int] = None,
    module_name: Optional[str] = None,
    extra_config: Optional[Mapping[str, Any]] = None,
    max_hits: int = DEFAULT_MAX_HITS,
) -> Vol3VerifyReport:
    """Run the emitted plugin in *source* over the dump at *path*.

    A single FLAT ``physical.FileLayer`` is registered by hand -- Volatility3's
    ``LayerStacker`` automagic is NOT run. That is deliberate: MemDiver's flat
    dumps carry an ELF header, so the stacker wraps them in an ``Elf64Layer``
    whose sections have no size, and the scan then sees nothing at all. This
    module measures the emitted *pattern*, so it scans the bytes on disk.
    """
    _require_volatility3()
    dump_path = Path(path)
    plugin_cls = load_plugin_class(source, module_name or _default_module_name(source))
    context = vol3_contexts.Context()
    context.config["base.location"] = dump_path.resolve().as_uri()
    layer = vol3_physical.FileLayer(context, "base", FLAT_LAYER_NAME)
    context.add_layer(layer)
    grid = _run_plugin(plugin_cls, context, FLAT_LAYER_NAME, extra_config=extra_config)
    return _build_report(
        source=source, plugin_cls=plugin_cls, grid=grid,
        layer_name=FLAT_LAYER_NAME, layer_bytes=dump_path.stat().st_size,
        expected_offset=expected_offset, max_hits=max_hits,
    )


def verify_key_recovered(source: str, data: bytes, key: bytes) -> bool:
    """Did the emitted plugin report *key* verbatim among its hits?

    The strongest single claim this harness can make: not "a hit landed near
    the key" but "the plugin handed back the key's exact bytes".
    """
    report = run_over_buffer(source, data)
    wanted = bytes(key).hex()
    return any(hit.key_hex == wanted for hit in report.hits)


_MODULE_NAME_SEQ = [0]


def _default_module_name(source: str) -> str:
    """A unique module name per emission, so two plugins never collide."""
    _MODULE_NAME_SEQ[0] += 1
    match = re.search(r"^PATTERN_NAME = \"(.*)\"$", source, re.M)
    stem = re.sub(r"\W+", "_", match.group(1)) if match else "plugin"
    return f"memdiver_emitted_vol3_{stem}_{_MODULE_NAME_SEQ[0]}"
