"""Volatility3Exporter - generate self-contained Volatility3 plugins from patterns."""

import logging
from datetime import datetime, timezone
from pathlib import Path
from string import Template
from typing import Optional

from .yara_exporter import YaraExporter, key_locator_from_pattern

logger = logging.getLogger("memdiver.architect.volatility3_exporter")

_PLUGIN_TEMPLATE = Template('''\
"""MemDiver Volatility3 plugin: $plugin_name
$description
Generated: $timestamp | Pattern: $pattern_name ($pattern_length bytes, $static_ratio static)
Key region: offset +$key_offset, length $key_length

Scan target
-----------
By DEFAULT this plugin scans the LOWEST layer beneath the configured
``primary`` -- the file/physical layer. MemDiver's flat process dumps begin with
``7f 45 4c 46`` and carry ``e_type = ET_DYN``, so Volatility3's ``LayerStacker``
wraps them in an ``Elf64Layer`` that exposes almost nothing ("Sections have no
size, nothing to scan"); binding the scan to ``primary`` therefore reported zero
hits on dumps that provably contain the key. The lowest layer is complete, and
its offsets are FILE offsets -- the same space MemDiver's own output is in.

Pass ``--virtual`` to scan the configured translation layer instead. That is the
correct choice for a genuine kernel memory image, where virtual addresses are
what you want reported.

--pid
-----
``--pid`` needs a kernel module (kernel image + matching symbols) so the OS
``PsList`` plugin can enumerate processes and hand back a process layer. A flat
process dump has no kernel symbols, so on such a dump the ``kernel``
ModuleRequirement stays unfilled and the PID cannot be honoured. When that
happens this plugin logs a LOUD warning and scans the whole layer anyway --
it does not silently pretend the results are restricted to that process.
"""
import importlib
import logging
import math
import re
from typing import List
from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
# ``renderers`` is a PACKAGE: importing it does not bind its ``format_hints``
# submodule, so reaching for that attribute through the parent package at
# module level raises AttributeError in a fresh interpreter. Volatility3's own
# bundled plugins all do this same explicit submodule import; keep it.
from volatility3.framework.renderers import format_hints

vollog = logging.getLogger(__name__)

YARA_RULE = r\'\'\'
$yara_rule
\'\'\'
PATTERN_LENGTH = $pattern_length
PATTERN_NAME = "$pattern_name"
KEY_OFFSET = $key_offset
KEY_LENGTH = $key_length
# Regex built from wildcard pattern: static bytes are literal, ?? becomes .
SCAN_REGEX = $scan_regex_repr
# Fallback: longest contiguous static run for BytesScanner.
NEEDLE = bytes.fromhex("$fallback_hex")
NEEDLE_OFFSET = $needle_offset
VTYPES = $vtypes_repr

_COLUMNS = [
    ("KeyOffset", format_hints.Hex),
    ("KeyHex", str),
    ("KeyEntropy", float),
    ("KeyLength", int),
    ("PatternOffset", format_hints.Hex),
    ("StaticRatio", float),
]

#: ``(module, listing classmethod, symbol-table metadata class)`` per OS, in the
#: order they are tried when the kernel's flavour cannot be determined.
_OS_BRANCHES = (
    ("volatility3.plugins.linux.pslist", "list_tasks", "LinuxMetadata"),
    ("volatility3.plugins.windows.pslist", "list_processes", "WindowsMetadata"),
)

class $class_name(interfaces.plugins.PluginInterface):
    """Scan process memory for MemDiver pattern: $pattern_name."""
    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary", description="Memory layer", optional=False),
            requirements.SymbolTableRequirement(
                name="symbols", description="OS kernel symbols", optional=True),
            # OPTIONAL is load-bearing. A mandatory ModuleRequirement would make
            # PluginInterface.__init__ fail its requirement gate on exactly the
            # flat process dumps this plugin exists to scan. Volatility3's
            # KernelModule automagic calls unsatisfied() on the requirement
            # directly (not unsatisfied_children), so it still FILLS this when a
            # kernel image plus symbols are present, and leaves it falsy
            # otherwise.
            requirements.ModuleRequirement(
                name="kernel", description="OS kernel module (required for --pid)",
                architectures=["Intel32", "Intel64"], optional=True),
            requirements.IntRequirement(
                name="pid", description="Target process PID",
                optional=True, default=None),
            requirements.BooleanRequirement(
                name="full_scan",
                description="Scan full memory instead of PID-filtered",
                optional=True, default=False),
            requirements.BooleanRequirement(
                name="virtual",
                description=("Scan the configured translation layer instead of "
                             "the underlying physical/file layer"),
                optional=True, default=False),
        ]

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        return -sum((c / n) * math.log2(c / n) for c in freq if c > 0)

    def _scan_layer_name(self) -> str:
        """The layer this plugin actually scans.

        Default: walk ``layer.dependencies`` down from ``primary`` until a layer
        has no dependencies left. That bottom layer is the file/physical one --
        complete, and addressed in file offsets. See this module's docstring for
        why binding the scan to ``primary`` was wrong for MemDiver's dumps.

        ``--virtual`` returns ``primary`` unchanged, which is what a genuine
        kernel image wants.

        The ``seen`` set guards against a dependency cycle; a malformed stack
        would otherwise loop forever instead of failing.
        """
        configured = self.config["primary"]
        if self.config.get("virtual", False):
            vollog.info("--virtual: scanning the translation layer %r", configured)
            return configured

        name = configured
        seen = {name}
        while True:
            candidates = [
                dep for dep in self.context.layers[name].dependencies
                if dep not in seen
            ]
            if not candidates:
                break
            name = candidates[0]
            seen.add(name)

        layer = self.context.layers[name]
        size = layer.maximum_address - layer.minimum_address + 1
        vollog.info(
            "scanning lowest layer %r (%d bytes) beneath %r; pass --virtual to "
            "scan %r itself", name, size, configured, configured,
        )
        return name

    def _scan_layer(self, layer_name: str):
        """Scan *layer_name* for the pattern.

        Primary: ``RegExScanner`` with the full wildcard pattern
        converted to a Python bytes regex — encodes both structural
        anchors and wildcard positions natively.

        Fallback: ``BytesScanner`` with the longest static needle,
        adjusted by ``NEEDLE_OFFSET`` to the pattern start, then
        verified against a compiled YARA rule on the read data.

        ``layer.scan()`` in Volatility3 >= 2.x yields plain ``int``
        offsets (not tuples).

        Note what is NOT guarded here: ``layer.scan``. Only the regex's
        *construction* is, because a bad regex is a nameable condition with a
        real fallback. An exception out of Volatility3's scan machinery is an API
        mismatch, and degrading that to the weaker BytesScanner would report
        "no results" -- indistinguishable from "the key is not there".
        """
        layer = self.context.layers[layer_name]

        # --- Primary: RegExScanner (full structural pattern) ---
        scanner = None
        if SCAN_REGEX:
            try:
                scanner = scanners.RegExScanner(SCAN_REGEX)
            except re.error as err:
                vollog.warning(
                    "SCAN_REGEX did not compile (%s); falling back to the "
                    "BytesScanner needle, which is a WEAKER detector", err,
                )
        if scanner is not None:
            seen = set()
            for offset in layer.scan(context=self.context, scanner=scanner):
                if offset in seen:
                    continue
                seen.add(offset)
                try:
                    data = layer.read(offset, PATTERN_LENGTH)
                except exceptions.InvalidAddressException:
                    # A window straddling the end of a mapped section is
                    # expected; anything else is a bug and must propagate.
                    continue
                yield offset, data
            return

        # --- Fallback: BytesScanner + optional YARA verify ---
        if not NEEDLE:
            return

        yara_rules = None
        try:
            import yara
        except ImportError:
            # Legitimate: this plugin runs inside the USER's Volatility3
            # environment, which need not carry yara-python.
            vollog.warning(
                "YARA verification disabled: yara-python is not installed in "
                "this volatility3 environment",
            )
        else:
            try:
                yara_rules = yara.compile(source=YARA_RULE)
            except yara.SyntaxError as err:
                # A rule that will not compile is a defect in MemDiver's
                # emitter, not a property of the user's environment.
                vollog.error(
                    "embedded YARA rule failed to compile (%s); this is a bug "
                    "in the MemDiver emitter, not in your environment", err,
                )

        seen = set()
        for needle_hit in layer.scan(
            context=self.context,
            scanner=scanners.BytesScanner(needle=NEEDLE)):
            pattern_start = needle_hit - NEEDLE_OFFSET
            if pattern_start < 0 or pattern_start in seen:
                continue
            seen.add(pattern_start)
            try:
                data = layer.read(pattern_start, PATTERN_LENGTH)
            except exceptions.InvalidAddressException:
                continue
            if yara_rules is not None:
                if not yara_rules.match(data=data):
                    continue
            yield pattern_start, data

    def _generator(self, layer_name: str):
        for pattern_offset, full_data in self._scan_layer(layer_name):
            key_bytes = full_data[KEY_OFFSET:KEY_OFFSET + KEY_LENGTH]
            key_entropy = self._entropy(key_bytes)
            key_vaddr = pattern_offset + KEY_OFFSET
            yield (0, (
                format_hints.Hex(key_vaddr),
                key_bytes.hex(),
                round(key_entropy, 4),
                KEY_LENGTH,
                format_hints.Hex(pattern_offset),
                $static_ratio,
            ))

    def _grid(self, layer_name: str):
        return renderers.TreeGrid(_COLUMNS, self._generator(layer_name))

    def _kernel_flavour(self, kernel_module_name: str):
        """Metadata class name of the kernel's symbol table, or ``None``.

        ``"LinuxMetadata"`` / ``"WindowsMetadata"`` / ``"MacMetadata"`` come off
        the ISF's own metadata block, so the right OS branch is picked rather
        than guessed. ``None`` means "no metadata" -- the caller then tries both
        branches in their declared order.
        """
        try:
            module = self.context.modules[kernel_module_name]
            table = self.context.symbol_space[module.symbol_table_name]
            metadata = table.metadata
        except (KeyError, AttributeError) as err:
            vollog.debug("kernel symbol-table metadata unavailable: %s", err)
            return None
        return None if metadata is None else type(metadata).__name__

    def _os_branches(self, kernel_module_name: str):
        """``(module, listing classmethod)`` pairs, most likely OS first."""
        flavour = self._kernel_flavour(kernel_module_name)
        ordered = sorted(
            _OS_BRANCHES,
            key=lambda row: flavour is None or row[2] != flavour,
        )
        return [(module, listing) for module, listing, _meta in ordered]

    def _pid_scan(self, pid: int):
        """Scan only *pid*'s own process layer, or return ``None``.

        ``None`` means the PID path is unavailable -- the normal case for a flat
        process dump, which carries no kernel image and therefore leaves the
        optional ``kernel`` ModuleRequirement unfilled. The caller turns that
        into a loud warning; it must never look like "that process has no hits".

        Each OS ``PsList`` supplies its own ``create_pid_filter`` factory, and
        that callable is what ``list_tasks`` / ``list_processes`` want as their
        ``filter_func`` argument. It filters OUT non-matching processes, so no
        further ``proc.pid == pid`` comparison is needed. The second positional
        argument is a MODULE name (``context.modules[...]``), never a
        translation-layer name.
        """
        kernel_module_name = self.config.get("kernel", None)
        if not kernel_module_name:
            return None

        for module_name, listing in self._os_branches(kernel_module_name):
            try:
                plugin = importlib.import_module(module_name)
            except ImportError:
                vollog.debug("%s is absent from this framework", module_name)
                continue
            pslist = plugin.PsList
            try:
                for proc in getattr(pslist, listing)(
                    self.context, kernel_module_name,
                    pslist.create_pid_filter([pid]),
                ):
                    proc_layer = proc.add_process_layer()
                    if proc_layer:
                        vollog.info(
                            "--pid %s resolved via %s to process layer %r",
                            pid, module_name, proc_layer,
                        )
                        return self._grid(proc_layer)
            except (exceptions.SymbolError,
                    exceptions.InvalidAddressException,
                    KeyError, TypeError) as err:
                # The wrong-OS branch legitimately raises these; a genuinely
                # broken API contract raises something else and propagates.
                vollog.debug(
                    "%s.%s did not apply to this image: %s",
                    module_name, listing, err,
                )
                continue
        return None

    def run(self):
        layer_name = self._scan_layer_name()
        full_scan = self.config.get("full_scan", False)
        pid = self.config.get("pid", None)

        if full_scan:
            return self._grid(layer_name)

        if pid is not None:
            result = self._pid_scan(pid)
            if result is not None:
                return result
            vollog.warning(
                "--pid %s could NOT be honoured: no kernel module is available "
                "(a flat process dump has no kernel symbols). Scanning the "
                "whole layer instead -- results are not restricted to that "
                "process.", pid,
            )
            return self._grid(layer_name)

        # Neither --pid nor --full-scan: default to full scan.
        return self._grid(layer_name)
''')


def _sanitize_class_name(name: str) -> str:
    """Convert to valid Python class name (CamelCase)."""
    sanitized = "".join(c if c.isalnum() else "_" for c in name)
    if sanitized and sanitized[0].isdigit():
        sanitized = "Scan" + sanitized
    return "".join(w.capitalize() for w in sanitized.split("_") if w)


def _longest_static_run(wildcard_pattern: str) -> tuple[str, int]:
    """Extract longest contiguous run of non-wildcard hex bytes.

    Returns ``(hex_string, byte_offset)`` where *byte_offset* is the
    position of the first byte of the run inside the full pattern.
    """
    tokens = wildcard_pattern.split()
    best: list[str] = []
    best_start = 0
    current: list[str] = []
    current_start = 0
    for i, token in enumerate(tokens):
        if "?" in token:
            if len(current) > len(best):
                best = current
                best_start = current_start
            current = []
            current_start = i + 1
        else:
            if not current:
                current_start = i
            current.append(token)
    if len(current) > len(best):
        best = current
        best_start = current_start
    return "".join(best).lower(), best_start


def _wildcard_to_regex(wildcard_pattern: str) -> bytes:
    r"""Convert a YARA-style wildcard hex pattern to a Python bytes regex.

    ``"aa bb ?? cc"`` → ``b'\xaa\xbb.\xcc'``

    Static bytes become literal ``\xNN``; ``??`` wildcards become ``.``
    (match any single byte).  The result is usable with
    ``scanners.RegExScanner`` in Volatility3.
    """
    tokens = wildcard_pattern.split()
    parts: list[bytes] = []
    for token in tokens:
        if "?" in token:
            parts.append(b".")
        else:
            byte_val = int(token, 16)
            # Escape bytes that are regex metacharacters.
            if byte_val in _REGEX_META:
                parts.append(b"\\" + bytes([byte_val]))
            else:
                parts.append(bytes([byte_val]))
    return b"".join(parts)


_REGEX_META = frozenset(b"\\^$.|?*+()[]{}")


class Volatility3Exporter:
    """Export byte patterns as self-contained Volatility3 Python plugins."""

    @staticmethod
    def export(
        pattern: dict,
        plugin_name: Optional[str] = None,
        description: Optional[str] = None,
        yara_rule: Optional[str] = None,
    ) -> str:
        """Export a pattern dict as a Volatility3 plugin Python source.

        Args:
            pattern: Pattern dict from PatternGenerator.generate(),
                optionally enriched with *key_offset*, *key_length*,
                *vtypes*, and *fields* by ``vol3_emit``.
            plugin_name: Plugin class name (defaults to CamelCase of pattern name).
            description: Human-readable description.
            yara_rule: Pre-built YARA rule string. Generated if not
                provided, in which case the pattern's own
                ``key_offset``/``key_length`` (when present) become YARA
                metas on the generated rule.

        Returns:
            Complete Python source code for a Volatility3 plugin.
        """
        raw_name = pattern.get("name", "memdiver_pattern")
        class_name = plugin_name or ("MemDiverScan" + _sanitize_class_name(raw_name))
        desc = description or f"Scan for MemDiver pattern: {raw_name}"
        # No caller-supplied rule: build one, carrying whatever key locator
        # the pattern dict itself holds (vol3_emit and the experiment
        # orchestrator enrich it; a bare PatternGenerator pattern does not,
        # and the metas are then omitted rather than invented). Note the
        # template's KEY_OFFSET/KEY_LENGTH below deliberately keep their
        # 0/pattern-length fallbacks -- the substitution needs a literal.
        meta_key_offset, meta_key_length = key_locator_from_pattern(pattern)
        rule = yara_rule or YaraExporter.export(
            pattern, key_offset=meta_key_offset, key_length=meta_key_length,
        )
        fallback_hex, needle_offset = _longest_static_run(
            pattern.get("wildcard_pattern", ""),
        )
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        key_offset = pattern.get("key_offset", 0)
        key_length = pattern.get("key_length", pattern.get("length", 0))
        vtypes = pattern.get("vtypes", {})

        wp = pattern.get("wildcard_pattern", "")
        scan_regex = _wildcard_to_regex(wp) if wp else b""

        # static_ratio is emitted as a bare Python literal in the generated
        # source; coerce to a float so a None/non-numeric value cannot produce
        # an un-importable plugin.
        try:
            static_ratio = float(pattern.get("static_ratio", 0) or 0)
        except (TypeError, ValueError):
            static_ratio = 0.0

        source = _PLUGIN_TEMPLATE.substitute(
            plugin_name=raw_name, description=desc, timestamp=timestamp,
            pattern_name=raw_name, pattern_length=pattern.get("length", 0),
            static_ratio=repr(static_ratio),
            yara_rule=rule, fallback_hex=fallback_hex,
            needle_offset=needle_offset, class_name=class_name,
            key_offset=key_offset, key_length=key_length,
            vtypes_repr=repr(vtypes),
            scan_regex_repr=repr(scan_regex),
        )
        logger.info("Exported Volatility3 plugin: %s (%d bytes)",
                     class_name, pattern.get("length", 0))
        return source

    @staticmethod
    def save(content: str, output_path: Path) -> None:
        """Write plugin source to a file."""
        output_path.write_text(content)
        logger.info("Saved Volatility3 plugin to %s", output_path)
