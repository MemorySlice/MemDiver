"""Volatility3Exporter - generate self-contained Volatility3 plugins from patterns."""

import logging
from datetime import datetime, timezone
from pathlib import Path
from string import Template
from typing import Optional

from .yara_exporter import YaraExporter

logger = logging.getLogger("memdiver.architect.volatility3_exporter")

_PLUGIN_TEMPLATE = Template('''\
"""MemDiver Volatility3 plugin: $plugin_name
$description
Generated: $timestamp | Pattern: $pattern_name ($pattern_length bytes, $static_ratio static)
Key region: offset +$key_offset, length $key_length
"""
import math
from typing import List
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners

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
    ("KeyOffset", renderers.format_hints.Hex),
    ("KeyHex", str),
    ("KeyEntropy", float),
    ("KeyLength", int),
    ("PatternOffset", renderers.format_hints.Hex),
    ("StaticRatio", float),
]

class $class_name(interfaces.plugins.PluginInterface):
    """Scan process memory for MemDiver pattern: $pattern_name."""
    _required_framework_version = (2, 0, 0)
    _version = (1, 1, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary", description="Memory layer", optional=False),
            requirements.SymbolTableRequirement(
                name="symbols", description="OS kernel symbols", optional=True),
            requirements.IntRequirement(
                name="pid", description="Target process PID",
                optional=True, default=None),
            requirements.BooleanRequirement(
                name="full_scan",
                description="Scan full memory instead of PID-filtered",
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
        """
        layer = self.context.layers[layer_name]

        # --- Primary: RegExScanner (full structural pattern) ---
        if SCAN_REGEX:
            try:
                seen = set()
                for offset in layer.scan(
                    context=self.context,
                    scanner=scanners.RegExScanner(SCAN_REGEX)):
                    if offset in seen:
                        continue
                    seen.add(offset)
                    try:
                        data = layer.read(offset, PATTERN_LENGTH)
                    except Exception:
                        continue
                    yield offset, data
                return
            except Exception:
                pass  # fall through to BytesScanner

        # --- Fallback: BytesScanner + optional YARA verify ---
        if not NEEDLE:
            return

        yara_rules = None
        try:
            import yara
            yara_rules = yara.compile(source=YARA_RULE)
        except Exception:
            pass

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
            except Exception:
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
                renderers.format_hints.Hex(key_vaddr),
                key_bytes.hex(),
                round(key_entropy, 4),
                KEY_LENGTH,
                renderers.format_hints.Hex(pattern_offset),
                $static_ratio,
            ))

    def _grid(self, layer_name: str):
        return renderers.TreeGrid(_COLUMNS, self._generator(layer_name))

    def _try_pid_scan(self, layer_name, pid):
        """Attempt PID-filtered scan on Linux then Windows."""
        for mod, cls, list_fn, pid_attr, layer_fn, sym_key in [
            ("volatility3.plugins.linux.pslist", "PsList",
             "list_tasks", "pid", "add_process_layer", "vmlinux"),
            ("volatility3.plugins.windows.pslist", "PsList",
             "list_processes", "UniqueProcessId", "add_process_layer",
             "nt_symbols"),
        ]:
            try:
                import importlib
                plugin = importlib.import_module(mod)
                # Resolve symbol table key: prefer OS-specific, fall back
                stab = self.config.get(sym_key) or self.config.get("symbols", "")
                for proc in getattr(getattr(plugin, cls), list_fn)(
                    self.context, layer_name, stab):
                    if getattr(proc, pid_attr) == pid:
                        proc_layer = getattr(proc, layer_fn)()
                        if proc_layer:
                            return self._grid(proc_layer)
            except Exception:
                continue
        return None

    def run(self):
        layer_name = self.config["primary"]
        full_scan = self.config.get("full_scan", False)
        pid = self.config.get("pid", None)

        if full_scan:
            return self._grid(layer_name)

        if pid is not None:
            result = self._try_pid_scan(layer_name, pid)
            if result is not None:
                return result
            # PID scan failed — fall back to full layer scan.
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
            yara_rule: Pre-built YARA rule string. Generated if not provided.

        Returns:
            Complete Python source code for a Volatility3 plugin.
        """
        raw_name = pattern.get("name", "memdiver_pattern")
        class_name = plugin_name or ("MemDiverScan" + _sanitize_class_name(raw_name))
        desc = description or f"Scan for MemDiver pattern: {raw_name}"
        rule = yara_rule or YaraExporter.export(pattern)
        fallback_hex, needle_offset = _longest_static_run(
            pattern.get("wildcard_pattern", ""),
        )
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        key_offset = pattern.get("key_offset", 0)
        key_length = pattern.get("key_length", pattern.get("length", 0))
        vtypes = pattern.get("vtypes", {})

        wp = pattern.get("wildcard_pattern", "")
        scan_regex = _wildcard_to_regex(wp) if wp else b""

        source = _PLUGIN_TEMPLATE.substitute(
            plugin_name=raw_name, description=desc, timestamp=timestamp,
            pattern_name=raw_name, pattern_length=pattern.get("length", 0),
            static_ratio=pattern.get("static_ratio", 0),
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
