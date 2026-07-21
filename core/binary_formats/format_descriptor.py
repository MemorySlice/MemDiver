"""Single source of truth describing each supported binary format.

Historically, adding a binary format meant editing three or four separate
hardcoded tables keyed on duplicated format-name strings:

* ``kaitai_registry._FORMAT_MAP`` -- name -> (module, Kaitai class)
* ``navigator.build_nav_tree`` -- name -> nav-tree builder function
* ``format_detect.MAGIC_SIGNATURES`` + hand-rolled branch logic
* per-format ``StructureDef`` lists in ``*_defs.py``

This module collapses those into one :class:`FormatDescriptor` per format and
a :class:`FormatRegistry` that the individual consumers read from.  The
consumers keep their existing public APIs and merely *derive* their tables from
the shared registry, so there is now a single place to register a new format.

Behaviour notes (be precise — this is not "byte-for-byte identical" everywhere):

* Kaitai lookup and nav-tree dispatch reproduce the former tables exactly.
* Detection is a *superset* of the historical ``format_detect`` results: the
  original formats (elf/pe/macho/msl) detect identically, and additional
  signatures (minidump — consumed by ``msl/importer.py`` — plus common embedded
  formats such as sqlite3/gzip/zip/png/pdf/asn1_der) are also recognised. These
  additions are purely additive for callers that branch on specific names
  (``msl/importer`` only routes ``minidump``/ELF; everything else falls through
  to the historical raw path) and enrich the ``suggest_formats`` UI surface.
* ``structure_defs`` are attached to descriptors but NOT yet consumed:
  ``structure_library`` still imports the per-format ``*_DEFS`` directly. Wiring
  that consumer through the registry is a tracked follow-up.

To add a format, build a :class:`FormatDescriptor` and call
:func:`register_format`.  See ``docs/contributing/adding_binary_format.md``.
"""

from __future__ import annotations

import logging
import struct
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("memdiver.core.binary_formats.format_descriptor")


def _safe_call(fn: Callable[[bytes], "str | None"], data: bytes, name: str) -> str | None:
    """Invoke a descriptor classifier/detector, isolating failures.

    A faulty (e.g. third-party) detector must not abort detection for every
    other format, so an exception is logged and treated as "no match"
    (returns ``None``). Mirrors the failure-isolation policy in
    ``core/plugin_discovery.py``.
    """
    try:
        return fn(data)
    except Exception:  # noqa: BLE001 - a bad detector must not break detection
        logger.warning("format detector/classifier for %r raised; skipping", name,
                       exc_info=True)
        return None

# A magic signature entry: (result_name, offset, expected_bytes).
# ``result_name`` is the format name returned by detection when this signature
# matches (before any :attr:`FormatDescriptor.classifier` refinement).
MagicSignature = tuple[str, int, bytes]

# Detection helpers return a format name (``str``) or ``None`` when the bytes do
# not match.  Classifiers refine an already-matched name.  Detectors are custom
# routines for formats whose detection is more than a fixed magic compare.
Classifier = Callable[[bytes], str]
Detector = Callable[[bytes], "str | None"]
NavBuilder = Callable[[bytes], Any]


@dataclass
class FormatDescriptor:
    """Everything MemDiver needs to know about one binary format.

    Attributes:
        name: Canonical format name.
        aliases: Additional names that resolve to this same format (e.g.
            ``elf64``/``elf32`` for the ELF descriptor).  ``name`` plus
            ``aliases`` is the full set of names that map to this descriptor's
            Kaitai parser.
        magics: Fixed magic signatures used for detection, in priority order.
        classifier: Optional refinement applied to the whole header after any
            of ``magics`` matches (e.g. ELF class byte -> ``elf64``/``elf32``).
        detector: Optional custom detector for formats whose detection needs
            more than a fixed magic compare (e.g. PE's ``MZ`` + ``PE\\0\\0``).
        kaitai: Optional ``(module_path, class_name)`` for the compiled Kaitai
            parser that handles ``name`` and every alias.
        nav_builders: Mapping of format name -> navigation-tree builder.  A
            format may build different trees per alias (32- vs 64-bit), so this
            is keyed by name rather than a single callable.
        structure_defs: Optional list of ``StructureDef`` objects for the
            format's on-disk header layout.
    """

    name: str
    aliases: tuple[str, ...] = ()
    magics: tuple[MagicSignature, ...] = ()
    classifier: Classifier | None = None
    detector: Detector | None = None
    kaitai: tuple[str, str] | None = None
    nav_builders: dict[str, NavBuilder] = field(default_factory=dict)
    structure_defs: list[Any] | None = None

    @property
    def names(self) -> tuple[str, ...]:
        """Canonical name followed by all aliases."""
        return (self.name, *self.aliases)


class FormatRegistry:
    """Ordered collection of :class:`FormatDescriptor` objects.

    Registration order is preserved and used by :meth:`detect` so that the
    detection precedence exactly matches the historical hand-rolled logic.
    """

    def __init__(self) -> None:
        self._by_name: dict[str, FormatDescriptor] = {}
        self._order: list[FormatDescriptor] = []

    def register(self, descriptor: FormatDescriptor) -> FormatDescriptor:
        """Register *descriptor* under its canonical name and every alias.

        Re-registering an existing canonical name replaces the descriptor in
        place (order preserved) so late binding -- e.g. the navigator attaching
        its nav builders -- stays idempotent.
        """
        existing = self._by_name.get(descriptor.name)
        for name in descriptor.names:
            self._by_name[name] = descriptor
        if existing is not None and existing in self._order:
            self._order[self._order.index(existing)] = descriptor
        else:
            self._order.append(descriptor)
        return descriptor

    def get(self, name: str) -> FormatDescriptor | None:
        """Return the descriptor registered for *name*, or ``None``."""
        return self._by_name.get(name)

    def all(self) -> list[FormatDescriptor]:
        """Return descriptors in registration order (deduplicated)."""
        return list(self._order)

    def detect(self, header_bytes: bytes) -> str | None:
        """Detect the format name for *header_bytes*, or ``None``.

        Fixed magic signatures are checked first (in registration order),
        then custom detectors (also in registration order), mirroring the
        original ``format_detect`` precedence.
        """
        data = header_bytes
        for desc in self._order:
            for result_name, off, magic in desc.magics:
                end = off + len(magic)
                if len(data) >= end and data[off:end] == magic:
                    if desc.classifier is not None:
                        return _safe_call(desc.classifier, data, desc.name) or result_name
                    return result_name
        for desc in self._order:
            if desc.detector is not None:
                result = _safe_call(desc.detector, data, desc.name)
                if result is not None:
                    return result
        return None


# ---------------------------------------------------------------------------
# Detection primitives (single source of truth; ``format_detect`` delegates).
# ---------------------------------------------------------------------------


def classify_elf(data: bytes) -> str:
    """Refine a matched ELF header into ``elf64``/``elf32``/``elf``."""
    if len(data) >= 5:
        ei_class = data[4]
        if ei_class == 2:
            return "elf64"
        if ei_class == 1:
            return "elf32"
    return "elf"


def classify_pe(data: bytes, pe_offset: int) -> str:
    """Classify a PE as ``pe32`` or ``pe64`` from the optional-header magic."""
    coff_start = pe_offset + 4
    opt_start = coff_start + 20
    if len(data) >= opt_start + 2:
        magic = struct.unpack_from("<H", data, opt_start)[0]
        if magic == 0x020B:
            return "pe64"
    return "pe32"


def _detect_pe(data: bytes) -> str | None:
    """Detect PE via ``MZ`` stub + ``PE\\0\\0`` at ``e_lfanew``."""
    if data[:2] == b"MZ" and len(data) >= 64:
        try:
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            if len(data) >= e_lfanew + 4 and data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00":
                return classify_pe(data, e_lfanew)
        except struct.error:
            return None
    return None


def _detect_fat_or_java(data: bytes) -> str | None:
    """Disambiguate the shared ``0xCAFEBABE`` magic (Mach-O fat vs Java class)."""
    if len(data) >= 8 and data[:4] == b"\xca\xfe\xba\xbe":
        nfat = struct.unpack_from(">I", data, 4)[0]
        if nfat <= 30:
            return "macho_fat"
        return "java_class"
    return None


def _detect_asn1_der(data: bytes) -> str | None:
    """Detect an ASN.1 DER SEQUENCE (common in PKCS / X.509)."""
    if len(data) >= 4 and data[0] == 0x30 and data[1] == 0x82:
        seq_len = struct.unpack_from(">H", data, 2)[0]
        if seq_len >= 64:
            return "asn1_der"
    return None


# ---------------------------------------------------------------------------
# Default registry populated with the built-in formats.
# ---------------------------------------------------------------------------


def _load_structure_defs(module_path: str, attr: str) -> list[Any] | None:
    """Best-effort import of a ``*_DEFS`` list; ``None`` if unavailable."""
    try:
        import importlib

        module = importlib.import_module(module_path)
        return list(getattr(module, attr))
    except Exception:  # noqa: BLE001 - structure defs are optional metadata
        return None


def _build_default_registry() -> FormatRegistry:
    """Build the registry describing MemDiver's built-in formats.

    Registration order reproduces the historical detection precedence and the
    original ``MAGIC_SIGNATURES`` ordering used by ``format_detect``.
    """
    registry = FormatRegistry()

    # ELF -- magic + class-byte classifier; single Kaitai parser for all names.
    registry.register(FormatDescriptor(
        name="elf",
        aliases=("elf64", "elf32"),
        magics=(("elf", 0, b"\x7fELF"),),
        classifier=classify_elf,
        kaitai=("memdiver.core.binary_formats.kaitai_compiled.elf", "Elf"),
        structure_defs=_load_structure_defs(
            "memdiver.core.binary_formats.elf_defs", "ELF_DEFS",
        ),
    ))

    # PE -- no fixed offset-0 magic; detected via the MZ/PE\0\0 detector.
    registry.register(FormatDescriptor(
        name="pe",
        aliases=("pe32", "pe64"),
        detector=_detect_pe,
        kaitai=("memdiver.core.binary_formats.kaitai_compiled.microsoft_pe", "MicrosoftPe"),
        structure_defs=_load_structure_defs(
            "memdiver.core.binary_formats.pe_defs", "PE_DEFS",
        ),
    ))

    # Mach-O -- four fixed magics plus the shared 0xCAFEBABE fat/java detector.
    registry.register(FormatDescriptor(
        name="macho",
        aliases=(
            "macho32", "macho64",
            "macho64_le", "macho32_le", "macho64_be", "macho32_be",
            "macho_fat",
        ),
        magics=(
            ("macho64_le", 0, b"\xcf\xfa\xed\xfe"),
            ("macho32_le", 0, b"\xce\xfa\xed\xfe"),
            ("macho64_be", 0, b"\xfe\xed\xfa\xcf"),
            ("macho32_be", 0, b"\xfe\xed\xfa\xce"),
        ),
        detector=_detect_fat_or_java,
        kaitai=("memdiver.core.binary_formats.kaitai_compiled.mach_o", "MachO"),
        structure_defs=_load_structure_defs(
            "memdiver.core.binary_formats.macho_defs", "MACHO_DEFS",
        ),
    ))

    # MSL -- MemSlice container format.
    registry.register(FormatDescriptor(
        name="msl",
        magics=(("msl", 0, b"MEMSLICE"),),
        kaitai=("memdiver.core.binary_formats.kaitai_compiled.msl", "MslV1"),
    ))

    # Detection-only formats (no Kaitai parser / nav builder today), preserved
    # in their original MAGIC_SIGNATURES order so ``format_detect`` is unchanged.
    registry.register(FormatDescriptor(
        name="minidump", magics=(("minidump", 0, b"MDMP"),),
    ))
    registry.register(FormatDescriptor(
        name="sqlite3", magics=(("sqlite3", 0, b"SQLite format 3\x00"),),
    ))
    registry.register(FormatDescriptor(
        name="gzip", magics=(("gzip", 0, b"\x1f\x8b"),),
    ))
    registry.register(FormatDescriptor(
        name="zip", magics=(("zip", 0, b"PK\x03\x04"),),
    ))
    registry.register(FormatDescriptor(
        name="png", magics=(("png", 0, b"\x89PNG\r\n\x1a\n"),),
    ))
    registry.register(FormatDescriptor(
        name="pdf", magics=(("pdf", 0, b"%PDF"),),
    ))

    # ASN.1 DER -- custom detector, runs after PE and the CAFEBABE detector.
    registry.register(FormatDescriptor(
        name="asn1_der", detector=_detect_asn1_der,
    ))

    return registry


#: Entry-point group under which out-of-tree packages advertise binary formats.
#: Each advertised entry point is a module (imported for its ``register_format``
#: side effects) or a callable (invoked to self-register). See
#: ``docs/contributing/adding_binary_format.md``.
FORMAT_ENTRY_POINT_GROUP = "memdiver.formats"

_DEFAULT_REGISTRY: FormatRegistry | None = None


def get_default_registry() -> FormatRegistry:
    """Return the process-wide default :class:`FormatRegistry` (lazy singleton).

    On first build the registry is populated with the built-in formats and
    then augmented with any advertised by installed packages under the
    ``memdiver.formats`` entry-point group (additive; a silent, failure-isolated
    no-op when none are installed).
    """
    global _DEFAULT_REGISTRY  # noqa: PLW0603
    if _DEFAULT_REGISTRY is None:
        # Publish the built-in registry before out-of-tree discovery runs:
        # entry-point plugins self-register via ``register_format`` ->
        # ``get_default_registry()``, so the singleton must already be set to
        # avoid re-entrant rebuilding.
        _DEFAULT_REGISTRY = _build_default_registry()
        from memdiver.core.plugin_discovery import load_entry_point_registrations
        load_entry_point_registrations(FORMAT_ENTRY_POINT_GROUP)
    return _DEFAULT_REGISTRY


def register_format(descriptor: FormatDescriptor) -> FormatDescriptor:
    """Register *descriptor* with the default registry (public extension point)."""
    return get_default_registry().register(descriptor)
