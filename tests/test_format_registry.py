"""Tests for the shared binary-format registry (single source of truth).

Covers:
  (a) a dummy FormatDescriptor is detectable via ``detect()`` and retrievable
      via ``get()``;
  (b) the built-in formats still detect the same names from representative
      magic bytes;
  (c) the three consumers -- the Kaitai lookup, the navigator builders and
      ``format_detect`` -- all agree with the registry for the built-ins.
"""

from __future__ import annotations

import logging
import struct

import pytest

from memdiver.core.binary_formats.format_descriptor import (
    FormatDescriptor,
    FormatRegistry,
    get_default_registry,
    register_format,
)


@pytest.fixture
def isolated_default_registry():
    """Snapshot the process-wide default registry and restore it afterwards.

    ``register_format`` mutates the singleton registry in place. Tests that add
    a descriptor with a ``kaitai`` field (or a faulty detector) must not leak it
    into other tests -- notably ``test_kaitai_format_map_matches_registry``,
    which iterates the live registry against the import-time ``_FORMAT_MAP``
    snapshot.
    """
    reg = get_default_registry()
    saved_by_name = dict(reg._by_name)
    saved_order = list(reg._order)
    try:
        yield reg
    finally:
        reg._by_name = saved_by_name
        reg._order = saved_order


# ---------------------------------------------------------------------------
# Representative magic byte samples for the built-in formats.
# ---------------------------------------------------------------------------


def _make_pe(pe_magic: int) -> bytes:
    """Minimal MZ/PE buffer whose optional-header magic selects pe32/pe64."""
    buf = bytearray(0x80)
    buf[0:2] = b"MZ"
    e_lfanew = 0x40
    struct.pack_into("<I", buf, 0x3C, e_lfanew)
    buf[e_lfanew:e_lfanew + 4] = b"PE\x00\x00"
    # optional header magic sits at e_lfanew + 4 (PE sig) + 20 (COFF header)
    struct.pack_into("<H", buf, e_lfanew + 24, pe_magic)
    return bytes(buf)


BUILTIN_SAMPLES: dict[str, bytes] = {
    "elf64": b"\x7fELF\x02" + b"\x00" * 59,
    "elf32": b"\x7fELF\x01" + b"\x00" * 59,
    "macho64_le": b"\xcf\xfa\xed\xfe",
    "macho32_le": b"\xce\xfa\xed\xfe",
    "macho64_be": b"\xfe\xed\xfa\xcf",
    "macho32_be": b"\xfe\xed\xfa\xce",
    "macho_fat": b"\xca\xfe\xba\xbe\x00\x00\x00\x02",
    "msl": b"MEMSLICE" + b"\x00" * 56,
    "minidump": b"MDMP",
    "sqlite3": b"SQLite format 3\x00",
    "gzip": b"\x1f\x8b\x08\x00",
    "zip": b"PK\x03\x04",
    "png": b"\x89PNG\r\n\x1a\n",
    "pdf": b"%PDF-1.7",
    "pe64": _make_pe(0x020B),
    "pe32": _make_pe(0x010B),
    "java_class": b"\xca\xfe\xba\xbe\x00\x00\x00\x40",
    "asn1_der": b"\x30\x82\x01\x00",
}


# ---------------------------------------------------------------------------
# (a) Dummy descriptor round-trips through a fresh registry and the default one.
# ---------------------------------------------------------------------------


def test_dummy_descriptor_detect_and_get():
    reg = FormatRegistry()
    dummy = FormatDescriptor(
        name="dummyfmt",
        aliases=("dummyfmt_v2",),
        magics=(("dummyfmt", 0, b"DUMMY!!"),),
    )
    reg.register(dummy)

    assert reg.get("dummyfmt") is dummy
    assert reg.get("dummyfmt_v2") is dummy  # aliases resolve to same descriptor
    assert reg.detect(b"DUMMY!!\x00\x00") == "dummyfmt"
    assert reg.detect(b"nope") is None
    assert dummy in reg.all()


def test_register_format_adds_to_default_registry():
    dummy = FormatDescriptor(
        name="zz_probe_fmt",
        magics=(("zz_probe_fmt", 0, b"ZZPROBE\x00"),),
    )
    register_format(dummy)
    registry = get_default_registry()
    assert registry.get("zz_probe_fmt") is dummy
    assert registry.detect(b"ZZPROBE\x00rest") == "zz_probe_fmt"


def test_dummy_classifier_refines_name():
    reg = FormatRegistry()
    reg.register(FormatDescriptor(
        name="base",
        magics=(("base", 0, b"BB"),),
        classifier=lambda d: "base_hi" if d[2:3] == b"\x01" else "base_lo",
    ))
    assert reg.detect(b"BB\x01") == "base_hi"
    assert reg.detect(b"BB\x00") == "base_lo"


# ---------------------------------------------------------------------------
# (b) Built-in formats detect the same names from representative magic bytes.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("expected", "sample"), list(BUILTIN_SAMPLES.items()))
def test_builtin_registry_detects_expected_name(expected, sample):
    assert get_default_registry().detect(sample) == expected


# ---------------------------------------------------------------------------
# (c) All three consumers agree with the registry for the built-ins.
# ---------------------------------------------------------------------------


def test_format_detect_matches_registry():
    from memdiver.core.format_detect import detect_format

    registry = get_default_registry()
    for sample in BUILTIN_SAMPLES.values():
        assert detect_format(sample) == registry.detect(sample)


def test_magic_signatures_shim_matches_original_table():
    # The shim is a snapshot built at import time; it must reproduce the exact
    # historical MAGIC_SIGNATURES table (only fixed magics, in original order).
    from memdiver.core.format_detect import MAGIC_SIGNATURES

    original = {
        "elf": (0, b"\x7fELF"),
        "macho64_le": (0, b"\xcf\xfa\xed\xfe"),
        "macho32_le": (0, b"\xce\xfa\xed\xfe"),
        "macho64_be": (0, b"\xfe\xed\xfa\xcf"),
        "macho32_be": (0, b"\xfe\xed\xfa\xce"),
        "msl": (0, b"MEMSLICE"),
        "minidump": (0, b"MDMP"),
        "sqlite3": (0, b"SQLite format 3\x00"),
        "gzip": (0, b"\x1f\x8b"),
        "zip": (0, b"PK\x03\x04"),
        "png": (0, b"\x89PNG\r\n\x1a\n"),
        "pdf": (0, b"%PDF"),
    }
    assert MAGIC_SIGNATURES == original
    assert list(MAGIC_SIGNATURES) == list(original)  # order preserved


def test_kaitai_format_map_matches_registry():
    from memdiver.core.binary_formats import kaitai_registry

    registry = get_default_registry()
    for descriptor in registry.all():
        if descriptor.kaitai is None:
            continue
        for name in descriptor.names:
            assert kaitai_registry._FORMAT_MAP[name] == descriptor.kaitai


def test_navigator_builders_match_registry():
    from memdiver.core.binary_formats import navigator

    registry = get_default_registry()
    expected: dict = {}
    for descriptor in registry.all():
        expected.update(descriptor.nav_builders)

    builders = navigator._nav_builders()
    assert set(builders) == set(expected)
    # Built-ins that historically had navigation trees are all present.
    for name in ("elf64", "elf32", "pe32", "pe64", "macho64_le", "macho32_le", "msl"):
        assert name in builders


# ---------------------------------------------------------------------------
# (B1) Late Kaitai registration is visible to the Kaitai registry.
#
# Guards the fix that ``kaitai_registry`` re-derives its format map per call
# instead of consulting the import-time ``_FORMAT_MAP`` snapshot: a descriptor
# registered *after* ``kaitai_registry`` was imported must still be found.
# ---------------------------------------------------------------------------


def test_late_kaitai_registration_visible_to_registry(
    isolated_default_registry, monkeypatch
):
    from memdiver.core.binary_formats import kaitai_registry as kr

    # Force the runtime "available" so available_formats() reports names even
    # on hosts without the optional kaitaistruct dependency.
    monkeypatch.setattr(kr, "_KAITAI_AVAILABLE", True, raising=False)

    kaitai_ref = ("memdiver.core.binary_formats.kaitai_compiled.msl", "MslV1")
    register_format(FormatDescriptor(
        name="latefmt",
        aliases=("latefmt_v2",),
        magics=(("latefmt", 0, b"LATEFMT\x00"),),
        kaitai=kaitai_ref,
    ))

    # parse()'s lookup path re-derives the map on every call.
    fmap = kr._build_format_map()
    assert fmap["latefmt"] == kaitai_ref
    assert fmap["latefmt_v2"] == kaitai_ref

    reg = kr.KaitaiFormatRegistry()
    available = reg.available_formats()
    assert "latefmt" in available
    assert "latefmt_v2" in available

    # The import-time snapshot did NOT capture it -- the fix is precisely that
    # live lookups no longer consult this stale snapshot.
    assert "latefmt" not in kr._FORMAT_MAP


# ---------------------------------------------------------------------------
# (B2) Detection isolates a faulty detector / classifier.
# ---------------------------------------------------------------------------


def test_detect_isolates_faulty_detector(isolated_default_registry, caplog):
    def boom(data: bytes):
        raise RuntimeError("bad detector")

    register_format(FormatDescriptor(name="boomfmt", detector=boom))
    reg = get_default_registry()

    # Bytes matching no fixed magic -> the detector loop runs and hits boom.
    with caplog.at_level(logging.WARNING):
        result = reg.detect(b"\x99\x98\x97\x96 not a known magic header")

    # The faulty detector was logged + skipped rather than propagating.
    assert any("boomfmt" in r.getMessage() for r in caplog.records)
    # It did not swallow detection of the built-ins.
    assert reg.detect(BUILTIN_SAMPLES["elf64"]) == "elf64"
    assert reg.detect(BUILTIN_SAMPLES["minidump"]) == "minidump"
    # The garbage header still resolves via the surviving detectors (or None).
    assert result in (None, "asn1_der")


def test_detect_isolates_faulty_classifier(isolated_default_registry, caplog):
    def boom(data: bytes) -> str:
        raise RuntimeError("bad classifier")

    register_format(FormatDescriptor(
        name="clsfmt",
        magics=(("clsfmt", 0, b"CLSMAGIC"),),
        classifier=boom,
    ))
    reg = get_default_registry()

    with caplog.at_level(logging.WARNING):
        result = reg.detect(b"CLSMAGIC" + b"\x00" * 8)

    # Classifier failure falls back to the matched magic's result name.
    assert result == "clsfmt"
    assert any("clsfmt" in r.getMessage() for r in caplog.records)
    # Built-ins remain detectable.
    assert reg.detect(BUILTIN_SAMPLES["png"]) == "png"


# ---------------------------------------------------------------------------
# (B3) Recognised-set lock: freezes the deliberate detection superset.
# ---------------------------------------------------------------------------


def test_recognised_set_lock():
    from memdiver.core.format_detect import detect_format

    # The exact set of names the built-in registry recognises for the
    # representative magic samples, INCLUDING the additive superset members
    # (minidump/sqlite3/gzip/zip/png/pdf/asn1_der). Locked so future drift is
    # caught rather than silently changing detection behaviour.
    expected = {
        "elf64", "elf32",
        "pe32", "pe64",
        "macho64_le", "macho32_le", "macho64_be", "macho32_be",
        "macho_fat", "java_class",
        "msl",
        "minidump", "sqlite3", "gzip", "zip", "png", "pdf", "asn1_der",
    }
    got = {detect_format(sample) for sample in BUILTIN_SAMPLES.values()}
    assert got == expected

    # The deliberately additive members are explicitly present.
    for name in ("minidump", "sqlite3", "gzip", "zip", "png", "pdf", "asn1_der"):
        assert name in got


def test_minidump_magic_detects_minidump():
    from memdiver.core.format_detect import detect_format

    assert detect_format(b"MDMP\x93\xa7\x00\x00" + b"\x00" * 24) == "minidump"
