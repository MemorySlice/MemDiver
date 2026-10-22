"""Name-based region classification (msl/region_names.py) and its plumbing.

The classification table is the shared vector file
``tests/fixtures/region_name_vectors.json`` (memslicer keeps a byte-identical
copy and checks its own columns against it); MemDiver checks the
``memdiver_category`` column.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from memdiver.msl.enums import Protection, RegionType
from memdiver.msl.region_names import (MappingNameIndex, anon_label,
                                       classify_mapping_name,
                                       legacy_live_region_type, looks_android,
                                       platform_for_names, strip_deleted)
from memdiver.msl.region_select import (DEFAULT_INTERACTIVE_CATEGORIES,
                                        REGION_NAMES_NOTE, RegionCategory,
                                        RegionInfo, RegionSelection,
                                        apply_name_override, classify,
                                        classify_stored, join_provenance_note,
                                        parse_provenance_note, parse_selection)
from memdiver.msl.types import MslVasEntry

VECTORS_PATH = Path(__file__).parent / "fixtures" / "region_name_vectors.json"
VECTORS = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
RW = int(Protection.READ | Protection.WRITE)
C = RegionCategory


# -- shared vectors -------------------------------------------------------------


def test_vector_file_shape():
    assert len(VECTORS) >= 90
    keys = {"name", "memslicer_category", "memslicer_region_type",
            "memdiver_category", "note"}
    assert all(set(row) == keys for row in VECTORS)
    assert len({row["name"] for row in VECTORS}) == len(VECTORS)


@pytest.mark.parametrize("row", VECTORS, ids=lambda r: r["name"] or "<empty>")
def test_classify_mapping_name_matches_vectors(row):
    got = classify_mapping_name(row["name"])
    assert (None if got is None else got.value) == row["memdiver_category"]


@pytest.mark.parametrize("name", [
    "[anon:.bss]", "/dev/binder", "/dev/hwbinder", "/dev/shm/x",
    "/dev/ashmem/CursorWindow (deleted)", "/memfd:wayland (deleted)",
    "/data/app/~~a==/com.x-b==/base.apk", "[anon:atexit handlers]",
])
def test_deliberate_no_override(name):
    assert classify_mapping_name(name) is None


def test_none_and_empty_name_have_no_override():
    assert classify_mapping_name(None) is None
    assert classify_mapping_name("") is None


# -- helpers --------------------------------------------------------------------


def test_strip_deleted():
    assert strip_deleted("/x.so (deleted)") == "/x.so"
    assert strip_deleted("/x.so") == "/x.so"


def test_anon_label():
    assert anon_label("[anon:scudo:primary]") == "scudo:primary"
    assert anon_label("[anon_shmem:foo]") == "foo"
    assert anon_label("[heap]") is None


def test_looks_android_and_platform():
    assert looks_android(["", "[anon:dalvik-main space]"])
    assert looks_android(["/system/lib64/libc.so"])
    assert not looks_android(["", None, "[heap]", "/usr/lib/libc.so.6"])
    assert platform_for_names(["/apex/x/libc.so"]) == "android"
    assert platform_for_names(["[heap]"]) == "linux"
    assert platform_for_names(["[heap]"], default=None) is None


@pytest.mark.parametrize("name,expected", [
    ("", RegionType.ANONYMOUS), (None, RegionType.ANONYMOUS),
    ("[heap]", RegionType.HEAP), ("[stack]", RegionType.STACK),
    ("/lib/libc.so", RegionType.IMAGE), ("C:\\x.dll", RegionType.IMAGE),
    ("/usr/lib/libc.so.6", RegionType.MAPPED_FILE),  # old rule: suffix only
    ("/x.so (deleted)", RegionType.MAPPED_FILE),
    ("[anon:scudo:primary]", RegionType.UNKNOWN),
    ("[anon:dalvik-main space]", RegionType.UNKNOWN),
    ("[vdso]", RegionType.UNKNOWN), ("[stack:12]", RegionType.UNKNOWN),
])
def test_legacy_live_region_type(name, expected):
    assert legacy_live_region_type(name) == int(expected)


def test_mapping_name_index_lookup():
    index = MappingNameIndex([(0x2000, 0x1000, "[heap]"), (0x1000, 0x1000, ""),
                              (0x5000, 0x2000, "/lib/x.so")])
    assert len(index) == 3
    assert index.name_for(0x1000) == ""
    assert index.name_for(0x2000) == "[heap]"
    assert index.name_for(0x2fff) == "[heap]"
    assert index.name_for(0x3000) is None   # gap
    assert index.name_for(0x0) is None      # before the first entry
    assert index.name_for(0x6000) == "/lib/x.so"


def test_mapping_name_index_from_vas_entries():
    index = MappingNameIndex.from_vas_entries(
        [MslVasEntry(0x1000, 0x1000, RW, 5, "[anon:scudo:primary]")])
    assert index.name_for(0x1000) == "[anon:scudo:primary]"


# -- category plumbing ------------------------------------------------------------


def test_runtime_is_last_and_not_default():
    assert list(RegionCategory)[-1] is C.RUNTIME
    assert C.RUNTIME not in DEFAULT_INTERACTIVE_CATEGORIES
    assert parse_selection("runtime").categories == {C.RUNTIME}


def test_old_seven_name_spec_means_all_but_runtime():
    old = "regions=heap,image_code,image_data,mapped_file,shared,stack," \
          "unclassified"
    sel = RegionSelection.from_note(old)
    assert sel.categories == frozenset(RegionCategory) - {C.RUNTIME}
    assert not sel.is_all
    assert RegionSelection.from_note("regions=all").is_all


def test_classify_without_name_unchanged():
    # OTHER (an [anon:...] mapping) stays unclassified without its name.
    assert classify(int(RegionType.OTHER), RW, 0, 0x1000) is C.UNCLASSIFIED
    assert classify(int(RegionType.OTHER), RW, 0, 0x1000,
                    name="[anon:atexit handlers]") is C.UNCLASSIFIED


@pytest.mark.parametrize("name,rtype,expected", [
    ("[anon:scudo:primary]", RegionType.OTHER, C.HEAP),
    ("[anon:stack_and_tls:1]", RegionType.OTHER, C.STACK),
    ("[anon:dalvik-zygote space]", RegionType.OTHER, C.RUNTIME),
    ("/system/framework/arm64/boot.oat", RegionType.MAPPED_FILE, C.RUNTIME),
    ("[vdso]", RegionType.OTHER, C.RUNTIME),
    # HEAP on stored SHARED_MEM stays shared; RUNTIME still wins.
    ("/dev/ashmem/dalvik-main space (deleted)", RegionType.SHARED_MEM,
     C.SHARED),
    ("/dev/ashmem/dalvik-zygote space (deleted)", RegionType.SHARED_MEM,
     C.RUNTIME),
])
def test_classify_with_name_override(name, rtype, expected):
    assert classify(int(rtype), RW, 0, 0x1000, name=name) is expected


def test_apply_name_override_none_keeps_category():
    assert apply_name_override(C.IMAGE_DATA, int(RegionType.IMAGE),
                               None) is C.IMAGE_DATA


def test_classify_stored_raw_rule_beats_name():
    from memdiver.msl.enums import SourceFormat
    assert classify_stored(int(RegionType.ANONYMOUS), RW, 0, 0x1000,
                           source_format=int(SourceFormat.RAW_DUMP),
                           name="[anon:dalvik-zygote space]") \
        is C.UNCLASSIFIED
    assert classify_stored(int(RegionType.OTHER), RW, 0, 0x1000,
                           name="[anon:dalvik-zygote space]") is C.RUNTIME


def test_region_info_to_dict_has_name():
    info = RegionInfo(0x1000, 0x1000, RW, 5, C.HEAP, None, 0x1000,
                      name="[anon:libc_malloc]")
    assert info.to_dict()["name"] == "[anon:libc_malloc]"
    assert RegionInfo(0, 0, 0, 0, C.HEAP).to_dict()["name"] is None


def test_provenance_region_names_marker():
    note = join_provenance_note(join_provenance_note(
        "Imported from x.bin with memory map x.maps", REGION_NAMES_NOTE),
        "regions=heap;excluded_regions=1;excluded_bytes=4096")
    fields = parse_provenance_note(note)
    assert fields.region_names is True
    assert fields.selection.categories == {C.HEAP}
    assert fields.to_dict()["region_names"] is True
    assert parse_provenance_note("Imported from x.bin").region_names is False
    assert parse_provenance_note(None).region_names is False
    assert parse_provenance_note("a; region_names=0").region_names is False
