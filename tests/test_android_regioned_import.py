"""Android-aware regioned import: names, ``runtime`` category, trust rule.

Uses ``tests/fixtures/android/app_process_arm64.maps`` (60 realistic arm64
app mappings, one page each) and the ``.bin`` its generator writes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from memdiver.core.models import CryptoSecret
from memdiver.core.region_view_filter import stored_region_infos
from memdiver.msl import importer as importer_mod
from memdiver.msl.enums import OSType, RegionType, SourceFormat
from memdiver.msl.import_preview import (msl_classification_context,
                                         preview_import, runtime_note)
from memdiver.msl.import_regioned import plan_regioned_raw
from memdiver.msl.importer import import_dump, import_msl_passthrough
from memdiver.msl.materialize import stored_regions
from memdiver.msl.reader import MslReader
from memdiver.msl.region_select import (RegionCategory as C, RegionSelection,
                                        classify, parse_provenance_note,
                                        parse_selection)
from memdiver.msl.types import MslVasEntry
from memdiver.msl.writer import MslWriter

from tests.fixtures.android.generate_app_process_bin import (
    MAPS_PATH, ZYGOTE_SPACE, maps_entry_names, write_app_process_bin)

DEFAULT = RegionSelection.default_interactive()
SECRET = b"ZYGOTE-ONLY-SECRET-0123456789abc"  # 32 bytes

# Expected category per mapping name of the fixture (first match wins).
EXPECTED = {
    "[anon:dalvik-main space (region space)]": C.HEAP,
    "[anon:dalvik-main space (region space) live bitmap]": C.RUNTIME,
    "[anon:dalvik-/system/framework/boot.art]": C.RUNTIME,
    "[anon:dalvik-zygote space]": C.RUNTIME,
    "[anon:dalvik-non moving space]": C.HEAP,
    "[anon:dalvik-card table]": C.RUNTIME,
    "/memfd:jit-cache (deleted)": C.RUNTIME,
    "[anon:scudo:primary]": C.HEAP,
    "[anon:libc_malloc]": C.HEAP,
    "[anon:.bss]": C.UNCLASSIFIED,
    "[anon:cfi shadow]": C.RUNTIME,
    "/dev/__properties__/property_info": C.RUNTIME,
    "/dev/kgsl-3d0": C.RUNTIME,
    "/dev/binderfs/binder": C.MAPPED_FILE,
    "/system/usr/icu/icudt66l.dat": C.RUNTIME,
    "/system/framework/arm64/boot.oat": C.RUNTIME,
    "[anon:dalvik-/data/app/~~Zx1==/com.example.app-Ab2==/oat/arm64/base.art]":
        C.HEAP,
    "[anon:stack_and_tls:12345]": C.STACK,
    "[anon:thread signal stack]": C.STACK,
    "[stack]": C.STACK,
    "[vdso]": C.RUNTIME,
    "[vvar]": C.RUNTIME,
}


@pytest.fixture
def android_bin(tmp_path) -> Path:
    return write_app_process_bin(tmp_path / "app.bin", secret=SECRET)


def _import(src: Path, out: Path, **kwargs):
    return import_dump(src, out, maps_path=src.with_suffix(".maps"), **kwargs)


def _vas(path: Path):
    with MslReader(path) as reader:
        return [e for vm in reader.collect_vas_map() for e in vm.entries]


def _key(info):
    return (info.base_addr, info.size, info.protection, info.region_type,
            info.category, info.name, info.captured_bytes)


# -- preview --------------------------------------------------------------------


def test_fixture_has_sixty_one_page_entries(android_bin):
    names = maps_entry_names()
    assert len(names) == 60
    assert android_bin.stat().st_size == 60 * 4096


def test_preview_classifies_android_names(android_bin):
    preview = preview_import(android_bin)
    by_name = {}
    for region in preview.regions:
        by_name.setdefault(region.name, region.category)
    for name, category in EXPECTED.items():
        assert by_name[name] is category, name
    assert by_name[None] is C.HEAP  # unnamed anonymous mapping


def test_preview_platform_and_runtime_fields(android_bin):
    preview = preview_import(android_bin)
    assert (preview.platform, preview.platform_source) == (
        "android", "mapping_names")
    runtime = [r for r in preview.regions if r.category is C.RUNTIME]
    assert preview.runtime_count == len(runtime) > 0
    assert preview.runtime_bytes == sum(r.captured_bytes for r in runtime)
    data = preview.to_dict(DEFAULT)
    assert data["platform"] == "android"
    assert data["runtime_count"] == preview.runtime_count
    assert data["runtime_bytes"] == preview.runtime_bytes
    assert all("name" in r for r in data["regions"])
    assert data["totals"]["runtime"]["count"] == preview.runtime_count
    assert any("'runtime'" in note for note in preview.notes)


def test_runtime_note_absent_without_runtime_regions(tmp_path):
    maps = tmp_path / "x.maps"
    maps.write_text("00400000-00401000 rw-p 00000000 00:00 0 [heap]\n")
    (tmp_path / "x.bin").write_bytes(b"\0" * 4096)
    preview = preview_import(tmp_path / "x.bin", maps_path=maps)
    assert preview.runtime_count == 0
    assert runtime_note(preview) is None
    assert (preview.platform, preview.platform_source) == ("linux", "format")


def test_plan_platform(android_bin):
    plan, _ = plan_regioned_raw(android_bin, MAPS_PATH)
    assert plan.platform == "android"


# -- import ---------------------------------------------------------------------


def test_regioned_import_writes_named_vas_map(android_bin, tmp_path):
    out = tmp_path / "app.msl"
    _import(android_bin, out)
    vas = sorted(_vas(out), key=lambda e: e.base_addr)
    plan, _ = plan_regioned_raw(android_bin, MAPS_PATH)
    expected = sorted((e.base_addr, e.region.path) for e in plan.entries)
    assert [(e.base_addr, e.mapped_path) for e in vas] == expected
    with MslReader(out) as reader:
        assert reader.file_header.os_type == OSType.ANDROID
        (prov,) = reader.collect_import_provenance()
        assert prov.source_format == SourceFormat.REGIONED_RAW
        assert parse_provenance_note(prov.note).region_names
        assert len(reader.collect_regions()) == 60


def test_regioned_stored_types_unchanged_by_names(android_bin, tmp_path):
    """Names never change the stored region_type (alignment keys)."""
    out = tmp_path / "app.msl"
    _import(android_bin, out)
    plan, _ = plan_regioned_raw(android_bin, MAPS_PATH)
    with MslReader(out) as reader:
        stored = [(r.base_addr, r.region_type) for r in reader.collect_regions()]
    assert stored == [(e.base_addr, e.region_type) for e in plan.entries]


def test_default_selection_excludes_runtime_keeps_heap_stack(android_bin,
                                                             tmp_path):
    out = tmp_path / "default.msl"
    result = _import(android_bin, out, selection=DEFAULT)
    preview = preview_import(android_bin)
    kept = {r.base_addr for r in preview.regions if DEFAULT.includes(r)}
    with MslReader(out) as reader:
        bases = {r.base_addr for r in reader.collect_regions()}
    assert bases == kept
    cats = {r.category for r in preview.regions if r.base_addr in bases}
    assert C.HEAP in cats and C.STACK in cats and C.RUNTIME not in cats
    assert result.excluded_region_count == len(preview.regions) - len(kept)
    assert len(_vas(out)) == 60  # full layout, excluded entries included


def test_secret_only_in_zygote_space_counted(android_bin, tmp_path):
    out = tmp_path / "default.msl"
    secret = CryptoSecret("CLIENT_RANDOM", b"\x00" * 32, SECRET)
    result = _import(android_bin, out, selection=DEFAULT, secrets=[secret])
    assert result.secrets_only_in_excluded == 1
    assert result.key_hints_written == 0
    assert any("only in excluded regions" in w for w in result.warnings)
    full = _import(android_bin, tmp_path / "full.msl", secrets=[secret])
    assert full.key_hints_written == 1


# -- equivalence across classifiers ---------------------------------------------


def test_classification_equivalent_across_paths(android_bin, tmp_path):
    out = tmp_path / "app.msl"
    _import(android_bin, out)
    from_bin = [_key(r) for r in preview_import(android_bin).regions]
    from_msl = [_key(r) for r in preview_import(out).regions]
    with MslReader(out) as reader:
        from_filter = [_key(r) for r in stored_region_infos(reader)]
        source_format = msl_classification_context(reader)[0]
        from_materialize = [_key(s.info)
                            for s in stored_regions(reader, source_format)]
    assert from_bin == from_msl == from_filter == from_materialize

    copy = tmp_path / "copy.msl"
    import_msl_passthrough(out, copy, selection=DEFAULT, materialize=True)
    kept = [k for k in from_bin if k[4] in DEFAULT.categories]
    assert [_key(r) for r in preview_import(copy).regions] == kept
    with MslReader(copy) as reader:
        (prov,) = reader.collect_import_provenance()
        assert parse_provenance_note(prov.note).region_names
        names = {e.base_addr: e.mapped_path
                 for vm in reader.collect_vas_map() for e in vm.entries}
    assert len(names) == 60 and names[0x70100000] == ZYGOTE_SPACE


# -- trust rule / backward compatibility ----------------------------------------


def _type_only(info):
    """Category the pre-names classifier gave (stored type, no name)."""
    return classify(info.region_type, info.protection, info.base_addr,
                    info.size)


@pytest.mark.parametrize("keep_vas", [False, True])
def test_old_regioned_msl_without_marker_classifies_identically(
        android_bin, tmp_path, monkeypatch, keep_vas):
    """No ``region_names=1`` marker -> names ignored, legacy categories."""
    monkeypatch.setattr(importer_mod, "_named_base_note", lambda note: note)
    if not keep_vas:  # pre-W1a importer: VAS_MAP only when excluding
        monkeypatch.setattr(importer_mod, "_add_named_vas_map",
                            importer_mod._add_vas_map_if_excluded)
    out = tmp_path / "old.msl"
    _import(android_bin, out)
    assert bool(_vas(out)) is keep_vas
    infos = preview_import(out).regions
    assert all(r.name is None for r in infos)
    assert [r.category for r in infos] == [_type_only(r) for r in infos]
    assert C.RUNTIME not in {r.category for r in infos}
    with MslReader(out) as reader:
        assert msl_classification_context(reader)[1:] == (None, False)
        assert [r.category for r in stored_region_infos(reader)] == \
            [r.category for r in infos]


def _live_msl(path: Path, imported: bool, with_vas: bool = True) -> Path:
    writer = MslWriter(path, imported=imported)
    writer.add_memory_region(0x7000000000, b"\x11" * 4096,
                             region_type=RegionType.HEAP)
    if with_vas:
        writer.add_vas_map([MslVasEntry(0x7000000000, 4096, 3,
                                        int(RegionType.HEAP),
                                        "[anon:dalvik-zygote space]")])
    writer.add_end_of_capture()
    writer.write()
    return path


def test_live_capture_with_vas_names_is_trusted(tmp_path):
    path = _live_msl(tmp_path / "live.msl", imported=False)
    with MslReader(path) as reader:
        source_format, names, live = msl_classification_context(reader)
    assert source_format is None and live
    assert names.name_for(0x7000000000) == "[anon:dalvik-zygote space]"
    (info,) = preview_import(path).regions
    assert info.category is C.RUNTIME


@pytest.mark.parametrize("imported,with_vas", [(True, True), (False, False)])
def test_untrusted_names_without_provenance(tmp_path, imported, with_vas):
    path = _live_msl(tmp_path / "x.msl", imported=imported, with_vas=with_vas)
    with MslReader(path) as reader:
        assert msl_classification_context(reader)[1:] == (None, False)
    (info,) = preview_import(path).regions
    assert info.category is C.HEAP and info.name is None


def test_materialized_live_capture_keeps_names_trusted(tmp_path):
    path = _live_msl(tmp_path / "live.msl", imported=False)
    copy = tmp_path / "copy.msl"
    import_msl_passthrough(path, copy, selection=parse_selection("runtime"),
                           materialize=True)
    with MslReader(copy) as reader:
        _, names, live = msl_classification_context(reader)
    assert live and names is not None
    (info,) = preview_import(copy).regions
    assert info.category is C.RUNTIME


# -- platform helpers -------------------------------------------------------------


def test_names_platform_and_os_type():
    from memdiver.msl.import_preview import names_platform
    assert names_platform(["/system/bin/linker64"]) == (
        "android", "mapping_names")
    assert names_platform(["/usr/lib/libc.so.6", None]) == ("linux", "format")
    assert importer_mod._os_type_for_platform("android") == OSType.ANDROID
    assert importer_mod._os_type_for_platform("linux") == OSType.LINUX
    assert importer_mod._os_type_for_platform(None) == OSType.LINUX


def test_linux_elf_core_keeps_linux_os_type_and_marks_names(tmp_path):
    from tests.fixtures import synth_elf_core
    core = tmp_path / "t.core"
    core.write_bytes(synth_elf_core.build_core_bytes())
    out = tmp_path / "t.msl"
    import_dump(core, out)
    preview = preview_import(core)
    assert (preview.platform, preview.platform_source) == ("linux", "format")
    with MslReader(out) as reader:
        assert reader.file_header.os_type == OSType.LINUX
        (prov,) = reader.collect_import_provenance()
        assert parse_provenance_note(prov.note).region_names
    assert [r.name for r in preview_import(out).regions] == \
        [r.name for r in preview.regions]


def test_msl_preview_platform_from_header(android_bin, tmp_path):
    out = tmp_path / "app.msl"
    _import(android_bin, out)
    preview = preview_import(out)
    assert (preview.platform, preview.platform_source) == ("android", "header")
    assert preview.runtime_count == preview_import(android_bin).runtime_count
