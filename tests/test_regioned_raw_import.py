"""Regioned raw import: flat .bin + /proc/<pid>/maps sidecar -> real regions."""

import json
from pathlib import Path

import pytest

from memdiver.core.models import CryptoSecret
from memdiver.core.proc_maps_parser import parse_maps_text
from memdiver.core.regioned_layout import (compute_regioned_layout,
                                           find_maps_sidecar)
from memdiver.msl.enums import PageState, Protection, RegionType, SourceFormat
from memdiver.msl.source_format import effective_source_format
from memdiver.msl.import_preview import (LAYOUT_MAPS, LAYOUT_NATIVE,
                                         LAYOUT_NONE, preview_import)
from memdiver.msl.import_regioned import (plan_regions, protection_from_perm,
                                          region_type_for_map)
from memdiver.msl.importer import (import_dump, import_regioned_raw,
                                   import_run_directory,
                                   run_directory_dump_files)
from memdiver.msl.page_map import get_region_page_data
from memdiver.msl.reader import MslReader
from memdiver.msl.region_select import (RegionCategory, RegionSelection,
                                        alignment_region_type,
                                        classify_stored, parse_selection)

PAGE = 4096
HEAP_VA, STACK_VA, LIB_VA, ANON_VA = 0x10000, 0x7ff000, 0x400000, 0x900000
SECRET = bytes(range(0x40, 0x60))

MAPS = (
    f"{LIB_VA:x}-{LIB_VA + PAGE:x} r-xp 00000000 08:01 1234 /usr/lib/libssl.so.3\n"
    f"{HEAP_VA + 0x400000:x}-{HEAP_VA + 0x400000 + 2 * PAGE:x} rw-p 00000000 00:00 0 [heap]\n"
    f"{STACK_VA + 0x800000:x}-{STACK_VA + 0x800000 + PAGE:x} rw-p 00000000 00:00 0 [stack]\n"
    f"{ANON_VA + 0x900000:x}-{ANON_VA + 0x900000 + PAGE:x} rw-s 00000000 00:00 0\n"
)


def _layout():
    return parse_maps_text(MAPS)


def _bodies():
    """Distinct bytes per region; the heap region holds SECRET at +0x123."""
    bodies = []
    for idx, region in enumerate(_layout()):
        body = bytearray([0x11 * (idx + 1)]) * region.size
        if region.path == "[heap]":
            body[PAGE + 0x123:PAGE + 0x123 + len(SECRET)] = SECRET
        bodies.append(bytes(body))
    return bodies


def _write_dump(tmp_path: Path, name="target.gdb_raw.bin", truncate=0,
                maps=MAPS, sidecar=True) -> Path:
    data = b"".join(_bodies())
    bin_path = tmp_path / name
    bin_path.write_bytes(data[:len(data) - truncate] if truncate else data)
    if sidecar:
        bin_path.with_suffix(".maps").write_text(maps)
    return bin_path


def _regions(path: Path):
    with MslReader(path) as reader:
        return {r.base_addr: (r, get_region_page_data(reader, r))
                for r in reader.collect_regions()}


def _provenance(path: Path):
    with MslReader(path) as reader:
        (prov,) = reader.collect_import_provenance()
        return prov


# -- shared layout helper ---------------------------------------------------------


def test_layout_clamps_last_region_and_reports_padding():
    layout = compute_regioned_layout([10, 20, 30], 25)
    assert layout.offsets == (0, 10, 25)
    assert layout.usable_count == 2 and not layout.is_exact
    exact = compute_regioned_layout([10, 20], 25)
    assert exact.is_exact and exact.last_clamped and exact.served(1) == 15
    padded = compute_regioned_layout([10], 25)
    assert padded.padding == 15 and not padded.is_exact


def test_sidecar_resolution_matches_regioned_source(tmp_path):
    bin_path = tmp_path / "a.lldb_raw.bin"
    bin_path.write_bytes(b"x")
    assert find_maps_sidecar(bin_path) is None
    legacy = tmp_path / "a.maps"
    legacy.write_text(MAPS)
    assert find_maps_sidecar(bin_path) == legacy
    primary = tmp_path / "a.lldb_raw.maps"
    primary.write_text(MAPS)
    assert find_maps_sidecar(bin_path) == primary
    assert find_maps_sidecar(primary) is None


def test_perm_and_shared_mapping():
    assert protection_from_perm("r-xp") == Protection.READ | Protection.EXECUTE
    assert protection_from_perm("rw-p") == Protection.READ | Protection.WRITE
    shared, = parse_maps_text("1000-2000 rw-s 0 00:00 0\n")
    assert region_type_for_map(shared) == RegionType.SHARED_MEM
    heap, = parse_maps_text("1000-2000 rw-s 0 00:00 0 [heap]\n")
    assert region_type_for_map(heap) == RegionType.HEAP


def test_plan_rejects_unaligned_and_overlapping():
    bad, = parse_maps_text("1001-2000 rw-p 0 00:00 0\n"),
    assert plan_regions(bad, 0xfff, Path("x.maps"))[0] is None
    overlap = parse_maps_text("1000-3000 rw-p 0 00:00 0\n"
                              "2000-4000 rw-p 0 00:00 0\n")
    plan, reason = plan_regions(overlap, 0x4000, Path("x.maps"))
    assert plan is None and "overlap" in reason


# -- import --------------------------------------------------------------------


def test_regions_at_real_vas_with_bytes_and_types(tmp_path):
    bin_path = _write_dump(tmp_path)
    out = tmp_path / "out.msl"
    result = import_regioned_raw(bin_path, bin_path.with_suffix(".maps"), out)
    assert result.regions_written == 4 and not result.warnings
    regions = _regions(out)
    for layout, body in zip(_layout(), _bodies()):
        region, data = regions[layout.start]
        assert data == body
        assert region.region_size == layout.size
    types = {base: r.region_type for base, (r, _) in regions.items()}
    expected = {e.start: t for e, t in zip(_layout(), (
        RegionType.IMAGE, RegionType.HEAP, RegionType.STACK,
        RegionType.SHARED_MEM))}
    assert types == expected
    lib, _ = regions[_layout()[0].start]
    assert lib.protection == Protection.READ | Protection.EXECUTE
    prov = _provenance(out)
    assert prov.source_format == SourceFormat.OTHER  # 0xFFFF + note origin
    assert effective_source_format(
        prov.source_format, prov.tool_name,
        prov.note) == SourceFormat.REGIONED_RAW
    with MslReader(out) as reader:
        modules = [e for idx in reader.collect_module_list_index()
                   for e in idx.entries]
    assert [m.path for m in modules] == ["/usr/lib/libssl.so.3"]


def test_categories_are_real_not_unclassified(tmp_path):
    bin_path = _write_dump(tmp_path)
    preview = preview_import(bin_path)
    cats = [r.category for r in preview.regions]
    assert cats == [RegionCategory.IMAGE_CODE, RegionCategory.HEAP,
                    RegionCategory.STACK, RegionCategory.SHARED]
    # Stored-region rule: REGIONED_RAW is not the raw "unclassified" rule,
    # and its [stack] is an observation (keys as STACK, no ANONYMOUS fold).
    assert classify_stored(int(RegionType.HEAP), 3, 0, PAGE,
                           source_format=SourceFormat.REGIONED_RAW) \
        is RegionCategory.HEAP
    assert alignment_region_type(int(RegionType.STACK),
                                 SourceFormat.REGIONED_RAW) == RegionType.STACK


def test_selection_heap_stack_writes_only_those_plus_vas_map(tmp_path):
    bin_path = _write_dump(tmp_path)
    out = tmp_path / "out.msl"
    sel = parse_selection("heap,stack")
    result = import_dump(bin_path, out, selection=sel)
    heap_va, stack_va = _layout()[1].start, _layout()[2].start
    assert sorted(_regions(out)) == [heap_va, stack_va]
    assert result.excluded_region_count == 2
    with MslReader(out) as reader:
        vas = [e for vm in reader.collect_vas_map() for e in vm.entries]
    assert sorted(e.base_addr for e in vas) == sorted(r.start for r in _layout())
    assert "regions=heap,stack" in _provenance(out).note


def test_keylog_hint_va_correct(tmp_path):
    bin_path = _write_dump(tmp_path)
    out = tmp_path / "out.msl"
    secret = CryptoSecret("CLIENT_RANDOM", b"\x00" * 32, SECRET)
    result = import_dump(bin_path, out, secrets=[secret])
    assert result.key_hints_written == 1
    with MslReader(out) as reader:
        (hint,) = reader.collect_key_hints()
        by_uuid = {r.block_header.block_uuid: r
                   for r in reader.collect_regions()}
    region = by_uuid[hint.region_uuid]
    assert region.base_addr + hint.region_offset == \
        _layout()[1].start + PAGE + 0x123


def test_truncated_last_region_has_failed_tail(tmp_path):
    bin_path = _write_dump(tmp_path, truncate=PAGE - 100)
    out = tmp_path / "out.msl"
    result = import_dump(bin_path, out)
    assert not result.warnings
    region, data = _regions(out)[_layout()[-1].start]
    assert region.region_size == PAGE
    assert data[:100] == _bodies()[-1][:100]
    assert region.page_states == [PageState.CAPTURED]


def test_truncated_last_region_failed_pages(tmp_path):
    maps = "10000-13000 rw-p 0 00:00 0 [heap]\n"
    bin_path = tmp_path / "h.bin"
    bin_path.write_bytes(b"\xaa" * (PAGE + 10))
    bin_path.with_suffix(".maps").write_text(maps)
    out = tmp_path / "h.msl"
    import_dump(bin_path, out)
    region, data = _regions(out)[0x10000]
    assert region.region_size == 3 * PAGE
    assert region.page_states == [PageState.CAPTURED] * 2 + \
        [PageState.FAILED]
    assert data[:PAGE + 10] == b"\xaa" * (PAGE + 10)
    assert data[PAGE + 10:] == b"\x00" * (PAGE - 10)


def test_mismatch_falls_back_to_raw_with_warning(tmp_path):
    bin_path = _write_dump(tmp_path)
    with open(bin_path, "ab") as fh:
        fh.write(b"\x00" * 10)  # trailing bytes the maps does not describe
    out = tmp_path / "out.msl"
    result = import_dump(bin_path, out, selection=parse_selection("heap"))
    assert result.regions_written == 1
    assert any("ignored" in w for w in result.warnings)
    assert _provenance(out).source_format == SourceFormat.RAW_DUMP
    preview = preview_import(bin_path)
    assert preview.layout == LAYOUT_NONE
    assert any("ignored" in n for n in preview.notes)


def test_explicit_maps_wins_and_missing_explicit_raises(tmp_path):
    bin_path = _write_dump(tmp_path, name="plain.dump", sidecar=False)
    maps = tmp_path / "elsewhere.txt"
    maps.write_text(MAPS)
    out = tmp_path / "out.msl"
    assert import_dump(bin_path, out).regions_written == 1  # no sidecar
    assert import_dump(bin_path, out, maps_path=maps).regions_written == 4
    with pytest.raises(ValueError, match="maps file not found"):
        import_dump(bin_path, out, maps_path=tmp_path / "nope.maps")


def test_preview_parity_with_import(tmp_path):
    bin_path = _write_dump(tmp_path)
    preview = preview_import(bin_path)
    assert preview.layout == LAYOUT_MAPS
    payload = preview.to_dict()
    assert payload["layout"] == "maps" and payload["maps_path"]
    out = tmp_path / "out.msl"
    import_dump(bin_path, out)
    stored = {b: (r.region_size, r.protection, r.region_type)
              for b, (r, _) in _regions(out).items()}
    assert stored == {r.base_addr: (r.size, r.protection, r.region_type)
                      for r in preview.regions}


def test_plain_raw_preview_says_layout_none(tmp_path):
    raw = tmp_path / "x.dump"
    raw.write_bytes(b"\x01" * 100)
    payload = preview_import(raw).to_dict()
    assert payload["layout"] == "none"
    assert any(n.startswith("layout=none") for n in payload["notes"])


def test_native_formats_report_native_layout(tmp_path):
    from memdiver.msl.writer import MslWriter

    msl = tmp_path / "n.msl"
    writer = MslWriter(msl)
    writer.add_memory_region(0x1000, b"\x00" * PAGE)
    writer.write()
    preview = preview_import(msl, maps_path=tmp_path / "x.maps")
    assert preview.layout == LAYOUT_NATIVE
    assert any("ignored" in n for n in preview.notes)


def test_import_dir_picks_up_gdb_raw_bin(tmp_path):
    _write_dump(tmp_path, name="run.gdb_raw.bin")
    stray = tmp_path / "stray.bin"
    stray.write_bytes(b"\x00" * 16)  # no sidecar: not a dump
    assert [p.name for p in run_directory_dump_files(tmp_path)] == \
        ["run.gdb_raw.bin"]
    results = import_run_directory(tmp_path, tmp_path / "out")
    assert [r.regions_written for r in results] == [4]


def test_import_dir_meta_json_maps(tmp_path):
    _write_dump(tmp_path, name="capture.bin", sidecar=False)
    (tmp_path / "layout").mkdir()
    (tmp_path / "layout" / "capture.maps").write_text(MAPS)
    (tmp_path / "meta.json").write_text(json.dumps(
        {"maps": "layout/capture.maps"}))
    results = import_run_directory(tmp_path, tmp_path / "out")
    assert [r.regions_written for r in results] == [4]


def test_import_dir_meta_json_rejects_escaping_maps(tmp_path):
    _write_dump(tmp_path, name="capture.bin", sidecar=False)
    (tmp_path / "meta.json").write_text(json.dumps({"maps": "../x.maps"}))
    assert run_directory_dump_files(tmp_path) == []


def test_selection_all_is_byte_identical_to_no_selection(tmp_path):
    bin_path = _write_dump(tmp_path)
    a, b = tmp_path / "a.msl", tmp_path / "b.msl"
    import_dump(bin_path, a)
    import_dump(bin_path, b, selection=RegionSelection.all())
    assert sorted(_regions(a)) == sorted(_regions(b))


# -- interfaces ------------------------------------------------------------------


def main(argv):
    from memdiver.cli import _cmd_import, build_parser

    return _cmd_import(build_parser().parse_args(argv))


def test_cli_import_with_maps_flag(tmp_path, capsys):
    bin_path = _write_dump(tmp_path, name="plain.dump", sidecar=False)
    maps = tmp_path / "layout.txt"
    maps.write_text(MAPS)
    out = tmp_path / "cli.msl"
    rc = main(["import", str(bin_path), "-o", str(out), "--maps", str(maps),
               "--yes"])
    assert rc in (0, None)
    payload = json.loads(capsys.readouterr().out)
    assert payload["regions"] == 4


def test_cli_list_regions_shows_layout(tmp_path, capsys):
    bin_path = _write_dump(tmp_path)
    rc = main(["import", str(bin_path), "--list-regions", "--json"])
    assert rc in (0, None)
    payload = json.loads(capsys.readouterr().out)
    assert payload["layout"] == "maps"
    assert {r["category"] for r in payload["regions"]} >= {"heap", "stack"}


def test_cli_prompt_skipped_for_layoutless_raw(tmp_path, capsys):
    import argparse

    from memdiver.cli.import_selection import (NO_LAYOUT_PROMPT_NOTE,
                                               choice_from_args, safe_preview)

    raw = tmp_path / "x.dump"
    raw.write_bytes(b"\x01" * 100)
    args = argparse.Namespace(regions=None, exclude_regions=None,
                              materialize=False, yes=False)
    asked = []
    choice = choice_from_args(args, lambda: safe_preview(raw),
                              input_fn=lambda *_: asked.append(1) or "",
                              interactive=True)
    assert choice.selection is None and not asked
    assert NO_LAYOUT_PROMPT_NOTE in capsys.readouterr().err


def test_tools_import_and_preview_maps_path(tmp_path):
    from memdiver.app import tools

    bin_path = _write_dump(tmp_path, name="plain.dump", sidecar=False)
    maps = tmp_path / "layout.txt"
    maps.write_text(MAPS)
    preview = tools.preview_import(None, str(bin_path), maps_path=str(maps))
    assert preview["layout"] == "maps"
    result = tools.import_dump(None, str(bin_path), str(tmp_path / "t.msl"),
                               maps_path=str(maps))
    assert result["regions_written"] == 4


@pytest.fixture
def api_client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from memdiver.api.config import get_settings
    from memdiver.api.main import create_app

    for sub, env in [("oracles", "MEMDIVER_ORACLE_DIR"),
                     ("tasks", "MEMDIVER_TASK_ROOT"),
                     ("uploads", "MEMDIVER_UPLOAD_DIR"),
                     ("sessions", "MEMDIVER_SESSION_DIR")]:
        (tmp_path / sub).mkdir()
        monkeypatch.setenv(env, str(tmp_path / sub))
    get_settings.cache_clear()
    with TestClient(create_app()) as client:
        yield client
    get_settings.cache_clear()


def test_api_preview_and_import_path_maps_path(tmp_path, api_client):
    bin_path = _write_dump(tmp_path, name="plain.dump", sidecar=False)
    maps = tmp_path / "layout.txt"
    maps.write_text(MAPS)
    resp = api_client.post("/api/dumps/preview",
                           json={"path": str(bin_path)})
    assert resp.status_code == 200 and resp.json()["layout"] == "none"
    resp = api_client.post("/api/dumps/preview",
                           json={"path": str(bin_path),
                                 "maps_path": str(maps)})
    assert resp.status_code == 200 and resp.json()["layout"] == "maps"
    resp = api_client.post("/api/dumps/import-path",
                           json={"path": str(bin_path),
                                 "maps_path": str(maps)})
    assert resp.status_code == 200, resp.text
    assert resp.json()["regions_written"] == 4
    resp = api_client.post("/api/dumps/preview",
                           json={"path": str(bin_path),
                                 "maps_path": str(tmp_path / "nope")})
    assert resp.status_code == 404


def test_api_upload_with_maps_file(tmp_path, api_client):
    data = b"".join(_bodies())
    resp = api_client.post(
        "/api/dumps/upload",
        files={"file": ("dump.bin", data, "application/octet-stream"),
               "maps": ("dump.maps", MAPS.encode(), "text/plain")})
    assert resp.status_code == 200, resp.text
    assert resp.json()["regions_written"] == 4
    resp = api_client.post(
        "/api/dumps/upload",
        files={"file": ("dump.bin", data, "application/octet-stream")})
    assert resp.status_code == 200 and resp.json()["regions_written"] == 1
