"""Import provenance exposure: note parser, producer, CLI, REST, MCP.

The IMPORT_PROVENANCE note records the region selection an import applied
(``regions=…;excluded_regions=N;excluded_bytes=B``) and, for a materialized
``.msl`` copy, ``materialized=1;orig_eoc_hash=…``. These tests pin the single
parser (``msl.region_select.parse_provenance_note``) and every surface that
exposes it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.app import tools_inspect  # noqa: E402
from memdiver.app.session import ToolSession  # noqa: E402
from memdiver.core.service_errors import FileNotFoundServiceError  # noqa: E402
from memdiver.core.service_result import Resolution  # noqa: E402
from memdiver.msl.enums import SourceFormat  # noqa: E402
from memdiver.msl.importer import import_dump  # noqa: E402
from memdiver.msl.reader import MslReader  # noqa: E402
from memdiver.msl.region_select import (  # noqa: E402
    RegionCategory, parse_provenance_note, parse_selection,
    selection_provenance_note, join_provenance_note,
)
from memdiver.msl.writer import MslEncryptionConfig  # noqa: E402

from tests.fixtures.generate_msl_fixtures import generate_msl_file  # noqa: E402
from tests.test_msl_materialize import _writer_built_msl  # noqa: E402

HEAP_STACK = parse_selection("heap,stack")
RAW_KEY = bytes(range(32))


# -- fixtures -----------------------------------------------------------------


@pytest.fixture
def materialized(tmp_path):
    """(source, copy, ImportResult): heap+stack materialized from a capture
    holding image + heap + stack, so exactly the image region is excluded."""
    src = _writer_built_msl(tmp_path)
    out = tmp_path / "copy.msl"
    result = import_dump(src, out, selection=HEAP_STACK, materialize=True)
    assert result.materialized
    return src, out, result


@pytest.fixture
def live_msl(tmp_path):
    """A live capture: no IMPORT_PROVENANCE block at all."""
    path = tmp_path / "live.msl"
    path.write_bytes(generate_msl_file())
    return path


def _session() -> ToolSession:
    return ToolSession()


def _eoc_hash(path: Path) -> str:
    with MslReader(path) as reader:
        return reader.collect_end_of_capture()[0].file_hash.hex()


# -- parse_provenance_note ----------------------------------------------------


def test_parse_plain_import_note():
    note = join_provenance_note(
        "Imported from ELF core t.core",
        selection_provenance_note(HEAP_STACK, 3, 12288))
    fields = parse_provenance_note(note)
    assert fields.base_note == "Imported from ELF core t.core"
    assert fields.selection == HEAP_STACK
    assert (fields.excluded_regions, fields.excluded_bytes) == (3, 12288)
    assert not fields.materialized and fields.orig_eoc_hash is None
    d = fields.to_dict()
    assert d["selected_categories"] == ["heap", "stack"]
    assert d["selection_all"] is False


def test_parse_materialized_note_takes_last_segment():
    note = ("orig; source_format=msl;materialized=1;dropped_key_hints=4;"
            "orig_eoc_hash=aa; source_format=msl;materialized=1;"
            "dropped_key_hints=1;orig_eoc_hash=bb; "
            + selection_provenance_note(parse_selection("heap"), 2, 8192))
    fields = parse_provenance_note(note)
    assert fields.materialized
    assert fields.orig_eoc_hash == "bb"
    assert fields.dropped_key_hints == 1
    assert fields.selection.categories == {RegionCategory.HEAP}
    assert fields.excluded_regions == 2


def test_parse_fallback_and_flags():
    sel = parse_selection("heap")
    sel = type(sel)(sel.categories, writable_only=True, module_globs=("libssl*",))
    note = selection_provenance_note(sel, 0, 0, fallback=True)
    d = parse_provenance_note(note).to_dict()
    assert d["fallback_all"] is True
    assert d["writable_only"] is True
    assert d["module_globs"] == ["libssl*"]
    assert d["base_note"] == ""


def test_parse_all_selection():
    note = selection_provenance_note(parse_selection("all"), 0, 0)
    d = parse_provenance_note(note).to_dict()
    assert d["selection_all"] is True
    assert len(d["selected_categories"]) == len(RegionCategory)


@pytest.mark.parametrize("note", ["", None, "Imported from raw dump x.dump",
                                  "regions=bogus;excluded_regions=x",
                                  "free text; regions="])
def test_parse_foreign_or_malformed_never_raises(note):
    fields = parse_provenance_note(note)
    assert fields.selection is None
    assert not fields.materialized
    assert fields.excluded_regions is None


# -- import_provenance_result -------------------------------------------------


def test_result_for_materialized_copy(materialized):
    src, out, result = materialized
    res = tools_inspect.import_provenance_result(_session(), str(out))
    assert res.status.resolution is Resolution.OK
    (rec,) = res.payload["provenance"]
    assert rec["materialized"] is True
    assert rec["orig_eoc_hash"] == _eoc_hash(src)
    assert rec["selected_categories"] == ["heap", "stack"]
    assert rec["excluded_regions"] == result.excluded_region_count == 1
    assert rec["excluded_bytes"] == result.excluded_bytes
    assert rec["source_format"] == SourceFormat.OTHER  # 0xFFFF + origin note
    assert rec["source_format_name"] == "MSL"  # effective classification
    assert rec["tool_name"] == "memdiver"
    assert "materialized=1" in rec["note"]
    assert len(rec["source_hash"]) == 64


def test_result_for_live_capture_is_empty(live_msl):
    res = tools_inspect.import_provenance_result(_session(), str(live_msl))
    assert res.payload == {"provenance": []}


def test_result_for_non_msl_is_empty_not_error(tmp_path):
    raw = tmp_path / "x.dump"
    raw.write_bytes(b"\0" * 64)
    res = tools_inspect.import_provenance_result(_session(), str(raw))
    assert res.payload == {"provenance": []}
    assert res.status.resolution is Resolution.OK


def test_result_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundServiceError):
        tools_inspect.import_provenance_result(_session(), str(tmp_path / "no.msl"))


def test_session_info_carries_provenance(materialized):
    _, out, _ = materialized
    res = tools_inspect.session_info_result(_session(), str(out))
    (rec,) = res.payload["import_provenance"]
    assert rec["materialized"] is True


def test_encrypted_copy_needs_key(tmp_path):
    src = _writer_built_msl(tmp_path, encryption=MslEncryptionConfig(raw_key=RAW_KEY))
    out = tmp_path / "enc_copy.msl"
    import_dump(src, out, selection=HEAP_STACK, materialize=True,
                key_material={"key": RAW_KEY})
    locked = tools_inspect.import_provenance_result(_session(), str(out))
    assert not locked.status.key.decrypted
    key_file = tmp_path / "k.bin"
    key_file.write_bytes(RAW_KEY)
    keyed = tools_inspect.import_provenance_result(
        _session(), str(out), key_file=str(key_file))
    assert keyed.status.key.decrypted
    (rec,) = keyed.payload["provenance"]
    assert rec["materialized"] and rec["excluded_regions"] == 1


# -- CLI ----------------------------------------------------------------------


def test_cli_provenance_json(tmp_path, materialized):
    from memdiver.cli import _build_parser, _cmd_inspect

    _, out, _ = materialized
    dest = tmp_path / "prov.json"
    args = _build_parser().parse_args(
        ["inspect", "provenance", str(out), "-o", str(dest)])
    assert _cmd_inspect(args) == 0
    (rec,) = json.loads(dest.read_text())["provenance"]
    assert rec["materialized"] is True and rec["excluded_regions"] == 1


def test_cli_provenance_text(capsys, materialized):
    from memdiver.cli import _cmd_inspect_provenance

    src, out, _ = materialized
    args = argparse.Namespace(msl_path=str(out), output=None, text=True)
    assert _cmd_inspect_provenance(args) == 0
    text = capsys.readouterr().out
    assert "regions kept:   heap, stack" in text
    assert "excluded:       1 region," in text
    assert "materialized:   yes" in text
    assert _eoc_hash(src) in text


def test_cli_provenance_text_empty(capsys, live_msl):
    from memdiver.cli import _cmd_inspect_provenance

    args = argparse.Namespace(msl_path=str(live_msl), output=None, text=True)
    assert _cmd_inspect_provenance(args) == 0
    assert "No import provenance" in capsys.readouterr().out


def test_cli_provenance_missing_file(tmp_path, capsys):
    from memdiver.cli import _cmd_inspect_provenance

    args = argparse.Namespace(msl_path=str(tmp_path / "no.msl"), output=None,
                              text=True)
    assert _cmd_inspect_provenance(args) == 1
    assert "error" in json.loads(capsys.readouterr().out)


# -- REST ---------------------------------------------------------------------


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from memdiver.api.main import create_app
    return TestClient(create_app())


def test_rest_materialized(client, materialized):
    _, out, _ = materialized
    resp = client.get("/api/inspect/import-provenance",
                      params={"msl_path": str(out)})
    assert resp.status_code == 200
    (rec,) = resp.json()["provenance"]
    assert rec["materialized"] is True
    assert rec["selected_categories"] == ["heap", "stack"]
    assert rec["excluded_regions"] == 1


def test_rest_non_msl_and_live_are_empty(client, tmp_path, live_msl):
    raw = tmp_path / "x.dump"
    raw.write_bytes(b"\0" * 64)
    for path in (raw, live_msl):
        resp = client.get("/api/inspect/import-provenance",
                          params={"msl_path": str(path)})
        assert resp.status_code == 200
        assert resp.json() == {"provenance": []}


def test_rest_missing_file_404(client, tmp_path):
    resp = client.get("/api/inspect/import-provenance",
                      params={"msl_path": str(tmp_path / "no.msl")})
    assert resp.status_code == 404


def test_rest_encrypted_with_key_hex(client, tmp_path):
    src = _writer_built_msl(tmp_path, encryption=MslEncryptionConfig(raw_key=RAW_KEY))
    out = tmp_path / "enc_copy.msl"
    import_dump(src, out, selection=HEAP_STACK, materialize=True,
                key_material={"key": RAW_KEY})
    locked = client.get("/api/inspect/import-provenance",
                        params={"msl_path": str(out)})
    assert locked.status_code == 200
    keyed = client.get("/api/inspect/import-provenance",
                       params={"msl_path": str(out), "key_hex": RAW_KEY.hex()})
    assert keyed.status_code == 200
    (rec,) = keyed.json()["provenance"]
    assert rec["materialized"] is True


# -- MCP (needs the mcp SDK; skipped without it) --------------------------------


def test_mcp_tool(materialized):
    pytest.importorskip("mcp.server.mcpserver")
    from memdiver.mcp_server.server import create_server

    _, out, _ = materialized
    server = create_server()
    (tool,) = [t for t in server._tool_manager.list_tools()
               if t.name == "get_import_provenance"]
    body = json.loads(tool.fn(msl_path=str(out)))
    (rec,) = body["provenance"]
    assert rec["materialized"] is True


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))


def test_rest_reports_region_names_marker(client, tmp_path):
    """ELF-core imports persist mapping names; REST exposes ``region_names``."""
    from tests.fixtures.synth_elf_core import build_core_bytes

    core = tmp_path / "x.core"
    core.write_bytes(build_core_bytes())
    out = tmp_path / "x.msl"
    import_dump(core, out)
    resp = client.get("/api/inspect/import-provenance",
                      params={"msl_path": str(out)})
    assert resp.status_code == 200
    (rec,) = resp.json()["provenance"]
    assert rec["region_names"] is True


def test_rest_region_names_false_without_marker(client, materialized):
    src, _, _ = materialized
    resp = client.get("/api/inspect/import-provenance",
                      params={"msl_path": str(src)})
    assert resp.status_code == 200
    for rec in resp.json()["provenance"]:
        assert rec["region_names"] is (
            "region_names=1" in rec["note"])
