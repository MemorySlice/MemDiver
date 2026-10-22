"""Key-material plumbing for the import tools: app/tools + MCP wrappers."""

from __future__ import annotations

import inspect
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.app import tools  # noqa: E402
from memdiver.app.session import ToolSession  # noqa: E402
from memdiver.core.service_errors import CapabilityError, ErrorCategory  # noqa: E402
from memdiver.msl.enums import TagStatus  # noqa: E402
from memdiver.msl.importer import DECRYPTED_OUTPUT_WARNING  # noqa: E402
from memdiver.msl.reader import MslReader  # noqa: E402
from memdiver.msl.writer import MslEncryptionConfig  # noqa: E402

from tests.test_msl_materialize import _writer_built_msl  # noqa: E402

RAW_KEY = bytes(range(32))
KEPT = {0x10000000, 0x7FFF0000}
KEY_PARAMS = ("key_file", "passphrase", "kem_key_file")


@pytest.fixture
def src(tmp_path):
    return _writer_built_msl(tmp_path, encryption=MslEncryptionConfig(
        raw_key=RAW_KEY))


@pytest.fixture
def key_file(tmp_path):
    path = tmp_path / "cek.bin"
    path.write_bytes(RAW_KEY)
    return str(path)


def _bases(path, **km):
    with MslReader(Path(path), **km) as reader:
        return {r.base_addr for r in reader.collect_regions()}


def test_import_dump_key_file_reencrypts(tmp_path, src, key_file):
    out = tmp_path / "mat.msl"
    result = tools.import_dump(ToolSession(), str(src), str(out),
                               selection="heap,stack", materialize=True,
                               key_file=key_file)
    assert result["reencrypted"] is True
    with MslReader(out) as locked:
        assert locked.tag_status is TagStatus.MISSING_KEY
    assert _bases(out, key=RAW_KEY) == KEPT


def test_import_raw_dump_alias_decrypt_output(tmp_path, src, key_file):
    out = tmp_path / "plain.msl"
    result = tools.import_raw_dump(ToolSession(), str(src), str(out),
                                   selection="heap,stack", materialize=True,
                                   key_file=key_file, decrypt_output=True)
    assert result["decrypted_output"] is True
    assert DECRYPTED_OUTPUT_WARNING in result["warnings"]
    assert _bases(out) == KEPT


def test_import_dump_missing_key_is_precondition(tmp_path, src):
    with pytest.raises(CapabilityError) as exc:
        tools.import_dump(ToolSession(), str(src), str(tmp_path / "o.msl"),
                          selection="heap,stack", materialize=True)
    assert exc.value.category is ErrorCategory.PRECONDITION
    assert "key material required" in str(exc.value)
    assert not (tmp_path / "o.msl").exists()


def test_preview_import_with_key_file(src, key_file):
    locked = tools.preview_import(ToolSession(), str(src))
    assert locked["encrypted"] and not locked["decrypted"]
    unlocked = tools.preview_import(ToolSession(), str(src), key_file=key_file)
    assert unlocked["decrypted"] and len(unlocked["regions"]) == 3


def test_explicit_key_material_dict_still_supported(tmp_path, src):
    out = tmp_path / "mat.msl"
    result = tools.import_dump(ToolSession(), str(src), str(out),
                               selection="heap,stack", materialize=True,
                               key_material={"key": RAW_KEY})
    assert result["reencrypted"] is True


# -- MCP wrappers (skipped where the mcp SDK is absent; run via the stub) -----


def _mcp_tools():
    pytest.importorskip("mcp.server.mcpserver")  # mcp 2.x (or the test stub)
    from memdiver.mcp_server.server import create_server
    mcp = create_server()
    return {t.name: t.fn for t in mcp._tool_manager.list_tools()}


def test_mcp_import_tools_expose_key_params():
    fns = _mcp_tools()
    imp = inspect.signature(fns["import_raw_dump"]).parameters
    prev = inspect.signature(fns["preview_import"]).parameters
    for name in KEY_PARAMS:
        assert name in imp and name in prev
    assert "decrypt_output" in imp


def test_mcp_import_and_preview_with_key(tmp_path, src, key_file):
    fns = _mcp_tools()
    preview = json.loads(fns["preview_import"](str(src), key_file=key_file))
    assert preview["decrypted"] and len(preview["regions"]) == 3
    out = tmp_path / "mcp.msl"
    result = json.loads(fns["import_raw_dump"](
        str(src), str(out), region_types="heap,stack", materialize=True,
        key_file=key_file))
    assert result["reencrypted"] is True
    assert _bases(out, key=RAW_KEY) == KEPT


def test_mcp_import_missing_key_returns_error_json(tmp_path, src):
    fns = _mcp_tools()
    result = json.loads(fns["import_raw_dump"](
        str(src), str(tmp_path / "o.msl"), region_types="heap,stack",
        materialize=True))
    assert "key material required" in result["error"]


def test_mcp_import_docstrings_document_runtime_and_platform():
    fns = _mcp_tools()
    import_doc = inspect.getdoc(fns["import_raw_dump"])
    assert "runtime" in import_doc and "NOT in the interactive default" in import_doc
    preview_doc = inspect.getdoc(fns["preview_import"])
    for field in ("platform", "platform_source", "runtime_count",
                  "runtime_bytes", "``name``"):
        assert field in preview_doc, field


def test_preview_import_reports_platform_and_runtime_fields(src, key_file):
    result = tools.preview_import(ToolSession(), str(src), key_file=key_file)
    for field in ("platform", "platform_source", "runtime_count",
                  "runtime_bytes"):
        assert field in result, field
    assert all("name" in region for region in result["regions"])
