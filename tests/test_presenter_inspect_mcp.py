"""Unit tests for the MCP inspect presenter.

These target ``mcp_server.presenters`` DIRECTLY — never through MCPServer (the
``mcp`` SDK is not installed in CI, so ``mcp_server/server.py`` is not
importable here). The presenter is the piece the server wrappers now route
through, so pinning its output here locks the observable MCP JSON contract:

* locked/undecrypted dump -> ``{"error": <hint>, "tag_status": <value>}``
* success (valid / not_encrypted / empty payload) -> the payload dict verbatim
* hard error (raised ``CapabilityError`` subclass) -> ``{"error": <msg>}``,
  merging ``.details`` (the byte-for-byte legacy out-of-range shape).

Also covers ``mcp_error_funnel`` — the standalone backstop decorator that
translates a propagating ``CapabilityError`` into ``json.dumps(err.to_dict())``
while leaving the success path untouched — and ``present_mcp_tool``, the
registration-layer wrapper ``server.py`` now applies to EVERY tool (encode +
present once; legacy ``to_error_body()`` only for the inspect family).
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.core.service_errors import (  # noqa: E402
    CapabilityError,
    ErrorCategory,
    FileNotFoundServiceError,
    OffsetOutOfRangeError,
)
from memdiver.core.service_result import (  # noqa: E402
    KeyStatus,
    Resolution,
    ServiceResult,
    StatusBlock,
)
from memdiver.mcp_server.presenters import (  # noqa: E402
    _KEY_PARAMS_HINT,
    LEGACY_ERROR_BODY_TOOLS,
    mcp_error_funnel,
    mcp_error_payload,
    present_mcp_tool,
    present_inspect_mcp,
    present_inspect_mcp_call,
)
from memdiver.msl.enums import TagStatus  # noqa: E402


def _result(payload, key: KeyStatus, resolution: Resolution) -> ServiceResult:
    return ServiceResult(payload=payload, status=StatusBlock(resolution=resolution, key=key))


# ---------------------------------------------------------------------------
# present_inspect_mcp — locked cases inline the tag diagnostic.
# ---------------------------------------------------------------------------


def test_missing_key_inlines_error_and_tag_status():
    # The core hint is neutral; the MCP presenter appends its PARAMETER remedy.
    core_hint = "dump is encrypted; no valid decryption key was supplied"
    key = KeyStatus(TagStatus.MISSING_KEY, decrypted=False, hint=core_hint)
    result = _result({"hex_lines": []}, key, Resolution.UNRESOLVED)

    out = present_inspect_mcp(result)
    assert out == {
        "error": f"{core_hint}; {_KEY_PARAMS_HINT}",
        "tag_status": "missing_key",
    }
    # MCP guidance names the tool parameters, never the CLI dash-flags.
    assert "key_file" in out["error"]
    assert "--key-file" not in out["error"]


def test_corrupted_inlines_error_and_tag_status():
    core_hint = "AEAD verification failed (wrong key or tampered file)"
    key = KeyStatus(TagStatus.CORRUPTED, decrypted=False, hint=core_hint)
    result = _result({"modules": []}, key, Resolution.UNRESOLVED)

    out = present_inspect_mcp(result)
    assert out == {
        "error": f"{core_hint}; {_KEY_PARAMS_HINT}",
        "tag_status": "corrupted",
    }
    assert "--" not in out["error"]


# ---------------------------------------------------------------------------
# present_inspect_mcp — decrypted cases return the payload unchanged.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tag_status", [TagStatus.VALID, TagStatus.NOT_ENCRYPTED])
def test_decrypted_returns_payload_verbatim(tag_status):
    payload = {"processes": [{"pid": 1, "ppid": 0}], "count": 1}
    key = KeyStatus(tag_status, decrypted=True)
    result = _result(payload, key, Resolution.OK)

    out = present_inspect_mcp(result)
    assert out is payload
    assert "error" not in out
    assert "tag_status" not in out


def test_empty_payload_passes_through_when_decrypted():
    payload = {"handles": []}
    key = KeyStatus(TagStatus.NOT_ENCRYPTED, decrypted=True)
    result = _result(payload, key, Resolution.OK)

    out = present_inspect_mcp(result)
    assert out == {"handles": []}
    assert "error" not in out and "tag_status" not in out


# ---------------------------------------------------------------------------
# present_inspect_mcp_call — hard errors render the legacy {"error": ...} dict.
# ---------------------------------------------------------------------------


def test_file_not_found_reproduces_legacy_error_dict():
    def produce():
        raise FileNotFoundServiceError("File not found: /nope.msl")

    assert present_inspect_mcp_call(produce) == {"error": "File not found: /nope.msl"}


def test_offset_out_of_range_merges_details():
    def produce():
        raise OffsetOutOfRangeError(
            "offset out of range",
            details={
                "offset": 999,
                "file_size": 128,
                "view": "raw",
                "format": "msl",
            },
        )

    assert present_inspect_mcp_call(produce) == {
        "error": "offset out of range",
        "offset": 999,
        "file_size": 128,
        "view": "raw",
        "format": "msl",
    }


def test_successful_produce_returns_payload():
    payload = {"va": 4096, "file_offset": 512, "vas_offset": 0}
    key = KeyStatus(TagStatus.NOT_ENCRYPTED, decrypted=True)
    result = _result(payload, key, Resolution.OK)

    assert present_inspect_mcp_call(lambda: result) == payload


# ---------------------------------------------------------------------------
# mcp_error_funnel — Phase 3 backstop for the non-inspect MCP tools.
# ---------------------------------------------------------------------------


def test_error_funnel_translates_capability_error_to_json():
    err = CapabilityError("dataset root not found", category=ErrorCategory.NOT_FOUND, code="ds.missing")

    @mcp_error_funnel
    def tool_body():
        raise err

    out = tool_body()

    assert out == json.dumps(err.to_dict())
    assert json.loads(out) == {
        "error": "dataset root not found",
        "code": "ds.missing",
        "category": "NOT_FOUND",
    }


def test_error_funnel_passes_success_through_untouched():
    @mcp_error_funnel
    def tool_body():
        return json.dumps({"ok": True})

    assert tool_body() == json.dumps({"ok": True})


def test_error_funnel_preserves_wrapped_metadata_for_mcpserver():
    def tool_body(dump_path: str, offset: int = 0) -> str:
        """Docstring MCPServer reads for the tool description."""
        return json.dumps({"dump_path": dump_path, "offset": offset})

    wrapped = mcp_error_funnel(tool_body)

    assert wrapped.__name__ == "tool_body"
    assert wrapped.__doc__ == "Docstring MCPServer reads for the tool description."
    assert wrapped.__wrapped__ is tool_body
    assert wrapped("a.msl", offset=8) == json.dumps({"dump_path": "a.msl", "offset": 8})


# ---------------------------------------------------------------------------
# present_mcp_tool — the registration-layer wrapper (encode + present once).
# ---------------------------------------------------------------------------


def _detailed_error():
    return OffsetOutOfRangeError(
        "offset out of range", details={"offset": 9, "file_size": 4})


def test_present_tool_encodes_a_service_result_through_the_mcp_presenter():
    key = KeyStatus(TagStatus.NOT_ENCRYPTED, decrypted=True)
    result = _result({"n": 1}, key, Resolution.OK)

    assert present_mcp_tool(lambda: result)() == json.dumps({"n": 1})


def test_present_tool_encodes_a_dict_and_passes_a_json_string_through():
    assert present_mcp_tool(lambda: {"ok": True})() == json.dumps({"ok": True})
    assert present_mcp_tool(lambda: '{"raw": 1}')() == '{"raw": 1}'


def test_present_tool_renders_the_structured_error_body_by_default():
    def tool_body():
        raise _detailed_error()

    body = json.loads(present_mcp_tool(tool_body)())

    assert body == mcp_error_payload(_detailed_error())
    assert {"error", "code", "category", "details"} <= body.keys()
    assert body["details"] == {"offset": 9, "file_size": 4}


def test_present_tool_keeps_the_legacy_body_for_inspect_tools():
    def tool_body():
        raise _detailed_error()

    body = json.loads(present_mcp_tool(tool_body, legacy_error_body=True)())

    assert body == {"error": "offset out of range", "offset": 9, "file_size": 4}


def test_present_tool_handles_coroutine_tools():
    import asyncio

    async def tool_body():
        raise CapabilityError("nope", category=ErrorCategory.NOT_FOUND, code="x.y")

    wrapped = present_mcp_tool(tool_body)

    assert json.loads(asyncio.run(wrapped())) == {
        "error": "nope", "code": "x.y", "category": "NOT_FOUND"}


def test_present_tool_preserves_wrapped_metadata_for_mcpserver():
    def tool_body(dump_path: str) -> str:
        """Tool description."""
        return dump_path

    wrapped = present_mcp_tool(tool_body)

    assert wrapped.__name__ == "tool_body" and wrapped.__wrapped__ is tool_body
    assert wrapped.__doc__ == "Tool description."


def test_legacy_error_body_tools_are_the_original_inspect_family():
    assert {"read_hex", "get_entropy", "analyze_region", "identify_structure"} \
        <= LEGACY_ERROR_BODY_TOOLS
    assert not {"heap_detect", "case_query", "vol3_run"} & LEGACY_ERROR_BODY_TOOLS
