"""Unit tests for the MCP inspect presenter.

These target ``mcp_server.presenters`` DIRECTLY — never through FastMCP (the
``mcp`` SDK is not installed in CI, so ``mcp_server/server.py`` is not
importable here). The presenter is the piece the server wrappers now route
through, so pinning its output here locks the observable MCP JSON contract:

* locked/undecrypted dump -> ``{"error": <hint>, "tag_status": <value>}``
* success (valid / not_encrypted / empty payload) -> the payload dict verbatim
* hard error (raised ``CapabilityError`` subclass) -> ``{"error": <msg>}``,
  merging ``.details`` (the byte-for-byte legacy out-of-range shape).

Also covers ``mcp_error_funnel`` — the Phase 3 backstop decorator applied to
the non-inspect MCP tools in ``server.py``, which translates a propagating
``CapabilityError`` into ``json.dumps(err.to_dict())`` while leaving the
success path (the wrapped function's own return value) untouched.
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
    mcp_error_funnel,
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


def test_error_funnel_preserves_wrapped_metadata_for_fastmcp():
    def tool_body(dump_path: str, offset: int = 0) -> str:
        """Docstring FastMCP reads for the tool description."""
        return json.dumps({"dump_path": dump_path, "offset": offset})

    wrapped = mcp_error_funnel(tool_body)

    assert wrapped.__name__ == "tool_body"
    assert wrapped.__doc__ == "Docstring FastMCP reads for the tool description."
    assert wrapped.__wrapped__ is tool_body
    assert wrapped("a.msl", offset=8) == json.dumps({"dump_path": "a.msl", "offset": 8})
