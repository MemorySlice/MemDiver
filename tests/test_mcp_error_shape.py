"""One MCP error shape: a raised CapabilityError and a path-guard denial agree.

Exercises ``create_server()`` so the registration-layer presenter
(``presenters.present_mcp_tool``, wired in ``_add_guarded_tool``) is what is
tested — not a hand-wrapped function. Non-inspect tools render
``{"error", "code", "category"}`` (``CapabilityError.to_dict``), the exact keys
the read sandbox returns on a denial; the original inspect family keeps its
pinned legacy ``to_error_body()``.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("mcp")

from memdiver.mcp_server.presenters import LEGACY_ERROR_BODY_TOOLS  # noqa: E402
from memdiver.mcp_server.server import create_server  # noqa: E402

OUTSIDE = "/definitely/not/admitted.bin"


@pytest.fixture()
def root(tmp_path, monkeypatch):
    """Sandbox ON with one configured root (as test_path_sandbox_and_messages)."""
    from memdiver.api.config import get_settings
    from memdiver.core import path_sandbox

    monkeypatch.setenv("MEMDIVER_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.setattr(path_sandbox, "STARTUP_CWD", str(tmp_path))
    get_settings.cache_clear()  # the settings (and so the roots) are cached
    yield tmp_path
    get_settings.cache_clear()


@pytest.fixture()
def tools(root):
    server = create_server()
    return {t.name: t for t in server._tool_manager.list_tools()}


def _call(tools, name, **kw):
    return json.loads(tools[name].fn(**kw))


def test_capability_error_and_path_denial_have_the_same_keys(tools, root):
    raised = _call(tools, "heap_detect", dump_path=str(root / "missing.dump"))
    denied = _call(tools, "heap_detect", dump_path=OUTSIDE)

    assert raised["category"] == "NOT_FOUND"
    assert denied["code"] == "path.outside_sandbox"
    assert raised.keys() == denied.keys() == {"error", "code", "category"}


def test_inspect_tools_keep_the_legacy_error_body(tools, root):
    assert "read_hex" in LEGACY_ERROR_BODY_TOOLS
    body = _call(tools, "read_hex", dump_path=str(root / "missing.dump"))

    assert body.keys() == {"error"}


def test_every_legacy_tool_name_is_a_registered_tool(tools):
    assert LEGACY_ERROR_BODY_TOOLS <= tools.keys()
