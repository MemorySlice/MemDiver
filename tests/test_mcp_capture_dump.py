"""MCP ``capture_dump`` tool: forwards every option to ``capture_result``."""

import json
import sys

import pytest


@pytest.fixture(scope="module")
def capture_tool():
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server

    tools = {t.name: t for t in create_server()._tool_manager.list_tools()}
    return tools["capture_dump"]


def test_capture_dump_forwards_options(capture_tool, monkeypatch):
    from memdiver.app import experiment_orchestration as eo

    seen = {}

    def fake(**kwargs):
        seen.update(kwargs)
        return {"ok": True, "skipped": [], "summary_warnings": []}

    monkeypatch.setattr(eo, "capture_result", fake)
    out = json.loads(capture_tool.fn(
        target="com.android.settings", output="/tmp/x.msl", tool="memslicer",
        device="usb:emulator-5556", max_region_size=4096,
        include_large_readonly=True, timeout=9.0))
    assert out["ok"] is True
    assert seen == {"target": "com.android.settings", "output": "/tmp/x.msl",
                    "tool": "memslicer", "device": "usb:emulator-5556",
                    "max_region_size": 4096, "include_large_readonly": True,
                    "timeout": 9.0}


def test_capture_dump_invalid_device_is_structured_error(capture_tool):
    out = json.loads(capture_tool.fn(target="1", output="/tmp/x.msl", device="bogus"))
    assert "invalid device" in json.dumps(out)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
