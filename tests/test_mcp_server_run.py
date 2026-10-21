"""Transport-dispatch test for ``mcp_server.server.main``.

mcp 2.x moved the SSE listener's host/port from the server constructor to
``MCPServer.run()``. This pins the exact ``run()`` call ``main()`` makes for
each transport — without binding a socket or blocking on stdio — and checks
the SSE keywords are ones the installed SDK's SSE runner actually accepts, so
an SDK signature change fails here instead of at ``memdiver mcp --sse``.

Skipped where the optional ``mcp`` SDK is absent.
"""

import inspect
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("mcp")

from mcp.server.mcpserver import MCPServer  # noqa: E402

from memdiver.mcp_server import server as server_mod  # noqa: E402


@pytest.fixture
def run_calls(monkeypatch):
    """Replace ``MCPServer.run`` with a recorder; return the recorded calls."""
    calls = []

    def _record_run(self, *args, **kwargs):
        calls.append((args, kwargs))

    monkeypatch.setattr(MCPServer, "run", _record_run)
    return calls


def test_main_stdio_runs_stdio_transport(run_calls):
    server_mod.main(transport="stdio", port=9999)
    assert run_calls == [((), {"transport": "stdio"})]


def test_main_sse_passes_loopback_host_and_port_to_run(run_calls):
    server_mod.main(transport="sse", port=8765)
    assert run_calls == [
        ((), {"transport": "sse", "host": "127.0.0.1", "port": 8765}),
    ]


def test_sse_run_keywords_match_installed_sdk(run_calls):
    server_mod.main(transport="sse", port=8765)
    (_, kwargs), = run_calls
    sse_kwargs = {k: v for k, v in kwargs.items() if k != "transport"}
    # Raises TypeError if the SDK renamed or dropped host/port.
    inspect.signature(MCPServer.run_sse_async).bind(None, **sse_kwargs)


def test_create_server_is_mcpserver_with_package_version():
    from memdiver import __version__

    server = server_mod.create_server()
    assert isinstance(server, MCPServer)
    assert server.name == "memdiver"
    assert server.version == __version__
