"""REST API routes wrapping mcp_server tool functions."""

import logging
from typing import Optional

from nicegui import app

logger = logging.getLogger("memdiver.ui.nicegui.api_routes")

# Lazy session singleton — created on first API call to defer heavy imports
_session = None


def _get_session():
    """Return shared ToolSession, creating on first use."""
    global _session
    if _session is None:
        from mcp_server.session import ToolSession
        _session = ToolSession()
    return _session


def register_api_routes():
    """Register REST API endpoints on the NiceGUI FastAPI app."""

    @app.get('/api/scan')
    def api_scan(root: str, keylog_filename: str = 'keylog.csv',
                 protocols: Optional[str] = None):
        from mcp_server import tools
        proto_list = protocols.split(',') if protocols else None
        return tools.scan_dataset(_get_session(), root, keylog_filename, proto_list)

    @app.get('/api/protocols')
    def api_protocols():
        from mcp_server import tools
        return tools.list_protocols(_get_session())

    @app.get('/api/phases')
    def api_phases(library_dir: str):
        from mcp_server import tools
        return tools.list_phases(_get_session(), library_dir)

    @app.get('/api/analyze')
    def api_analyze(
        library_dirs: str,  # comma-separated
        phase: str,
        protocol_version: str,
        keylog_filename: str = 'keylog.csv',
        template_name: str = 'Auto-detect',
        max_runs: int = 10,
        normalize: bool = False,
        expand_keys: bool = True,
    ):
        from mcp_server import tools
        dirs = [d.strip() for d in library_dirs.split(',')]
        return tools.analyze_library(
            _get_session(), dirs, phase, protocol_version,
            keylog_filename, template_name, max_runs, normalize, expand_keys,
        )

    @app.get('/api/hex')
    def api_hex(dump_path: str, offset: int = 0, length: int = 256):
        from mcp_server import tools_inspect
        return tools_inspect.read_hex(_get_session(), dump_path, offset, length)

    @app.get('/api/entropy')
    def api_entropy(dump_path: str, offset: int = 0, length: int = 0,
                    window: int = 32, step: int = 16, threshold: float = 7.5):
        from mcp_server import tools_inspect
        return tools_inspect.get_entropy(
            _get_session(), dump_path, offset, length, window, step, threshold,
        )

    logger.info("API routes registered")
