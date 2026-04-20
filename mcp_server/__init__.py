"""MCP server for MemDiver — requires the 'mcp' package."""


def _check_mcp_available() -> bool:
    try:
        import mcp  # noqa: F401
        return True
    except ImportError:
        return False


MCP_AVAILABLE = _check_mcp_available()
