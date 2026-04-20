"""ToolSession — stateful context for tool calls across a session."""

import logging
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("memdiver.mcp_server.session")


class ToolSession:
    """Holds state that persists across tool calls within one session.

    For MCP (single-user stdio): one global instance in server.py.
    For future web gateway (multi-user): Dict[session_id, ToolSession].
    """

    def __init__(self):
        self.dataset_root: Optional[Path] = None
        self.scan_cache: Optional[dict] = None
        self._scan_protocols: Optional[tuple] = None
        self.protocol_version: str = ""
        self._consensus_cache = None

    def set_dataset(self, root: str) -> dict:
        """Set dataset root, clear caches, return confirmation."""
        path = Path(root).resolve()
        if not path.is_dir():
            return {"error": f"Directory not found: {root}"}
        self.dataset_root = path
        self.scan_cache = None
        logger.info("Dataset root set to %s", path)
        return {"dataset_root": str(path), "status": "ok"}

    def require_dataset(self) -> Path:
        """Return dataset root or raise ValueError if not set."""
        if self.dataset_root is None:
            raise ValueError(
                "No dataset root set. Call scan_dataset first with a dataset_root path."
            )
        return self.dataset_root

    def get_or_scan(
        self,
        keylog_filename: str = "keylog.csv",
        protocols: Optional[List[str]] = None,
    ) -> dict:
        """Return cached scan or trigger a new scan."""
        proto_key = tuple(sorted(protocols)) if protocols else None
        if self.scan_cache is not None and self._scan_protocols == proto_key:
            return self.scan_cache

        root = self.require_dataset()
        from core.discovery import DatasetScanner
        from engine.serializer import serialize_dataset_info

        scanner = DatasetScanner(root, keylog_filename)
        info = scanner.fast_scan(protocols=protocols)
        self.scan_cache = serialize_dataset_info(info)
        self._scan_protocols = proto_key
        return self.scan_cache

    def clear(self) -> None:
        """Reset all session state."""
        self.dataset_root = None
        self.scan_cache = None
        self._scan_protocols = None
        self.protocol_version = ""
