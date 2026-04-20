"""SidecarParser - parse JSON/YAML metadata sidecars."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("memdiver.harvester.sidecar")


class SidecarParser:
    """Parse sidecar metadata files associated with dump directories.

    Supports JSON (.json) and plain-text (.meta) sidecar formats.
    Sidecars provide extra context: library versions, build flags,
    capture environment, analysis notes.
    """

    SIDECAR_EXTENSIONS = [".json", ".meta"]

    @staticmethod
    def find_sidecar(run_dir: Path) -> Optional[Path]:
        """Find a sidecar metadata file in a run directory."""
        for ext in SidecarParser.SIDECAR_EXTENSIONS:
            candidates = list(run_dir.glob(f"*{ext}"))
            # Skip keylog and timing files
            sidecars = [
                c for c in candidates
                if not c.stem.startswith("keylog")
                and not c.stem.startswith("timing")
            ]
            if sidecars:
                return sidecars[0]
        return None

    @staticmethod
    def parse(sidecar_path: Path) -> Dict[str, Any]:
        """Parse a sidecar file and return its contents as a dict."""
        if not sidecar_path.exists():
            logger.warning("Sidecar not found: %s", sidecar_path)
            return {}

        suffix = sidecar_path.suffix.lower()
        try:
            if suffix == ".json":
                return SidecarParser._parse_json(sidecar_path)
            elif suffix == ".meta":
                return SidecarParser._parse_meta(sidecar_path)
            else:
                logger.warning("Unknown sidecar format: %s", suffix)
                return {}
        except Exception as e:
            logger.error("Failed to parse sidecar %s: %s", sidecar_path, e)
            return {}

    @staticmethod
    def _parse_json(path: Path) -> Dict[str, Any]:
        """Parse a JSON sidecar file."""
        with open(path, "r") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            logger.warning("JSON sidecar is not a dict: %s", path)
            return {}
        return data

    @staticmethod
    def _parse_meta(path: Path) -> Dict[str, Any]:
        """Parse a plain-text key=value sidecar file."""
        result: Dict[str, Any] = {}
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, _, value = line.partition("=")
                    result[key.strip()] = value.strip()
        return result
