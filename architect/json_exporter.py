"""JsonExporter - export patterns as JSON signature files."""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("memdiver.architect.json_exporter")


class JsonExporter:
    """Export byte patterns as JSON signatures compatible with pattern_loader."""

    @staticmethod
    def export(
        pattern: dict,
        library: str = "",
        tls_version: str = "",
        description: str = "",
        structural_rules: Optional[Dict[str, List[dict]]] = None,
    ) -> dict:
        """Export a pattern as a JSON signature dict.

        Args:
            pattern: Pattern dict from PatternGenerator.generate().
            library: Target library name.
            tls_version: TLS version ('12' or '13').
            description: Human-readable description.
            structural_rules: Optional before/after structural rules.

        Returns:
            JSON-serializable dict compatible with pattern_loader.
        """
        name = pattern.get("name", "unnamed")
        length = pattern.get("length", 32)

        signature = {
            "name": name,
            "description": description or f"MemDiver pattern: {name}",
            "applicable_to": {},
            "key_spec": {
                "length": length,
                "entropy_min": 4.5,
            },
            "pattern": structural_rules or {"before": [], "after": []},
            "metadata": {
                "generated_by": "MemDiver",
                "static_ratio": pattern.get("static_ratio", 0),
                "wildcard_pattern": pattern.get("wildcard_pattern", ""),
            },
        }

        if library:
            signature["applicable_to"]["libraries"] = [library]
        if tls_version:
            signature["applicable_to"]["protocol_versions"] = [tls_version]

        logger.info("Exported JSON signature: %s", name)
        return signature

    @staticmethod
    def save(signature: dict, output_path: Path) -> None:
        """Save a JSON signature to a file."""
        with open(output_path, "w") as f:
            json.dump(signature, f, indent=4)
        logger.info("Saved signature to %s", output_path)

    @staticmethod
    def to_string(signature: dict) -> str:
        """Convert a signature to a formatted JSON string."""
        return json.dumps(signature, indent=4)
