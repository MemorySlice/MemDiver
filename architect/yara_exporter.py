"""YaraExporter - export patterns as YARA rules."""

import logging
from typing import Optional

logger = logging.getLogger("memdiver.architect.yara_exporter")


class YaraExporter:
    """Export byte patterns as YARA detection rules."""

    @staticmethod
    def export(
        pattern: dict,
        rule_name: Optional[str] = None,
        description: Optional[str] = None,
        tags: Optional[list] = None,
    ) -> str:
        """Export a pattern dict as a YARA rule string.

        Args:
            pattern: Pattern dict from PatternGenerator.generate().
            rule_name: YARA rule name (defaults to sanitized pattern name).
            description: Rule description.
            tags: Optional YARA tags.

        Returns:
            YARA rule as a string.
        """
        name = rule_name or _sanitize_identifier(pattern.get("name", "memdiver_pattern"))
        desc = description or f"MemDiver pattern: {pattern.get('name', 'unknown')}"
        tag_str = " : " + " ".join(tags) if tags else ""

        wildcard = pattern.get("wildcard_pattern", "")
        # Convert space-separated hex to YARA format (curly braces)
        yara_hex = wildcard.upper()

        lines = [
            f'rule {name}{tag_str}',
            '{',
            '    meta:',
            f'        description = "{desc}"',
            f'        pattern_length = {pattern.get("length", 0)}',
            f'        static_ratio = "{pattern.get("static_ratio", 0)}"',
            '        generated_by = "MemDiver"',
            '',
            '    strings:',
            f'        $key = {{ {yara_hex} }}',
            '',
            '    condition:',
            '        $key',
            '}',
        ]
        rule = "\n".join(lines)

        logger.info("Exported YARA rule: %s (%d bytes)", name, pattern.get("length", 0))
        return rule


def _sanitize_identifier(name: str) -> str:
    """Convert a string to a valid YARA identifier."""
    sanitized = ""
    for c in name:
        if c.isalnum() or c == "_":
            sanitized += c
        else:
            sanitized += "_"
    if sanitized and sanitized[0].isdigit():
        sanitized = "r_" + sanitized
    return sanitized or "unnamed_rule"
