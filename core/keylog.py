"""KeylogParser - parse keylog CSV files into CryptoSecret objects."""

import csv
import logging
from pathlib import Path
from typing import List, Optional

from .models import CryptoSecret
from .protocols import REGISTRY

logger = logging.getLogger("memdiver.keylog")


def _get_tls13_secret_types():
    """Lazy lookup to avoid import-order fragility."""
    tls = REGISTRY.get("TLS")
    return tls.secret_types["13"] if tls else set()


def _get_all_secret_types():
    """Lazy lookup to avoid import-order fragility."""
    result = set()
    for name in REGISTRY.list_protocols():
        desc = REGISTRY.get(name)
        if desc:
            result |= desc.all_secret_types()
    return result


# Public constants resolved lazily on first access via __getattr__
def __getattr__(name):
    if name == "TLS13_SECRET_TYPES":
        return _get_tls13_secret_types()
    if name == "ALL_SECRET_TYPES":
        return _get_all_secret_types()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def format_keylog_lines(secrets: List[CryptoSecret]) -> str:
    """Render CryptoSecrets as a standard NSS key-log (SSLKEYLOGFILE) body.

    Each secret becomes one ``<LABEL> <client_random_hex> <secret_hex>`` line —
    the exact format Wireshark / ``tshark -o tls.keylog_file=...`` loads to
    decrypt a capture (RFC-adjacent NSS format). This is the emit inverse of
    :meth:`KeylogParser._parse_line`; note the *parser* reads a CSV whose ``line``
    column holds these strings, whereas Wireshark consumes the plaintext lines
    directly — so the artifact this produces is the plaintext key log, not the CSV.

    Secrets with an empty ``secret_type`` or ``secret_value`` are skipped.
    Duplicate ``(secret_type, identifier, secret_value)`` triples are emitted
    once, preserving input order.
    """
    lines: List[str] = []
    seen = set()
    for s in secrets:
        if not s.secret_type or not s.secret_value:
            continue
        key = (s.secret_type, s.identifier, s.secret_value)
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"{s.secret_type} {s.identifier.hex()} {s.secret_value.hex()}")
    return "\n".join(lines) + ("\n" if lines else "")


def write_keylog(secrets: List[CryptoSecret], path: Path) -> int:
    """Write *secrets* to *path* as an NSS key log. Returns the line count."""
    body = format_keylog_lines(secrets)
    Path(path).write_text(body)
    return 0 if not body.strip() else body.count("\n")


class KeylogParser:
    """Parse keylog.csv files into CryptoSecret objects."""

    @staticmethod
    def parse(keylog_path: Path, template=None) -> List[CryptoSecret]:
        secrets = []
        seen = set()

        try:
            allowed_types = template.secret_types if template is not None else _get_all_secret_types()
            with open(keylog_path, "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    line = row.get("line", "").strip()
                    if not line:
                        continue
                    secret = KeylogParser._parse_line(line, allowed_types=allowed_types)
                    if secret and (secret.secret_type, secret.secret_value) not in seen:
                        seen.add((secret.secret_type, secret.secret_value))
                        secrets.append(secret)
        except FileNotFoundError:
            logger.warning("Keylog not found: %s", keylog_path)
        except Exception as e:
            logger.warning("Error parsing %s: %s", keylog_path, e)

        return secrets

    @staticmethod
    def _parse_line(line: str, allowed_types=None) -> Optional[CryptoSecret]:
        parts = line.split()
        if len(parts) != 3:
            return None

        secret_type, client_random_hex, secret_hex = parts
        effective_types = allowed_types if allowed_types is not None else _get_all_secret_types()
        if secret_type not in effective_types:
            return None

        try:
            identifier = bytes.fromhex(client_random_hex)
            secret_value = bytes.fromhex(secret_hex)
        except ValueError:
            return None

        return CryptoSecret(
            secret_type=secret_type,
            identifier=identifier,
            secret_value=secret_value,
        )
