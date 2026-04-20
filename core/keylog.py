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
