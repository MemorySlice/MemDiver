"""Keylog template presets for filtering which secret types to parse.

Provides predefined templates for TLS 1.2, TLS 1.3, and auto-detect modes,
each specifying which secret type labels should be included when parsing
keylog files.
"""

from dataclasses import dataclass
from typing import List, Optional, Set


@dataclass
class KeylogTemplate:
    """A preset defining which secret types to include when parsing keylogs."""

    name: str
    protocol: str
    description: str
    secret_types: Set[str]
    version: Optional[str] = None


TLS12_TEMPLATE = KeylogTemplate(
    name="TLS 1.2",
    protocol="TLS 1.2",
    description="TLS 1.2 secrets only (CLIENT_RANDOM)",
    secret_types={"CLIENT_RANDOM"},
    version="12",
)

TLS13_TEMPLATE = KeylogTemplate(
    name="TLS 1.3",
    protocol="TLS 1.3",
    description="TLS 1.3 secrets only",
    secret_types={
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_TRAFFIC_SECRET_0",
        "SERVER_TRAFFIC_SECRET_0",
        "EXPORTER_SECRET",
    },
    version="13",
)

SSH2_TEMPLATE = KeylogTemplate(
    name="SSH 2",
    protocol="SSH 2",
    description="SSH 2 secrets only",
    secret_types={
        "SSH2_SESSION_KEY",
        "SSH2_SESSION_ID",
        "SSH2_ENCRYPTION_KEY_CS",
        "SSH2_ENCRYPTION_KEY_SC",
    },
    version="2",
)

AES256_TEMPLATE = KeylogTemplate(
    name="AES-256",
    protocol="AES",
    description="AES-256 symmetric key only",
    secret_types={"AES256_KEY"},
    version="256",
)

AUTO_DETECT_TEMPLATE = KeylogTemplate(
    name="Auto-detect",
    protocol="All",
    description="All known secret types",
    secret_types=(
        TLS12_TEMPLATE.secret_types
        | TLS13_TEMPLATE.secret_types
        | SSH2_TEMPLATE.secret_types
        | AES256_TEMPLATE.secret_types
    ),
    version=None,
)

_TEMPLATES = {
    TLS12_TEMPLATE.name: TLS12_TEMPLATE,
    TLS13_TEMPLATE.name: TLS13_TEMPLATE,
    SSH2_TEMPLATE.name: SSH2_TEMPLATE,
    AES256_TEMPLATE.name: AES256_TEMPLATE,
    AUTO_DETECT_TEMPLATE.name: AUTO_DETECT_TEMPLATE,
}


def get_template(name: str) -> Optional[KeylogTemplate]:
    """Look up a keylog template by name.

    Args:
        name: The template name to look up.

    Returns:
        The matching KeylogTemplate, or None if not found.
    """
    return _TEMPLATES.get(name)


def list_template_names() -> List[str]:
    """Return the list of available template names, with 'Auto-detect' first.

    Returns:
        Ordered list of template name strings.
    """
    return [AUTO_DETECT_TEMPLATE.name] + [
        n for n in _TEMPLATES if n != AUTO_DETECT_TEMPLATE.name
    ]
