"""Protocol descriptors and registry for multi-protocol support."""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger("memdiver.core.protocols")


@dataclass
class ProtocolDescriptor:
    """Describes a cryptographic protocol's metadata for discovery and display."""
    name: str
    versions: List[str]
    secret_types: Dict[str, Set[str]]
    dir_prefix: str
    display_labels: Dict[Tuple[str, str], str] = field(default_factory=dict)
    short_labels: Dict[Tuple[str, str], str] = field(default_factory=dict)

    def get_display_label(self, secret_type: str, version: str) -> Optional[str]:
        return self.display_labels.get((secret_type, version))

    def get_short_label(self, secret_type: str, version: str) -> Optional[str]:
        return self.short_labels.get((secret_type, version))

    def all_secret_types(self) -> Set[str]:
        result: Set[str] = set()
        for types in self.secret_types.values():
            result |= types
        return result


class ProtocolRegistry:
    """Registry of protocol descriptors."""

    def __init__(self):
        self._protocols: Dict[str, ProtocolDescriptor] = {}

    def register(self, descriptor: ProtocolDescriptor) -> None:
        self._protocols[descriptor.name] = descriptor
        logger.debug("Registered protocol: %s", descriptor.name)

    def get(self, name: str) -> Optional[ProtocolDescriptor]:
        return self._protocols.get(name)

    def list_protocols(self) -> List[str]:
        return list(self._protocols.keys())

    def get_by_dir_prefix(self, prefix: str) -> Optional[ProtocolDescriptor]:
        for desc in self._protocols.values():
            if desc.dir_prefix == prefix:
                return desc
        return None

    def lookup_label(
        self, secret_type: str, version: str, short: bool = False,
    ) -> Optional[str]:
        """Search all protocols for a display label matching (secret_type, version)."""
        method = "get_short_label" if short else "get_display_label"
        for desc in self._protocols.values():
            label = getattr(desc, method)(secret_type, version)
            if label is not None:
                return label
        return None


# --- TLS Protocol Descriptor ---

TLS_DESCRIPTOR = ProtocolDescriptor(
    name="TLS",
    versions=["12", "13"],
    secret_types={
        "12": {"CLIENT_RANDOM"},
        "13": {
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            "CLIENT_TRAFFIC_SECRET_0",
            "SERVER_TRAFFIC_SECRET_0",
            "EXPORTER_SECRET",
        },
    },
    dir_prefix="TLS",
    display_labels={
        ("CLIENT_RANDOM", "12"): "Master Secret (via CLIENT_RANDOM)",
        ("CLIENT_HANDSHAKE_TRAFFIC_SECRET", "13"): "Client Handshake Traffic Secret",
        ("SERVER_HANDSHAKE_TRAFFIC_SECRET", "13"): "Server Handshake Traffic Secret",
        ("CLIENT_TRAFFIC_SECRET_0", "13"): "Client Traffic Secret 0",
        ("SERVER_TRAFFIC_SECRET_0", "13"): "Server Traffic Secret 0",
        ("EXPORTER_SECRET", "13"): "Exporter Secret",
    },
    short_labels={
        ("CLIENT_RANDOM", "12"): "Master Secret",
        ("CLIENT_HANDSHAKE_TRAFFIC_SECRET", "13"): "Client HTS",
        ("SERVER_HANDSHAKE_TRAFFIC_SECRET", "13"): "Server HTS",
        ("CLIENT_TRAFFIC_SECRET_0", "13"): "Client TS0",
        ("SERVER_TRAFFIC_SECRET_0", "13"): "Server TS0",
        ("EXPORTER_SECRET", "13"): "Exporter",
    },
)

# --- SSH Protocol Descriptor ---

SSH_DESCRIPTOR = ProtocolDescriptor(
    name="SSH",
    versions=["2"],
    secret_types={
        "2": {
            "SSH2_SESSION_KEY",
            "SSH2_SESSION_ID",
            "SSH2_ENCRYPTION_KEY_CS",
            "SSH2_ENCRYPTION_KEY_SC",
        },
    },
    dir_prefix="SSH",
    display_labels={
        ("SSH2_SESSION_KEY", "2"): "Session Key",
        ("SSH2_SESSION_ID", "2"): "Session ID",
        ("SSH2_ENCRYPTION_KEY_CS", "2"): "Encryption Key (Client→Server)",
        ("SSH2_ENCRYPTION_KEY_SC", "2"): "Encryption Key (Server→Client)",
    },
    short_labels={
        ("SSH2_SESSION_KEY", "2"): "Session Key",
        ("SSH2_SESSION_ID", "2"): "Session ID",
        ("SSH2_ENCRYPTION_KEY_CS", "2"): "Enc C→S",
        ("SSH2_ENCRYPTION_KEY_SC", "2"): "Enc S→C",
    },
)

# --- AES Protocol Descriptor ---

AES_DESCRIPTOR = ProtocolDescriptor(
    name="AES",
    versions=["256"],
    secret_types={
        "256": {"AES256_KEY"},
    },
    dir_prefix="AES",
    display_labels={
        ("AES256_KEY", "256"): "AES-256 Symmetric Key",
    },
    short_labels={
        ("AES256_KEY", "256"): "AES-256 Key",
    },
)

# Module-level singleton
REGISTRY = ProtocolRegistry()
REGISTRY.register(TLS_DESCRIPTOR)
REGISTRY.register(SSH_DESCRIPTOR)
REGISTRY.register(AES_DESCRIPTOR)
