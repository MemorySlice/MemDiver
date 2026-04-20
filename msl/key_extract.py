"""Extract CryptoSecret objects from MSL key hints.

Converts MslKeyHint blocks into pipeline-compatible CryptoSecret instances
by mapping MSL enum values and reading actual key bytes from memory regions.
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional

from core.models import CryptoSecret

from .enums import MslKeyType, MslProtocol, PageState
from .page_map import count_captured_pages
from .types import MslKeyHint, MslMemoryRegion

logger = logging.getLogger("memdiver.msl.key_extract")

# -- Enum mapping tables --

_KEY_TYPE_MAP: Dict[int, str] = {
    MslKeyType.PRE_MASTER_SECRET: "PRE_MASTER_SECRET",
    MslKeyType.MASTER_SECRET: "MASTER_SECRET",
    MslKeyType.SESSION_KEY: "SESSION_KEY",
    MslKeyType.HANDSHAKE_SECRET: "HANDSHAKE_SECRET",
    MslKeyType.APP_TRAFFIC_SECRET: "APP_TRAFFIC_SECRET",
    MslKeyType.RSA_PRIVATE_KEY: "RSA_PRIVATE_KEY",
    MslKeyType.ECDH_PRIVATE_KEY: "ECDH_PRIVATE_KEY",
    MslKeyType.IKE_SA_KEY: "IKE_SA_KEY",
    MslKeyType.ESP_AH_KEY: "ESP_AH_KEY",
    MslKeyType.SSH_SESSION_KEY: "SSH2_SESSION_KEY",
    MslKeyType.WIREGUARD_KEY: "WIREGUARD_KEY",
    MslKeyType.ML_KEM_PRIVATE_KEY: "ML_KEM_PRIVATE_KEY",
}

_PROTOCOL_MAP: Dict[int, str] = {
    MslProtocol.TLS_12: "TLS",
    MslProtocol.TLS_13: "TLS",
    MslProtocol.DTLS_12: "TLS",
    MslProtocol.DTLS_13: "TLS",
    MslProtocol.QUIC: "TLS",
    MslProtocol.PQ_TLS: "TLS",
    MslProtocol.IKEV2_IPSEC: "IPsec",
    MslProtocol.SSH: "SSH",
    MslProtocol.WIREGUARD: "WireGuard",
}


def map_key_type(msl_key_type: int) -> str:
    """Map MslKeyType enum value to CryptoSecret.secret_type string."""
    if msl_key_type in _KEY_TYPE_MAP:
        return _KEY_TYPE_MAP[msl_key_type]
    try:
        return MslKeyType(msl_key_type).name
    except ValueError:
        return f"UNKNOWN_0x{msl_key_type:04X}"


def map_protocol(msl_protocol: int) -> str:
    """Map MslProtocol enum value to CryptoSecret.protocol string."""
    if msl_protocol in _PROTOCOL_MAP:
        return _PROTOCOL_MAP[msl_protocol]
    return "UNKNOWN"


def extract_key_bytes(reader, hint: MslKeyHint) -> Optional[bytes]:
    """Read actual key bytes from the memory region referenced by a key hint.

    Returns None if the region is missing, offset is out of bounds,
    or the referenced pages are not captured.
    """
    regions = reader.collect_regions()
    region_by_uuid = {r.block_header.block_uuid: r for r in regions}

    region = region_by_uuid.get(hint.region_uuid)
    if region is None:
        logger.warning("Key hint references unknown region %s", hint.region_uuid)
        return None

    if hint.region_offset + hint.key_length > region.region_size:
        logger.warning(
            "Key hint offset %d + length %d exceeds region size %d",
            hint.region_offset, hint.key_length, region.region_size,
        )
        return None

    return _read_region_bytes(reader, region, hint.region_offset, hint.key_length)


def _read_region_bytes(
    reader, region: MslMemoryRegion, offset: int, length: int,
) -> Optional[bytes]:
    """Read bytes from a region's captured page data at the given offset."""
    page_size = region.page_size
    start_page = offset // page_size
    end_page = (offset + length - 1) // page_size

    # Verify all pages in range are captured
    for p in range(start_page, end_page + 1):
        if p >= len(region.page_states):
            logger.warning("Page %d out of range for region", p)
            return None
        if region.page_states[p] != PageState.CAPTURED:
            logger.warning("Page %d not captured (state=%s)", p, region.page_states[p])
            return None

    captured_before = sum(
        1 for i in range(start_page)
        if i < len(region.page_states)
        and region.page_states[i] == PageState.CAPTURED
    )
    data_offset = captured_before * page_size + (offset % page_size)

    page_data = _get_region_page_data(reader, region)
    if data_offset + length > len(page_data):
        logger.warning("Computed data offset exceeds available page data")
        return None
    return page_data[data_offset:data_offset + length]


def _get_region_page_data(reader, region: MslMemoryRegion) -> bytes:
    """Read page data for a region, handling compressed blocks."""
    payload = reader.read_block_payload(region.block_header)
    map_bytes = ((region.num_pages + 3) // 4 + 7) & ~7
    data_start = 0x20 + map_bytes
    num_captured = count_captured_pages(region.page_states)
    end = data_start + num_captured * region.page_size
    return payload[data_start:end]


def extract_secrets_from_msl(reader) -> List[CryptoSecret]:
    """Extract all key hints from an open MslReader as CryptoSecret objects.

    Deduplicates by (secret_type, secret_value).
    """
    hints = reader.collect_key_hints()
    if not hints:
        return []

    secrets: List[CryptoSecret] = []
    seen = set()

    for hint in hints:
        key_bytes = extract_key_bytes(reader, hint)
        if key_bytes is None:
            continue
        secret_type = map_key_type(hint.key_type)
        protocol = map_protocol(hint.protocol)
        dedup_key = (secret_type, key_bytes)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        secrets.append(CryptoSecret(
            secret_type=secret_type,
            identifier=key_bytes[:32] if len(key_bytes) >= 32 else key_bytes,
            secret_value=key_bytes,
            protocol=protocol,
        ))

    logger.debug("Extracted %d secrets from %d key hints", len(secrets), len(hints))
    return secrets


def extract_secrets_from_path(msl_path: Path) -> List[CryptoSecret]:
    """Open an MSL file, extract key hints as CryptoSecrets, and close."""
    from .reader import MslReader
    with MslReader(msl_path) as reader:
        return extract_secrets_from_msl(reader)
