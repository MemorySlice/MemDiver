"""Built-in TLS 1.2 and TLS 1.3 structure definitions.

TLS 1.3 per-secret structures are polymorphic over hash length (32 for
SHA-256, 48 for SHA-384) via `FieldDef.size_choices`. TLS 1.2 structures
follow RFC 5246 §§6.3, 8.1.
"""

from typing import List, Tuple

from core.structure_defs import FieldDef, FieldType, StructureDef


_KEY_SCHEDULE_TAG = "key_schedule"
_TRAFFIC_TAG = "traffic_secret"

# Secrets that are part of the key-schedule chain (not direct traffic secrets).
_TLS13_KEY_SCHEDULE_SECRETS = {
    "early_secret",
    "binder_key",
    "early_exporter_master_secret",
    "handshake_secret",
    "master_secret",
    "exporter_master_secret",
    "resumption_master_secret",
}

# (secret_name, description)
_TLS13_SECRETS: List[Tuple[str, str]] = [
    ("early_secret", "TLS 1.3 early_secret (PSK seed, RFC 8446 §7.1)"),
    ("binder_key", "TLS 1.3 binder_key (PSK binder auth)"),
    ("client_early_traffic_secret", "TLS 1.3 client_early_traffic_secret (0-RTT app data)"),
    ("early_exporter_master_secret", "TLS 1.3 early_exporter_master_secret"),
    ("handshake_secret", "TLS 1.3 handshake_secret (handshake encryption seed)"),
    ("client_handshake_traffic_secret", "TLS 1.3 client_handshake_traffic_secret"),
    ("server_handshake_traffic_secret", "TLS 1.3 server_handshake_traffic_secret"),
    ("master_secret", "TLS 1.3 master_secret (app traffic seed)"),
    ("client_application_traffic_secret_0", "TLS 1.3 client_application_traffic_secret_0"),
    ("server_application_traffic_secret_0", "TLS 1.3 server_application_traffic_secret_0"),
    ("exporter_master_secret", "TLS 1.3 exporter_master_secret"),
    ("resumption_master_secret", "TLS 1.3 resumption_master_secret"),
]


def _tls13_secret(secret_name: str, desc: str) -> StructureDef:
    category = _KEY_SCHEDULE_TAG if secret_name in _TLS13_KEY_SCHEDULE_SECRETS else _TRAFFIC_TAG
    return StructureDef(
        name=f"tls13_{secret_name}",
        total_size=32,
        fields=(
            FieldDef(
                "secret", FieldType.BYTES, 0, 32,
                description=desc,
                constraints={"not_zero": True},
                size_choices=(48, 32),
            ),
        ),
        protocol="TLS",
        description=desc,
        tags=("crypto", "tls13", category),
        auto_offsets=True,
    )


def _build_tls13() -> List[StructureDef]:
    return [_tls13_secret(name, desc) for name, desc in _TLS13_SECRETS]


# TLS 1.2 structures

_TLS12_MASTER_SECRET = StructureDef(
    name="tls12_master_secret",
    total_size=48,
    fields=(
        FieldDef("master_secret", FieldType.BYTES, 0, 48,
                 description="TLS 1.2 master_secret (48 bytes)",
                 constraints={"not_zero": True}),
    ),
    protocol="TLS",
    description="TLS 1.2 master_secret (48 bytes, RFC 5246 §8.1)",
    tags=("crypto", "tls12", "master_secret"),
)

_TLS12_PMS_RSA = StructureDef(
    name="tls12_pre_master_secret_rsa",
    total_size=48,
    fields=(
        FieldDef(
            "pre_master_secret", FieldType.BYTES, 0, 48,
            description="TLS 1.2 RSA pre_master_secret",
            constraints={
                "not_zero": True,
                "byte_in": {"0": [0x03], "1": [0x00, 0x01, 0x02, 0x03, 0x04]},
            },
        ),
    ),
    protocol="TLS",
    description=(
        "TLS 1.2 RSA pre_master_secret (48 bytes; first 2 bytes = "
        "client_version (0x03xx), RFC 5246 §7.4.7.1)"
    ),
    tags=("crypto", "tls12", "pre_master"),
)

def _tls12_key_block(name: str, key_size: int, cipher_tag: str) -> StructureDef:
    iv_off = key_size * 2
    bits = key_size * 8
    return StructureDef(
        name=name,
        total_size=iv_off + 8,
        fields=(
            FieldDef("client_write_key", FieldType.BYTES, 0, key_size,
                     description=f"AES-{bits} client write key",
                     constraints={"not_zero": True}),
            FieldDef("server_write_key", FieldType.BYTES, key_size, key_size,
                     description=f"AES-{bits} server write key",
                     constraints={"not_zero": True}),
            FieldDef("client_write_iv", FieldType.BYTES, iv_off, 4,
                     description="GCM client write IV (salt)"),
            FieldDef("server_write_iv", FieldType.BYTES, iv_off + 4, 4,
                     description="GCM server write IV (salt)"),
        ),
        protocol="TLS",
        description=(
            f'TLS 1.2 AES-{bits}-GCM key block from PRF("key expansion", ...) '
            f'— RFC 5246 §6.3'
        ),
        tags=("crypto", "tls12", "key_block", cipher_tag),
    )


_TLS12_KEY_BLOCK_AES128 = _tls12_key_block("tls12_key_block_aes128_gcm", 16, "aes128")
_TLS12_KEY_BLOCK_AES256 = _tls12_key_block("tls12_key_block_aes256_gcm", 32, "aes256")


BORINGSSL_TLS13_HANDSHAKE_TRAFFIC_SECRETS = StructureDef(
    name="boringssl_tls13_handshake_traffic_secrets_sha256",
    total_size=64,
    fields=(
        FieldDef("client_handshake_traffic_secret", FieldType.BYTES, 0, 32,
                 description="Client -> Server handshake traffic secret",
                 constraints={"not_zero": True}),
        FieldDef("server_handshake_traffic_secret", FieldType.BYTES, 32, 32,
                 description="Server -> Client handshake traffic secret",
                 constraints={"not_zero": True}),
    ),
    protocol="TLS",
    description=(
        "EXPERIMENTAL: contiguous client+server handshake traffic secrets as "
        "observed in some BoringSSL builds. Offsets are library-specific and "
        "require calibration per build — this struct is a starting template, "
        "not a verified layout."
    ),
    tags=("crypto", "tls13", "boringssl", "experimental"),
    library="boringssl",
    library_version="~1.x",
    stability="experimental",
)


TLS_BUILTINS: List[StructureDef] = (
    _build_tls13()
    + [
        _TLS12_MASTER_SECRET,
        _TLS12_PMS_RSA,
        _TLS12_KEY_BLOCK_AES128,
        _TLS12_KEY_BLOCK_AES256,
        BORINGSSL_TLS13_HANDSHAKE_TRAFFIC_SECRETS,
    ]
)
