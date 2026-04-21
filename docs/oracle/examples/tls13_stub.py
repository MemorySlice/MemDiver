"""TLS 1.3 traffic-secret oracle — fill in the key schedule.

Treats each candidate as a 32- or 48-byte traffic secret (SHA-256 or
SHA-384 cipher suite), re-derives the record protection keys via
HKDF-Expand-Label, and attempts to AEAD-decrypt one captured TLS
record. Returns True on a successful tag verify.

This is a scaffold — the ``_derive_keys`` body is a TODO. Point it at
RFC 8446 §7.1 once you know the AEAD your target uses.

Driven by TOML:

    # tls13_oracle.toml
    encrypted_record   = "/path/to/record0.bin"   # full TLS record body
    record_nonce_hex   = "001122334455"           # explicit nonce bytes
    aead               = "AES-128-GCM"            # or "AES-256-GCM"
    hash_algo          = "SHA-256"                # or "SHA-384"
"""

from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SHA256_LENGTH = 32
SHA384_LENGTH = 48


def build_oracle(config: dict) -> "Tls13Oracle":
    return Tls13Oracle(config)


class Tls13Oracle:
    def __init__(self, config: dict):
        self.record = Path(config["encrypted_record"]).read_bytes()
        self.nonce = bytes.fromhex(config["record_nonce_hex"])
        self.aead_name = config.get("aead", "AES-128-GCM")
        self.hash_name = config.get("hash_algo", "SHA-256")
        self.expected_length = (
            SHA256_LENGTH if self.hash_name == "SHA-256" else SHA384_LENGTH
        )

    def _derive_keys(self, traffic_secret: bytes) -> bytes:
        """Return the AEAD key derived from a TLS 1.3 traffic secret.

        TODO: implement per RFC 8446 §7.1 using HKDF-Expand-Label with
        the label "tls13 key". Return the AEAD key bytes (16 for
        AES-128-GCM, 32 for AES-256-GCM).
        """
        raise NotImplementedError("fill in TLS 1.3 HKDF-Expand-Label here")

    def verify(self, candidate: bytes) -> bool:
        if len(candidate) != self.expected_length:
            return False
        try:
            key = self._derive_keys(candidate)
            AESGCM(key).decrypt(self.nonce, self.record, None)
            return True
        except Exception:
            return False
