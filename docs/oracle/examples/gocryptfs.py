"""Gocryptfs master-key oracle.

A candidate is treated as the 32-byte **unwrapped** master key (already
resident in process memory — scrypt is irrelevant on the hot path).
Verification derives the per-instance content key and AEAD-decrypts the
first block of a real ciphertext file from the vault.

gocryptfs v2 on-disk format (per file):

    file_header = version(2 big-endian) || file_id(16)
    block_0     = nonce(16) || ciphertext(4096) || gcm_tag(16)
    block_1     = nonce(16) || ciphertext(4096) || gcm_tag(16)
    ...

Content key:

    content_key = HKDF-SHA256(master_key,
                              info="AES-GCM file content encryption",
                              length=32)

Per-block AEAD:

    AES-256-GCM( key    = content_key,
                 nonce  = block.nonce,
                 ct+tag = block.ciphertext || block.gcm_tag,
                 aad    = block_num (8 big-endian) || file_id (16) )

A successful tag verify on block 0 ⇒ this candidate is the real master
key. Wrong candidates fail with ``InvalidTag``; the ``except`` below
returns False. ~150 µs per candidate on CPython, no filesystem mount.

Requires ``pip install cryptography``.

Driven by a TOML config passed via ``--oracle-config``:

    # gocryptfs_oracle.toml
    sample_ciphertext = "/path/to/vault/<encrypted_file>"

The ``sample_ciphertext`` path must point at any file encrypted by the
target gocryptfs instance. Its header_id is read directly from the
first 18 bytes.
"""

from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MASTER_KEY_LENGTH = 32
HEADER_VERSION_LENGTH = 2
HEADER_ID_LENGTH = 16
NONCE_LENGTH = 16
GCM_TAG_LENGTH = 16
CONTENT_KEY_INFO = b"AES-GCM file content encryption"


def build_oracle(config: dict) -> "GocryptfsOracle":
    return GocryptfsOracle(config)


class GocryptfsOracle:
    def __init__(self, config: dict):
        sample = Path(config["sample_ciphertext"]).read_bytes()
        min_size = (
            HEADER_VERSION_LENGTH + HEADER_ID_LENGTH
            + NONCE_LENGTH + GCM_TAG_LENGTH
        )
        if len(sample) < min_size:
            raise ValueError(
                f"sample ciphertext too short ({len(sample)} < {min_size})"
            )
        self.header_id = sample[
            HEADER_VERSION_LENGTH : HEADER_VERSION_LENGTH + HEADER_ID_LENGTH
        ]
        body = sample[HEADER_VERSION_LENGTH + HEADER_ID_LENGTH :]
        self.nonce = body[:NONCE_LENGTH]
        self.ct_and_tag = body[NONCE_LENGTH:]
        # Block 0 AAD = block_num(8 BE) || file_header_id(16)
        self.aad = (0).to_bytes(8, "big") + self.header_id

    def verify(self, candidate: bytes) -> bool:
        if len(candidate) != MASTER_KEY_LENGTH:
            return False
        try:
            content_key = HKDF(
                algorithm=hashes.SHA256(),
                length=MASTER_KEY_LENGTH,
                salt=None,
                info=CONTENT_KEY_INFO,
            ).derive(candidate)
            AESGCM(content_key).decrypt(self.nonce, self.ct_and_tag, self.aad)
            return True
        except Exception:
            return False
