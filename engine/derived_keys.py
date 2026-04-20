"""DerivedKeyExpander - compute derived keys via the KDF registry."""

import logging
from typing import List

from core.kdf_registry import get_kdf_registry
from core.models import CryptoSecret

logger = logging.getLogger("memdiver.engine.derived_keys")


class DerivedKeyExpander:
    """Expand traffic/session secrets into derived keys and IVs.

    Delegates to registered KDF plugins via the KDF registry rather than
    hard-coding TLS 1.3 HKDF.  Each KDF plugin advertises the secret
    types it can expand via ``supported_secret_types()``.
    """

    # Kept for backward compatibility -- callers that reference
    # DerivedKeyExpander.TRAFFIC_SECRET_TYPES will still work.
    TRAFFIC_SECRET_TYPES = {
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_TRAFFIC_SECRET_0",
        "SERVER_TRAFFIC_SECRET_0",
    }

    def expand_secrets(
        self,
        secrets: List[CryptoSecret],
        key_lengths: List[int] = None,
        hash_algo: str = "sha256",
    ) -> List[CryptoSecret]:
        """Expand secrets into derived keys using registered KDF plugins.

        For each secret, finds the first KDF plugin whose
        ``supported_secret_types()`` contains the secret's type and
        delegates expansion to ``kdf.expand_traffic_secret()``.

        Args:
            secrets: List of secrets to expand.
            key_lengths: Key sizes to try (forwarded to KDF plugin).
            hash_algo: Hash algorithm (forwarded to KDF plugin).

        Returns:
            New CryptoSecret objects for each derived key/IV.
        """
        registry = get_kdf_registry()
        type_to_kdf = {}
        for kdf in registry.list_all():
            for st in kdf.supported_secret_types():
                type_to_kdf.setdefault(st, kdf)
        derived: List[CryptoSecret] = []
        expanded_count = 0

        for secret in secrets:
            kdf = type_to_kdf.get(secret.secret_type)
            if kdf is not None:
                expanded_count += 1
                derived.extend(
                    kdf.expand_traffic_secret(secret, key_lengths, hash_algo)
                )

        logger.info(
            "Expanded %d secrets into %d derived keys",
            expanded_count,
            len(derived),
        )
        return derived
