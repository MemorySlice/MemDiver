"""Constraint-based validation of candidate cryptographic keys via KDF relationships.

Given a set of candidate key-material regions (typically from a prior
change-point or differential analysis), this algorithm attempts to verify
whether any pair of candidates is related through the protocol's Key
Derivation Function, discovered via the KDF plugin registry.

Confirmed KDF relationships boost the confidence of both endpoints, turning
statistical candidates into cryptographically validated ones.

All functions are stdlib-only (hmac, hashlib) with no external dependencies.
"""

from typing import Callable, Dict, List, Optional, Tuple

from algorithms.base import AlgorithmResult, AnalysisContext, BaseAlgorithm, Match
from core.constants import UNKNOWN_KEY
from core.kdf import TLS12PRF, TLS13HKDF
from core.kdf_registry import get_kdf_registry
from core.kdf_ssh import SSH2KDF


# Expected key sizes per protocol version.
_TLS12_KEY_SIZE = 48  # pre-master / master secret
_TLS13_KEY_SIZE = 32  # HKDF-based secrets (SHA-256)
_SSH2_KEY_SIZE = 32

# Confidence thresholds.
_KDF_MATCH_CONFIDENCE = 0.95
_GROUND_TRUTH_CONFIDENCE = 1.0
_PARTIAL_MATCH_CONFIDENCE = 0.70

# Protocol string -> (protocol_name, version) for registry lookup.
_PROTOCOL_MAP: Dict[str, Tuple[str, str]] = {
    "TLS12": ("TLS", "12"),
    "TLS13": ("TLS", "13"),
    "SSH2": ("SSH", "2"),
}

# Protocol string -> (key_size, validation_label).
_CHAIN_PARAMS: Dict[str, Tuple[int, str]] = {
    "TLS12": (_TLS12_KEY_SIZE, "tls12_prf"),
    "TLS13": (_TLS13_KEY_SIZE, "tls13_hkdf"),
    "SSH2": (_SSH2_KEY_SIZE, "ssh2_kdf"),
}


class ConstraintValidatorAlgorithm(BaseAlgorithm):
    """Validate candidate keys via KDF relationship verification.

    Reads ``context.extra["candidates"]`` (a ``List[Match]`` produced by a
    prior algorithm such as ``change_point`` or ``entropy_scan``) and tests
    all pairwise KDF derivations to find cryptographically linked pairs.

    If ``context.secrets`` contains ground-truth secrets from a keylog file,
    candidates are also validated against those known values.
    """

    name = "constraint_validator"
    description = "Validate candidate keys via KDF relationship verification"
    mode = UNKNOWN_KEY

    # ------------------------------------------------------------------ #
    #  Public interface
    # ------------------------------------------------------------------ #

    def run(self, dump_data: bytes, context: AnalysisContext) -> AlgorithmResult:
        """Run constraint validation on candidate keys.

        Args:
            dump_data: Raw memory dump bytes.
            context:   Analysis context. Expected extra keys:
                       - ``candidates``: ``List[Match]`` from a prior run.

        Returns:
            ``AlgorithmResult`` with validated matches and metadata.
        """
        candidates: List[Match] = context.extra.get("candidates", [])
        if not candidates:
            return AlgorithmResult(
                algorithm_name=self.name,
                confidence=0.0,
                matches=[],
                metadata={"reason": "no candidates provided"},
            )

        tls_version = context.protocol_version
        validated: List[Match] = []
        kdf_links_found = 0

        # Step 1: pairwise KDF validation via registry lookup.
        proto_info = _PROTOCOL_MAP.get(tls_version)
        if proto_info is None:
            return AlgorithmResult(
                algorithm_name=self.name,
                confidence=0.0,
                matches=[],
                metadata={"reason": f"unsupported protocol version: {tls_version}"},
            )
        registry = get_kdf_registry()
        kdf_plugin = registry.get_for_protocol(*proto_info)
        if kdf_plugin is None:
            return AlgorithmResult(
                algorithm_name=self.name,
                confidence=0.0,
                matches=[],
                metadata={"reason": f"no KDF plugin for {tls_version}"},
            )

        # Dispatch to chain validation with protocol-specific probe function.
        chain_params = _CHAIN_PARAMS.get(tls_version)
        probe_fn = self._PROBE_FUNCTIONS.get(tls_version)
        pairwise_matches, kdf_links_found = self._validate_chain(
            candidates, dump_data, kdf_plugin,
            key_size=chain_params[0],
            validation_label=chain_params[1],
            probe_fn=probe_fn,
        )
        validated.extend(pairwise_matches)

        # Step 2: ground-truth validation (if secrets are available).
        gt_matches = 0
        if context.secrets:
            for match in validated:
                for secret in context.secrets:
                    if match.data == secret.secret_value:
                        match.confidence = _GROUND_TRUTH_CONFIDENCE
                        match.metadata["ground_truth_type"] = secret.secret_type
                        gt_matches += 1

        # Overall confidence: ratio of validated candidates.
        overall = (
            min(len(validated) / max(len(candidates), 1), 1.0)
            if validated
            else 0.0
        )

        return AlgorithmResult(
            algorithm_name=self.name,
            confidence=round(overall, 4),
            matches=validated,
            metadata={
                "total_candidates": len(candidates),
                "validated_count": len(validated),
                "kdf_links_found": kdf_links_found,
                "ground_truth_matches": gt_matches,
                "protocol_version": tls_version,
            },
        )

    # ------------------------------------------------------------------ #
    #  Unified chain validation
    # ------------------------------------------------------------------ #

    def _validate_chain(
        self,
        candidates: List[Match],
        dump_data: bytes,
        kdf_plugin,
        key_size: int,
        validation_label: str,
        probe_fn: Optional[Callable[[bytes, int], bytes]] = None,
    ) -> Tuple[List[Match], int]:
        """Validate KDF chains among candidates of a given key size.

        1. Pairwise validation via ``kdf_plugin.validate_pair()``.
        2. Probe-in-dump fallback using ``probe_fn(candidate_data, key_size)``.

        Returns:
            Tuple of (validated matches, number of KDF links found).
        """
        sized = [c for c in candidates if len(c.data) == key_size]
        validated: List[Match] = []
        seen_offsets: set = set()
        links = 0

        for i, cand_a in enumerate(sized):
            for j in range(i + 1, len(sized)):
                cand_b = sized[j]
                confidence = kdf_plugin.validate_pair(
                    cand_a.data, cand_b.data, dump_data,
                )
                if confidence > 0.0:
                    links += 1
                    for cand in (cand_a, cand_b):
                        if cand.offset not in seen_offsets:
                            seen_offsets.add(cand.offset)
                            validated.append(Match(
                                offset=cand.offset,
                                length=cand.length,
                                confidence=confidence,
                                label=f"kdf_validated_{cand.label}",
                                data=cand.data,
                                metadata={
                                    **cand.metadata,
                                    "validation": validation_label,
                                    "kdf_confidence": round(confidence, 4),
                                },
                            ))

        # Probe-in-dump fallback for unvalidated candidates.
        if probe_fn is not None:
            for cand in sized:
                if cand.offset in seen_offsets:
                    continue
                derived = probe_fn(cand.data, key_size)
                if derived in dump_data:
                    seen_offsets.add(cand.offset)
                    links += 1
                    validated.append(Match(
                        offset=cand.offset,
                        length=cand.length,
                        confidence=_PARTIAL_MATCH_CONFIDENCE,
                        label=f"kdf_probe_{cand.label}",
                        data=cand.data,
                        metadata={
                            **cand.metadata,
                            "validation": f"{validation_label}_probe",
                        },
                    ))

        return validated, links

    # ------------------------------------------------------------------ #
    #  Protocol-specific probe functions
    # ------------------------------------------------------------------ #

    @staticmethod
    def _probe_tls12(data: bytes, key_size: int) -> bytes:
        probe_random = b"\x00" * 32
        return TLS12PRF.derive_master_secret(data, probe_random, probe_random)

    @staticmethod
    def _probe_tls13(data: bytes, key_size: int) -> bytes:
        zero_salt = b"\x00" * key_size
        return TLS13HKDF.hkdf_extract(zero_salt, data)

    @staticmethod
    def _probe_ssh2(data: bytes, key_size: int) -> bytes:
        probe_hash = b"\x00" * key_size
        return SSH2KDF.derive_key(data, probe_hash, "A", probe_hash, key_size)

    _PROBE_FUNCTIONS: Dict[str, Callable] = {
        "TLS12": _probe_tls12,
        "TLS13": _probe_tls13,
        "SSH2": _probe_ssh2,
    }

