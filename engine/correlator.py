"""SearchCorrelator - search static-mask-filtered regions for secrets."""

import logging
from pathlib import Path
from typing import List, Optional, Union

import numpy as np

try:
    import ahocorasick
    _HAS_AC = True
except ImportError:
    _HAS_AC = False

from algorithms.base import Match
from core.models import CryptoSecret
from core.variance import ByteClass
from .consensus import ConsensusVector
from .results import SecretHit

logger = logging.getLogger("memdiver.engine.correlator")


class SearchCorrelator:
    """Search only static regions for persistent key material.

    By filtering out volatile regions before searching, we reduce false
    positives from dynamic heap data that coincidentally matches key bytes.
    """

    def __init__(self, consensus: Optional[ConsensusVector] = None):
        self.consensus = consensus

    def search_all(
        self,
        dump_path: Union[Path, object],
        secrets: List[CryptoSecret],
        library: str = "",
        phase: str = "",
        run_id: int = 0,
    ) -> List[SecretHit]:
        """Search a dump for all secrets, optionally filtering by static mask.

        Args:
            dump_path: A Path to a dump file, or a DumpSource-compatible
                object with read_all() and path attributes.
        """
        if hasattr(dump_path, "read_all"):
            data = dump_path.read_all()
            resolved_path = dump_path.path if hasattr(dump_path, "path") else dump_path
        else:
            data = dump_path.read_bytes()
            resolved_path = dump_path

        if _HAS_AC and len(secrets) >= 2:
            return self._search_aho_corasick(
                data, secrets, library, phase, run_id, resolved_path,
            )

        hits = []

        for secret in secrets:
            needle = secret.secret_value
            start = 0
            while True:
                idx = data.find(needle, start)
                if idx == -1:
                    break
                hits.append(SecretHit(
                    secret_type=secret.secret_type,
                    offset=idx,
                    length=len(needle),
                    dump_path=resolved_path,
                    library=library,
                    phase=phase,
                    run_id=run_id,
                ))
                start = idx + 1

        path_name = resolved_path.name if hasattr(resolved_path, "name") else str(resolved_path)
        logger.debug("Found %d hits in %s", len(hits), path_name)
        return hits

    def _search_aho_corasick(
        self,
        data: bytes,
        secrets: List[CryptoSecret],
        library: str,
        phase: str,
        run_id: int,
        resolved_path,
    ) -> List[SecretHit]:
        """Single-pass multi-pattern search using Aho-Corasick automaton.

        pyahocorasick requires str keys, so we use latin-1 decoding
        which is a lossless 1:1 mapping for all byte values (0-255).
        """
        A = ahocorasick.Automaton()
        for i, secret in enumerate(secrets):
            key = secret.secret_value.decode("latin-1")
            A.add_word(key, (i, secret))
        A.make_automaton()
        text = data.decode("latin-1")
        hits = []
        for end_idx, (i, secret) in A.iter(text):
            start = end_idx - len(secret.secret_value) + 1
            hits.append(SecretHit(
                secret_type=secret.secret_type,
                offset=start,
                length=len(secret.secret_value),
                dump_path=resolved_path,
                library=library,
                phase=phase,
                run_id=run_id,
            ))
        path_name = resolved_path.name if hasattr(resolved_path, "name") else str(resolved_path)
        logger.debug("AC search: %d hits in %s", len(hits), path_name)
        return hits

    def search_static(
        self,
        dump_data: bytes,
        secrets: List[CryptoSecret],
    ) -> List[Match]:
        """Search only static regions of dump data for secrets."""
        if not self.consensus or not self.consensus.classifications:
            return self._search_unfiltered(dump_data, secrets)

        matches = []
        for secret in secrets:
            needle = secret.secret_value
            start = 0
            while True:
                idx = dump_data.find(needle, start)
                if idx == -1:
                    break
                if self._is_in_static_region(idx, len(needle)):
                    matches.append(Match(
                        offset=idx,
                        length=len(needle),
                        confidence=1.0,
                        label=secret.secret_type,
                        data=needle,
                        metadata={"source": "static_filtered"},
                    ))
                start = idx + 1
        return matches

    def _is_in_static_region(self, offset: int, length: int) -> bool:
        """Check if the given range falls within a non-volatile region."""
        if not self.consensus or not self.consensus.classifications:
            return True
        cls = self.consensus.classifications
        end = min(offset + length, len(cls))
        region = cls[offset:end]
        if hasattr(region, '__len__') and hasattr(region, '__eq__'):
            return not np.any(np.asarray(region) == ByteClass.KEY_CANDIDATE)
        return all(c != ByteClass.KEY_CANDIDATE for c in region)

    @staticmethod
    def _search_unfiltered(dump_data: bytes, secrets: List[CryptoSecret]) -> List[Match]:
        """Fallback: search without consensus filtering."""
        matches = []
        for secret in secrets:
            needle = secret.secret_value
            start = 0
            while True:
                idx = dump_data.find(needle, start)
                if idx == -1:
                    break
                matches.append(Match(
                    offset=idx,
                    length=len(needle),
                    confidence=1.0,
                    label=secret.secret_type,
                    data=needle,
                ))
                start = idx + 1
        return matches
