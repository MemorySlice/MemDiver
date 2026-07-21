"""Tests for the constraint validator algorithm (TLS KDF relationship verification).

Validates empty-candidate handling, TLS 1.2 PRF chain detection, TLS 1.3
HKDF-Expand-Label chain detection, ground-truth confidence boosting, and
size filtering behavior for mixed-size candidates.
"""

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from memdiver.algorithms.unknown_key.constraint_validator import ConstraintValidatorAlgorithm
from memdiver.algorithms.base import AnalysisContext, Match
from memdiver.core.models import TLSSecret
from memdiver.core.kdf import TLS12PRF, TLS13HKDF
from memdiver.core.kdf_ssh import SSH2KDF


def test_empty_candidates():
    """No candidates provided results in zero confidence and a reason in metadata."""
    algo = ConstraintValidatorAlgorithm()
    context = AnalysisContext(
        library="test",
        tls_version="TLS13",
        phase="pre_abort",
        extra={"candidates": []},
    )
    result = algo.run(b"\x00" * 256, context)
    assert result.confidence == 0.0
    assert "reason" in result.metadata


def test_tls12_kdf_link():
    """Two 48-byte candidates linked by TLS 1.2 PRF derivation are validated.

    candidate_a is treated as a pre-master secret. candidate_b is the master
    secret derived via PRF(pms, 'master secret', client_random + server_random)
    with zero-filled randoms (the probe mode used by the validator).
    """
    algo = ConstraintValidatorAlgorithm()
    pms = b"\x42" * 48
    probe_random = b"\x00" * 32
    ms = TLS12PRF.derive_master_secret(pms, probe_random, probe_random)

    match_pms = Match(
        offset=0, length=48, confidence=0.5, label="pms", data=pms, metadata={}
    )
    match_ms = Match(
        offset=100, length=48, confidence=0.5, label="ms", data=ms, metadata={}
    )

    # Build dump_data containing both candidates so the probe search can
    # also find the derived master secret in the dump.
    dump_data = pms + b"\x00" * 52 + ms + b"\x00" * 100

    context = AnalysisContext(
        library="test",
        tls_version="TLS12",
        phase="pre_abort",
        extra={"candidates": [match_pms, match_ms]},
    )
    result = algo.run(dump_data, context)
    assert result.metadata["kdf_links_found"] > 0
    assert len(result.matches) > 0


def test_tls13_kdf_link():
    """Two 32-byte candidates linked by TLS 1.3 HKDF-Expand-Label are validated.

    candidate_a is a secret; candidate_b is derived via
    HKDF-Expand-Label(secret_a, 'derived', empty_hash, 32).  The pairwise
    check in the validator tries this label and should find the match.
    """
    algo = ConstraintValidatorAlgorithm()
    secret_a = b"\x42" * 32
    # Real TLS 1.3 Derive-Secret over the empty transcript uses SHA256(""),
    # not zero bytes (RFC 8446 Section 7.1).
    empty_hash = hashlib.sha256(b"").digest()
    derived = TLS13HKDF.hkdf_expand_label(secret_a, "derived", empty_hash, 32)

    match_a = Match(
        offset=0, length=32, confidence=0.5, label="a", data=secret_a, metadata={}
    )
    match_b = Match(
        offset=100, length=32, confidence=0.5, label="b", data=derived, metadata={}
    )

    dump_data = secret_a + b"\x00" * 68 + derived + b"\x00" * 100

    context = AnalysisContext(
        library="test",
        tls_version="TLS13",
        phase="pre_abort",
        extra={"candidates": [match_a, match_b]},
    )
    result = algo.run(dump_data, context)
    assert result.metadata["kdf_links_found"] > 0
    assert len(result.matches) > 0


def test_ground_truth_boost():
    """After a KDF link is found, ground-truth matching boosts confidence to 1.0.

    Uses TLS 1.2 PRF to create a validated pair, then provides a ground-truth
    secret whose value matches one of the validated candidates.  The validator
    should set that match's confidence to 1.0 and increment ground_truth_matches.
    """
    algo = ConstraintValidatorAlgorithm()
    pms = b"\x42" * 48
    probe_random = b"\x00" * 32
    ms = TLS12PRF.derive_master_secret(pms, probe_random, probe_random)

    match_pms = Match(
        offset=0, length=48, confidence=0.5, label="pms", data=pms, metadata={}
    )
    match_ms = Match(
        offset=100, length=48, confidence=0.5, label="ms", data=ms, metadata={}
    )

    dump_data = pms + b"\x00" * 52 + ms + b"\x00" * 100

    # Provide ground truth that matches the PMS candidate.
    secret = TLSSecret(
        secret_type="CLIENT_RANDOM",
        client_random=b"\x00" * 32,
        secret_value=pms,
    )

    context = AnalysisContext(
        library="test",
        tls_version="TLS12",
        phase="pre_abort",
        secrets=[secret],
        extra={"candidates": [match_pms, match_ms]},
    )
    result = algo.run(dump_data, context)
    assert result.metadata["ground_truth_matches"] > 0
    # At least one validated match should have confidence boosted to 1.0.
    boosted = [m for m in result.matches if m.confidence == 1.0]
    assert len(boosted) > 0


def test_mixed_sizes_only_matching_evaluated():
    """Only candidates matching the expected key size for the TLS version are evaluated.

    For TLS 1.2, only 48-byte candidates participate in pairwise KDF checks.
    A 32-byte candidate mixed in should not produce spurious links.
    """
    algo = ConstraintValidatorAlgorithm()
    pms = b"\x42" * 48
    probe_random = b"\x00" * 32
    ms = TLS12PRF.derive_master_secret(pms, probe_random, probe_random)

    # 48-byte candidates that are KDF-linked.
    match_48a = Match(
        offset=0, length=48, confidence=0.5, label="pms", data=pms, metadata={}
    )
    match_48b = Match(
        offset=100, length=48, confidence=0.5, label="ms", data=ms, metadata={}
    )
    # 32-byte candidate that should be ignored for TLS 1.2 pairwise checks.
    match_32 = Match(
        offset=200, length=32, confidence=0.5, label="noise",
        data=b"\xaa" * 32, metadata={},
    )

    dump_data = pms + b"\x00" * 52 + ms + b"\x00" * 52 + b"\xaa" * 32 + b"\x00" * 68

    context = AnalysisContext(
        library="test",
        tls_version="TLS12",
        phase="pre_abort",
        extra={"candidates": [match_48a, match_48b, match_32]},
    )
    result = algo.run(dump_data, context)
    # KDF links should be found from the 48-byte pair.
    assert result.metadata["kdf_links_found"] > 0
    # The 32-byte candidate should NOT appear in validated matches.
    validated_offsets = [m.offset for m in result.matches]
    assert 200 not in validated_offsets, (
        "32-byte candidate should not be validated in TLS 1.2 mode"
    )


def test_plugin_dispatch():
    """KDF registry lookup dispatches to the correct plugin for TLS 1.3.

    Creates two 32-byte candidates linked by HKDF-Expand-Label (via the
    'derived' label) and verifies the constraint validator finds the link
    through the KDF registry rather than inline code.
    """
    algo = ConstraintValidatorAlgorithm()
    secret_a = b"\x55" * 32
    # Real TLS 1.3 Derive-Secret over the empty transcript uses SHA256("").
    empty_hash = hashlib.sha256(b"").digest()
    derived = TLS13HKDF.hkdf_expand_label(secret_a, "derived", empty_hash, 32)

    match_a = Match(
        offset=0, length=32, confidence=0.5, label="a", data=secret_a, metadata={}
    )
    match_b = Match(
        offset=100, length=32, confidence=0.5, label="b", data=derived, metadata={}
    )

    dump_data = secret_a + b"\x00" * 68 + derived + b"\x00" * 100

    context = AnalysisContext(
        library="test",
        tls_version="TLS13",
        phase="pre_abort",
        extra={"candidates": [match_a, match_b]},
    )
    result = algo.run(dump_data, context)
    assert result.metadata["kdf_links_found"] > 0
    assert result.metadata["protocol_version"] == "TLS13"
    assert len(result.matches) == 2
    # Both candidates should be validated with high confidence.
    for m in result.matches:
        assert m.confidence >= 0.9
        assert "kdf_validated_" in m.label


def test_unknown_protocol_graceful():
    """Unsupported protocol version returns zero confidence with an explanatory reason."""
    algo = ConstraintValidatorAlgorithm()
    dummy_match = Match(
        offset=0, length=32, confidence=0.5, label="x",
        data=b"\xaa" * 32, metadata={},
    )

    context = AnalysisContext(
        library="test",
        tls_version="WPA2",
        phase="capture",
        extra={"candidates": [dummy_match]},
    )
    result = algo.run(b"\x00" * 256, context)
    assert result.confidence == 0.0
    assert len(result.matches) == 0
    assert "reason" in result.metadata
    assert "WPA2" in result.metadata["reason"]


def test_ssh2_non_32_byte_candidate_reaches_validation():
    """SSH-2 mode no longer drops non-32-byte candidates from validation.

    Regression: the chain filter kept only ``len == 32`` candidates, so links
    to SSH-2 IVs (8/12/16) and HMAC keys (20) were never even tested. A
    non-32-byte candidate must now participate. This exercises the zero-filled
    ``_probe_ssh2`` FALLBACK: when no real exchange-hash / session_id blobs are
    discoverable in the candidate pool, the deterministic zero-filled probe
    derivation placed in the dump must still validate the candidate.

    A 16-byte IV-length candidate is used: 16 is NOT one of the SSH hash sizes
    (20/32/64), so it is not mistaken for a discovered H/session_id, and the
    pool yields no hash candidates -- forcing the zero-filled fallback path.
    """
    algo = ConstraintValidatorAlgorithm()
    iv_candidate = b"\x09" * 16  # 16-byte candidate that previously was dropped
    assert len(iv_candidate) == 16

    # _probe_ssh2 derives derive_key(data, zero32, "A", zero32, 32) and checks
    # membership in the dump. Place that exact value in the dump.
    probe_out = SSH2KDF.derive_key(
        iv_candidate, b"\x00" * 32, "A", b"\x00" * 32, 32
    )

    match_hmac = Match(
        offset=0, length=16, confidence=0.5, label="iv",
        data=iv_candidate, metadata={},
    )

    dump_data = iv_candidate + b"\x00" * 64 + probe_out + b"\x00" * 64

    context = AnalysisContext(
        library="test",
        tls_version="SSH2",
        phase="pre_abort",
        extra={"candidates": [match_hmac]},
    )
    result = algo.run(dump_data, context)
    assert result.metadata["kdf_links_found"] > 0
    validated_offsets = {m.offset for m in result.matches}
    assert 0 in validated_offsets, "20-byte SSH-2 candidate should be validated"


def test_ssh2_probe_uses_key_size_not_candidate_length():
    """_probe_ssh2 derives a fixed 32-byte probe regardless of candidate length."""
    derived = ConstraintValidatorAlgorithm._probe_ssh2(b"\x05" * 20, 32)
    assert len(derived) == 32


# ------------------------------------------------------------------ #
#  Honest SSH-2 detection via discovered exchange hash / session_id
# ------------------------------------------------------------------ #


def _ssh2_handshake():
    """Synthetic SSH-2 handshake: K, not-zero 32-byte H and session_id."""
    K = bytes(range(100, 132))
    H = bytes(range(32, 64))
    session_id = bytes(range(64, 96))
    derived = SSH2KDF.derive_all_keys(K, H, session_id, 32)
    return K, H, session_id, derived


def test_ssh2_probe_validates_lone_k_with_discovered_hashes():
    """A lone K candidate validates when (H, session_id) are discoverable.

    The candidate pool surfaces H and session_id (32-byte hash-sized blobs) and
    the shared secret K. The genuine SSH probe derives keys A-F from K using the
    discovered (H, session_id) pairs; those derived keys planted in the dump
    confirm K via the probe-in-dump path.
    """
    algo = ConstraintValidatorAlgorithm()
    K, H, session_id, derived = _ssh2_handshake()

    match_k = Match(
        offset=0, length=32, confidence=0.5, label="k", data=K, metadata={}
    )
    match_h = Match(
        offset=100, length=32, confidence=0.5, label="h", data=H, metadata={}
    )
    match_sid = Match(
        offset=200, length=32, confidence=0.5, label="sid",
        data=session_id, metadata={},
    )

    # Dump contains K, H, session_id and the real derived keys among padding.
    dump_data = (
        b"\x00" * 8 + K + b"\x11" * 8 + H + b"\x22" * 8 + session_id
        + b"\x33" * 8 + b"".join(derived.values()) + b"\x44" * 16
    )

    context = AnalysisContext(
        library="test",
        tls_version="SSH2",
        phase="pre_abort",
        extra={"candidates": [match_k, match_h, match_sid]},
    )
    result = algo.run(dump_data, context)
    assert result.metadata["kdf_links_found"] > 0
    validated_offsets = {m.offset for m in result.matches}
    assert 0 in validated_offsets, "lone K should be validated via discovered hashes"


def test_ssh2_full_run_detects_planted_keys():
    """A full run() over an SSH-2 context detects planted, KDF-linked keys.

    K and a true derived key (type C) form a genuine pair; H and session_id are
    present in the candidate pool so validate_pair can confirm the link.
    """
    algo = ConstraintValidatorAlgorithm()
    K, H, session_id, derived = _ssh2_handshake()

    match_k = Match(
        offset=0, length=32, confidence=0.5, label="k", data=K, metadata={}
    )
    match_c = Match(
        offset=300, length=32, confidence=0.5, label="enc",
        data=derived["C"], metadata={},
    )
    match_h = Match(
        offset=100, length=32, confidence=0.5, label="h", data=H, metadata={}
    )
    match_sid = Match(
        offset=200, length=32, confidence=0.5, label="sid",
        data=session_id, metadata={},
    )

    dump_data = (
        b"\x00" * 8 + K + b"\x11" * 8 + H + b"\x22" * 8 + session_id
        + b"\x33" * 8 + derived["C"] + b"\x44" * 16
    )

    context = AnalysisContext(
        library="test",
        tls_version="SSH2",
        phase="pre_abort",
        extra={"candidates": [match_k, match_c, match_h, match_sid]},
    )
    result = algo.run(dump_data, context)
    assert result.metadata["kdf_links_found"] > 0
    validated_offsets = {m.offset for m in result.matches}
    # The genuine K / derived-C pair must be detected.
    assert 0 in validated_offsets
    assert 300 in validated_offsets
