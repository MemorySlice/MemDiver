"""Tests for the ``inspect_pcap`` producer (app.tools_pipeline).

``inspect_pcap`` is the pcap "arm/validate" step: it parses a capture's TLS
handshakes and returns one JSON-friendly summary dict per session — the single
implementation behind the ``POST /api/pcaps/validate`` route, the MCP
``inspect_pcap`` tool, and the CLI ``inspect-pcap`` command. These tests cover
its three contract paths: a real capture (happy), the ``pcap`` extra missing
(UNSUPPORTED), and an unreadable/non-pcap file (INVALID_INPUT).

The happy path needs dpkt (the ``[pcap]`` extra); it skips cleanly otherwise.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from memdiver.app.tools_pipeline import inspect_pcap
from memdiver.core.service_errors import CapabilityError, ErrorCategory

# A real TLS 1.3 capture produced by an openssl run (one session on the wire).
REAL_PCAP = Path(
    "/Users/danielbaier/Desktop/tls_dumps/TLS13/"
    "100_iterations_Abort_KeyUpdate/openssl/openssl_run_13_1/"
    "run_data/traffic.pcap"
)


# ---------------------------------------------------------------------------
# Happy path — a genuine capture yields at least one session
# ---------------------------------------------------------------------------


def test_inspect_pcap_happy_path(tmp_path):
    """A real capture parses to >=1 session with a 64-hex client_random."""
    pytest.importorskip("dpkt")
    if not REAL_PCAP.is_file():
        pytest.skip(f"sample capture not present: {REAL_PCAP}")

    # Copy into a tmp dir so the test does not depend on the source's mode.
    local = tmp_path / "traffic.pcap"
    local.write_bytes(REAL_PCAP.read_bytes())

    result = inspect_pcap(pcap_path=str(local))

    assert result["pcap_path"] == str(local)
    assert result["session_count"] >= 1
    assert len(result["sessions"]) == result["session_count"]

    session = result["sessions"][0]
    assert len(session["client_random"]) == 64  # 32 bytes rendered as hex
    bytes.fromhex(session["client_random"])      # must be valid hex
    assert session["version"] in ("12", "13")
    assert isinstance(session["cipher_suite"], int)
    assert isinstance(session["cipher_name"], str) and session["cipher_name"]
    assert isinstance(session["client_app_records"], int)
    assert isinstance(session["server_app_records"], int)


# ---------------------------------------------------------------------------
# dpkt missing → CapabilityError(UNSUPPORTED)
# ---------------------------------------------------------------------------


def test_inspect_pcap_without_dpkt_is_unsupported(tmp_path, monkeypatch):
    """When the pcap extra (dpkt) is absent, the error funnels to UNSUPPORTED."""
    import memdiver.engine.resources.tls_pcap as tls_pcap

    monkeypatch.setattr(tls_pcap, "HAS_PCAP", False)

    # A path need not even exist: the availability guard fires first.
    with pytest.raises(CapabilityError) as exc_info:
        inspect_pcap(pcap_path=str(tmp_path / "whatever.pcap"))

    assert exc_info.value.category is ErrorCategory.UNSUPPORTED
    assert exc_info.value.status == 400  # UNSUPPORTED → 400 (no 503 in the model)


# ---------------------------------------------------------------------------
# bad / non-pcap file → CapabilityError(INVALID_INPUT)
# ---------------------------------------------------------------------------


def test_inspect_pcap_bad_file_is_invalid_input(tmp_path):
    """A file that is not a readable capture funnels to INVALID_INPUT."""
    pytest.importorskip("dpkt")

    junk = tmp_path / "not-a-capture.pcap"
    junk.write_bytes(b"this is plainly not a pcap file" * 4)

    with pytest.raises(CapabilityError) as exc_info:
        inspect_pcap(pcap_path=str(junk))

    assert exc_info.value.category is ErrorCategory.INVALID_INPUT
    assert exc_info.value.status == 400


def test_inspect_pcap_truncated_capture_is_invalid_input(tmp_path):
    """A truncated capture (valid pcap magic, body cut short) funnels cleanly.

    dpkt raises its own ``dpkt.dpkt.NeedData`` (base ``dpkt.dpkt.Error``, which
    is NOT an ``OSError``/``ValueError``) when the global header is incomplete;
    without the widened funnel that escaped as an uncaught stack trace / HTTP
    500. It must now map to a ``CapabilityError(INVALID_INPUT)``.
    """
    pytest.importorskip("dpkt")

    # 7 bytes: the classic little-endian pcap magic + a partial global header.
    truncated = tmp_path / "truncated.pcap"
    truncated.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x00")

    with pytest.raises(CapabilityError) as exc_info:
        inspect_pcap(pcap_path=str(truncated))

    assert exc_info.value.category is ErrorCategory.INVALID_INPUT
    assert exc_info.value.status == 400


def test_inspect_pcap_reports_has_app_records(tmp_path):
    """Each session summary carries a bool ``has_app_records`` flag.

    A genuine capture with encrypted application-data records reports True — the
    signal the frontend uses to disable oracle-unusable (0-record) sessions.
    """
    pytest.importorskip("dpkt")
    if not REAL_PCAP.is_file():
        pytest.skip(f"sample capture not present: {REAL_PCAP}")

    local = tmp_path / "traffic.pcap"
    local.write_bytes(REAL_PCAP.read_bytes())

    result = inspect_pcap(pcap_path=str(local))
    session = result["sessions"][0]
    assert "has_app_records" in session
    assert isinstance(session["has_app_records"], bool)
    # The real capture carries application-data records in at least one direction.
    assert session["has_app_records"] is True
    # Consistency: the flag agrees with the per-direction counts.
    assert session["has_app_records"] == bool(
        session["client_app_records"] + session["server_app_records"] > 0
    )
