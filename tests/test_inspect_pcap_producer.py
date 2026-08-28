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


# ---------------------------------------------------------------------------
# Reportable truncation (Wave 0 D0c): the four additive accounting keys
# ---------------------------------------------------------------------------


def test_inspect_pcap_reports_drop_accounting(tmp_path):
    """The four additive keys are present and correctly typed on a real parse.

    A corpus sweep reads these to tell "this capture held one session" apart
    from "this capture held one session and we quietly threw three away".
    """
    pytest.importorskip("dpkt")
    if not REAL_PCAP.is_file():
        pytest.skip(f"sample capture not present: {REAL_PCAP}")

    local = tmp_path / "traffic.pcap"
    local.write_bytes(REAL_PCAP.read_bytes())

    result = inspect_pcap(pcap_path=str(local))

    # Nothing the producer returned before has gone away.
    assert {"pcap_path", "session_count", "sessions"} <= set(result)

    assert isinstance(result["skipped_sessions"], list)
    for entry in result["skipped_sessions"]:
        assert isinstance(entry, dict)
        assert isinstance(entry["reason"], str) and entry["reason"]

    assert isinstance(result["flow_count"], int)
    # A capture that yielded a session must have yielded at least its two flows.
    assert result["flow_count"] >= 2

    assert isinstance(result["caps"], dict)
    assert isinstance(result["caps"]["max_records_per_direction"], int)
    assert result["caps"]["max_records_per_direction"] > 0
    # Both caps are reported, not just the record one: a challenge cap truncates
    # verification just as silently. No cap argument was passed here, so this is
    # the resource default (no cap) -- but the KEY is always present, so a caller
    # can never mistake "uncapped" for "unreported".
    assert "max_challenges" in result["caps"]
    assert result["caps"]["max_challenges"] is None

    assert isinstance(result["records_truncated"], bool)

    # Per-session accounting makes the cap's effect checkable, not just flagged.
    session = result["sessions"][0]
    assert isinstance(session["app_records_seen"], int)
    assert isinstance(session["records_returned"], int)
    assert session["records_returned"] <= session["app_records_seen"]
    assert session["app_records_seen"] == (
        session["client_app_records"] + session["server_app_records"]
    )
    # The headline flag agrees with the per-session numbers.
    assert result["records_truncated"] == any(
        s["records_returned"] < s["app_records_seen"] for s in result["sessions"]
    )


def test_inspect_pcap_zero_session_capture_still_reports_counts(tmp_path):
    """A parseable capture with no TLS session keeps ``session_count: 0``.

    Documented existing behaviour (a zero-session capture is NOT an error); the
    new accounting keys must explain the zero rather than replace it.
    """
    dpkt = pytest.importorskip("dpkt")
    import socket

    # One plain HTTP-over-TCP frame: readable pcap, zero TLS handshakes.
    tcp = dpkt.tcp.TCP(sport=5555, dport=80, seq=1000, ack=0,
                       flags=dpkt.tcp.TH_ACK, data=b"GET / HTTP/1.0\r\n\r\n")
    ip = dpkt.ip.IP(src=socket.inet_aton("10.0.0.1"), dst=socket.inet_aton("10.0.0.2"),
                    p=dpkt.ip.IP_PROTO_TCP, data=tcp)
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x00" * 6,
                                 type=dpkt.ethernet.ETH_TYPE_IP, data=ip)

    capture = tmp_path / "no-tls.pcap"
    with open(capture, "wb") as handle:
        dpkt.pcap.Writer(handle).writepkt(bytes(eth), ts=0.0)

    result = inspect_pcap(pcap_path=str(capture))

    assert result["session_count"] == 0
    assert result["sessions"] == []
    assert result["records_truncated"] is False
    # The zero is now explained: one flow seen, one flow dropped, with a reason.
    assert result["flow_count"] == 1
    assert [e["reason"] for e in result["skipped_sessions"]] == ["no_client_hello"]


def test_inspect_pcap_records_returned_tracks_the_challenge_stream(tmp_path):
    """``records_returned`` counts coverable records, not raw ones (BUG 1).

    A TLS 1.2 capture with no ChangeCipherSpec is the realistic case: its
    application data is not decryptable under the negotiated keys, so the oracle
    verifies nothing. The producer must surface that as zero coverage and a True
    ``records_truncated`` -- it previously reported the raw record total and
    ``False``, i.e. full coverage for a session that proves nothing.
    """
    dpkt = pytest.importorskip("dpkt")
    import socket

    def record(content_type, fragment):
        return (bytes([content_type]) + b"\x03\x03"
                + len(fragment).to_bytes(2, "big") + fragment)

    def handshake(msg_type, body):
        return bytes([msg_type]) + len(body).to_bytes(3, "big") + body

    client_random, server_random = bytes(range(32)), bytes(range(32, 64))
    cipher = (0xC02F).to_bytes(2, "big")
    client_hello = handshake(1, b"\x03\x03" + client_random + b"\x00"
                             + b"\x00\x02" + cipher + b"\x01\x00" + b"\x00\x00")
    server_hello = handshake(2, b"\x03\x03" + server_random + b"\x00"
                             + cipher + b"\x00" + b"\x00\x00")
    # Application data with NO preceding ChangeCipherSpec in either direction.
    client_flight = [record(22, client_hello)] + [record(23, bytes(64))] * 3
    server_flight = [record(22, server_hello)]

    def frame(src, dst, sport, dport, seq, payload):
        tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq, ack=0,
                           flags=dpkt.tcp.TH_ACK, data=payload)
        ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst),
                        p=dpkt.ip.IP_PROTO_TCP, data=tcp)
        ip.len = len(ip)
        return bytes(dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x00" * 6,
                                            type=dpkt.ethernet.ETH_TYPE_IP, data=ip))

    capture = tmp_path / "no-ccs.pcap"
    with open(capture, "wb") as handle:
        writer = dpkt.pcap.Writer(handle)
        seq = 1000
        for idx, rec in enumerate(client_flight):
            writer.writepkt(frame("10.0.0.1", "10.0.0.2", 12345, 443, seq, rec), ts=float(idx))
            seq += len(rec)
        writer.writepkt(frame("10.0.0.2", "10.0.0.1", 443, 12345, 5000, server_flight[0]),
                        ts=99.0)

    result = inspect_pcap(pcap_path=str(capture))

    session = result["sessions"][0]
    assert session["app_records_seen"] == 3
    assert session["records_returned"] == 0
    assert result["records_truncated"] is True
    # And the zero is explained rather than left as a bare zero.
    assert "no_change_cipher_spec" in [e["reason"] for e in result["skipped_sessions"]]


# ---------------------------------------------------------------------------
# Cap passthrough: the arm step must report the caps a RUN will actually use
# ---------------------------------------------------------------------------
#
# Without cap arguments this producer could only echo the resource DEFAULTS, so
# an operator who capped a brute-force run read back "uncapped" from the arm
# step and had no way to see the truncation coming. These tests pin the
# passthrough and the honesty keys that make a cap's effect visible.


def _tls12_no_ccs_capture(path, app_record_count):
    """Write a TLS 1.2 capture whose application data has no ChangeCipherSpec.

    Shares the frame construction with the record-accounting test above; kept
    local (not a fixture) so each caller picks its own record count.
    """
    import socket

    import dpkt

    def record(content_type, fragment):
        return (bytes([content_type]) + b"\x03\x03"
                + len(fragment).to_bytes(2, "big") + fragment)

    def handshake(msg_type, body):
        return bytes([msg_type]) + len(body).to_bytes(3, "big") + body

    client_random, server_random = bytes(range(32)), bytes(range(32, 64))
    cipher = (0xC02F).to_bytes(2, "big")
    client_hello = handshake(1, b"\x03\x03" + client_random + b"\x00"
                             + b"\x00\x02" + cipher + b"\x01\x00" + b"\x00\x00")
    server_hello = handshake(2, b"\x03\x03" + server_random + b"\x00"
                             + cipher + b"\x00" + b"\x00\x00")
    client_flight = ([record(22, client_hello)]
                     + [record(23, bytes(64))] * app_record_count)

    def frame(src, dst, sport, dport, seq, payload):
        tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq, ack=0,
                           flags=dpkt.tcp.TH_ACK, data=payload)
        ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst),
                        p=dpkt.ip.IP_PROTO_TCP, data=tcp)
        ip.len = len(ip)
        return bytes(dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x00" * 6,
                                            type=dpkt.ethernet.ETH_TYPE_IP, data=ip))

    with open(path, "wb") as handle:
        writer = dpkt.pcap.Writer(handle)
        seq = 1000
        for idx, rec in enumerate(client_flight):
            writer.writepkt(frame("10.0.0.1", "10.0.0.2", 12345, 443, seq, rec),
                            ts=float(idx))
            seq += len(rec)
        writer.writepkt(frame("10.0.0.2", "10.0.0.1", 443, 12345, 5000,
                              record(22, server_hello)), ts=99.0)
    return path


def test_inspect_pcap_reports_the_caps_it_was_given(tmp_path):
    """Explicit caps are echoed back in ``caps``, not the resource defaults."""
    pytest.importorskip("dpkt")
    capture = _tls12_no_ccs_capture(tmp_path / "capped.pcap", 3)

    result = inspect_pcap(pcap_path=str(capture),
                          pcap_max_records=2, pcap_max_challenges=5)

    assert result["caps"]["max_records_per_direction"] == 2
    assert result["caps"]["max_challenges"] == 5


def test_inspect_pcap_caps_default_to_the_resource_defaults(tmp_path):
    """Omitting a cap leaves the resource default in place (no restating here)."""
    pytest.importorskip("dpkt")
    from memdiver.engine.resources.tls_pcap import TlsPcapResource

    capture = _tls12_no_ccs_capture(tmp_path / "uncapped.pcap", 3)
    default = TlsPcapResource(str(capture))

    result = inspect_pcap(pcap_path=str(capture))

    assert result["caps"]["max_records_per_direction"] == default.max_records_per_direction
    assert result["caps"]["max_challenges"] is None


def test_inspect_pcap_record_cap_clips_the_session_and_flags_it(tmp_path):
    """A record cap shows up as reported truncation on a real capture.

    ``app_records_seen`` stays the RAW total (that is the point of the honesty
    pair) while ``records_returned`` drops to the cap, so the operator can read
    off exactly how much verification the cap is discarding.
    """
    pytest.importorskip("dpkt")
    if not REAL_PCAP.is_file():
        pytest.skip(f"sample capture not present: {REAL_PCAP}")

    local = tmp_path / "traffic.pcap"
    local.write_bytes(REAL_PCAP.read_bytes())

    uncapped = inspect_pcap(pcap_path=str(local))
    assert uncapped["records_truncated"] is False

    capped = inspect_pcap(pcap_path=str(local), pcap_max_records=1)

    session = capped["sessions"][0]
    assert capped["caps"]["max_records_per_direction"] == 1
    assert session["app_records_seen"] == uncapped["sessions"][0]["app_records_seen"]
    assert session["records_returned"] < session["app_records_seen"]
    assert capped["records_truncated"] is True


def test_inspect_pcap_reports_the_capture_level_challenge_stream(tmp_path):
    """The three challenge keys are present, typed, and internally consistent."""
    pytest.importorskip("dpkt")
    capture = _tls12_no_ccs_capture(tmp_path / "challenges.pcap", 3)

    result = inspect_pcap(pcap_path=str(capture))

    assert isinstance(result["challenges_available"], int)
    assert isinstance(result["challenges_returned"], int)
    assert isinstance(result["challenges_truncated"], bool)
    assert result["challenges_returned"] <= result["challenges_available"]
    assert result["challenges_truncated"] == (
        result["challenges_returned"] < result["challenges_available"]
    )
    # Capture-level totals are the sum of the per-session numbers, so a reader
    # can cross-check one against the other.
    assert result["challenges_available"] == sum(
        s["challenges_available"] for s in result["sessions"]
    )
    assert result["challenges_returned"] == sum(
        s["challenges_returned"] for s in result["sessions"]
    )


def test_inspect_pcap_real_capture_challenge_stream_is_capped_reportably(tmp_path):
    """On a real capture a challenge cap is visible as a truncated stream.

    The synthetic TLS 1.2 captures above yield zero coverable challenges, so
    only a genuine session can prove the cap reaches the challenge accounting.
    """
    pytest.importorskip("dpkt")
    if not REAL_PCAP.is_file():
        pytest.skip(f"sample capture not present: {REAL_PCAP}")

    local = tmp_path / "traffic.pcap"
    local.write_bytes(REAL_PCAP.read_bytes())

    uncapped = inspect_pcap(pcap_path=str(local))
    assert uncapped["challenges_available"] > 1
    assert uncapped["challenges_truncated"] is False

    capped = inspect_pcap(pcap_path=str(local), pcap_max_challenges=1)
    assert capped["caps"]["max_challenges"] == 1
    assert capped["challenges_returned"] == 1
    assert capped["challenges_truncated"] is True


@pytest.mark.parametrize("cap", ["pcap_max_records", "pcap_max_challenges"])
@pytest.mark.parametrize("value", [0, -1])
def test_inspect_pcap_rejects_a_cap_below_one(tmp_path, cap, value):
    """A cap below 1 is refused here exactly as ``brute_force`` refuses it.

    The arm step must not bless a cap the run itself would reject; a cap of 0
    verifies nothing, so accepting it here would advertise a setting that turns
    a genuine key into "0 confirmed".
    """
    pytest.importorskip("dpkt")
    capture = _tls12_no_ccs_capture(tmp_path / "bad-cap.pcap", 1)

    with pytest.raises(CapabilityError) as excinfo:
        inspect_pcap(pcap_path=str(capture), **{cap: value})

    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert cap in str(excinfo.value)
