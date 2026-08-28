"""End-to-end proof for TlsPcapResource.

Builds a *genuine* synthetic TLS 1.2 AES-128-GCM session as a real ``.pcap`` on
disk — Ethernet/IP/TCP frames carrying a ClientHello, a ServerHello, both
ChangeCipherSpecs, and one application_data record encrypted with keys derived
from a known master secret via ``derive_tls12_keys`` — then feeds it through
``TlsPcapResource`` and a ``ResourceOracle`` and asserts:

  * the handshake facts (client/server random, cipher code, version) are
    extracted correctly onto the emitted challenge, and
  * the *correct* master secret verifies True while a wrong one verifies False.

That is the real contract: the parser's output must be shaped so the untouched
oracle confirms a memory-recovered key against captured bytes.

Skips cleanly when dpkt (the ``[pcap]`` extra) or cryptography is absent.
"""

import socket

import pytest

dpkt = pytest.importorskip("dpkt")

from memdiver.core.kdf_tls import derive_tls12_keys  # noqa: E402
from memdiver.engine.resources.oracle import ResourceOracle  # noqa: E402
from memdiver.engine.resources.tls_pcap import (  # noqa: E402
    PcapParseError,
    TlsPcapResource,
)
from memdiver.engine.verification import HAS_CRYPTO  # noqa: E402

pytestmark = pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")

if HAS_CRYPTO:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

# -- fixed session facts ---------------------------------------------------- #
MASTER_SECRET = bytes(range(1, 49))          # 48-byte TLS 1.2 master secret
WRONG_SECRET = bytes(range(48, 0, -1))       # a different 48-byte secret
CLIENT_RANDOM = bytes(range(32))
SERVER_RANDOM = bytes(range(32, 64))
CIPHER_CODE = 0xC02F                          # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
PLAINTEXT = b"GET /secret HTTP/1.1\r\nHost: x\r\n\r\n"

CLIENT_IP, CLIENT_PORT = "10.0.0.1", 12345
SERVER_IP, SERVER_PORT = "10.0.0.2", 443


# --------------------------------------------------------------------------- #
# Synthetic wire builders
# --------------------------------------------------------------------------- #

def _handshake(msg_type: int, body: bytes) -> bytes:
    """Wrap a handshake message body: type(1) || length(3) || body."""
    return bytes([msg_type]) + len(body).to_bytes(3, "big") + body


def _client_hello() -> bytes:
    body = (
        b"\x03\x03" + CLIENT_RANDOM + b"\x00"          # version, random, no session id
        + b"\x00\x02" + CIPHER_CODE.to_bytes(2, "big") # cipher suites (len 2, one suite)
        + b"\x01\x00"                                   # compression: null
        + b"\x00\x00"                                   # no extensions
    )
    return _handshake(1, body)


def _server_hello() -> bytes:
    body = (
        b"\x03\x03" + SERVER_RANDOM + b"\x00"           # version, random, no session id
        + CIPHER_CODE.to_bytes(2, "big")               # chosen cipher suite
        + b"\x00"                                        # compression: null
        + b"\x00\x00"                                   # no extensions
    )
    return _handshake(2, body)


def _tls_record(content_type: int, fragment: bytes) -> bytes:
    return bytes([content_type]) + b"\x03\x03" + len(fragment).to_bytes(2, "big") + fragment


def _app_data_record(seq: int) -> bytes:
    """A real AES-128-GCM application_data record under the client write keys."""
    keys = derive_tls12_keys(MASTER_SECRET, CLIENT_RANDOM, SERVER_RANDOM, CIPHER_CODE)
    explicit_nonce = seq.to_bytes(8, "big")            # any 8 bytes; echoed as record_iv
    nonce = keys.client_write_iv + explicit_nonce      # salt(4) || explicit(8)
    aad = seq.to_bytes(8, "big") + b"\x17\x03\x03" + len(PLAINTEXT).to_bytes(2, "big")
    blob = AESGCM(keys.client_write_key).encrypt(nonce, PLAINTEXT, aad)  # ciphertext||tag
    return _tls_record(23, explicit_nonce + blob)


def _frame(src_ip: str, dst_ip: str, sport: int, dport: int, seq: int, payload: bytes) -> bytes:
    tcp = dpkt.tcp.TCP(
        sport=sport, dport=dport, seq=seq, ack=0,
        flags=dpkt.tcp.TH_ACK, data=payload,
    )
    ip = dpkt.ip.IP(
        src=socket.inet_aton(src_ip), dst=socket.inet_aton(dst_ip),
        p=dpkt.ip.IP_PROTO_TCP, data=tcp,
    )
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(
        src=b"\x00\x00\x00\x00\x00\x01", dst=b"\x00\x00\x00\x00\x00\x02",
        type=dpkt.ethernet.ETH_TYPE_IP, data=ip,
    )
    return bytes(eth)


def _write_capture(path: str) -> None:
    """Emit a complete TLS 1.2 GCM session (client app-data record at seq 0)."""
    # client->server flight: ClientHello, ChangeCipherSpec, then app-data (seq 0)
    client_records = [
        _tls_record(22, _client_hello()),
        _tls_record(20, b"\x01"),
        _app_data_record(0),
    ]
    # server->client flight: ServerHello, ChangeCipherSpec
    server_records = [
        _tls_record(22, _server_hello()),
        _tls_record(20, b"\x01"),
    ]

    packets = []
    c_seq = 1000
    for rec in client_records:
        packets.append(_frame(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, c_seq, rec))
        c_seq += len(rec)
    s_seq = 5000
    for rec in server_records:
        packets.append(_frame(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, s_seq, rec))
        s_seq += len(rec)

    with open(path, "wb") as handle:
        writer = dpkt.pcap.Writer(handle)
        for idx, pkt in enumerate(packets):
            writer.writepkt(pkt, ts=float(idx))


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #

def test_extracts_handshake_facts(tmp_path):
    """client/server random, cipher code, and version land on the challenge."""
    pcap = tmp_path / "session.pcap"
    _write_capture(str(pcap))

    challenges = list(TlsPcapResource(str(pcap)).challenges())
    assert challenges, "expected at least one application_data challenge"

    ch = challenges[0]
    d = ch.derivation
    assert d is not None
    assert d.protocol == "TLS"
    assert d.version == "12"
    assert d.client_random == CLIENT_RANDOM
    assert d.server_random == SERVER_RANDOM
    assert d.cipher_suite == CIPHER_CODE
    assert d.seq_num == 0                                   # first record after CCS
    assert d.record_iv == (0).to_bytes(8, "big")           # explicit GCM nonce split off
    assert ch.cipher == "AES-128-GCM"
    assert ch.tag is None                                   # tag stays inside ciphertext
    # AAD = seq(8) || 0x17 0x03 0x03 || plaintext_len(2)
    assert ch.aad == (0).to_bytes(8, "big") + b"\x17\x03\x03" + len(PLAINTEXT).to_bytes(2, "big")


def test_correct_secret_verifies_wrong_one_does_not(tmp_path):
    """The end-to-end proof: right master secret decrypts, wrong one cannot."""
    pcap = tmp_path / "session.pcap"
    _write_capture(str(pcap))

    resource = TlsPcapResource(str(pcap))
    assert resource.protocol == "TLS"

    oracle = ResourceOracle(resource)
    assert len(oracle) >= 1
    assert oracle.verify(MASTER_SECRET) is True
    assert oracle.verify(WRONG_SECRET) is False


def test_client_random_filter_selects_session(tmp_path):
    """A matching client_random yields challenges; a mismatch raises clearly."""
    pcap = tmp_path / "session.pcap"
    _write_capture(str(pcap))

    matched = list(TlsPcapResource(str(pcap), client_random=CLIENT_RANDOM).challenges())
    assert matched

    with pytest.raises(PcapParseError):
        list(TlsPcapResource(str(pcap), client_random=b"\xaa" * 32).challenges())


def test_missing_capture_raises_parse_error(tmp_path):
    with pytest.raises(PcapParseError):
        list(TlsPcapResource(str(tmp_path / "does-not-exist.pcap")).challenges())


# --------------------------------------------------------------------------- #
# Reportable truncation (Wave 0 D0c): describe_capture must expose every drop
# --------------------------------------------------------------------------- #

# A cipher suite that is in NEITHER kdf_tls table, so ``_negotiated_version``
# cannot classify the session and the parser must drop it. 0x00FF is the real
# TLS_EMPTY_RENEGOTIATION_INFO_SCSV signalling value — never a negotiable suite.
OUT_OF_TABLE_CIPHER = 0x00FF


def _server_hello_with(cipher_code: int) -> bytes:
    """A ServerHello advertising an arbitrary (possibly unsupported) suite."""
    body = (
        b"\x03\x03" + SERVER_RANDOM + b"\x00"
        + cipher_code.to_bytes(2, "big")
        + b"\x00"
        + b"\x00\x00"
    )
    return _handshake(2, body)


def _write_unsupported_suite_capture(path: str) -> None:
    """A complete handshake whose negotiated suite is outside the IANA tables."""
    client_records = [_tls_record(22, _client_hello()), _tls_record(20, b"\x01")]
    server_records = [
        _tls_record(22, _server_hello_with(OUT_OF_TABLE_CIPHER)),
        _tls_record(20, b"\x01"),
    ]
    packets = []
    c_seq = 1000
    for rec in client_records:
        packets.append(_frame(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, c_seq, rec))
        c_seq += len(rec)
    s_seq = 5000
    for rec in server_records:
        packets.append(_frame(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, s_seq, rec))
        s_seq += len(rec)
    with open(path, "wb") as handle:
        writer = dpkt.pcap.Writer(handle)
        for idx, pkt in enumerate(packets):
            writer.writepkt(pkt, ts=float(idx))


def _write_flows(path: str, flows) -> None:
    """Write one capture holding *flows*: ``(client_port, client_recs, server_recs)``.

    Shared by the multi-record and multi-session writers so a new session is one
    extra tuple rather than another copy of the frame loop.
    """
    packets = []
    for client_port, client_records, server_records in flows:
        c_seq, s_seq = 1000, 5000
        for rec in client_records:
            packets.append(
                _frame(CLIENT_IP, SERVER_IP, client_port, SERVER_PORT, c_seq, rec)
            )
            c_seq += len(rec)
        for rec in server_records:
            packets.append(
                _frame(SERVER_IP, CLIENT_IP, SERVER_PORT, client_port, s_seq, rec)
            )
            s_seq += len(rec)
    with open(path, "wb") as handle:
        writer = dpkt.pcap.Writer(handle)
        for idx, pkt in enumerate(packets):
            writer.writepkt(pkt, ts=float(idx))


def _session_flow(
    record_count: int,
    *,
    client_port: int = CLIENT_PORT,
    client_ccs: bool = True,
    server_ccs: bool = True,
    server_record_count: int = 0,
):
    """One TLS 1.2 session's two record flights, with the CCS knobs BUG 1 needs.

    ``client_ccs`` / ``server_ccs`` decide whether that direction sends a
    ChangeCipherSpec at all: without one, its application-data records are not
    decryptable under the negotiated keys, so the challenge stream cannot cover
    them (a truncated capture start or a dropped CCS packet in the wild).
    """
    client_records = [_tls_record(22, _client_hello())]
    if client_ccs:
        client_records.append(_tls_record(20, b"\x01"))
    client_records += [_app_data_record(seq) for seq in range(record_count)]
    server_records = [_tls_record(22, _server_hello())]
    if server_ccs:
        server_records.append(_tls_record(20, b"\x01"))
    server_records += [_app_data_record(seq) for seq in range(server_record_count)]
    return (client_port, client_records, server_records)


def _write_multi_record_capture(path: str, record_count: int, **session_kwargs) -> None:
    """The standard session, but with *record_count* client app-data records.

    Extra keyword arguments are forwarded to :func:`_session_flow` (the CCS and
    server-side-record knobs); with none passed the capture is byte-identical to
    what this helper produced before.
    """
    _write_flows(path, [_session_flow(record_count, **session_kwargs)])


def test_describe_sessions_shape_is_unchanged(tmp_path):
    """The frozen contract: ``describe_sessions`` keys/types must not drift.

    The web router (``POST /api/pcaps/validate``) and the React frontend read
    this dict, so ``describe_capture`` had to be built *around* it rather than by
    changing it. This test is the guard on that promise.
    """
    pcap = tmp_path / "session.pcap"
    _write_capture(str(pcap))

    sessions = TlsPcapResource(str(pcap)).describe_sessions()
    assert len(sessions) == 1
    assert set(sessions[0]) == {
        "client_random",
        "server_random",
        "version",
        "cipher_suite",
        "cipher_name",
        "client_app_records",
        "server_app_records",
        "has_app_records",
    }
    assert sessions[0]["client_random"] == CLIENT_RANDOM.hex()
    assert sessions[0]["server_random"] == SERVER_RANDOM.hex()
    assert sessions[0]["version"] == "12"
    assert sessions[0]["cipher_suite"] == CIPHER_CODE
    assert sessions[0]["client_app_records"] == 1
    assert sessions[0]["server_app_records"] == 0
    assert sessions[0]["has_app_records"] is True


def test_describe_capture_wraps_describe_sessions(tmp_path):
    """``describe_capture`` reports the same sessions plus record accounting."""
    pcap = tmp_path / "session.pcap"
    _write_capture(str(pcap))

    resource = TlsPcapResource(str(pcap))
    capture = resource.describe_capture()

    assert set(capture) == {
        "sessions",
        "skipped",
        "flow_count",
        "caps",
        "records_truncated",
        "challenges_available",
        "challenges_returned",
        "challenges_truncated",
    }
    assert capture["flow_count"] == 2                      # one flow per direction
    # Both caps are reported, ``max_challenges`` included: a challenge cap is as
    # silent a truncation of coverage as the record cap, so it cannot be absent
    # from the honesty report.
    assert capture["caps"] == {
        "max_records_per_direction": 16,
        "max_challenges": None,
    }
    assert capture["skipped"] == []
    assert capture["records_truncated"] is False
    assert capture["challenges_truncated"] is False

    session = capture["sessions"][0]
    # Every describe_sessions key survives, additively extended.
    for key, value in resource.describe_sessions()[0].items():
        assert session[key] == value
    assert session["app_records_seen"] == 1
    assert session["records_returned"] == 1
    assert session["challenges_available"] == 1
    assert session["challenges_returned"] == 1
    assert capture["challenges_available"] == 1
    assert capture["challenges_returned"] == 1


def test_describe_capture_reports_unsupported_cipher_suite(tmp_path):
    """A session dropped for an out-of-table suite appears in ``skipped``.

    Previously this loss was a ``logger.debug`` line only: the whole session
    vanished from every surface with nothing to say it had been there.
    """
    pcap = tmp_path / "unsupported.pcap"
    _write_unsupported_suite_capture(str(pcap))

    capture = TlsPcapResource(str(pcap)).describe_capture()

    assert capture["sessions"] == []
    assert len(capture["skipped"]) == 1
    entry = capture["skipped"][0]
    assert entry["reason"] == "unsupported_cipher_suite"
    assert entry["cipher_suite"] == OUT_OF_TABLE_CIPHER
    assert f"{CLIENT_IP}:{CLIENT_PORT}" in entry["flow"]


def test_describe_capture_reports_flow_without_client_hello(tmp_path):
    """A plain (non-TLS) TCP flow is reported as ``no_client_hello``, not silence."""
    pcap = tmp_path / "plain-tcp.pcap"
    with open(pcap, "wb") as handle:
        writer = dpkt.pcap.Writer(handle)
        writer.writepkt(
            _frame(CLIENT_IP, SERVER_IP, 5555, 80, 1000, b"GET / HTTP/1.0\r\n\r\n"),
            ts=0.0,
        )

    capture = TlsPcapResource(str(pcap)).describe_capture()

    assert capture["sessions"] == []
    assert capture["flow_count"] == 1
    assert [e["reason"] for e in capture["skipped"]] == ["no_client_hello"]


def test_records_truncated_flags_the_record_cap(tmp_path):
    """``records_truncated`` is True only when the cap actually clips a direction."""
    pcap = tmp_path / "many-records.pcap"
    _write_multi_record_capture(str(pcap), record_count=5)

    uncapped = TlsPcapResource(str(pcap)).describe_capture()
    assert uncapped["sessions"][0]["app_records_seen"] == 5
    assert uncapped["sessions"][0]["records_returned"] == 5
    assert uncapped["records_truncated"] is False

    capped = TlsPcapResource(str(pcap), max_records_per_direction=2).describe_capture()
    assert capped["caps"] == {
        "max_records_per_direction": 2,
        "max_challenges": None,
    }
    assert capped["sessions"][0]["app_records_seen"] == 5
    assert capped["sessions"][0]["records_returned"] == 2
    assert capped["records_truncated"] is True

    # And the flag matches reality: the cap really does drop challenges.
    all_challenges = list(TlsPcapResource(str(pcap)).challenges())
    clipped = list(TlsPcapResource(str(pcap), max_records_per_direction=2).challenges())
    assert len(clipped) < len(all_challenges)


# --------------------------------------------------------------------------- #
# BUG 1 regression guard: ``records_returned`` must equal the number of records
# the challenge stream really covers, never the raw record total.
#
# TLS 1.2 records only decrypt AFTER their direction's ChangeCipherSpec, so a
# capture whose CCS is missing (truncated start, dropped packet, one-sided CCS)
# carries application data no challenge can reach. Reporting the raw count there
# claimed full coverage for a session that verified nothing — a false ``False``
# on ``records_truncated``, the exact silent-understatement failure inverted.
# --------------------------------------------------------------------------- #


def _real_challenge_count(pcap, **kwargs) -> int:
    """How many challenges the emitter ACTUALLY yields for this capture."""
    return len(list(TlsPcapResource(str(pcap), **kwargs).challenges()))


def test_no_change_cipher_spec_reports_zero_coverage(tmp_path):
    """No CCS at all: 5 records seen, 0 coverable, and the report says so."""
    pcap = tmp_path / "no-ccs.pcap"
    _write_multi_record_capture(
        str(pcap), record_count=5, client_ccs=False, server_ccs=False
    )

    capture = TlsPcapResource(str(pcap)).describe_capture()
    session = capture["sessions"][0]

    assert session["app_records_seen"] == 5          # the parser did see them
    assert session["records_returned"] == 0         # ...and can cover none
    assert session["challenges_available"] == 0
    assert capture["records_truncated"] is True     # was a false False
    assert _real_challenge_count(pcap) == 0         # the stream agrees

    # The operator learns WHY the session verified nothing, not just that it did.
    entries = [e for e in capture["skipped"] if e["reason"] == "no_change_cipher_spec"]
    assert [e["direction"] for e in entries] == ["client"]
    assert entries[0]["app_records_seen"] == 5
    assert f"{CLIENT_IP}:{CLIENT_PORT}" in entries[0]["flow"]


def test_client_only_change_cipher_spec_reports_half_coverage(tmp_path):
    """One-sided CCS: only the client direction's records are coverable."""
    pcap = tmp_path / "client-ccs-only.pcap"
    _write_multi_record_capture(
        str(pcap), record_count=5, server_ccs=False, server_record_count=5
    )

    capture = TlsPcapResource(str(pcap)).describe_capture()
    session = capture["sessions"][0]

    assert session["app_records_seen"] == 10        # 5 each direction
    assert session["records_returned"] == 5        # only the client's are usable
    assert capture["records_truncated"] is True
    assert _real_challenge_count(pcap) == 5

    entries = [e for e in capture["skipped"] if e["reason"] == "no_change_cipher_spec"]
    assert [e["direction"] for e in entries] == ["server"]
    assert entries[0]["app_records_seen"] == 5


def test_records_returned_equals_the_stream_at_and_over_the_cap(tmp_path):
    """The invariant, exactly at the cap and one past it (no off-by-one)."""
    for record_count, cap, expected in ((2, 2, 2), (3, 2, 2), (1, 2, 1)):
        pcap = tmp_path / f"cap-{record_count}-{cap}.pcap"
        _write_multi_record_capture(str(pcap), record_count=record_count)

        capture = TlsPcapResource(
            str(pcap), max_records_per_direction=cap
        ).describe_capture()
        session = capture["sessions"][0]

        assert session["app_records_seen"] == record_count
        assert session["records_returned"] == expected
        assert session["records_returned"] == _real_challenge_count(
            pcap, max_records_per_direction=cap
        )
        assert capture["records_truncated"] is (expected < record_count)


# --------------------------------------------------------------------------- #
# BUG 3 regression guard: the report must see ``max_challenges`` too. The cap
# slices the FLAT challenge list, so it truncates across sessions.
# --------------------------------------------------------------------------- #


def test_max_challenges_is_reported_and_flagged(tmp_path):
    """``caps.max_challenges`` plus a truthful ``challenges_truncated``."""
    pcap = tmp_path / "five.pcap"
    _write_multi_record_capture(str(pcap), record_count=5)

    uncapped = TlsPcapResource(str(pcap)).describe_capture()
    assert uncapped["caps"]["max_challenges"] is None
    assert uncapped["challenges_available"] == 5
    assert uncapped["challenges_returned"] == 5
    assert uncapped["challenges_truncated"] is False

    capped = TlsPcapResource(str(pcap), max_challenges=1).describe_capture()
    assert capped["caps"] == {"max_records_per_direction": 16, "max_challenges": 1}
    assert capped["challenges_available"] == 5
    assert capped["challenges_returned"] == 1
    assert capped["challenges_truncated"] is True
    # The record accounting follows the budget: 4 of the 5 records go unverified.
    assert capped["sessions"][0]["records_returned"] == 1
    assert capped["records_truncated"] is True

    # And the number matches what the oracle — which owns the enforcement —
    # actually keeps, so the report is not describing a different run.
    oracle = ResourceOracle(TlsPcapResource(str(pcap)), max_challenges=1)
    assert len(oracle) == capped["challenges_returned"]


def test_challenge_cap_truncates_across_sessions_not_per_session(tmp_path):
    """A two-session capture: the budget is spent on the first session."""
    pcap = tmp_path / "two-sessions.pcap"
    _write_flows(str(pcap), [
        _session_flow(3, client_port=CLIENT_PORT),
        _session_flow(3, client_port=CLIENT_PORT + 1),
    ])

    capture = TlsPcapResource(str(pcap), max_challenges=4).describe_capture()
    assert len(capture["sessions"]) == 2
    assert capture["challenges_available"] == 6
    assert capture["challenges_returned"] == 4
    assert capture["challenges_truncated"] is True
    # Per session: the first gets all 3, the second only the 1 challenge left —
    # not 4 each, which a per-session reading of the cap would have implied.
    assert [s["records_returned"] for s in capture["sessions"]] == [3, 1]
    assert [s["challenges_available"] for s in capture["sessions"]] == [3, 3]
    assert [s["challenges_returned"] for s in capture["sessions"]] == [3, 1]

    oracle = ResourceOracle(TlsPcapResource(str(pcap)), max_challenges=4)
    assert len(oracle) == 4


# --------------------------------------------------------------------------- #
# BUG 4: what the ``skipped`` reasons can REALLY be. Two of the five the report
# advertises guard ServerHello shapes the bundled dpkt cannot produce, so the
# docstring now marks them defensive; these tests pin both halves of that claim.
# --------------------------------------------------------------------------- #


def _write_short_random_server_hello_capture(path: str) -> None:
    """A ServerHello whose random is 16 bytes instead of the mandatory 32."""
    short_hello = _handshake(2, b"\x03\x03" + b"\xaa" * 16 + b"\x00"
                             + CIPHER_CODE.to_bytes(2, "big") + b"\x00" + b"\x00\x00")
    _write_flows(path, [(
        CLIENT_PORT,
        [_tls_record(22, _client_hello()), _tls_record(20, b"\x01"), _app_data_record(0)],
        [_tls_record(22, short_hello), _tls_record(20, b"\x01")],
    )])


def test_short_random_server_hello_surfaces_as_no_server_hello(tmp_path):
    """dpkt rejects the record outright, so the reason is not ``short_random``.

    The parser's own ``short_random`` guard is therefore unreachable through a
    real capture — the report's docstring says as much rather than advertising a
    reason a caller can never see.
    """
    pcap = tmp_path / "short-random.pcap"
    _write_short_random_server_hello_capture(str(pcap))

    capture = TlsPcapResource(str(pcap)).describe_capture()
    assert capture["sessions"] == []
    assert [e["reason"] for e in capture["skipped"]] == ["no_server_hello"]


def test_defensive_short_random_guard_reports_its_own_reason(tmp_path, monkeypatch):
    """If a future dpkt DID hand back a short random, the reason is right.

    Covers the defensive branch the docstring keeps but does not promise: the
    guard is exercised by forcing the hello shape dpkt refuses to produce.
    """
    import memdiver.engine.resources.tls_pcap as tls_pcap

    class _ShortHello:
        random = b"\xaa" * 16
        ciphersuite = type("_Suite", (), {"code": CIPHER_CODE})()

    monkeypatch.setattr(tls_pcap, "_find_hello", lambda records, hs_type: _ShortHello())

    pcap = tmp_path / "session.pcap"
    _write_capture(str(pcap))

    capture = TlsPcapResource(str(pcap)).describe_capture()
    assert capture["sessions"] == []
    entry = capture["skipped"][0]
    assert entry["reason"] == "short_random"
    assert entry["client_random_len"] == 16
    assert entry["server_random_len"] == 16


def test_defensive_no_cipher_suite_guard_reports_its_own_reason(tmp_path, monkeypatch):
    """Same for ``no_cipher_suite``: the bundled dpkt always yields an int code.

    ``TLSServerHello.unpack`` falls back to ``get_unknown_ciphersuite(code)`` for
    an unlisted suite, so the attribute is never absent; an out-of-table suite
    surfaces as ``unsupported_cipher_suite`` instead.
    """
    import memdiver.engine.resources.tls_pcap as tls_pcap

    monkeypatch.setattr(tls_pcap, "_server_hello_cipher_code", lambda hello: None)

    pcap = tmp_path / "session.pcap"
    _write_capture(str(pcap))

    capture = TlsPcapResource(str(pcap)).describe_capture()
    assert capture["sessions"] == []
    assert [e["reason"] for e in capture["skipped"]] == ["no_cipher_suite"]


# --------------------------------------------------------------------------- #
# A capture that stats fine but cannot be OPENED must fail typed, not raw.
# --------------------------------------------------------------------------- #


def test_unopenable_capture_raises_parse_error(tmp_path):
    """A mode-000 capture funnels ``PermissionError`` into ``PcapParseError``.

    ``PermissionError`` is an ``OSError``, so ``_read_flows``' funnel catches it;
    this pins that, because an unhandled ``PermissionError`` would escape
    ``inspect_pcap``'s ``CapabilityError`` mapping as an HTTP 500.
    """
    import os

    pcap = tmp_path / "locked.pcap"
    _write_capture(str(pcap))
    os.chmod(pcap, 0o000)
    try:
        with open(pcap, "rb"):
            pytest.skip("filesystem/user ignores mode 000 (running as root?)")
    except PermissionError:
        pass

    try:
        with pytest.raises(PcapParseError):
            TlsPcapResource(str(pcap)).describe_capture()
        with pytest.raises(PcapParseError):
            list(TlsPcapResource(str(pcap)).challenges())
    finally:
        os.chmod(pcap, 0o600)


def test_client_random_filter_reports_the_session_it_skips(tmp_path):
    """A pinned run must not report coverage for a session it never touches.

    ``challenges()`` skips every session whose client_random is not the one the
    caller pinned, so counting that session's records as returned would claim
    coverage the oracle will never attempt.
    """
    pcap = tmp_path / "session.pcap"
    _write_multi_record_capture(str(pcap), record_count=3)

    pinned = TlsPcapResource(str(pcap), client_random=CLIENT_RANDOM).describe_capture()
    assert pinned["sessions"][0]["records_returned"] == 3
    assert pinned["challenges_available"] == 3
    assert pinned["skipped"] == []

    other = TlsPcapResource(str(pcap), client_random=b"\xbb" * 32).describe_capture()
    session = other["sessions"][0]
    # The session is still described (it IS in the capture) but claims nothing.
    assert session["app_records_seen"] == 3
    assert session["records_returned"] == 0
    assert session["challenges_available"] == 0
    assert other["records_truncated"] is True
    entry = other["skipped"][0]
    assert entry["reason"] == "client_random_mismatch"
    assert entry["client_random"] == CLIENT_RANDOM.hex()

    # ...which is exactly what the stream does: it refuses outright.
    with pytest.raises(PcapParseError):
        list(TlsPcapResource(str(pcap), client_random=b"\xbb" * 32).challenges())


@pytest.mark.parametrize("bad_cap", [0, -1])
def test_constructor_rejects_a_record_cap_below_one(tmp_path, bad_cap):
    """The resource refuses the cap itself, not only its callers.

    ``build_oracle`` validates the config it is handed, but a library caller
    constructs ``TlsPcapResource`` directly and reaches neither that loader nor
    the producer layer's ``_validate_pcap_caps``. A cap of 0 emits no records,
    so the oracle confirms nothing and a genuine key is reported as
    "0 confirmed" by a run that looks successful; a negative cap slices the
    record list from the wrong end. Rejected at construction, before any capture
    is opened -- the path here need not even exist.
    """
    with pytest.raises(ValueError) as excinfo:
        TlsPcapResource(str(tmp_path / "missing.pcap"),
                        max_records_per_direction=bad_cap)

    message = str(excinfo.value)
    assert "max_records_per_direction must be >= 1" in message
    assert str(bad_cap) in message


def test_constructor_keeps_a_valid_record_cap(tmp_path):
    """Non-vacuity: the guard rejects a value, not the keyword."""
    resource = TlsPcapResource(str(tmp_path / "missing.pcap"),
                               max_records_per_direction=1)
    assert resource.max_records_per_direction == 1
    assert TlsPcapResource(str(tmp_path / "missing.pcap")).max_records_per_direction == 16


def test_the_constructor_rejects_an_explicit_none_record_cap() -> None:
    """``None`` is a caller bug here, not "uncapped".

    ``max_records_per_direction`` is annotated ``int`` with a default of 16, so
    "no cap supplied" is spelled by omitting the argument. Letting ``None``
    through would defer the failure to the ``emitted < cap`` comparison during
    record emission, surfacing as an unrelated ``TypeError`` from deep inside
    the parser rather than as a rejected argument.
    """
    with pytest.raises(ValueError) as excinfo:
        TlsPcapResource("/nonexistent.pcap", max_records_per_direction=None)
    assert "max_records_per_direction" in str(excinfo.value)
    assert "None is not a cap" in str(excinfo.value)


def test_the_challenge_cap_still_accepts_none_as_uncapped() -> None:
    """The sibling cap IS ``Optional[int]`` -- the two must not be conflated."""
    resource = TlsPcapResource("/nonexistent.pcap", max_challenges=None)
    assert resource.max_challenges is None
