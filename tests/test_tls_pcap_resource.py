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
