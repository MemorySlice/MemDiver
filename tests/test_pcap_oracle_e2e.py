"""Flagship end-to-end: recover a TLS key from a memory blob and PROVE it
decrypts a real captured pcap — through the whole vertical the user asked for:

    memory candidates -> run_brute_force -> builtin resource oracle
                      -> load_oracle(BUILTIN_ORACLE_PATH, {pcap...})
                      -> ResourceOracle -> TlsPcapResource -> C1 verifier

Builds genuine synthetic captures (real AES-128-GCM / CBC / TLS 1.3 records
under keys derived from a known secret) and drives them through the full stack;
also covers the opt-in ground-truth ledger persistence.
"""

import hmac
import json
import socket
from pathlib import Path

import pytest

dpkt = pytest.importorskip("dpkt")

from memdiver.core.kdf_tls import (  # noqa: E402
    derive_tls12_keys,
    derive_tls13_record_keys,
)
from memdiver.engine.brute_force import run_brute_force  # noqa: E402
from memdiver.engine.oracle import load_oracle  # noqa: E402
from memdiver.engine.resources.builtin_oracle import (  # noqa: E402
    BUILTIN_ORACLE_PATH,
    build_oracle,
)
from memdiver.engine.resources.oracle import ResourceOracle  # noqa: E402
from memdiver.engine.resources.tls_pcap import TlsPcapResource  # noqa: E402
from memdiver.engine.verification import HAS_CRYPTO  # noqa: E402

pytestmark = pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")

if HAS_CRYPTO:
    from cryptography.hazmat.primitives.ciphers import (  # noqa: E402
        Cipher,
        algorithms,
        modes,
    )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

# -- fixed synthetic TLS 1.2 AES-128-GCM session facts ---------------------- #
MASTER_SECRET = bytes(range(1, 49))
WRONG_SECRET = bytes(range(48, 0, -1))
CLIENT_RANDOM = bytes(range(32))
SERVER_RANDOM = bytes(range(32, 64))
CIPHER_CODE = 0xC02F                       # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
PLAINTEXT = b"GET /secret HTTP/1.1\r\n\r\n"
SECRET_OFFSET = 64


def _hs(msg_type, body):
    return bytes([msg_type]) + len(body).to_bytes(3, "big") + body


def _rec(content_type, frag):
    return bytes([content_type]) + b"\x03\x03" + len(frag).to_bytes(2, "big") + frag


def _app_data(seq):
    keys = derive_tls12_keys(MASTER_SECRET, CLIENT_RANDOM, SERVER_RANDOM, CIPHER_CODE)
    explicit = seq.to_bytes(8, "big")
    nonce = keys.client_write_iv + explicit
    aad = seq.to_bytes(8, "big") + b"\x17\x03\x03" + len(PLAINTEXT).to_bytes(2, "big")
    blob = AESGCM(keys.client_write_key).encrypt(nonce, PLAINTEXT, aad)
    return _rec(23, explicit + blob)


def _frame(src, dst, sport, dport, seq, payload):
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq, ack=0,
                       flags=dpkt.tcp.TH_ACK, data=payload)
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst),
                    p=dpkt.ip.IP_PROTO_TCP, data=tcp)
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(src=b"\x00\x00\x00\x00\x00\x01",
                                 dst=b"\x00\x00\x00\x00\x00\x02",
                                 type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
    return bytes(eth)


def _pcap(tmp_path) -> str:
    path = tmp_path / "session.pcap"
    client = [_rec(22, _hs(1, b"\x03\x03" + CLIENT_RANDOM + b"\x00"
                           + b"\x00\x02" + CIPHER_CODE.to_bytes(2, "big")
                           + b"\x01\x00" + b"\x00\x00")),
              _rec(20, b"\x01"), _app_data(0)]
    server = [_rec(22, _hs(2, b"\x03\x03" + SERVER_RANDOM + b"\x00"
                           + CIPHER_CODE.to_bytes(2, "big") + b"\x00" + b"\x00\x00")),
              _rec(20, b"\x01")]
    packets, cseq, sseq = [], 1000, 5000
    for r in client:
        packets.append(_frame("10.0.0.1", "10.0.0.2", 12345, 443, cseq, r)); cseq += len(r)
    for r in server:
        packets.append(_frame("10.0.0.2", "10.0.0.1", 443, 12345, sseq, r)); sseq += len(r)
    with open(path, "wb") as fh:
        w = dpkt.pcap.Writer(fh)
        for i, p in enumerate(packets):
            w.writepkt(p, ts=float(i))
    return str(path)


def test_builtin_oracle_seam(tmp_path):
    """load_oracle resolves the builtin, build_oracle parses the pcap, verify works."""
    config = {"resource_type": "tls-pcap", "pcap": _pcap(tmp_path)}
    # Direct build_oracle
    oracle = build_oracle(config)
    assert oracle.verify(MASTER_SECRET) is True
    assert oracle.verify(WRONG_SECRET) is False
    # Through the untrusted-code loader (sandbox off: builtin is first-party)
    fn = load_oracle(BUILTIN_ORACLE_PATH, config, sandbox=False)
    assert fn(MASTER_SECRET) is True
    assert fn(WRONG_SECRET) is False


def test_run_brute_force_recovers_key_from_memory(tmp_path):
    """The full vertical: brute-force a memory blob, confirm the hit against the pcap."""
    pcap = _pcap(tmp_path)
    # A "memory dump" with the master secret embedded at a known offset.
    reference = b"\x11" * SECRET_OFFSET + MASTER_SECRET + b"\x22" * SECRET_OFFSET
    cand_path = tmp_path / "candidates.json"
    cand_path.write_text(json.dumps({"regions": [{"offset": 0, "length": len(reference)}]}))

    result = run_brute_force(
        candidates_path=cand_path,
        reference_data=reference,
        oracle_path=Path(BUILTIN_ORACLE_PATH),
        oracle_config={"resource_type": "tls-pcap", "pcap": pcap},
        oracle_trusted=True,
        key_sizes=(48,),   # TLS 1.2 master secret length
        stride=8,
    )

    assert result.verified_count == 1
    hit = result.hits[0]
    assert hit.offset == SECRET_OFFSET
    assert hit.length == 48
    assert hit.key_hex == MASTER_SECRET.hex()


# --------------------------------------------------------------------------- #
# Genuine-pcap decrypt E2E for the other suite families (TLS 1.3, TLS 1.2 CBC)
# --------------------------------------------------------------------------- #

TRAFFIC_SECRET = bytes(range(1, 33))          # 32-byte TLS 1.3 traffic secret
CIPHER13 = 0x1301                             # TLS_AES_128_GCM_SHA256
CIPHER_CBC = 0xC013                          # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA


def _client_hello(cipher_code):
    return _rec(22, _hs(1, b"\x03\x03" + CLIENT_RANDOM + b"\x00"
                        + b"\x00\x02" + cipher_code.to_bytes(2, "big")
                        + b"\x01\x00" + b"\x00\x00"))


def _server_hello(cipher_code):
    return _rec(22, _hs(2, b"\x03\x03" + SERVER_RANDOM + b"\x00"
                        + cipher_code.to_bytes(2, "big") + b"\x00" + b"\x00\x00"))


def _app_data_tls13(seq):
    rk = derive_tls13_record_keys(TRAFFIC_SECRET, CIPHER13)
    nonce = bytes(a ^ b for a, b in zip(rk.iv, seq.to_bytes(len(rk.iv), "big")))
    ct = AESGCM(rk.key)  # aad computed below once we know fragment length
    # fragment (before aad) = ct||tag; its length feeds the record-header aad.
    inner = PLAINTEXT
    # length = plaintext + 16-byte tag
    aad = b"\x17\x03\x03" + (len(inner) + 16).to_bytes(2, "big")
    frag = ct.encrypt(nonce, inner, aad)
    return _rec(23, frag)


def _app_data_cbc(seq):
    keys = derive_tls12_keys(MASTER_SECRET, CLIENT_RANDOM, SERVER_RANDOM, CIPHER_CBC)
    header = b"\x17\x03\x03"                    # type || version (MAC prefix)
    mac_input = seq.to_bytes(8, "big") + header + len(PLAINTEXT).to_bytes(2, "big") + PLAINTEXT
    mac = hmac.new(keys.client_mac_key, mac_input, keys.suite.mac_hash).digest()
    body = PLAINTEXT + mac
    pad_needed = 16 - (len(body) % 16)
    plain = body + bytes([pad_needed - 1]) * pad_needed
    record_iv = bytes(range(16))
    enc = Cipher(algorithms.AES(keys.client_write_key), modes.CBC(record_iv)).encryptor()
    return _rec(23, record_iv + enc.update(plain) + enc.finalize())


def _write_pcap(path, client_records, server_records):
    packets, cseq, sseq = [], 1000, 5000
    for r in client_records:
        packets.append(_frame("10.0.0.1", "10.0.0.2", 12345, 443, cseq, r)); cseq += len(r)
    for r in server_records:
        packets.append(_frame("10.0.0.2", "10.0.0.1", 443, 12345, sseq, r)); sseq += len(r)
    with open(path, "wb") as fh:
        w = dpkt.pcap.Writer(fh)
        for i, p in enumerate(packets):
            w.writepkt(p, ts=float(i))


def test_tls13_pcap_e2e(tmp_path):
    """Genuine TLS 1.3 capture: the traffic secret decrypts the real record."""
    pcap = tmp_path / "tls13.pcap"
    # TLS 1.3: no ChangeCipherSpec needed; app-data is record #0 in its direction.
    _write_pcap(pcap,
                client_records=[_client_hello(CIPHER13), _app_data_tls13(0)],
                server_records=[_server_hello(CIPHER13)])
    oracle = ResourceOracle(TlsPcapResource(str(pcap)))
    assert len(oracle) >= 1
    assert oracle.verify(TRAFFIC_SECRET) is True
    assert oracle.verify(bytes(32)) is False


def test_tls12_cbc_pcap_e2e(tmp_path):
    """Genuine TLS 1.2 CBC (HMAC-SHA1) capture: the master secret decrypts + MACs."""
    pcap = tmp_path / "tls12cbc.pcap"
    # First record after CCS is seq 0 per the parser's TLS 1.2 rule.
    _write_pcap(pcap,
                client_records=[_client_hello(CIPHER_CBC), _rec(20, b"\x01"), _app_data_cbc(0)],
                server_records=[_server_hello(CIPHER_CBC), _rec(20, b"\x01")])
    oracle = ResourceOracle(TlsPcapResource(str(pcap)))
    assert len(oracle) >= 1
    assert oracle.verify(MASTER_SECRET) is True
    assert oracle.verify(WRONG_SECRET) is False


# --------------------------------------------------------------------------- #
# Follow-up: oracle-confirmed hits land in the ground-truth ledger (opt-in)
# --------------------------------------------------------------------------- #

def test_producer_persists_confirmed_hit_as_ground_truth(tmp_path, monkeypatch):
    """persist_ground_truth=True files the pcap-confirmed hit into the DB ledger."""
    pytest.importorskip("duckdb")
    pytest.importorskip("ibis")
    # Redirect the project DB into the temp dir (memdiver_home honours XDG_DATA_HOME).
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))

    pcap = _pcap(tmp_path)
    reference = b"\x11" * SECRET_OFFSET + MASTER_SECRET + b"\x22" * SECRET_OFFSET
    ref_path = tmp_path / "reference.bin"
    ref_path.write_bytes(reference)
    cand_path = tmp_path / "candidates.json"
    cand_path.write_text(json.dumps({"regions": [{"offset": 0, "length": len(reference)}]}))

    from memdiver.app.tools_pipeline import brute_force
    result = brute_force(
        candidates_path=str(cand_path),
        reference_path=str(ref_path),
        output_dir=str(tmp_path / "out"),
        pcap_path=pcap,
        persist_ground_truth=True,
        key_sizes=(48,),
        stride=8,
    )
    assert result["verified_count"] == 1
    run_id = result["ground_truth_run_id"]
    assert run_id  # a real run was created

    from memdiver.app.composition import resolve_project_db
    db = resolve_project_db()
    assert db is not None
    try:
        rows = db.list_ground_truth(run_id)
    finally:
        db.close()
    assert len(rows) == 1
    assert rows[0]["confirmed_by"] == "pcap"
    assert rows[0]["key_hex"] == MASTER_SECRET.hex()
    assert rows[0]["offset"] == SECRET_OFFSET
    # The pcap-confirmed hit carries its provenance on the wire too.
    assert result["hits"][0]["verified"] is True
    assert result["hits"][0]["confirmed_by"] == "pcap"


# A minimal BYO oracle: the sandboxed, user-supplied counterpart to the
# first-party pcap oracle. It vouches for exactly the planted secret.
BYO_ORACLE_SRC = (
    "TARGET = bytes(range(1, 49))\n"
    "def verify(candidate):\n"
    "    return candidate == TARGET\n"
)


def test_producer_stamps_byo_oracle_hit_as_confirmed(tmp_path, monkeypatch):
    """A BYO-oracle (non-pcap) hit is stamped ``confirmed_by="oracle"`` on the
    returned hits, in the ``stage_end`` event, and in the ground-truth ledger —
    the same single label at every site, so they cannot drift."""
    pytest.importorskip("duckdb")
    pytest.importorskip("ibis")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))

    oracle_path = tmp_path / "byo_oracle.py"
    oracle_path.write_text(BYO_ORACLE_SRC)
    reference = b"\x11" * SECRET_OFFSET + MASTER_SECRET + b"\x22" * SECRET_OFFSET
    ref_path = tmp_path / "reference.bin"
    ref_path.write_bytes(reference)
    cand_path = tmp_path / "candidates.json"
    cand_path.write_text(json.dumps({"regions": [{"offset": 0, "length": len(reference)}]}))

    events = []

    from memdiver.app.tools_pipeline import brute_force
    result = brute_force(
        candidates_path=str(cand_path),
        reference_path=str(ref_path),
        output_dir=str(tmp_path / "out"),
        oracle_path=str(oracle_path),
        persist_ground_truth=True,
        key_sizes=(48,),
        stride=8,
        on_progress=lambda event, **fields: events.append((event, fields)),
    )
    assert result["verified_count"] == 1
    hit = result["hits"][0]
    assert hit["verified"] is True
    assert hit["confirmed_by"] == "oracle"
    assert hit["offset"] == SECRET_OFFSET

    # Same stamped dicts reach the wire via the stage_end event.
    stage_end = [f for e, f in events if e == "stage_end" and f.get("stage") == "brute_force"]
    assert len(stage_end) == 1
    assert stage_end[0]["extra"]["hits"][0]["confirmed_by"] == "oracle"

    # ...and the persisted hits.json holds the same provenance.
    on_disk = json.loads(Path(result["hits_path"]).read_text())
    assert on_disk["hits"][0]["confirmed_by"] == "oracle"

    run_id = result["ground_truth_run_id"]
    assert run_id

    from memdiver.app.composition import resolve_project_db
    db = resolve_project_db()
    assert db is not None
    try:
        rows = db.list_ground_truth(run_id)
    finally:
        db.close()
    assert len(rows) == 1
    assert rows[0]["confirmed_by"] == "oracle"
    assert rows[0]["key_hex"] == MASTER_SECRET.hex()
    assert rows[0]["offset"] == SECRET_OFFSET


# --------------------------------------------------------------------------- #
# A pcap-oracle run whose tls_client_random matches no session must funnel to
# CapabilityError(INVALID_INPUT), not escape as a raw PcapParseError.
# --------------------------------------------------------------------------- #

# A real TLS 1.3 capture (one session) — reused only to have a genuinely
# parseable pcap whose sole session cannot match a bogus client_random.
REAL_PCAP = Path(
    "/Users/danielbaier/Desktop/tls_dumps/TLS13/"
    "100_iterations_Abort_KeyUpdate/openssl/openssl_run_13_1/"
    "run_data/traffic.pcap"
)


def test_brute_force_bogus_client_random_is_invalid_input(tmp_path):
    """A pcap oracle armed with a client_random matching no session raises a
    ``CapabilityError(INVALID_INPUT)`` — the underlying ``PcapParseError`` (a
    bare ``Exception`` raised eagerly from ``ResourceOracle.__init__``) is
    funnelled rather than leaking a raw stack trace to the surface."""
    if not REAL_PCAP.is_file():
        pytest.skip(f"sample capture not present: {REAL_PCAP}")

    from memdiver.app.tools_pipeline import brute_force
    from memdiver.core.service_errors import CapabilityError, ErrorCategory

    reference = b"\x00" * 128
    ref_path = tmp_path / "reference.bin"
    ref_path.write_bytes(reference)
    cand_path = tmp_path / "candidates.json"
    cand_path.write_text(
        json.dumps({"regions": [{"offset": 0, "length": len(reference)}]})
    )

    with pytest.raises(CapabilityError) as exc_info:
        brute_force(
            candidates_path=str(cand_path),
            reference_path=str(ref_path),
            output_dir=str(tmp_path / "out"),
            pcap_path=str(REAL_PCAP),
            tls_client_random="ff" * 32,  # bogus: matches no captured session
            key_sizes=(48,),
            stride=8,
        )

    assert exc_info.value.category is ErrorCategory.INVALID_INPUT


# --------------------------------------------------------------------------- #
# Honesty of the coverage report on the TLS 1.3 path, where one record yields a
# WINDOW of challenges (the undetectable handshake->application epoch change),
# so "records" and "challenges" are not the same number and the report has to
# say both. Uses the genuine TLS 1.3 records built above.
# --------------------------------------------------------------------------- #


def _tls13_capture(tmp_path, record_count, name="tls13-many.pcap"):
    pcap = tmp_path / name
    _write_pcap(pcap,
                client_records=[_client_hello(CIPHER13)]
                + [_app_data_tls13(i) for i in range(record_count)],
                server_records=[_server_hello(CIPHER13)])
    return pcap


def test_tls13_challenge_accounting_matches_the_emitted_stream(tmp_path):
    """``challenges_available`` counts the sequence-window bursts, not records."""
    pcap = _tls13_capture(tmp_path, 12)

    capture = TlsPcapResource(str(pcap)).describe_capture()
    session = capture["sessions"][0]
    emitted = list(TlsPcapResource(str(pcap)).challenges())

    assert session["app_records_seen"] == 12
    assert session["records_returned"] == 12
    # 12 records, window of 8: bursts 1,2,...,9,9,9,9 -> 72 challenges.
    assert session["challenges_available"] == len(emitted) == 72
    assert capture["challenges_returned"] == 72
    assert capture["challenges_truncated"] is False


def test_tls13_challenge_cap_reports_partial_record_coverage(tmp_path):
    """A challenge budget mid-window: fewer records covered, and it says so."""
    pcap = _tls13_capture(tmp_path, 12, name="tls13-capped.pcap")

    capture = TlsPcapResource(str(pcap), max_challenges=5).describe_capture()
    session = capture["sessions"][0]

    assert capture["caps"]["max_challenges"] == 5
    assert session["challenges_available"] == 72
    assert capture["challenges_returned"] == 5
    assert capture["challenges_truncated"] is True
    # Bursts 1 + 2 + (2 of 3) exhaust the budget, so only 3 of the 12 records
    # are reached at all -- reporting 12 here would have claimed full coverage.
    assert session["records_returned"] == 3
    assert capture["records_truncated"] is True

    # The oracle owns the enforcement; the report must match what it keeps.
    assert len(ResourceOracle(TlsPcapResource(str(pcap)), max_challenges=5)) == 5


def test_builtin_oracle_config_caps_reach_the_report(tmp_path):
    """One config drives both the oracle's cap and the resource's report of it.

    ``build_oracle`` enforces ``max_challenges`` on the flat challenge list while
    ``build_resource`` hands the same value to the resource for reporting, so
    ``describe_capture`` describes the run that will actually happen.
    """
    config = {
        "resource_type": "tls-pcap",
        "pcap": _pcap(tmp_path),
        "max_records_per_direction": 4,
        "max_challenges": 1,
    }

    from memdiver.engine.resources.builtin_oracle import build_resource

    capture = build_resource(config).describe_capture()
    assert capture["caps"] == {"max_records_per_direction": 4, "max_challenges": 1}

    # The single record this capture holds is still fully covered by a cap of 1.
    assert capture["challenges_available"] == 1
    assert capture["challenges_returned"] == 1
    assert capture["challenges_truncated"] is False
    assert len(build_oracle(config)) == 1
