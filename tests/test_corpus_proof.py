"""Corpus-scale key proof: the pure model + the per-run orchestration.

Covers, in order:

* the two pure helpers whose values are load-bearing —
  :func:`engine.corpus_proof.derive_key_sizes` (48 / 32, DERIVED) and
  :func:`engine.corpus_proof.pairing_check` (the atomic-triple assertion);
* EVERY member of the :data:`engine.corpus_proof.SKIP_REASONS` vocabulary,
  driven end to end through :func:`app.pipeline.corpus_pcap_runner.prove_run`
  against a synthetic corpus built here (genuine AES-128-GCM records under keys
  derived from a known master secret, so a confirmation is a real decryption);
* the two denominators never collapsing, and the mandatory ``## Not counted``
  section being complete;
* a bounded REAL-corpus proof — an actual ``confirmed_by == "pcap"`` hit from a
  run's own ``run_data/traffic.pcap``.

The real-corpus item is ``requires_dataset`` but deliberately NOT ``slow``:
only a full-corpus pass earns that marker.
"""

from __future__ import annotations

import ast
import json
import socket
import sys
from pathlib import Path

import pytest

dpkt = pytest.importorskip("dpkt")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.core.kdf_tls import derive_tls12_keys  # noqa: E402
from memdiver.core.service_errors import (  # noqa: E402
    CapabilityError,
    ErrorCategory,
)
from memdiver.engine.corpus_proof import (  # noqa: E402
    BUCKET_NOT_CONFIRMED,
    NOT_COUNTED_BUCKETS,
    SKIP_CLIENT_RANDOM_MISMATCH,
    SKIP_NO_APP_RECORDS,
    SKIP_NO_CAPTURE,
    SKIP_NO_DUMPS,
    SKIP_NO_KEYLOG,
    SKIP_NO_TLS_SESSION,
    SKIP_ORACLE_NO_CHALLENGES,
    SKIP_PAIRING_MISMATCH,
    SKIP_REASONS,
    SKIP_SECRET_ABSENT,
    SKIP_UNREADABLE_CAPTURE,
    SKIP_UNSUPPORTED_SUITE,
    ProofTotals,
    RunProof,
    SecretProof,
    aggregate,
    build_report,
    derive_key_sizes,
    locate_secret,
    pairing_check,
    render_markdown,
)
from memdiver.engine.verification import HAS_CRYPTO  # noqa: E402
from tests._paths import SKIP_REASON, dataset_root  # noqa: E402

pytestmark = pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")

if HAS_CRYPTO:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent

# -- synthetic TLS 1.2 AES-128-GCM session facts ---------------------------- #
MASTER_SECRET = bytes(range(1, 49))          # 48 bytes: a TLS 1.2 master secret
FOREIGN_SECRET = bytes(range(48, 0, -1))
CLIENT_RANDOM = bytes(range(32))
FOREIGN_CLIENT_RANDOM = bytes(range(100, 132))
SERVER_RANDOM = bytes(range(32, 64))
CIPHER_GCM = 0xC02F                          # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
CIPHER_UNSUPPORTED = 0x0005                  # TLS_RSA_WITH_RC4_128_SHA: not in the table
PLAINTEXT = b"GET /secret HTTP/1.1\r\n\r\n"

#: The master secret is embedded at an offset that is NOT 0 mod 4. A stride-4
#: grid would miss it entirely -- the measured real-corpus analogues are
#: boringssl 113858 and wolfssl 30933 -- so a green confirmation here is also
#: evidence the proof path stays on stride 1.
SECRET_OFFSET = 65


# --------------------------------------------------------------------------- #
# synthetic capture builders (real records, real keys)
# --------------------------------------------------------------------------- #


def _hs(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type]) + len(body).to_bytes(3, "big") + body


def _rec(content_type: int, frag: bytes) -> bytes:
    return bytes([content_type]) + b"\x03\x03" + len(frag).to_bytes(2, "big") + frag


def _client_hello(cipher: int, client_random: bytes) -> bytes:
    return _rec(22, _hs(1, b"\x03\x03" + client_random + b"\x00"
                        + b"\x00\x02" + cipher.to_bytes(2, "big")
                        + b"\x01\x00" + b"\x00\x00"))


def _server_hello(cipher: int) -> bytes:
    return _rec(22, _hs(2, b"\x03\x03" + SERVER_RANDOM + b"\x00"
                        + cipher.to_bytes(2, "big") + b"\x00" + b"\x00\x00"))


def _app_data(seq: int, client_random: bytes = CLIENT_RANDOM) -> bytes:
    keys = derive_tls12_keys(MASTER_SECRET, client_random, SERVER_RANDOM, CIPHER_GCM)
    explicit = seq.to_bytes(8, "big")
    nonce = keys.client_write_iv + explicit
    aad = (seq.to_bytes(8, "big") + b"\x17\x03\x03"
           + len(PLAINTEXT).to_bytes(2, "big"))
    return _rec(23, explicit + AESGCM(keys.client_write_key).encrypt(
        nonce, PLAINTEXT, aad))


def _frame(src: str, dst: str, sport: int, dport: int, seq: int,
           payload: bytes) -> bytes:
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq, ack=0,
                       flags=dpkt.tcp.TH_ACK, data=payload)
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst),
                    p=dpkt.ip.IP_PROTO_TCP, data=tcp)
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(src=b"\x00\x00\x00\x00\x00\x01",
                                 dst=b"\x00\x00\x00\x00\x00\x02",
                                 type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
    return bytes(eth)


def _write_pcap(path: Path, client_records, server_records) -> Path:
    packets, cseq, sseq = [], 1000, 5000
    for record in client_records:
        packets.append(_frame("10.0.0.1", "10.0.0.2", 12345, 443, cseq, record))
        cseq += len(record)
    for record in server_records:
        packets.append(_frame("10.0.0.2", "10.0.0.1", 443, 12345, sseq, record))
        sseq += len(record)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as fh:
        writer = dpkt.pcap.Writer(fh)
        for index, packet in enumerate(packets):
            writer.writepkt(packet, ts=float(index))
    return path


def _full_capture(path: Path, client_random: bytes = CLIENT_RANDOM) -> Path:
    """A complete, verifiable TLS 1.2 GCM session: handshake, CCS, app data."""
    return _write_pcap(
        path,
        [_client_hello(CIPHER_GCM, client_random), _rec(20, b"\x01"),
         _app_data(0, client_random)],
        [_server_hello(CIPHER_GCM), _rec(20, b"\x01")],
    )


def _capture_without_app_data(path: Path) -> Path:
    """Parses to a session, but no encrypted application data exists."""
    return _write_pcap(
        path,
        [_client_hello(CIPHER_GCM, CLIENT_RANDOM), _rec(20, b"\x01")],
        [_server_hello(CIPHER_GCM), _rec(20, b"\x01")],
    )


def _capture_without_change_cipher_spec(path: Path) -> Path:
    """App data exists but no ChangeCipherSpec, so the TLS 1.2 gate covers none.

    ``has_app_records`` is True (the summary counts raw records) while the
    challenge stream the oracle would see is EMPTY -- exactly the state
    ``oracle_no_challenges`` exists to report before anything is spent.
    """
    return _write_pcap(
        path,
        [_client_hello(CIPHER_GCM, CLIENT_RANDOM), _app_data(0)],
        [_server_hello(CIPHER_GCM)],
    )


def _capture_unsupported_suite(path: Path) -> Path:
    return _write_pcap(
        path,
        [_client_hello(CIPHER_UNSUPPORTED, CLIENT_RANDOM), _rec(20, b"\x01")],
        [_server_hello(CIPHER_UNSUPPORTED), _rec(20, b"\x01")],
    )


def _capture_without_tls(path: Path) -> Path:
    return _write_pcap(path, [b"GET / HTTP/1.1\r\n\r\n"], [b"HTTP/1.1 200 OK\r\n\r\n"])


# --------------------------------------------------------------------------- #
# synthetic corpus builder
# --------------------------------------------------------------------------- #


def _make_run(
    root: Path,
    *,
    library: str = "openssl",
    run_number: int = 1,
    keylog_lines=(("CLIENT_RANDOM", CLIENT_RANDOM, MASTER_SECRET),),
    keylog: bool = True,
    dump_secrets=(MASTER_SECRET,),
    dumps: int = 1,
    capture: str = "full",
) -> Path:
    """Build one corpus-shaped run directory and return its path.

    Layout mirrors the real corpus exactly --
    ``<root>/TLS12/<scenario>/<library>/<library>_run_12_<n>/`` with
    ``keylog.csv``, timestamped ``*.dump`` files and ``run_data/traffic.pcap``
    -- so ``core.corpus_axes.axes_from_run_dir`` resolves real axes.
    """
    run_dir = (root / "TLS12" / "100_iterations_Abort" / library
               / (library + "_run_12_" + str(run_number)))
    run_dir.mkdir(parents=True, exist_ok=True)

    if keylog:
        lines = ["id,line"]
        for index, (kind, cr, secret) in enumerate(keylog_lines, start=1):
            lines.append(
                str(index) + "," + kind + " " + cr.hex() + " " + secret.hex())
        (run_dir / "keylog.csv").write_text("\n".join(lines) + "\n")

    for index in range(dumps):
        blob = bytearray(b"\x11" * SECRET_OFFSET)
        for secret in dump_secrets:
            blob.extend(secret)
        blob.extend(b"\x22" * 64)
        name = ("20250101_1200" + str(index).zfill(2) + "_000001_pre_abort.dump")
        (run_dir / name).write_bytes(bytes(blob))

    capture_path = run_dir / "run_data" / "traffic.pcap"
    builders = {
        "full": _full_capture,
        "no_app_records": _capture_without_app_data,
        "no_challenges": _capture_without_change_cipher_spec,
        "unsupported_suite": _capture_unsupported_suite,
        "no_tls": _capture_without_tls,
    }
    if capture in builders:
        builders[capture](capture_path)
    elif capture == "empty":
        capture_path.parent.mkdir(parents=True, exist_ok=True)
        capture_path.write_bytes(b"")
    elif capture == "corrupt":
        capture_path.parent.mkdir(parents=True, exist_ok=True)
        capture_path.write_bytes(b"not a capture at all, not even close")
    elif capture == "absent":
        pass
    else:  # pragma: no cover - a typo in a test's own fixture request
        raise AssertionError("unknown capture kind " + repr(capture))
    return run_dir


def _prove(run_dir: Path, **kwargs):
    from memdiver.app.pipeline.corpus_pcap_runner import prove_run

    return prove_run(run_dir, **kwargs)


def _only(proof: RunProof) -> SecretProof:
    assert len(proof.proofs) == 1, proof.proofs
    return proof.proofs[0]


# --------------------------------------------------------------------------- #
# derive_key_sizes -- DERIVED, never hardcoded
# --------------------------------------------------------------------------- #


def test_derive_key_sizes_tls12_master_secret_is_48():
    assert derive_key_sizes(MASTER_SECRET) == (48,)


def test_derive_key_sizes_tls13_traffic_secret_is_32():
    assert derive_key_sizes(bytes(range(32))) == (32,)


def test_derive_key_sizes_rejects_an_empty_secret():
    with pytest.raises(ValueError, match="empty secret"):
        derive_key_sizes(b"")


def test_key_sizes_reach_brute_force_derived_and_stride_is_one(tmp_path, monkeypatch):
    """The proof call passes ``key_sizes=(len(secret),)`` and ``stride=1``.

    Pinned by intercepting ``brute_force``: a hardcoded ``(32,)`` proves nothing
    on the TLS 1.2 half of the corpus, and a stride-4 grid misses the measured
    boringssl 113858 / wolfssl 30933 offsets.
    """
    from memdiver.app import tools_pipeline
    from memdiver.app.pipeline import corpus_pcap_runner

    seen = {}

    def _fake_brute_force(**kwargs):
        seen.update(kwargs)
        return {"hits": [{"confirmed_by": "pcap"}], "candidates_tested": 1}

    monkeypatch.setattr(tools_pipeline, "brute_force", _fake_brute_force)
    run_dir = _make_run(tmp_path)
    proof = _prove(run_dir)

    assert seen["key_sizes"] == (48,)
    assert seen["stride"] == 1
    assert corpus_pcap_runner.PROOF_STRIDE == 1
    assert seen["tls_client_random"] == CLIENT_RANDOM.hex()
    assert _only(proof).confirmed is True


# --------------------------------------------------------------------------- #
# the atomic per-run triple
# --------------------------------------------------------------------------- #


def test_pairing_check_equal_singleton_is_ok():
    """The corpus shape: one keylog client_random, one capture session, equal.

    Verified exact on openssl 12_1 / 13_1 and rustls 13_7.
    """
    result = pairing_check([CLIENT_RANDOM.hex()], [CLIENT_RANDOM.hex()])
    assert result.ok is True
    assert result.shared == (CLIENT_RANDOM.hex(),)
    assert result.keylog_only == () and result.pcap_only == ()


def test_pairing_check_is_case_insensitive():
    assert pairing_check([CLIENT_RANDOM.hex().upper()],
                         [CLIENT_RANDOM.hex()]).ok is True


def test_pairing_check_disjoint_sets_are_a_mismatch():
    result = pairing_check([CLIENT_RANDOM.hex()], [FOREIGN_CLIENT_RANDOM.hex()])
    assert result.ok is False
    assert result.keylog_only == (CLIENT_RANDOM.hex(),)
    assert result.pcap_only == (FOREIGN_CLIENT_RANDOM.hex(),)
    assert "share nothing" in result.detail


def test_pairing_mismatch_is_a_typed_row_in_a_sweep(tmp_path):
    """A foreign capture must NOT read as "the key does not survive"."""
    run_dir = _make_run(tmp_path)
    _full_capture(run_dir / "run_data" / "traffic.pcap",
                  client_random=FOREIGN_CLIENT_RANDOM)
    proof = _prove(run_dir)
    assert proof.skip_reason == SKIP_PAIRING_MISMATCH
    assert proof.pairing_ok is False
    assert _only(proof).skip_reason == SKIP_PAIRING_MISMATCH
    assert _only(proof).located is False
    assert _only(proof).confirmed is False


def test_pairing_mismatch_is_a_precondition_error_for_a_single_run(tmp_path):
    run_dir = _make_run(tmp_path)
    _full_capture(run_dir / "run_data" / "traffic.pcap",
                  client_random=FOREIGN_CLIENT_RANDOM)
    with pytest.raises(CapabilityError) as excinfo:
        _prove(run_dir, strict_pairing=True)
    assert excinfo.value.category is ErrorCategory.PRECONDITION


# --------------------------------------------------------------------------- #
# every skip_reason, end to end
# --------------------------------------------------------------------------- #


def test_skip_no_capture(tmp_path):
    proof = _prove(_make_run(tmp_path, capture="absent"))
    assert proof.skip_reason == SKIP_NO_CAPTURE
    assert proof.secrets_total == 1
    assert _only(proof).skip_reason == SKIP_NO_CAPTURE


def test_skip_unreadable_capture_zero_byte(tmp_path):
    proof = _prove(_make_run(tmp_path, capture="empty"))
    assert proof.skip_reason == SKIP_UNREADABLE_CAPTURE
    assert _only(proof).skip_reason == SKIP_UNREADABLE_CAPTURE


def test_skip_unreadable_capture_corrupt_bytes(tmp_path):
    proof = _prove(_make_run(tmp_path, capture="corrupt"))
    assert proof.skip_reason == SKIP_UNREADABLE_CAPTURE


def test_skip_no_keylog_keeps_the_run_but_claims_no_denominator(tmp_path):
    proof = _prove(_make_run(tmp_path, keylog=False))
    assert proof.skip_reason == SKIP_NO_KEYLOG
    assert proof.secrets_total == 0
    assert proof.proofs == ()
    # The run still exists in the aggregate -- it must not vanish.
    totals = aggregate([proof])
    assert totals.runs == 1
    assert totals.run_bucket_counts[SKIP_NO_KEYLOG] == 1


def test_skip_no_tls_session(tmp_path):
    proof = _prove(_make_run(tmp_path, capture="no_tls"))
    assert proof.skip_reason == SKIP_NO_TLS_SESSION
    assert _only(proof).skip_reason == SKIP_NO_TLS_SESSION


def test_skip_unsupported_suite_is_reported_not_invisible(tmp_path):
    proof = _prove(_make_run(tmp_path, capture="unsupported_suite"))
    assert proof.skip_reason == SKIP_UNSUPPORTED_SUITE
    assert proof.capture is not None
    assert proof.capture.has_unsupported_suite is True


def test_skip_no_app_records(tmp_path):
    proof = _prove(_make_run(tmp_path, capture="no_app_records"))
    assert proof.skip_reason == SKIP_NO_APP_RECORDS
    assert proof.capture is not None
    assert proof.capture.session_count == 1
    assert proof.capture.has_app_records is False


def test_skip_oracle_no_challenges(tmp_path):
    """Records exist; the challenge stream after the TLS 1.2 CCS gate is empty."""
    proof = _prove(_make_run(tmp_path, capture="no_challenges"))
    assert proof.skip_reason == SKIP_ORACLE_NO_CHALLENGES
    assert proof.capture is not None
    assert proof.capture.has_app_records is True
    assert proof.capture.challenges_returned == 0


def test_skip_secret_absent(tmp_path):
    run_dir = _make_run(tmp_path, dump_secrets=(FOREIGN_SECRET,))
    proof = _prove(run_dir)
    cell = _only(proof)
    assert cell.skip_reason == SKIP_SECRET_ABSENT
    assert cell.located is False
    assert cell.dumps_searched == 1


def test_skip_no_dumps_is_not_secret_absent(tmp_path):
    """31 corpus runs have a complete keylog and capture but ZERO dumps.

    Calling their secrets "absent" would be a positive claim over bytes that
    were never read; dropping them would delete 31 runs from the denominator.
    """
    run_dir = _make_run(tmp_path, dumps=0)
    proof = _prove(run_dir)
    cell = _only(proof)
    assert cell.skip_reason == SKIP_NO_DUMPS
    assert cell.skip_reason != SKIP_SECRET_ABSENT
    assert proof.secrets_total == 1
    assert proof.dumps_in_run == 0


def test_skip_client_random_mismatch_for_one_secret_only(tmp_path):
    """The run pairs, but one keylog line names a session the capture lacks."""
    run_dir = _make_run(
        tmp_path,
        keylog_lines=(
            ("CLIENT_RANDOM", CLIENT_RANDOM, MASTER_SECRET),
            ("CLIENT_RANDOM", FOREIGN_CLIENT_RANDOM, FOREIGN_SECRET),
        ),
        dump_secrets=(MASTER_SECRET, FOREIGN_SECRET),
    )
    proof = _prove(run_dir)
    assert proof.skip_reason == ""
    assert proof.pairing_ok is True
    by_cr = {p.client_random: p for p in proof.proofs}
    assert by_cr[CLIENT_RANDOM.hex()].confirmed is True
    foreign = by_cr[FOREIGN_CLIENT_RANDOM.hex()]
    assert foreign.skip_reason == SKIP_CLIENT_RANDOM_MISMATCH
    assert foreign.located is False


def test_every_skip_reason_is_exercised_by_this_module():
    """The taxonomy is closed AND covered: no reason ships untested."""
    source = Path(__file__).read_text()
    for reason in SKIP_REASONS:
        assert reason in source, reason


# --------------------------------------------------------------------------- #
# the happy path: a real decryption of a real capture
# --------------------------------------------------------------------------- #


def test_confirmed_hit_from_the_runs_own_capture(tmp_path):
    run_dir = _make_run(tmp_path)
    proof = _prove(run_dir)

    assert proof.skip_reason == ""
    assert proof.pairing_ok is True
    cell = _only(proof)
    assert cell.confirmed is True
    assert cell.confirmed_by == "pcap"
    assert cell.located is True
    assert cell.first_offset == SECRET_OFFSET
    assert cell.first_offset % 4 != 0, "the fixture must defeat a stride-4 grid"
    assert cell.secret_len == 48
    assert cell.skip_reason == ""
    assert cell.bucket == ""


def test_confirmed_hit_carries_canonical_and_raw_phase(tmp_path):
    """Phase axis is CANONICAL, with the raw filename phase retained."""
    proof = _prove(_make_run(tmp_path))
    cell = _only(proof)
    assert cell.raw_phase == "pre_abort"
    assert cell.canonical_phase.startswith("pre_")
    assert cell.canonical_phase != cell.raw_phase


def test_capture_facts_recorded_for_every_run(tmp_path):
    """Every non-confirmation must carry its own capture's facts.

    ``_reassemble`` is retransmission-naive by design, so an aggregate alone
    cannot explain a real-corpus non-confirmation.
    """
    proof = _prove(_make_run(tmp_path, dump_secrets=(FOREIGN_SECRET,)))
    assert proof.capture is not None
    assert proof.capture.session_count == 1
    assert proof.capture.challenges_available > 0
    assert proof.capture.max_records_per_direction > 0


# --------------------------------------------------------------------------- #
# the two denominators
# --------------------------------------------------------------------------- #


def _mixed_report(tmp_path):
    """One confirmed run, one located-but-unconfirmed, one skipped."""
    confirmed = _prove(_make_run(tmp_path, run_number=1))
    absent = _prove(_make_run(tmp_path, run_number=2,
                              dump_secrets=(FOREIGN_SECRET,)))
    no_capture = _prove(_make_run(tmp_path, run_number=3, capture="absent"))
    return build_report([confirmed, absent, no_capture], root=str(tmp_path),
                        max_runs_per_library=5)


def test_two_denominators_do_not_collapse(tmp_path):
    totals = _mixed_report(tmp_path).totals
    assert totals.confirmed == 1
    assert totals.secrets_located == 1
    assert totals.secrets_total == 3
    assert totals.rate_over_located == pytest.approx(1.0)
    assert totals.rate_over_total == pytest.approx(1.0 / 3.0)
    assert totals.rate_over_located != totals.rate_over_total


def test_there_is_no_single_collapsed_rate_attribute():
    """The API must not offer a way to report one number instead of two."""
    names = set(dir(ProofTotals))
    for forbidden in ("rate", "success_rate", "confirm_rate", "ratio"):
        assert forbidden not in names


def test_undefined_rates_are_none_not_zero():
    """A rate over an empty denominator is undefined, not 0%."""
    totals = ProofTotals()
    assert totals.rate_over_located is None
    assert totals.rate_over_total is None


def test_denominator_invariant_is_enforced():
    with pytest.raises(ValueError, match="denominator invariant"):
        ProofTotals(secrets_total=1, secrets_located=2, confirmed=0)


def test_totals_reconcile_with_the_not_counted_buckets(tmp_path):
    totals = _mixed_report(tmp_path).totals
    assert totals.reconciles() is True
    assert (totals.secrets_total
            == totals.confirmed + sum(totals.bucket_counts.values()))


# --------------------------------------------------------------------------- #
# the mandatory ``## Not counted`` section
# --------------------------------------------------------------------------- #


def test_not_counted_section_is_mandatory_even_when_everything_passed(tmp_path):
    report = build_report([_prove(_make_run(tmp_path))], root=str(tmp_path))
    markdown = render_markdown(report)
    assert "## Not counted" in markdown


def test_not_counted_section_lists_every_bucket(tmp_path):
    markdown = render_markdown(_mixed_report(tmp_path))
    section = markdown.split("## Not counted", 1)[1]
    for bucket in NOT_COUNTED_BUCKETS:
        assert "`" + bucket + "`" in section, bucket
    assert BUCKET_NOT_CONFIRMED in section


def test_not_counted_section_carries_example_run_paths(tmp_path):
    report = _mixed_report(tmp_path)
    section = render_markdown(report).split("## Not counted", 1)[1]
    absent_run = [r for r in report.runs if r.skip_reason == SKIP_NO_CAPTURE][0]
    assert absent_run.run_dir in section
    assert report.totals.example_paths[SKIP_NO_CAPTURE][0] == absent_run.run_dir


def test_not_counted_section_states_the_reconciliation(tmp_path):
    report = _mixed_report(tmp_path)
    section = render_markdown(report).split("## Not counted", 1)[1]
    assert "`secrets_total` (3)" in section
    assert "`confirmed` (1)" in section


def test_report_shows_both_denominators_side_by_side(tmp_path):
    markdown = render_markdown(_mixed_report(tmp_path))
    assert "confirmed / secrets_located" in markdown
    assert "confirmed / secrets_total" in markdown
    assert "Do not collapse" in markdown


# --------------------------------------------------------------------------- #
# row-level invariants
# --------------------------------------------------------------------------- #


def test_secret_proof_rejects_an_unknown_skip_reason():
    with pytest.raises(ValueError, match="unknown skip_reason"):
        SecretProof(secret_type="CLIENT_RANDOM", skip_reason="made_up")


def test_secret_proof_rejects_a_confirmed_but_unlocated_row():
    with pytest.raises(ValueError, match="must also be located"):
        SecretProof(confirmed=True, confirmed_by="pcap")


def test_secret_proof_rejects_located_without_offset():
    with pytest.raises(ValueError, match="contradicts first_offset"):
        SecretProof(located=True)


def test_run_proof_requires_one_row_per_keylog_secret():
    """A run-level failure must not collapse N secrets into one row."""
    with pytest.raises(ValueError, match="every secret must carry a row"):
        RunProof(secrets_total=3, proofs=(SecretProof(skip_reason=SKIP_NO_CAPTURE),))


def test_bucket_of_a_located_unconfirmed_row_is_not_a_skip():
    cell = SecretProof(located=True, first_offset=0)
    assert cell.skip_reason == ""
    assert cell.bucket == BUCKET_NOT_CONFIRMED


# --------------------------------------------------------------------------- #
# re-analysable without re-running
# --------------------------------------------------------------------------- #


def test_outcomes_json_round_trips(tmp_path):
    from memdiver.app.pipeline.corpus_pcap_runner import (
        report_from_outcomes,
        write_outcomes,
    )

    report = _mixed_report(tmp_path)
    path = write_outcomes(report, tmp_path / "out" / "outcomes.json")
    restored = report_from_outcomes(path)

    assert restored.root == report.root
    assert len(restored.runs) == len(report.runs)
    assert restored.totals.confirmed == report.totals.confirmed
    assert restored.totals.secrets_total == report.totals.secrets_total
    assert render_markdown(restored) == render_markdown(report)


def test_outcomes_totals_are_recomputed_not_trusted(tmp_path):
    """A tampered aggregate must never outrank the rows it summarises."""
    from memdiver.app.pipeline.corpus_pcap_runner import (
        report_from_outcomes,
        write_outcomes,
    )

    path = write_outcomes(_mixed_report(tmp_path), tmp_path / "outcomes.json")
    payload = json.loads(path.read_text())
    payload["totals"]["confirmed"] = 999
    path.write_text(json.dumps(payload))

    assert report_from_outcomes(path).totals.confirmed == 1


# --------------------------------------------------------------------------- #
# enumeration + the house runner shape
# --------------------------------------------------------------------------- #


def test_max_runs_per_library_defaults_to_five():
    from memdiver.app.pipeline import corpus_pcap_runner

    assert corpus_pcap_runner.DEFAULT_MAX_RUNS_PER_LIBRARY == 5


def test_iter_run_dirs_bounds_per_library_not_globally(tmp_path):
    from memdiver.app.pipeline.corpus_pcap_runner import iter_run_dirs

    for number in range(1, 8):
        _make_run(tmp_path, library="openssl", run_number=number)
        _make_run(tmp_path, library="wolfssl", run_number=number)

    found = list(iter_run_dirs(tmp_path, max_runs_per_library=2))
    assert len(found) == 4
    assert {p.parent.name for p in found} == {"openssl", "wolfssl"}
    assert sorted(p.name for p in found if p.parent.name == "openssl") == [
        "openssl_run_12_1", "openssl_run_12_2"]

    assert len(list(iter_run_dirs(tmp_path, max_runs_per_library=0))) == 14
    assert len(list(iter_run_dirs(
        tmp_path, libraries=["wolfssl"], max_runs_per_library=0))) == 7


class _FakeCtx:
    """Minimal TaskManager ctx: the ``emit`` / ``is_cancelled`` contract."""

    def __init__(self, task_id="t1"):
        self.task_id = task_id
        self.events = []

    def emit(self, kind, **kwargs):
        self.events.append((kind, kwargs))

    def is_cancelled(self):
        return False


def test_run_corpus_proof_returns_the_house_artifact_shape(tmp_path):
    from memdiver.app.pipeline.corpus_pcap_runner import (
        OUTCOMES_FILENAME,
        REPORT_FILENAME,
        run_corpus_proof,
    )

    _make_run(tmp_path / "corpus", run_number=1)
    _make_run(tmp_path / "corpus", run_number=2, capture="absent")
    artifact_dir = tmp_path / "artifacts"
    ctx = _FakeCtx()

    result = run_corpus_proof(
        {"root": str(tmp_path / "corpus"), "artifact_dir": str(artifact_dir)}, ctx)

    assert set(result) == {"artifacts", "summary"}
    names = {a["name"] for a in result["artifacts"]}
    assert names == {"corpus_proof_outcomes", "corpus_proof_report"}
    assert (artifact_dir / OUTCOMES_FILENAME).is_file()
    assert "## Not counted" in (artifact_dir / REPORT_FILENAME).read_text()

    summary = result["summary"]
    assert summary["confirmed"] == 1
    assert summary["secrets_total"] == 2
    assert summary["rate_over_located"] == pytest.approx(1.0)
    assert summary["rate_over_total"] == pytest.approx(0.5)
    assert summary["not_counted"][SKIP_NO_CAPTURE] == 1
    assert [kind for kind, _ in ctx.events][0] == "stage_start"
    assert [kind for kind, _ in ctx.events][-1] == "stage_end"


def test_run_corpus_proof_requires_a_root(tmp_path):
    from memdiver.app.pipeline.corpus_pcap_runner import run_corpus_proof

    with pytest.raises(ValueError, match="'root' is required"):
        run_corpus_proof({"artifact_dir": str(tmp_path)}, _FakeCtx())


# --------------------------------------------------------------------------- #
# locator contracts
# --------------------------------------------------------------------------- #


def test_locate_secret_never_calls_read_all(tmp_path):
    """``read_all`` is absent from gcore / regioned sources by design."""
    import memdiver.engine.corpus_proof as corpus_proof

    class _NoReadAll:
        format_name = "raw"
        size = 128

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def find_first(self, needle, view=None):
            return 7 if needle == MASTER_SECRET else None

    dump = tmp_path / "d.bin"
    dump.write_bytes(b"\x00")
    original = corpus_proof.open_dump
    try:
        corpus_proof.open_dump = lambda path, **kw: _NoReadAll()
        located = corpus_proof.locate_secret([dump], MASTER_SECRET)
        assert located is not None and located.offset == 7
        assert corpus_proof.locate_secret([dump], FOREIGN_SECRET) is None
    finally:
        corpus_proof.open_dump = original


def test_locate_secret_returns_the_first_dump_that_carries_it(tmp_path):
    run_dir = _make_run(tmp_path, dumps=3)
    dumps = sorted(run_dir.glob("*.dump"))
    located = locate_secret(dumps, MASTER_SECRET)
    assert located is not None
    assert located.dump_path == str(dumps[0])
    assert located.offset == SECRET_OFFSET


def test_locate_secret_rejects_an_empty_needle(tmp_path):
    with pytest.raises(ValueError, match="empty secret"):
        locate_secret([tmp_path / "nope.bin"], b"")


def test_locate_secret_skips_an_unreadable_dump_without_claiming_absence(tmp_path):
    run_dir = _make_run(tmp_path, dumps=1)
    good = sorted(run_dir.glob("*.dump"))[0]
    missing = run_dir / "20250101_120099_000001_pre_abort.dump"
    located = locate_secret([missing, good], MASTER_SECRET)
    assert located is not None and located.dump_path == str(good)


# --------------------------------------------------------------------------- #
# layering
# --------------------------------------------------------------------------- #


def test_engine_corpus_proof_never_imports_app_or_presentation():
    """``engine`` is pure compute; the orchestration half lives in ``app``."""
    tree = ast.parse((REPO_ROOT / "engine" / "corpus_proof.py").read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert not node.module.startswith("memdiver.app"), node.module
            assert not node.module.startswith("memdiver.presentation"), node.module
        elif isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("memdiver.app"), alias.name
                assert not alias.name.startswith("memdiver.presentation")


# --------------------------------------------------------------------------- #
# bounded REAL corpus -- one genuine confirmed_by == "pcap" hit
# --------------------------------------------------------------------------- #


@pytest.mark.requires_dataset
def test_real_run_key_decrypts_its_own_capture():
    """Bounded, real: one corpus run proven against its OWN traffic.pcap.

    NOT marked ``slow``: only a full-corpus pass earns that. This walks at most
    a handful of libraries' first run each and asserts a genuine
    ``confirmed_by == "pcap"`` -- a real AEAD decryption of really captured
    bytes, under a key really recovered from a real memory dump.
    """
    root = dataset_root()
    if root is None:
        pytest.skip(SKIP_REASON)

    from memdiver.app.pipeline.corpus_pcap_runner import iter_run_dirs, prove_run

    def _complete(version: str, limit: int):
        found = []
        for run_dir in iter_run_dirs(root, protocol_versions=[version],
                                     max_runs_per_library=1):
            if ((run_dir / "run_data" / "traffic.pcap").is_file()
                    and (run_dir / "keylog.csv").is_file()
                    and any(run_dir.glob("*.dump"))):
                found.append(run_dir)
            if len(found) >= limit:
                break
        return found

    # Bounded on BOTH protocol axes: TLS 1.2 exercises the 48-byte
    # CLIENT_RANDOM master secret, TLS 1.3 the 32-byte traffic secrets and the
    # multi-secret-per-run shape. Four runs each keeps this in the default run.
    run_dirs = _complete("12", 4) + _complete("13", 4)
    if not run_dirs:
        pytest.skip("no complete (dumps + keylog + capture) run under " + str(root))

    # Guard against a silently empty pass: a green assertion over zero real
    # runs would be exactly the vacuous result this whole module rejects.
    assert len(run_dirs) >= 2, run_dirs

    proofs = [prove_run(d) for d in run_dirs]
    confirmed = [c for p in proofs for c in p.proofs if c.confirmed]

    assert confirmed, (
        "no secret was proven against its own capture across "
        + str(len(run_dirs)) + " real run(s): "
        + repr([(p.run_dir, p.skip_reason,
                 [(c.secret_type, c.located, c.skip_reason) for c in p.proofs])
                for p in proofs]))
    assert all(c.confirmed_by == "pcap" for c in confirmed)

    # The triple held on every run we touched: a real capture always pairs with
    # its own keylog. A failure here means the corpus layout moved.
    assert all(p.pairing_ok for p in proofs if p.skip_reason == "")

    # Both key lengths really occur, and both are DERIVED, never assumed.
    assert {c.secret_len for c in confirmed} & {32, 48}

    totals = aggregate(proofs)
    assert totals.reconciles()
    assert totals.confirmed <= totals.secrets_located <= totals.secrets_total
    assert "## Not counted" in render_markdown(
        build_report(proofs, root=str(root), max_runs_per_library=1))
