"""C3 — ``analysis.locate_field_pairs`` on all four surfaces.

``locate_key`` already searches N dumps — for ONE needle. That is the right
question for a single session under investigation and the wrong one for a
corpus: 40 runs of the same client each negotiated their own handshake, so one
client random answers about 39 runs it was never in. ``locate_field_across_pairs``
asks the question that scales instead: *for each dump, is the ``field_id`` of the
capture that belongs to THAT dump present in it, and where?*

What these tests pin, in order:

* the exactly-one-of guard over ``pairs`` / ``dump_paths`` — both forms, and
  neither, are refused BY NAME rather than resolved by precedence;
* the three-valued pair model, which is the whole capability: a dump with no
  capture is a typed ``pairing: "unpaired"`` ROW and a capture that yields no
  usable field is ``"field_unresolved"``, and NEITHER is a zero-hit row.
  "Absent" (we looked and it is not there) and "never searched" (we could not
  look) must stay distinguishable, or every survival ratio computed from the
  result is over a silently deflated denominator;
* the ``status``/``location`` biconditional, ``_pair_row``'s lifted version of
  ``DumpKeyLocation``'s ``status``/``present`` rule;
* that the discovery form reuses the ONE run-discovery walker, and that the
  sibling probe appended to it cannot change a conventional run's answer;
* the four surfaces routing to one producer, and the real corpus proving the
  whole thing on a run of ten dumps and a real capture, with NO key log read.

The synthetic captures are handshake-only (ClientHello + ServerHello +
ChangeCipherSpec), so this module needs ``dpkt`` but not ``cryptography``: the
field extractor parses handshakes, and no record is ever decrypted here.
"""

from __future__ import annotations

import json
import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

dpkt = pytest.importorskip("dpkt")

from memdiver.core.service_errors import (  # noqa: E402
    CapabilityError,
    ErrorCategory,
    FileNotFoundServiceError,
)
from memdiver.app.tools_pipeline import (  # noqa: E402
    LOCATE_PAIRS_ABSENT_CODE,
    LOCATE_PAIRS_FIELD_UNRESOLVED_CODE,
    LOCATE_PAIRS_NOT_SEARCHED_CODE,
    LOCATE_PAIRS_OFFSET_DRIFT_CODE,
    LOCATE_PAIRS_PARTIAL_CODE,
    LOCATE_PAIRS_SHARED_CAPTURE_CODE,
    LOCATE_PAIRS_UNPAIRED_CODE,
    PAIR_FIELD_UNRESOLVED,
    PAIR_SEARCHED,
    PAIR_UNPAIRED,
    locate_field_across_pairs,
)
from memdiver.core.discovery import RunDiscovery  # noqa: E402

_ROUTE = "/api/pcaps/locate-field"
_CIPHER_CODE = 0xC02F  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

#: Where a planted needle is written into a synthetic dump. Non-zero on
#: purpose: an offset of 0 would let a bug that reports "found at 0" for every
#: dump pass, and 0 is also what a half-initialised result looks like.
_PLANT_OFFSET = 4096
_DUMP_SIZE = 16384


# --------------------------------------------------------------------------- #
# Synthetic wire + dump builders
# --------------------------------------------------------------------------- #

def _handshake(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type]) + len(body).to_bytes(3, "big") + body


def _client_hello(client_random: bytes) -> bytes:
    body = (
        b"\x03\x03" + client_random + b"\x00"
        + b"\x00\x02" + _CIPHER_CODE.to_bytes(2, "big")
        + b"\x01\x00"
        + b"\x00\x00"
    )
    return _handshake(1, body)


def _server_hello(server_random: bytes) -> bytes:
    body = (
        b"\x03\x03" + server_random + b"\x00"
        + _CIPHER_CODE.to_bytes(2, "big")
        + b"\x00"
        + b"\x00\x00"
    )
    return _handshake(2, body)


def _tls_record(content_type: int, fragment: bytes) -> bytes:
    return (bytes([content_type]) + b"\x03\x03"
            + len(fragment).to_bytes(2, "big") + fragment)


def _frame(sport: int, dport: int, seq: int, payload: bytes,
           *, to_server: bool) -> bytes:
    src, dst = ("10.0.0.1", "10.0.0.2") if to_server else ("10.0.0.2", "10.0.0.1")
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq, ack=0,
                       flags=dpkt.tcp.TH_ACK, data=payload)
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst),
                    p=dpkt.ip.IP_PROTO_TCP, data=tcp)
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(
        src=b"\x00\x00\x00\x00\x00\x01", dst=b"\x00\x00\x00\x00\x00\x02",
        type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
    return bytes(eth)


def _session_packets(client_random: bytes, client_port: int) -> list:
    """One handshake-only TLS 1.2 session on its own TCP flow."""
    server_random = bytes((b + 0x40) & 0xFF for b in client_random)
    packets = []
    seq = 1000
    for record in (_tls_record(22, _client_hello(client_random)),
                   _tls_record(20, b"\x01")):
        packets.append(_frame(client_port, 443, seq, record, to_server=True))
        seq += len(record)
    seq = 5000
    for record in (_tls_record(22, _server_hello(server_random)),
                   _tls_record(20, b"\x01")):
        packets.append(_frame(443, client_port, seq, record, to_server=False))
        seq += len(record)
    return packets


def write_capture(path: Path, *client_randoms: bytes) -> Path:
    """Write a capture holding one handshake-only session per client random."""
    path.parent.mkdir(parents=True, exist_ok=True)
    packets = []
    for index, client_random in enumerate(client_randoms):
        packets.extend(_session_packets(client_random, 12345 + index))
    with open(path, "wb") as handle:
        writer = dpkt.pcap.Writer(handle)
        for index, packet in enumerate(packets):
            writer.writepkt(packet, ts=float(index))
    return path


def write_dump(path: Path, needle: bytes = b"", *,
               offset: int = _PLANT_OFFSET) -> Path:
    """A dump of fixed size, optionally with *needle* planted at *offset*."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = bytearray(b"\xcc" * _DUMP_SIZE)
    if needle:
        data[offset:offset + len(needle)] = needle
    path.write_bytes(bytes(data))
    return path


def make_run(root: Path, name: str, client_random: bytes,
             *, present: bool = True, capture: bool = True) -> Path:
    """A conventional run dir: dumps plus ``run_data/traffic.pcap``."""
    run = root / name
    write_dump(run / "phase_a.dump", client_random if present else b"")
    if capture:
        write_capture(run / "run_data" / "traffic.pcap", client_random)
    return run


def _codes(payload: dict) -> set:
    return {d["code"] for d in payload["diagnostics"]}


def _random(seed: int) -> bytes:
    """A distinct, deterministic 32-byte client random per seed."""
    return bytes(((seed * 7 + i * 11) & 0xFF) for i in range(32))


# --------------------------------------------------------------------------- #
# (a) the exactly-one-of guard
# --------------------------------------------------------------------------- #

def test_both_input_forms_is_refused_naming_both(tmp_path):
    """No precedence: a caller sending both forms believes something specific
    about which capture each dump is matched against, and honouring one
    silently would produce a confident census read from the wrong capture."""
    run = make_run(tmp_path, "run_1", _random(1))
    with pytest.raises(CapabilityError) as excinfo:
        locate_field_across_pairs(
            pairs=[{"dump_path": str(run / "phase_a.dump"),
                    "pcap_path": str(run / "run_data" / "traffic.pcap")}],
            dump_paths=[str(run / "phase_a.dump")],
        )
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    message = str(excinfo.value)
    assert "pairs" in message and "dump_paths" in message
    assert "exactly ONE" in message


def test_neither_input_form_is_refused_naming_both():
    """The other half of the same guard — and it names the two forms rather
    than saying "missing argument", so the fix is readable from the message."""
    with pytest.raises(CapabilityError) as excinfo:
        locate_field_across_pairs()
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert "'pairs', 'dump_paths'" in str(excinfo.value)
    assert "none" in str(excinfo.value)


@pytest.mark.parametrize("kwargs", [{"pairs": []}, {"dump_paths": []}])
def test_an_empty_supplied_sequence_is_a_precondition(kwargs):
    """``pairs=[]`` is SUPPLIED-but-empty, not "not supplied": it passes the
    exactly-one-of guard and fails on the count, so the message is about the
    empty list rather than about which form to use."""
    with pytest.raises(CapabilityError) as excinfo:
        locate_field_across_pairs(**kwargs)
    assert excinfo.value.category is ErrorCategory.PRECONDITION
    assert "got 0" in str(excinfo.value)


def test_an_empty_field_id_is_refused(tmp_path):
    """An empty field name would resolve to nothing and read as a corpus-wide
    "field_unresolved", which is a finding about the corpus rather than about
    the request."""
    run = make_run(tmp_path, "run_1", _random(1))
    with pytest.raises(CapabilityError) as excinfo:
        locate_field_across_pairs(
            dump_paths=[str(run / "phase_a.dump")], field_id="   ")
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert "field_id" in str(excinfo.value)


@pytest.mark.parametrize("cap", ["pcap_max_records", "pcap_max_challenges"])
def test_a_cap_below_one_is_refused(tmp_path, cap):
    """Reuses ``_validate_pcap_caps``, so this producer cannot bless a cap the
    brute-force run itself would reject."""
    run = make_run(tmp_path, "run_1", _random(1))
    with pytest.raises(CapabilityError) as excinfo:
        locate_field_across_pairs(
            dump_paths=[str(run / "phase_a.dump")], **{cap: 0})
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert cap in str(excinfo.value)


# --------------------------------------------------------------------------- #
# (b) malformed explicit pairs — validated BEFORE anything is read
# --------------------------------------------------------------------------- #

def test_an_unknown_pair_key_is_refused_by_name(tmp_path):
    """A misspelt ``pcap`` silently dropped would leave the pair looking
    UNPAIRED, which reads as a fact about the corpus rather than a typo."""
    dump = write_dump(tmp_path / "a.dump", _random(1))
    with pytest.raises(CapabilityError) as excinfo:
        locate_field_across_pairs(
            pairs=[{"dump_path": str(dump), "pcap": "/x.pcap"}])
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert "pairs[0]" in str(excinfo.value)
    assert "'pcap'" in str(excinfo.value)


def test_a_missing_pair_key_is_refused_with_its_index(tmp_path):
    """The index is in the message: a 400-pair request needs to say WHICH."""
    dump = write_dump(tmp_path / "a.dump", _random(1))
    capture = write_capture(tmp_path / "a.pcap", _random(1))
    with pytest.raises(CapabilityError) as excinfo:
        locate_field_across_pairs(pairs=[
            {"dump_path": str(dump), "pcap_path": str(capture)},
            {"dump_path": str(dump)},
        ])
    assert "pairs[1]" in str(excinfo.value)
    assert "pcap_path" in str(excinfo.value)


def test_a_non_mapping_pair_is_refused(tmp_path):
    """A JSON list-of-lists is the shape a hand-written request most often
    arrives in; it fails with its own type named rather than an AttributeError."""
    with pytest.raises(CapabilityError) as excinfo:
        locate_field_across_pairs(pairs=[["/a.dump", "/a.pcap"]])
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert "list" in str(excinfo.value)


def test_a_missing_dump_is_not_found(tmp_path):
    """Checked up front, over BOTH sides of every pair, so a typo is reported
    before N dumps have been swept."""
    capture = write_capture(tmp_path / "a.pcap", _random(1))
    with pytest.raises(FileNotFoundServiceError) as excinfo:
        locate_field_across_pairs(pairs=[
            {"dump_path": str(tmp_path / "nope.dump"),
             "pcap_path": str(capture)}])
    assert "nope.dump" in str(excinfo.value)


def test_a_missing_explicit_capture_is_not_found(tmp_path):
    """An explicitly named capture that does not exist is a caller mistake, NOT
    an unpaired row: the caller asserted the pairing, so the assertion is
    wrong. A *discovered* capture that is missing is the other case, and it
    becomes a row (see the unpaired tests below)."""
    dump = write_dump(tmp_path / "a.dump", _random(1))
    with pytest.raises(FileNotFoundServiceError) as excinfo:
        locate_field_across_pairs(pairs=[
            {"dump_path": str(dump), "pcap_path": str(tmp_path / "nope.pcap")}])
    assert "nope.pcap" in str(excinfo.value)


# --------------------------------------------------------------------------- #
# (c) discovery: each dump finds its OWN capture
# --------------------------------------------------------------------------- #

def test_discovery_pairs_each_dump_with_its_own_run_capture(tmp_path):
    """THE capability. Three runs, three different client randoms, three
    captures — and each dump is searched for ITS run's random, not for one
    needle picked for all of them. A single-needle search would find one of
    the three and report the other two absent."""
    runs = [make_run(tmp_path, f"run_{i}", _random(i)) for i in (1, 2, 3)]
    dumps = [str(run / "phase_a.dump") for run in runs]

    payload = locate_field_across_pairs(dump_paths=dumps)

    assert payload["verdict"] == "found"
    assert payload["mode"] == "discovery"
    assert payload["field_id"] == "client_random"
    counts = payload["counts"]
    assert counts["pairs_total"] == counts["pairs_searched"] == 3
    assert counts["pairs_present"] == 3
    assert counts["pairs_absent"] == 0
    # The two numbers that say this was a REAL pairing rather than one needle
    # wearing three hats.
    assert counts["captures_distinct"] == 3
    assert counts["needles_distinct"] == 3
    assert LOCATE_PAIRS_SHARED_CAPTURE_CODE not in _codes(payload)

    for row, run, seed in zip(payload["pairs"], runs, (1, 2, 3)):
        assert row["pairing"] == "discovered"
        assert row["capture_status"] == "present"
        assert row["status"] == PAIR_SEARCHED
        assert row["needle_hex"] == _random(seed).hex()
        assert row["pcap_path"] == str(run / "run_data" / "traffic.pcap")
        assert row["location"]["verdict"] == "found"
        assert row["location"]["first_offset"] == _PLANT_OFFSET


def test_rows_come_back_in_the_supplied_order(tmp_path):
    """The row order is the request order, so a caller can zip its own list
    against ``pairs`` without matching on paths."""
    runs = [make_run(tmp_path, f"run_{i}", _random(i)) for i in (1, 2, 3)]
    dumps = [str(runs[2] / "phase_a.dump"), str(runs[0] / "phase_a.dump"),
             str(runs[1] / "phase_a.dump")]

    payload = locate_field_across_pairs(dump_paths=dumps)

    assert [r["dump_path"] for r in payload["pairs"]] == dumps


def test_a_run_directory_resolves_its_own_capture(tmp_path):
    """``find_capture_for`` normalises a dump to its parent, so passing the
    directory and passing a dump inside it must agree."""
    run = make_run(tmp_path, "run_1", _random(1))
    capture = str(run / "run_data" / "traffic.pcap")

    assert RunDiscovery.find_capture_for(run) == (Path(capture), "present")
    assert RunDiscovery.find_capture_for(run / "phase_a.dump") == (
        Path(capture), "present")


def test_a_capture_beside_the_dumps_is_found_by_the_sibling_probe(tmp_path):
    """The relaxation C3 needed: an ad-hoc directory (one dump, one capture, no
    ``run_data/``) can be paired at all. Reached ONLY because the conventional
    candidates returned absent."""
    flat = tmp_path / "flat"
    write_dump(flat / "a.dump", _random(9))
    write_capture(flat / "session.pcap", _random(9))

    found, status = RunDiscovery.find_capture_for(flat / "a.dump")
    assert (found, status) == (flat / "session.pcap", "present")

    payload = locate_field_across_pairs(dump_paths=[str(flat / "a.dump")])
    assert payload["verdict"] == "found"
    assert payload["pairs"][0]["pairing"] == "discovered"


def test_the_conventional_capture_still_wins_over_a_sibling(tmp_path):
    """The sibling probe is APPENDED, never merged in, so today's corpus
    resolution is bit-identical: a run that follows the convention has already
    matched before the sibling candidates are ever examined."""
    run = tmp_path / "run_1"
    write_dump(run / "a.dump", _random(1))
    write_capture(run / "run_data" / "traffic.pcap", _random(1))
    write_capture(run / "decoy.pcap", _random(2))

    found, status = RunDiscovery.find_capture_for(run / "a.dump")
    assert (found, status) == (run / "run_data" / "traffic.pcap", "present")


def test_the_sibling_probe_is_deterministic(tmp_path):
    """Two captures in one directory must resolve to the same one on every run,
    or a corpus sweep is not reproducible. ``.pcap`` before ``.pcapng``, and
    sorted within each."""
    flat = tmp_path / "flat"
    write_dump(flat / "a.dump", _random(1))
    write_capture(flat / "zzz.pcap", _random(1))
    write_capture(flat / "aaa.pcapng", _random(2))

    found, _ = RunDiscovery.find_capture_for(flat / "a.dump")
    assert found == flat / "zzz.pcap"


def test_find_capture_for_never_raises_on_a_missing_directory():
    """A pairing pass over a partial corpus must not abort on one bad path."""
    assert RunDiscovery.find_capture_for("/nonexistent/deep/a.dump") == (
        None, "absent")


# --------------------------------------------------------------------------- #
# (d) the three-valued pair model — the whole capability
# --------------------------------------------------------------------------- #

def test_an_unpaired_dump_is_a_typed_row_not_an_absence(tmp_path):
    """A dump with no capture had NO NEEDLE, so nothing was searched. It is a
    row with ``pairing: "unpaired"``, an empty ``needle_hex`` and a NULL
    ``location`` — never a zero-hit row, which would claim an absence over
    bytes nobody read."""
    orphan = write_dump(tmp_path / "lonely" / "a.dump", _random(1))

    payload = locate_field_across_pairs(dump_paths=[str(orphan)])

    assert payload["verdict"] == "not_searched"
    row = payload["pairs"][0]
    assert row["pairing"] == PAIR_UNPAIRED
    assert row["status"] == PAIR_UNPAIRED
    assert row["capture_status"] == "absent"
    assert row["needle_hex"] == ""
    assert row["location"] is None
    assert "no capture" in row["detail"]
    counts = payload["counts"]
    assert counts["pairs_unpaired"] == 1
    assert counts["pairs_searched"] == counts["pairs_absent"] == 0
    assert {LOCATE_PAIRS_UNPAIRED_CODE, LOCATE_PAIRS_NOT_SEARCHED_CODE} <= _codes(payload)


def test_an_unreadable_capture_is_unpaired_not_absent(tmp_path):
    """A zero-byte ``traffic.pcap`` is a corpus DEFECT, not a corpus fact. The
    walker's own three-state verdict rides through, so ``"unreadable"`` stays
    distinguishable from ``"absent"`` and neither becomes a hit count."""
    run = tmp_path / "run_1"
    write_dump(run / "a.dump", _random(1))
    (run / "run_data").mkdir(parents=True)
    (run / "run_data" / "traffic.pcap").write_bytes(b"")

    payload = locate_field_across_pairs(dump_paths=[str(run / "a.dump")])

    row = payload["pairs"][0]
    assert row["status"] == PAIR_UNPAIRED
    assert row["capture_status"] == "unreadable"
    assert row["pcap_path"].endswith("traffic.pcap")  # the path IS reported
    assert row["location"] is None
    assert payload["verdict"] == "not_searched"


def test_an_unpaired_dump_does_not_deflate_the_denominator(tmp_path):
    """The reason the row exists. Two dumps, one paired and holding the field,
    one unpaired: the honest survival statement is 1 of 1 SEARCHED with the
    second UNKNOWN, and every count in ``counts`` is over a stated
    denominator."""
    paired = make_run(tmp_path, "run_1", _random(1))
    orphan = write_dump(tmp_path / "lonely" / "b.dump", _random(2))

    payload = locate_field_across_pairs(
        dump_paths=[str(paired / "phase_a.dump"), str(orphan)])

    counts = payload["counts"]
    assert payload["verdict"] == "found"
    assert counts["pairs_total"] == 2
    assert counts["pairs_searched"] == 1
    assert counts["pairs_present"] == 1
    assert counts["pairs_unpaired"] == 1
    # 1/1, never 1/2.
    assert counts["pairs_present"] + counts["pairs_absent"] == counts["pairs_searched"]
    assert LOCATE_PAIRS_UNPAIRED_CODE in _codes(payload)


def test_a_mismatched_pair_is_a_measured_absence(tmp_path):
    """The counter-case to "unpaired": a dump paired with a capture whose
    client random it genuinely does not contain WAS searched, so it is an
    absence — a real finding over a known denominator, and it must not be
    confused with the unsearched rows above."""
    dump = write_dump(tmp_path / "a.dump", _random(1))
    other = write_capture(tmp_path / "other.pcap", _random(2))

    payload = locate_field_across_pairs(
        pairs=[{"dump_path": str(dump), "pcap_path": str(other)}])

    assert payload["verdict"] == "absent"
    row = payload["pairs"][0]
    assert row["pairing"] == "explicit"
    assert row["capture_status"] == "supplied"
    assert row["status"] == PAIR_SEARCHED
    assert row["needle_hex"] == _random(2).hex()  # searched for, not found
    assert row["location"]["verdict"] == "absent"
    assert row["location"]["first_offset"] is None
    assert LOCATE_PAIRS_ABSENT_CODE in _codes(payload)
    assert LOCATE_PAIRS_UNPAIRED_CODE not in _codes(payload)


def test_partial_survival_is_reported_as_evidence(tmp_path):
    """The normal shape of a real value across a process lifecycle, and the
    shape the reference corpus actually has (6 of 10)."""
    present = [make_run(tmp_path, f"live_{i}", _random(i)) for i in (1, 2)]
    absent = [make_run(tmp_path, f"wiped_{i}", _random(i), present=False)
              for i in (3, 4)]
    dumps = [str(r / "phase_a.dump") for r in present + absent]

    payload = locate_field_across_pairs(dump_paths=dumps)

    assert payload["verdict"] == "found"
    assert (payload["counts"]["pairs_present"],
            payload["counts"]["pairs_absent"]) == (2, 2)
    assert LOCATE_PAIRS_PARTIAL_CODE in _codes(payload)


def test_a_capture_without_the_field_is_field_unresolved_not_a_zero_hit(tmp_path):
    """Requirement 3. A capture that carries no usable ``field_id`` reports
    ``needle_hex: ""`` plus a diagnostic — not a searched row with zero hits.
    ``sni`` is absent from these extension-less hellos, so the resolver's own
    "unknown field_id" message rides through verbatim."""
    run = make_run(tmp_path, "run_1", _random(1))

    payload = locate_field_across_pairs(
        dump_paths=[str(run / "phase_a.dump")], field_id="sni")

    assert payload["verdict"] == "not_searched"
    row = payload["pairs"][0]
    assert row["pairing"] == "discovered"   # the CAPTURE was found...
    assert row["status"] == PAIR_FIELD_UNRESOLVED   # ...the field was not
    assert row["needle_hex"] == ""
    assert row["location"] is None
    assert "unknown pcap field_id" in row["detail"]
    assert payload["counts"]["pairs_field_unresolved"] == 1
    assert payload["counts"]["pairs_absent"] == 0
    assert LOCATE_PAIRS_FIELD_UNRESOLVED_CODE in _codes(payload)


def test_a_non_searchable_field_is_refused_per_pair(tmp_path):
    """C2's searchable gate, reused verbatim: a 2-byte ``cipher_suite`` occurs
    everywhere in any real dump, so a hit on it carries no information. The
    refusal becomes a row rather than an exception, so one bad field does not
    discard the census for the rest of the set."""
    run = make_run(tmp_path, "run_1", _random(1))

    payload = locate_field_across_pairs(
        dump_paths=[str(run / "phase_a.dump")], field_id="cipher_suite")

    row = payload["pairs"][0]
    assert row["status"] == PAIR_FIELD_UNRESOLVED
    assert row["needle_hex"] == ""
    assert "not searchable" in row["detail"]


def test_one_unresolvable_capture_does_not_discard_the_other_pairs(tmp_path):
    """Caught, not propagated: raising would throw away the answer for every
    other pair, which is the all-or-nothing failure the row model exists to
    avoid."""
    good = make_run(tmp_path, "good", _random(1))
    empty = tmp_path / "empty"
    write_dump(empty / "a.dump", _random(2))
    write_capture(empty / "run_data" / "traffic.pcap")  # zero sessions

    payload = locate_field_across_pairs(dump_paths=[
        str(good / "phase_a.dump"), str(empty / "a.dump")])

    assert payload["verdict"] == "found"
    assert payload["pairs"][0]["status"] == PAIR_SEARCHED
    assert payload["pairs"][1]["status"] == PAIR_FIELD_UNRESOLVED
    assert "no parsed TLS session" in payload["pairs"][1]["detail"]


def test_a_multi_session_capture_refuses_to_guess_per_pair(tmp_path):
    """There is no default session on purpose — the wrong session's field is a
    valid-looking needle from another handshake. The refusal arrives as a
    ``field_unresolved`` row carrying the choices, not as an aborted call."""
    dump = write_dump(tmp_path / "a.dump", _random(1))
    capture = write_capture(tmp_path / "two.pcap", _random(1), _random(2))

    payload = locate_field_across_pairs(
        pairs=[{"dump_path": str(dump), "pcap_path": str(capture)}])

    row = payload["pairs"][0]
    assert row["status"] == PAIR_FIELD_UNRESOLVED
    assert row["needle_hex"] == ""
    assert "2 sessions" in row["detail"]


def test_client_random_selects_one_session_of_a_multi_session_capture(tmp_path):
    """...and naming the session resolves it. Two pairs over the SAME capture
    pick different sessions, which is why the needle memo is keyed by the
    selector as well as the path."""
    capture = write_capture(tmp_path / "two.pcap", _random(1), _random(2))
    first = write_dump(tmp_path / "first.dump", _random(1))
    second = write_dump(tmp_path / "second.dump", _random(2))

    payload = locate_field_across_pairs(pairs=[
        {"dump_path": str(first), "pcap_path": str(capture),
         "client_random": _random(1).hex()},
        {"dump_path": str(second), "pcap_path": str(capture),
         "client_random": _random(2).hex()},
    ])

    assert payload["verdict"] == "found"
    assert payload["counts"]["pairs_present"] == 2
    assert payload["counts"]["captures_distinct"] == 1
    # ONE capture, TWO needles — the memo did not collapse the two selectors.
    assert payload["counts"]["needles_distinct"] == 2
    assert [r["needle_hex"] for r in payload["pairs"]] == [
        _random(1).hex(), _random(2).hex()]


def test_every_row_honours_the_status_location_biconditional(tmp_path):
    """``location`` is non-NULL if and ONLY IF ``status == "searched"``, over a
    set containing all three statuses at once."""
    searched = make_run(tmp_path, "run_1", _random(1))
    orphan = write_dump(tmp_path / "lonely" / "b.dump", _random(2))
    no_field = make_run(tmp_path, "run_3", _random(3))

    payload = locate_field_across_pairs(dump_paths=[
        str(searched / "phase_a.dump"), str(orphan),
        str(no_field / "phase_a.dump")])
    # ``sni`` is missing from every synthetic capture, so re-run for that one
    # pair rather than fabricating a row.
    unresolved = locate_field_across_pairs(
        dump_paths=[str(no_field / "phase_a.dump")], field_id="sni")

    rows = payload["pairs"] + unresolved["pairs"]
    statuses = {r["status"] for r in rows}
    assert statuses == {PAIR_SEARCHED, PAIR_UNPAIRED, PAIR_FIELD_UNRESOLVED}
    for row in rows:
        assert (row["location"] is not None) == (row["status"] == PAIR_SEARCHED)
        assert bool(row["needle_hex"]) == (row["status"] == PAIR_SEARCHED)


# --------------------------------------------------------------------------- #
# (e) cross-pair aggregation
# --------------------------------------------------------------------------- #

def test_one_capture_for_n_dumps_is_reported_as_a_shared_capture(tmp_path):
    """N dumps of ONE run share one capture, so this is one session's field
    traced across N dumps — not N independently paired sessions. Saying so is
    the difference between a corpus claim and a single-session one."""
    run = tmp_path / "run_1"
    write_capture(run / "run_data" / "traffic.pcap", _random(1))
    for name in ("phase_a.dump", "phase_b.dump", "phase_c.dump"):
        write_dump(run / name, _random(1))

    payload = locate_field_across_pairs(
        dump_paths=[str(run / n) for n in
                    ("phase_a.dump", "phase_b.dump", "phase_c.dump")])

    assert payload["counts"]["captures_distinct"] == 1
    assert payload["counts"]["needles_distinct"] == 1
    assert LOCATE_PAIRS_SHARED_CAPTURE_CODE in _codes(payload)


def test_agreeing_offsets_report_a_common_offset(tmp_path):
    """The genuinely new cross-pair fact: independent sessions landing their
    field at the SAME offset is what makes an offset-based rule generalise."""
    runs = [make_run(tmp_path, f"run_{i}", _random(i)) for i in (1, 2, 3)]

    payload = locate_field_across_pairs(
        dump_paths=[str(r / "phase_a.dump") for r in runs])

    assert payload["offsets_agree"] is True
    assert payload["common_offset"] == _PLANT_OFFSET
    assert LOCATE_PAIRS_OFFSET_DRIFT_CODE not in _codes(payload)


def test_drifting_offsets_report_no_common_offset(tmp_path):
    """...and when they do not agree, no single offset generalises, which is
    reported rather than papered over with a first/modal value."""
    first = tmp_path / "run_1"
    write_dump(first / "a.dump", _random(1), offset=_PLANT_OFFSET)
    write_capture(first / "run_data" / "traffic.pcap", _random(1))
    second = tmp_path / "run_2"
    write_dump(second / "a.dump", _random(2), offset=_PLANT_OFFSET + 512)
    write_capture(second / "run_data" / "traffic.pcap", _random(2))

    payload = locate_field_across_pairs(
        dump_paths=[str(first / "a.dump"), str(second / "a.dump")])

    assert payload["offsets_agree"] is False
    assert payload["common_offset"] is None
    assert LOCATE_PAIRS_OFFSET_DRIFT_CODE in _codes(payload)


def test_the_location_block_is_locate_key_shaped(tmp_path):
    """One shape for "where is this value", whether asked via ``locate_key`` or
    as one pair of this search — so a consumer renders one block, not two."""
    from memdiver.app.tools_pipeline import locate_key

    run = make_run(tmp_path, "run_1", _random(1))
    dump = str(run / "phase_a.dump")
    capture = str(run / "run_data" / "traffic.pcap")

    paired = locate_field_across_pairs(dump_paths=[dump])["pairs"][0]["location"]
    direct = locate_key(dump_paths=[dump], pcap_field={
        "pcap_path": capture, "field_id": "client_random"})

    assert set(paired) == set(direct)
    assert paired["input_form"] == direct["input_form"] == "pcap_field"
    assert paired["secret_type"] == direct["secret_type"] == "client_random"
    assert paired["needle_sha256"] == direct["needle_sha256"]
    assert paired["dumps"] == direct["dumps"]


# --------------------------------------------------------------------------- #
# (f) the web surface — POST /api/pcaps/locate-field
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient

    from memdiver.api.main import create_app

    return TestClient(create_app())


def test_route_returns_the_producer_payload(client, tmp_path):
    """The route hands back the producer's dict verbatim."""
    runs = [make_run(tmp_path, f"web_{i}", _random(i)) for i in (1, 2)]
    resp = client.post(_ROUTE, json={
        "dump_paths": [str(r / "phase_a.dump") for r in runs]})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["verdict"] == "found"
    assert body["mode"] == "discovery"
    assert body["counts"]["needles_distinct"] == 2
    assert body["pairs"][0]["pairing"] == "discovered"


def test_route_accepts_explicit_pairs(client, tmp_path):
    """The other input form over HTTP, with the ``pairs`` entries typed as
    plain dicts so the PRODUCER owns their validation."""
    dump = write_dump(tmp_path / "web_x.dump", _random(5))
    capture = write_capture(tmp_path / "web_x.pcap", _random(5))
    resp = client.post(_ROUTE, json={"pairs": [
        {"dump_path": str(dump), "pcap_path": str(capture)}]})

    assert resp.status_code == 200, resp.text
    assert resp.json()["mode"] == "explicit"
    assert resp.json()["pairs"][0]["pairing"] == "explicit"


def test_route_returns_200_for_a_legitimate_absence(client, tmp_path):
    """An absence is a FINDING, not an error: 200 with verdict ``absent``."""
    dump = write_dump(tmp_path / "web_miss.dump", _random(1))
    capture = write_capture(tmp_path / "web_miss.pcap", _random(2))
    resp = client.post(_ROUTE, json={"pairs": [
        {"dump_path": str(dump), "pcap_path": str(capture)}]})

    assert resp.status_code == 200, resp.text
    assert resp.json()["verdict"] == "absent"


def test_route_returns_200_and_a_typed_row_for_an_unpaired_dump(client, tmp_path):
    """Also not an error: the honest answer is a row saying nothing was
    searched, which the route must not turn into a 4xx."""
    orphan = write_dump(tmp_path / "web_lonely" / "a.dump", _random(1))
    resp = client.post(_ROUTE, json={"dump_paths": [str(orphan)]})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["verdict"] == "not_searched"
    assert body["pairs"][0]["pairing"] == "unpaired"


def test_route_rejects_both_input_forms(client, tmp_path):
    """The exactly-one-of guard reaches the transport through the app's single
    global CapabilityError handler — there is no try/except in the route."""
    run = make_run(tmp_path, "web_both", _random(1))
    dump = str(run / "phase_a.dump")
    resp = client.post(_ROUTE, json={
        "dump_paths": [dump],
        "pairs": [{"dump_path": dump,
                   "pcap_path": str(run / "run_data" / "traffic.pcap")}],
    })

    assert resp.status_code == 400, resp.text
    # The global funnel's ``{error, code, category}`` body, not FastAPI's
    # ``detail`` — the category is what a client switches on.
    body = resp.json()
    assert body["category"] == "INVALID_INPUT"
    assert "exactly ONE" in body["error"]


def test_route_404s_a_missing_dump(client, tmp_path):
    resp = client.post(_ROUTE, json={
        "dump_paths": [str(tmp_path / "web_nope.dump")]})

    assert resp.status_code == 404, resp.text
    body = resp.json()
    assert body["category"] == "NOT_FOUND"
    assert "web_nope.dump" in body["error"]


def test_route_rejects_a_cap_below_one(client, tmp_path):
    """``ge=1`` on the model, matching ``ValidatePcapRequest``: FastAPI answers
    422 before the producer is reached, which is the same refusal one layer
    earlier."""
    run = make_run(tmp_path, "web_cap", _random(1))
    resp = client.post(_ROUTE, json={
        "dump_paths": [str(run / "phase_a.dump")], "pcap_max_records": 0})

    assert resp.status_code == 422, resp.text


# --------------------------------------------------------------------------- #
# (g) the MCP surface
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def mcp_tool():
    """The registered MCP tool's callable, funnel and all."""
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server

    tools = {t.name: t for t in create_server()._tool_manager.list_tools()}
    assert "locate_field_across_pairs" in tools, sorted(tools)
    return tools["locate_field_across_pairs"].fn


def test_mcp_tool_returns_json_payload(mcp_tool, tmp_path):
    """A JSON STRING (the MCP transport contract) carrying the producer's dict."""
    runs = [make_run(tmp_path, f"mcp_{i}", _random(i)) for i in (1, 2)]
    raw = mcp_tool(dump_paths=[str(r / "phase_a.dump") for r in runs])

    assert isinstance(raw, str)
    payload = json.loads(raw)
    assert "error" not in payload, payload
    assert payload["verdict"] == "found"
    assert payload["counts"]["captures_distinct"] == 2


def test_mcp_tool_funnels_the_both_forms_error(mcp_tool, tmp_path):
    """A CapabilityError escaping the body is rendered as the structured
    ``{error, code, category}`` dict — an agent gets machine-readable text."""
    run = make_run(tmp_path, "mcp_both", _random(1))
    dump = str(run / "phase_a.dump")
    payload = json.loads(mcp_tool(
        dump_paths=[dump],
        pairs=[{"dump_path": dump,
                "pcap_path": str(run / "run_data" / "traffic.pcap")}]))

    assert payload["category"] == "INVALID_INPUT"
    assert "exactly ONE" in payload["error"]


def test_mcp_tool_funnels_not_found(mcp_tool, tmp_path):
    payload = json.loads(mcp_tool(dump_paths=[str(tmp_path / "mcp_nope.dump")]))

    assert payload["category"] == "NOT_FOUND"
    assert payload["error"].startswith("File not found:")


def test_mcp_and_web_agree_on_the_same_pairs(mcp_tool, client, tmp_path):
    """Cross-surface parity: both adapters dispatch through the ONE producer,
    so the same inputs must yield the same census. Any future change that
    inlines the pairing in one adapter fails here."""
    runs = [make_run(tmp_path, f"parity_{i}", _random(i)) for i in (1, 2)]
    dumps = [str(r / "phase_a.dump") for r in runs]

    from_mcp = json.loads(mcp_tool(dump_paths=dumps))
    resp = client.post(_ROUTE, json={"dump_paths": dumps})

    assert resp.status_code == 200, resp.text
    from_web = resp.json()
    assert from_mcp["counts"] == from_web["counts"]
    assert ([r["needle_hex"] for r in from_mcp["pairs"]]
            == [r["needle_hex"] for r in from_web["pairs"]])
    assert from_mcp["common_offset"] == from_web["common_offset"]


# --------------------------------------------------------------------------- #
# (h) the CLI surface
# --------------------------------------------------------------------------- #

def _run_cli(argv, tmp_path):
    """Invoke the ``locate-field-pairs`` handler and return (exit, payload)."""
    from memdiver.cli import _cmd_locate_field_pairs, build_parser

    out = tmp_path / f"cli_{abs(hash(tuple(argv))) % 10**8}.json"
    args = build_parser().parse_args(
        ["locate-field-pairs", *argv, "-o", str(out)])
    code = _cmd_locate_field_pairs(args)
    return code, json.loads(out.read_text())


def test_cli_exits_zero_on_found(tmp_path, capsys):
    """Exit 0 = found, and the verdict line plus every diagnostic go to STDERR
    so an operator piping the JSON onward still sees the qualifications."""
    runs = [make_run(tmp_path, f"cli_{i}", _random(i)) for i in (1, 2)]
    code, payload = _run_cli(
        [str(r / "phase_a.dump") for r in runs], tmp_path)

    assert code == 0
    assert payload["verdict"] == "found"
    err = capsys.readouterr().err
    assert "verdict=found" in err
    assert "field=client_random" in err


def test_cli_exits_three_on_absent(tmp_path):
    """Exit 3 is ``_CLI_EXIT[NOT_FOUND]``, reused rather than reinvented — and
    the full payload is still written, because a non-zero exit is a verdict."""
    run = tmp_path / "cli_miss"
    write_dump(run / "a.dump", _random(1))
    write_capture(run / "run_data" / "traffic.pcap", _random(2))
    code, payload = _run_cli([str(run / "a.dump")], tmp_path)

    assert code == 3
    assert payload["verdict"] == "absent"
    assert payload["pairs"][0]["status"] == PAIR_SEARCHED


def test_cli_exits_two_when_nothing_was_searched(tmp_path):
    """Exit 2 is the caller-correctable code, which is what an unpaired set is:
    nothing was read, and the inputs need fixing."""
    orphan = write_dump(tmp_path / "cli_lonely" / "a.dump", _random(1))
    code, payload = _run_cli([str(orphan)], tmp_path)

    assert code == 2
    assert payload["verdict"] == "not_searched"


def test_cli_reads_explicit_pairs_from_a_json_file(tmp_path):
    """The ordinary way to pass an explicit pairing — a real corpus pairing is
    far too long to type."""
    dump = write_dump(tmp_path / "cli_x.dump", _random(7))
    capture = write_capture(tmp_path / "cli_x.pcap", _random(7))
    pairs_file = tmp_path / "pairs.json"
    pairs_file.write_text(json.dumps(
        [{"dump_path": str(dump), "pcap_path": str(capture)}]))

    code, payload = _run_cli(["--pairs", str(pairs_file)], tmp_path)

    assert code == 0
    assert payload["mode"] == "explicit"
    assert payload["pairs"][0]["needle_hex"] == _random(7).hex()


def test_cli_accepts_inline_pairs_json(tmp_path):
    """A path is tried FIRST and inline JSON only when no such file exists, so
    a filename that happens to look like JSON is never reinterpreted."""
    dump = write_dump(tmp_path / "cli_y.dump", _random(8))
    capture = write_capture(tmp_path / "cli_y.pcap", _random(8))
    inline = json.dumps([{"dump_path": str(dump), "pcap_path": str(capture)}])

    code, payload = _run_cli(["--pairs", inline], tmp_path)

    assert code == 0
    assert payload["mode"] == "explicit"


def test_cli_accepts_an_inline_pairing_longer_than_a_path(tmp_path):
    """The inline form must survive a pairing too long to be a path at all.

    ``Path(raw).is_file()`` RAISES ``OSError`` ENAMETOOLONG rather than
    returning ``False`` once the value exceeds the filesystem's limits, so
    before the guard a legitimate multi-pair ``--pairs '[{...}]'`` — the very
    case the flag's "far too long to type" doc describes — died with a
    traceback instead of parsing. Eight pairs of real absolute paths clears
    ``PATH_MAX`` comfortably; the assertion on the length keeps the test from
    passing vacuously if a future tmp layout got shorter.
    """
    pairs = []
    for index in range(8):
        run = make_run(tmp_path, f"cli_long_{index}", _random(index + 20))
        pairs.append({"dump_path": str(run / "phase_a.dump"),
                      "pcap_path": str(run / "run_data" / "traffic.pcap")})
    inline = json.dumps(pairs)
    assert len(inline) > 255

    code, payload = _run_cli(["--pairs", inline], tmp_path)

    assert code == 0
    assert payload["mode"] == "explicit"
    assert payload["counts"]["pairs_present"] == 8


def test_cli_rejects_unparseable_pairs(tmp_path):
    from memdiver.cli import build_parser, _cmd_locate_field_pairs

    args = build_parser().parse_args(
        ["locate-field-pairs", "--pairs", "{not json"])
    with pytest.raises(CapabilityError) as excinfo:
        _cmd_locate_field_pairs(args)
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert "--pairs" in str(excinfo.value)


def test_cli_rejects_pairs_that_are_not_a_list(tmp_path):
    from memdiver.cli import build_parser, _cmd_locate_field_pairs

    args = build_parser().parse_args(
        ["locate-field-pairs", "--pairs", '{"dump_path": "/a"}'])
    with pytest.raises(CapabilityError) as excinfo:
        _cmd_locate_field_pairs(args)
    assert "JSON list" in str(excinfo.value)


def test_cli_refuses_pairs_together_with_positional_dumps(tmp_path):
    """--pairs drops the positional dumps to ``None`` rather than passing an
    empty list, so the producer sees exactly one form... and a caller giving
    BOTH still reaches the producer's own both-forms refusal."""
    dump = write_dump(tmp_path / "cli_both.dump", _random(1))
    capture = write_capture(tmp_path / "cli_both.pcap", _random(1))
    inline = json.dumps([{"dump_path": str(dump), "pcap_path": str(capture)}])
    from memdiver.cli import build_parser, _cmd_locate_field_pairs

    # With --pairs AND positional dumps, --pairs wins at the CLI boundary
    # (documented on the flag) and the run succeeds against the explicit form.
    args = build_parser().parse_args(
        ["locate-field-pairs", str(dump), "--pairs", inline])
    assert _cmd_locate_field_pairs(args) == 0


# --------------------------------------------------------------------------- #
# (i) the real corpus — the committed fixture is ONE pair by construction
# --------------------------------------------------------------------------- #

_TLS13_RUN = ("TLS13/100_iterations_Abort_KeyUpdate/openssl/openssl_run_13_1")


def _tls13_run_dir() -> Path:
    from tests.fixtures.tls_ground_truth import tls_dumps_dir

    return Path(tls_dumps_dir()) / _TLS13_RUN


@pytest.mark.requires_dataset
def test_real_run_locates_the_client_random_with_no_keylog_read():
    """THE load-bearing assertion. A real OpenSSL TLS 1.3 run: ten dumps, one
    ``run_data/traffic.pcap``, and NO key log read anywhere — the needle is the
    capture's own ClientHello random, resolved off the wire.

    The measured answer: present in 6 of the 10 dumps at offset 583560 and
    provably absent from the last 4 (the run's later ``*_cleanup`` phases), with
    every one of the six agreeing on the offset. The 6/4 split is the same
    partial-survival shape ``locate_key``'s TLS 1.2 test measures as 2-of-8 for
    a master secret; here it is a handshake field, which survives longer.
    """
    run_dir = _tls13_run_dir()
    dumps = sorted(run_dir.glob("*.dump"))
    if len(dumps) != 10 or not (run_dir / "run_data" / "traffic.pcap").is_file():
        pytest.skip(f"TLS 1.3 reference run not present under {run_dir}")

    payload = locate_field_across_pairs(dump_paths=[str(p) for p in dumps])

    assert payload["verdict"] == "found"
    assert payload["mode"] == "discovery"
    assert payload["field_id"] == "client_random"

    counts = payload["counts"]
    assert counts["pairs_total"] == counts["pairs_searched"] == 10
    assert (counts["pairs_present"], counts["pairs_absent"]) == (6, 4)
    assert counts["pairs_unpaired"] == counts["pairs_field_unresolved"] == 0
    # One run, one capture: the honest reading is "one session's field across
    # ten dumps", and the diagnostic says exactly that.
    assert (counts["captures_distinct"], counts["needles_distinct"]) == (1, 1)
    assert LOCATE_PAIRS_SHARED_CAPTURE_CODE in _codes(payload)
    assert LOCATE_PAIRS_PARTIAL_CODE in _codes(payload)

    # Non-zero, and identical in all six — an accidental "found at 0" cannot
    # pass, and neither can a first_offset carried over between pairs.
    assert payload["offsets_agree"] is True
    assert payload["common_offset"] == 583560
    present = [r for r in payload["pairs"] if r["location"]["verdict"] == "found"]
    assert [r["location"]["first_offset"] for r in present] == [583560] * 6
    # ``hit_count`` lives on the per-dump row inside the location block (the
    # top level carries the aggregate), and it is the TRUE total: one copy of
    # the client random per dump, so no truncation is in play.
    assert all(r["location"]["dumps"][0]["hit_count"] == 1 for r in present)

    # Every pair was discovered from the run's own capture, and every needle is
    # the SAME 32-byte ClientHello random, read off the wire.
    assert {r["pairing"] for r in payload["pairs"]} == {"discovered"}
    assert {r["capture_status"] for r in payload["pairs"]} == {"present"}
    needle = {r["needle_hex"] for r in payload["pairs"]}
    assert len(needle) == 1 and len(needle.pop()) == 64

    # The absences are the run's LATER phases: the field is wiped by cleanup,
    # which is what makes the 6/4 split evidence rather than a shortfall.
    absent_names = [r["dump_name"] for r in payload["pairs"]
                    if r["location"]["verdict"] == "absent"]
    assert len(absent_names) == 4
    assert all("cleanup" in name for name in absent_names)


@pytest.mark.requires_dataset
def test_real_runs_pair_independently_and_agree_on_the_offset():
    """The multi-run case the committed fixture cannot express: THREE separate
    runs, each with its own capture and its own ClientHello random, paired
    independently. Three distinct needles, and all three land at the same
    offset — a cross-session fact no single-needle search can produce."""
    from tests.fixtures.tls_ground_truth import tls_dumps_dir

    base = (Path(tls_dumps_dir()) / "TLS13"
            / "100_iterations_Abort_KeyUpdate" / "openssl")
    runs = sorted(base.glob("openssl_run_13_*"))[:3]
    if len(runs) < 3:
        pytest.skip(f"fewer than 3 TLS 1.3 reference runs under {base}")

    dumps = []
    for run in runs:
        phase = sorted(run.glob("*_pre_server_key_update.dump"))
        if not phase or not (run / "run_data" / "traffic.pcap").is_file():
            pytest.skip(f"{run} is not a complete reference run")
        dumps.append(str(phase[0]))

    payload = locate_field_across_pairs(dump_paths=dumps)

    counts = payload["counts"]
    assert payload["verdict"] == "found"
    assert counts["pairs_present"] == 3
    # THREE captures, THREE needles — this is the pairing, not one needle
    # wearing three hats, and the shared-capture caveat must NOT fire.
    assert (counts["captures_distinct"], counts["needles_distinct"]) == (3, 3)
    assert LOCATE_PAIRS_SHARED_CAPTURE_CODE not in _codes(payload)

    assert payload["offsets_agree"] is True
    assert payload["common_offset"] == 583560
    assert len({r["needle_hex"] for r in payload["pairs"]}) == 3
