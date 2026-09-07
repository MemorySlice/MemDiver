"""C4a — detect the capture's protocol, report it, and REFUSE rather than guess.

Before this, a capture with no TLS handshake produced exactly one sentence:
``no complete TLS handshake found in 'x.pcap'``. True, and useless to the user
who captured QUIC — it names what was looked for and never what is there. C4a
adds the missing half: :mod:`memdiver.engine.resources.protocol_detect` reports
one candidate per protocol the capture carries, ``inspect_pcap`` publishes that
under a flag, and ``brute_force`` / ``n_sweep`` turn it into a refusal that says
what was found and whether anything installed can decrypt it.

What these tests pin, in order:

1. **The default is byte-identical.** ``detect_protocols`` unset returns exactly
   the pre-C4a payload — asserted as an equality over the whole dict, not a
   key-set check, because a changed VALUE would regress the arm step just as
   badly (the shape C2 established for the same reason).
2. **Detection is right about the four cases that matter**: a real TLS capture
   is ``tls`` and decryptable; plain TCP and plain UDP are named but NOT
   decryptable; QUIC and DTLS are recognised off the wire without being
   guessed at from a port number.
3. **Detection never raises.** A garbage file, a missing file and a
   text file all answer with an empty tuple, because this code runs on the
   failure path — a detector that threw would replace a bad-but-true error with
   a traceback about the diagnostic.
4. **``decryptable`` comes from the LIVE registry.** A second registered
   resource type makes its protocol decryptable with no edit to the detector,
   which is the whole point of C4b's entry-point group.
5. **The refusals.** One decryptable protocol that is not the one we were told
   to use names it; SEVERAL raise ``PRECONDITION`` and demand an explicit
   ``resource_type`` rather than picking one — the same rule, in the same shape,
   as C2's multi-session refusal.
6. **``resource_type`` is reachable.** The refusal demands it, so ``brute_force``
   / ``n_sweep`` / MCP / CLI must all accept it; an error demanding what the
   caller cannot supply is a dead end, not an error.

The repo has no non-TLS capture and this does not add one: every capture below
is synthesised in ``tmp_path`` with dpkt, the way
``tests/test_tls_pcap_resource.py`` does. The committed TLS 1.3 fixture covers
the positive case. No corpus.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

pytest.importorskip("dpkt")

import dpkt  # noqa: E402

from memdiver.app import tools_pipeline  # noqa: E402
from memdiver.app.tools_pipeline import (  # noqa: E402
    DEFAULT_RESOURCE_TYPE,
    inspect_pcap,
)
from memdiver.core.service_errors import CapabilityError, ErrorCategory  # noqa: E402
from memdiver.engine.resources import builtin_oracle  # noqa: E402
from memdiver.engine.resources.protocol_detect import (  # noqa: E402
    PROTOCOL_RESOURCE_TYPES,
    ProtocolCandidate,
    detect_protocols,
)

_FIXTURE_PCAP = (
    Path(__file__).resolve().parent / "e2e" / "fixtures" / "pcap" / "session_tls13.pcap"
)

CLIENT_IP, SERVER_IP = "10.0.0.1", "10.0.0.2"
CLIENT_PORT, SERVER_PORT = 40001, 443


# --------------------------------------------------------------------------- #
# Synthetic wire builders — one capture per protocol, none of them committed.
# --------------------------------------------------------------------------- #


def _frame(proto_layer, src_ip: str, dst_ip: str, proto: int) -> bytes:
    """Wrap a TCP/UDP layer in IP + Ethernet, the link type dpkt defaults to."""
    ip = dpkt.ip.IP(
        src=socket.inet_aton(src_ip), dst=socket.inet_aton(dst_ip),
        p=proto, data=proto_layer,
    )
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(
        src=b"\x00\x00\x00\x00\x00\x01", dst=b"\x00\x00\x00\x00\x00\x02",
        type=dpkt.ethernet.ETH_TYPE_IP, data=ip,
    )
    return bytes(eth)


def _tcp_frame(src_ip, dst_ip, sport, dport, seq, payload) -> bytes:
    tcp = dpkt.tcp.TCP(
        sport=sport, dport=dport, seq=seq, ack=0,
        flags=dpkt.tcp.TH_ACK, data=payload,
    )
    return _frame(tcp, src_ip, dst_ip, dpkt.ip.IP_PROTO_TCP)


def _udp_frame(src_ip, dst_ip, sport, dport, payload) -> bytes:
    udp = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    udp.ulen = len(udp)
    return _frame(udp, src_ip, dst_ip, dpkt.ip.IP_PROTO_UDP)


def _write_pcap(path: Path, packets) -> str:
    with open(path, "wb") as handle:
        writer = dpkt.pcap.Writer(handle)
        for idx, pkt in enumerate(packets):
            writer.writepkt(pkt, ts=float(idx))
    return str(path)


def _tcp_exchange(request: bytes, response: bytes, *, client_port=CLIENT_PORT):
    """One bidirectional TCP connection carrying *request* / *response*."""
    return [
        _tcp_frame(CLIENT_IP, SERVER_IP, client_port, SERVER_PORT, 1000, request),
        _tcp_frame(SERVER_IP, CLIENT_IP, SERVER_PORT, client_port, 5000, response),
    ]


#: A handshake record dpkt's ``tls_multi_factory`` accepts. Deliberately NOT a
#: parseable ClientHello: this is the "record layer is TLS, handshake is not
#: minable" capture, which is exactly the state ``challenges()`` refuses.
_TLS_RECORD = b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00"

#: A QUIC v1 long header: header-form + fixed bit set, then version 0x00000001.
_QUIC_INITIAL = b"\xc0\x00\x00\x00\x01" + b"\x00" * 40

#: A DTLS 1.2 handshake record header (type 22, version 0xfefd) + 8 bytes of
#: epoch/sequence/length, so the 13-byte header requirement is met.
_DTLS_RECORD = b"\x16\xfe\xfd" + b"\x00" * 10

#: Bytes that are not any protocol we sniff for: no TLS record version, no
#: HTTP start line, no SSH banner, and neither QUIC nor DTLS bits.
_OPAQUE = b"\x00\x01\x02\x03" * 16


@pytest.fixture
def fixture_pcap() -> str:
    """The committed one-session TLS 1.3 capture, or a clean skip."""
    if not _FIXTURE_PCAP.is_file():  # pragma: no cover - committed fixture
        pytest.skip(f"fixture capture missing: {_FIXTURE_PCAP}")
    return str(_FIXTURE_PCAP)


@pytest.fixture
def extra_resource_type(monkeypatch):
    """Register an extra resource type, restoring the registry afterwards.

    Stands in for an out-of-tree oracle installed through the
    ``memdiver.oracles`` entry-point group — the mechanism C4b added and
    ``tests/test_oracle_entry_point_discovery.py`` exercises. Registration
    happens inside the ``_LOADING_ENTRY_POINTS`` window rather than outside it,
    because that flag is what stamps a factory out-of-tree — registering
    outside it would mint a FIRST-PARTY type and hand the fake the trusted-load
    exemption a real plugin never gets, quietly testing the wrong thing.

    Both registry dicts are snapshotted and restored, and
    ``_ENTRY_POINTS_LOADED`` is left latched so no real discovery fires.
    """
    monkeypatch.setattr(
        builtin_oracle, "RESOURCE_FACTORIES",
        dict(builtin_oracle.RESOURCE_FACTORIES),
    )
    monkeypatch.setattr(
        builtin_oracle, "RESOURCE_TYPE_PROVENANCE",
        dict(builtin_oracle.RESOURCE_TYPE_PROVENANCE),
    )
    monkeypatch.setattr(builtin_oracle, "_ENTRY_POINTS_LOADED", True)

    def _register(name: str) -> None:
        monkeypatch.setattr(builtin_oracle, "_LOADING_ENTRY_POINTS", True)
        try:
            builtin_oracle.register_resource_type(name, lambda config: object())
        finally:
            monkeypatch.setattr(builtin_oracle, "_LOADING_ENTRY_POINTS", False)

    return _register


# ---------------------------------------------------------------------------
# (1) the default is byte-identical — the whole reason the flag exists
# ---------------------------------------------------------------------------


def test_detect_protocols_off_is_byte_identical_to_today(fixture_pcap):
    """``detect_protocols`` unset returns EXACTLY the pre-C4a payload.

    One equality over the whole dict, not a key-set comparison: a changed value
    would regress the arm step just as badly as a changed shape. Two calls of
    the default are compared to each other as well, so the assertion cannot
    pass by accident on a producer that became non-deterministic.
    """
    baseline = inspect_pcap(pcap_path=fixture_pcap)
    again = inspect_pcap(pcap_path=fixture_pcap)
    assert baseline == again
    assert "protocols" not in baseline

    # And the flagged response is a strict SUPERSET: every pre-existing key
    # keeps its value, so an upgrading caller re-reads nothing.
    enriched = inspect_pcap(pcap_path=fixture_pcap, detect_protocols=True)
    assert {k: enriched[k] for k in baseline} == baseline
    assert set(enriched) - set(baseline) == {"protocols"}


def test_the_two_flags_are_independent(fixture_pcap):
    """``include_fields`` and ``detect_protocols`` compose without interfering.

    They are separate reads of the same capture, so a payload asked for both
    must carry both extra keys and neither must disturb the shared ones.
    """
    both = inspect_pcap(
        pcap_path=fixture_pcap, include_fields=True, detect_protocols=True
    )
    assert both["field_index"]
    assert both["protocols"]
    fields_only = inspect_pcap(pcap_path=fixture_pcap, include_fields=True)
    assert "protocols" not in fields_only


def test_inspect_pcap_publishes_the_candidate_dicts(fixture_pcap):
    """``protocols`` carries the documented six keys, decryptable TLS first."""
    protocols = inspect_pcap(
        pcap_path=fixture_pcap, detect_protocols=True
    )["protocols"]
    assert protocols
    assert set(protocols[0]) == {
        "protocol", "resource_type", "decryptable", "flows", "detail", "evidence",
    }
    assert protocols[0]["protocol"] == "tls"
    assert protocols[0]["resource_type"] == "tls-pcap"
    assert protocols[0]["decryptable"] is True
    # JSON-serialisable, because three of the four surfaces hand it to json.dumps.
    json.dumps(protocols)


# ---------------------------------------------------------------------------
# (2) detection is right about the cases that matter
# ---------------------------------------------------------------------------


def test_a_real_tls_capture_is_tls_and_decryptable(fixture_pcap):
    """The committed capture: one connection, ``tls``, first-party decryptable."""
    candidates = detect_protocols(fixture_pcap)
    assert [c.protocol for c in candidates] == ["tls"]
    only = candidates[0]
    assert only.resource_type == "tls-pcap"
    assert only.decryptable is True
    # One CONNECTION, not two directional flows — the de-duplication the TLS
    # session parser applies, so the two numbers cannot be read as two sessions.
    assert only.flows == 1
    assert only.evidence and ":" in only.evidence[0]


def test_plain_tcp_is_named_but_not_decryptable(tmp_path):
    """Opaque TCP is reported as ``tcp`` with no resource type.

    The load-bearing half is ``decryptable is False``: claiming otherwise would
    send a user to a resource that cannot read their capture.
    """
    path = _write_pcap(
        tmp_path / "opaque.pcap", _tcp_exchange(_OPAQUE, _OPAQUE)
    )
    candidates = detect_protocols(path)
    assert [c.protocol for c in candidates] == ["tcp"]
    assert candidates[0].resource_type == ""
    assert candidates[0].decryptable is False


def test_cleartext_http_is_named_as_http(tmp_path):
    """An HTTP/1.x start line in either direction names the connection."""
    path = _write_pcap(tmp_path / "http.pcap", _tcp_exchange(
        b"GET /index.html HTTP/1.1\r\nHost: example.test\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    ))
    candidates = detect_protocols(path)
    assert [c.protocol for c in candidates] == ["http"]
    assert candidates[0].decryptable is False
    assert "nothing to decrypt" in candidates[0].detail


def test_ssh_is_named_from_its_identification_string(tmp_path):
    path = _write_pcap(tmp_path / "ssh.pcap", _tcp_exchange(
        b"SSH-2.0-OpenSSH_9.6\r\n", b"SSH-2.0-OpenSSH_9.6\r\n",
    ))
    candidates = detect_protocols(path)
    assert [c.protocol for c in candidates] == ["ssh"]
    assert candidates[0].decryptable is False


def test_plain_udp_is_named_but_not_decryptable(tmp_path):
    """The hazard this module exists for: ``_extract_tcp`` drops every datagram.

    A UDP-only capture used to be indistinguishable from an empty one, because
    the TLS path's flow reader gates on ``isinstance(tcp, dpkt.tcp.TCP)``. This
    proves the separate UDP pass sees it — and that it is honest about not
    recognising it, rather than guessing "QUIC because port 443".
    """
    path = _write_pcap(tmp_path / "udp.pcap", [
        _udp_frame(CLIENT_IP, SERVER_IP, CLIENT_PORT, 443, _OPAQUE),
    ])
    candidates = detect_protocols(path)
    assert [c.protocol for c in candidates] == ["udp"]
    assert candidates[0].decryptable is False


def test_quic_is_recognised_from_its_long_header(tmp_path):
    path = _write_pcap(tmp_path / "quic.pcap", [
        _udp_frame(CLIENT_IP, SERVER_IP, CLIENT_PORT, 443, _QUIC_INITIAL),
    ])
    candidates = detect_protocols(path)
    assert [c.protocol for c in candidates] == ["quic"]
    assert candidates[0].resource_type == "quic-pcap"
    # Nothing in-tree decrypts QUIC, and the report says so rather than
    # advertising a resource that does not exist.
    assert candidates[0].decryptable is False
    assert "version 0x00000001" in candidates[0].evidence[0]


def test_dtls_is_recognised_from_its_record_header(tmp_path):
    path = _write_pcap(tmp_path / "dtls.pcap", [
        _udp_frame(CLIENT_IP, SERVER_IP, CLIENT_PORT, 4433, _DTLS_RECORD),
    ])
    candidates = detect_protocols(path)
    assert [c.protocol for c in candidates] == ["dtls"]
    assert candidates[0].resource_type == "dtls-pcap"
    assert candidates[0].decryptable is False


def test_a_mixed_capture_reports_every_protocol_decryptable_first(tmp_path):
    """Ordering is part of the contract: decryptable, then most connections."""
    path = _write_pcap(tmp_path / "mixed.pcap", [
        *_tcp_exchange(_TLS_RECORD, _TLS_RECORD),
        *_tcp_exchange(_OPAQUE, _OPAQUE, client_port=CLIENT_PORT + 1),
        *_tcp_exchange(_OPAQUE, _OPAQUE, client_port=CLIENT_PORT + 2),
        _udp_frame(CLIENT_IP, SERVER_IP, CLIENT_PORT, 443, _QUIC_INITIAL),
    ])
    candidates = detect_protocols(path)
    assert [c.protocol for c in candidates] == ["tls", "tcp", "quic"]
    assert [c.flows for c in candidates] == [1, 2, 1]
    assert [c.decryptable for c in candidates] == [True, False, False]


def test_both_directions_of_one_connection_count_as_one_flow(tmp_path):
    """A bidirectional pair is one connection, however many directions it has."""
    path = _write_pcap(tmp_path / "pair.pcap", _tcp_exchange(_OPAQUE, _OPAQUE))
    assert detect_protocols(path)[0].flows == 1


def test_evidence_is_bounded_and_deterministic(tmp_path):
    """A many-flow capture yields a readable refusal, not a wall of endpoints."""
    packets = []
    for offset in range(12):
        packets += _tcp_exchange(_OPAQUE, _OPAQUE, client_port=CLIENT_PORT + offset)
    path = _write_pcap(tmp_path / "many.pcap", packets)

    first = detect_protocols(path)[0]
    assert first.flows == 12
    assert len(first.evidence) == 5          # 4 samples + the elision line
    assert first.evidence[-1] == "... and 8 more"
    # Stable across runs: flow dicts are ordered by packet arrival, and an error
    # naming different connections on each run is evidence of nothing.
    assert detect_protocols(path)[0].evidence == first.evidence


# ---------------------------------------------------------------------------
# (3) detection never raises
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("payload", [
    b"",                                        # empty file
    b"not a capture at all, just some text\n",  # wrong file entirely
    bytes(range(256)) * 4,                      # binary garbage
    b"\x0a\x0d\x0d\x0a" + b"\xff" * 32,         # pcapng magic, truncated body
])
def test_a_weird_file_yields_no_candidates_instead_of_raising(tmp_path, payload):
    """Detection runs on the FAILURE path, so it must never add a failure.

    Each of these makes the dpkt reader unhappy in a different place (no magic,
    a bad magic, a valid magic over nonsense). All four must answer with an
    empty tuple: the caller is mid-way through explaining why something else
    broke, and a traceback from the explainer replaces a bad-but-true message
    with none at all.
    """
    path = tmp_path / "weird.bin"
    path.write_bytes(payload)
    assert detect_protocols(str(path)) == ()


def test_a_missing_file_yields_no_candidates(tmp_path):
    assert detect_protocols(str(tmp_path / "nope.pcap")) == ()


def test_a_capture_with_no_ip_traffic_yields_no_candidates(tmp_path):
    """An ARP-only capture is parseable and holds nothing we can name."""
    arp = dpkt.arp.ARP(sha=b"\x00" * 6, spa=b"\x0a\x00\x00\x01",
                       tha=b"\x00" * 6, tpa=b"\x0a\x00\x00\x02")
    eth = dpkt.ethernet.Ethernet(
        src=b"\x00" * 6, dst=b"\xff" * 6,
        type=dpkt.ethernet.ETH_TYPE_ARP, data=arp,
    )
    path = _write_pcap(tmp_path / "arp.pcap", [bytes(eth)])
    assert detect_protocols(path) == ()


# ---------------------------------------------------------------------------
# (4) decryptable is read from the LIVE registry, never a hardcoded list
# ---------------------------------------------------------------------------


def test_a_newly_registered_resource_type_makes_its_protocol_decryptable(
    tmp_path, extra_resource_type,
):
    """C4b's whole point: install an oracle, and detection notices.

    ``quic-pcap`` reports ``decryptable=False`` above because nothing registers
    it. Register it — as an out-of-tree package's entry point would — and the
    SAME capture reports True, with no edit to ``protocol_detect``. A hardcoded
    answer would tell this user their capture cannot be handled while the code
    to handle it is installed.
    """
    path = _write_pcap(tmp_path / "quic.pcap", [
        _udp_frame(CLIENT_IP, SERVER_IP, CLIENT_PORT, 443, _QUIC_INITIAL),
    ])
    assert detect_protocols(path)[0].decryptable is False

    extra_resource_type("quic-pcap")
    only = detect_protocols(path)[0]
    assert only.protocol == "quic"
    assert only.decryptable is True
    # Decryptable, but NOT trusted: an out-of-tree factory keeps the load
    # sandbox (the provenance rule C4b established).
    assert builtin_oracle.is_first_party_resource_type("quic-pcap") is False


def test_the_resource_type_table_covers_every_detectable_protocol():
    """A protocol added to the classifier must be added to the name table too.

    Otherwise it would silently fall through to ``resource_type=""`` and be
    reported as undecryptable no matter what is installed.
    """
    from memdiver.engine.resources import protocol_detect

    assert set(PROTOCOL_RESOURCE_TYPES) == set(protocol_detect._PROTOCOL_DETAILS)
    assert PROTOCOL_RESOURCE_TYPES["tls"] == DEFAULT_RESOURCE_TYPE


def test_a_candidate_describes_itself_for_an_error_message():
    decryptable = ProtocolCandidate(
        protocol="tls", resource_type="tls-pcap", decryptable=True,
        flows=1, detail="TLS record layer on 1 connection(s)",
    )
    assert "resource_type='tls-pcap'" in decryptable.describe()
    opaque = ProtocolCandidate(
        protocol="udp", resource_type="", decryptable=False,
        flows=2, detail="2 UDP association(s)",
    )
    assert "no registered resource can decrypt it" in opaque.describe()


# ---------------------------------------------------------------------------
# (5) the refusals — brute_force / n_sweep report, and refuse to guess
# ---------------------------------------------------------------------------


def _run_brute_force(tmp_path, pcap: str, **kwargs):
    """Drive the real producer against *pcap* with a real candidates file.

    Nothing is stubbed: the pcap oracle is built for real, and
    ``ResourceOracle.__init__`` materialises the challenge list, so a capture
    with no minable handshake raises ``PcapParseError`` on the way in. That is
    the exact path a user hits, which is the point — C4a's predecessors all
    passed a green suite and failed when run.
    """
    reference = tmp_path / "ref.bin"
    reference.write_bytes(b"\x00" * 4096)
    candidates = tmp_path / "candidates.json"
    candidates.write_text(json.dumps({"regions": [{"offset": 0, "length": 32}]}))
    return tools_pipeline.brute_force(
        candidates_path=str(candidates),
        reference_path=str(reference),
        output_dir=str(tmp_path / "out"),
        pcap_path=pcap,
        **kwargs,
    )


def test_brute_force_error_names_what_the_capture_actually_holds(tmp_path):
    """The C4a headline: the refusal reports the capture, not just the miss.

    The oracle's own sentence is kept verbatim — it is the right diagnosis when
    the capture really is TLS — and the inventory plus the registry listing are
    appended, so the user learns (a) this is HTTP, (b) nothing installed reads
    HTTP. Neither fact was available before.
    """
    path = _write_pcap(tmp_path / "http.pcap", _tcp_exchange(
        b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n\r\n",
    ))
    with pytest.raises(CapabilityError) as excinfo:
        _run_brute_force(tmp_path, path)

    message = str(excinfo.value)
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    # The original message, unchanged.
    assert "no complete TLS handshake found" in message
    # What is actually there, and that nothing can read it.
    assert "http" in message
    assert "no registered resource can decrypt it" in message
    assert "tls-pcap" in message


def test_brute_force_error_says_so_when_the_capture_is_unreadable(tmp_path):
    """A non-capture keeps its own diagnosis; detection adds only honesty."""
    path = tmp_path / "garbage.pcap"
    path.write_bytes(b"this is not a capture")
    with pytest.raises(CapabilityError) as excinfo:
        _run_brute_force(tmp_path, str(path))

    message = str(excinfo.value)
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert "could not read capture" in message
    assert "no protocol MemDiver can name" in message


def test_brute_force_points_at_the_one_resource_type_that_could_work(
    tmp_path, extra_resource_type,
):
    """Exactly one decryptable protocol, and it is not the one we were told.

    PRECONDITION, not INVALID_INPUT: the input is fine, the *selection* is
    wrong, and the fix is one argument the caller now has.
    """
    extra_resource_type("quic-pcap")
    path = _write_pcap(tmp_path / "quic.pcap", [
        _udp_frame(CLIENT_IP, SERVER_IP, CLIENT_PORT, 443, _QUIC_INITIAL),
    ])
    with pytest.raises(CapabilityError) as excinfo:
        _run_brute_force(tmp_path, path)

    message = str(excinfo.value)
    assert excinfo.value.category is ErrorCategory.PRECONDITION
    assert "resource_type='quic-pcap'" in message
    assert "quic" in message


def test_brute_force_refuses_to_pick_between_two_decryptable_protocols(
    tmp_path, extra_resource_type,
):
    """THE 'ask, never guess' rule.

    With TLS and QUIC both decryptable, defaulting to either would verify a
    recovered key against the wrong protocol's records and report a real key as
    unconfirmed — which reads as "the key is not in this dump", the single most
    expensive wrong answer this tool can give. So it refuses, lists both, and
    demands an explicit ``resource_type``. Same rule and same shape as C2's
    multi-session refusal.
    """
    extra_resource_type("quic-pcap")
    path = _write_pcap(tmp_path / "mixed.pcap", [
        *_tcp_exchange(_TLS_RECORD, _TLS_RECORD),
        _udp_frame(CLIENT_IP, SERVER_IP, CLIENT_PORT, 443, _QUIC_INITIAL),
    ])
    with pytest.raises(CapabilityError) as excinfo:
        _run_brute_force(tmp_path, path)

    message = str(excinfo.value)
    assert excinfo.value.category is ErrorCategory.PRECONDITION
    assert "2 protocols" in message
    assert "tls-pcap" in message and "quic-pcap" in message
    assert "no default on purpose" in message


def test_the_refusal_is_shared_by_n_sweep(tmp_path, extra_resource_type):
    """One helper, two producers: a sweep and a brute force must not describe
    the same capture differently — a user comparing the two errors would
    reasonably conclude one of them is broken."""
    extra_resource_type("quic-pcap")
    dump = tmp_path / "dump.bin"
    dump.write_bytes(b"\x00" * 4096)
    path = _write_pcap(tmp_path / "mixed.pcap", [
        *_tcp_exchange(_TLS_RECORD, _TLS_RECORD),
        _udp_frame(CLIENT_IP, SERVER_IP, CLIENT_PORT, 443, _QUIC_INITIAL),
    ])
    with pytest.raises(CapabilityError) as excinfo:
        tools_pipeline.n_sweep(
            source_paths=[str(dump)],
            output_dir=str(tmp_path / "out"),
            n_values=[1],
            pcap_path=path,
        )
    assert excinfo.value.category is ErrorCategory.PRECONDITION
    assert "2 protocols" in str(excinfo.value)


def test_the_refusal_helper_is_pure_over_a_capture_path(tmp_path):
    """Directly, so the branch table is testable without a brute-force run."""
    path = _write_pcap(tmp_path / "opaque.pcap", _tcp_exchange(_OPAQUE, _OPAQUE))
    error = tools_pipeline._pcap_protocol_refusal(
        path, DEFAULT_RESOURCE_TYPE, RuntimeError("original message")
    )
    assert isinstance(error, CapabilityError)
    assert error.category is ErrorCategory.INVALID_INPUT
    assert "original message" in str(error)
    assert "tcp" in str(error)


# ---------------------------------------------------------------------------
# (6) resource_type is reachable — an unactionable demand is not an error
# ---------------------------------------------------------------------------


def test_the_producers_accept_the_resource_type_the_refusal_demands():
    """The refusal says "name one with resource_type"; both producers take it."""
    import inspect as inspect_module

    for producer in (tools_pipeline.brute_force, tools_pipeline.n_sweep):
        params = inspect_module.signature(producer).parameters
        assert "resource_type" in params
        assert params["resource_type"].default == DEFAULT_RESOURCE_TYPE


def test_the_resource_type_reaches_the_oracle_config():
    """It is not merely accepted — it lands in the spec the oracle is built from.

    Both producers share ONE config builder, so this is asserted on the builder
    rather than twice through the producers.
    """
    config = tools_pipeline._pcap_oracle_config(
        "/c/session.pcap", None, None, None, "quic-pcap"
    )
    assert config["resource_type"] == "quic-pcap"
    # And the trusted-load exemption is NOT inherited by it.
    assert tools_pipeline._pcap_oracle_trusted(config) is False


def test_an_unknown_resource_type_is_refused_with_the_registry(tmp_path):
    """A typo must not become a traceback.

    Promoting ``resource_type`` to a real flag also made mistyping it reachable.
    Unchecked, an unknown name lands in ``build_resource``'s ``ValueError``
    inside the oracle loader, is re-wrapped as ``OracleLoadError`` (a bare
    ``RuntimeError`` no surface funnels) and reaches the user as a stack trace —
    the exact failure mode C4a exists to remove. So it is refused up front, with
    the names that WOULD have worked.
    """
    path = _write_pcap(tmp_path / "opaque.pcap", _tcp_exchange(_OPAQUE, _OPAQUE))
    with pytest.raises(CapabilityError) as excinfo:
        _run_brute_force(tmp_path, path, resource_type="tsl-pcap")

    message = str(excinfo.value)
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert "unknown resource_type 'tsl-pcap'" in message
    assert "tls-pcap" in message


def test_the_up_front_check_gates_on_the_registry_not_a_name_list(
    extra_resource_type,
):
    """The guard must not become a wall against real out-of-tree resources.

    Asserted on the predicate rather than through a run, because a
    non-first-party type loads SANDBOXED — in a subprocess, where an in-process
    monkeypatched registry does not exist. A real plugin is a real installed
    package and resolves there; a fake cannot be, so pushing this through
    ``brute_force`` would only re-test the sandbox.
    """
    assert tools_pipeline._validate_resource_type(DEFAULT_RESOURCE_TYPE) is None
    with pytest.raises(CapabilityError):
        tools_pipeline._validate_resource_type("quic-pcap")

    extra_resource_type("quic-pcap")
    assert tools_pipeline._validate_resource_type("quic-pcap") is None


def test_n_sweep_applies_the_same_up_front_check(tmp_path):
    """One helper, two producers — the sweep cannot accept what the run refuses."""
    dump = tmp_path / "dump.bin"
    dump.write_bytes(b"\x00" * 4096)
    with pytest.raises(CapabilityError) as excinfo:
        tools_pipeline.n_sweep(
            source_paths=[str(dump)],
            output_dir=str(tmp_path / "out"),
            n_values=[1],
            pcap_path=str(tmp_path / "any.pcap"),
            resource_type="nope",
        )
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert "unknown resource_type 'nope'" in str(excinfo.value)


def test_mcp_tools_forward_both_new_parameters():
    """The generic signature-parity ratchet catches this too; asserted here so a
    C4a regression names C4a."""
    import inspect as inspect_module

    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server

    tools = {t.name: t for t in create_server()._tool_manager.list_tools()}
    assert "detect_protocols" in inspect_module.signature(
        tools["inspect_pcap"].fn).parameters
    for name in ("brute_force", "n_sweep"):
        params = inspect_module.signature(tools[name].fn).parameters
        assert "resource_type" in params
        assert params["resource_type"].default == DEFAULT_RESOURCE_TYPE


def test_mcp_inspect_pcap_returns_the_protocols_inline(fixture_pcap):
    """An agent handed a server-side path cannot read the capture, so the
    inventory has to come back in the response."""
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server

    tools = {t.name: t for t in create_server()._tool_manager.list_tools()}
    payload = json.loads(
        tools["inspect_pcap"].fn(pcap_path=fixture_pcap, detect_protocols=True))
    assert payload["protocols"][0]["protocol"] == "tls"
    lean = json.loads(tools["inspect_pcap"].fn(pcap_path=fixture_pcap))
    assert "protocols" not in lean


def test_cli_exposes_all_three_spellings():
    from memdiver.cli import build_parser

    parser = build_parser()

    args = parser.parse_args(["inspect-pcap", "x.pcap"])
    assert args.protocols is False
    args = parser.parse_args(["inspect-pcap", "x.pcap", "--protocols"])
    assert args.protocols is True

    args = parser.parse_args(
        ["brute-force", "--candidates", "c.json", "--dump", "d", "-o", "o.json"])
    assert args.resource_type == DEFAULT_RESOURCE_TYPE
    args = parser.parse_args([
        "brute-force", "--candidates", "c.json", "--dump", "d", "-o", "o.json",
        "--resource-type", "quic-pcap",
    ])
    assert args.resource_type == "quic-pcap"

    args = parser.parse_args(
        ["n-sweep", "--runs-dir", "r", "--output-dir", "o",
         "--resource-type", "quic-pcap"])
    assert args.resource_type == "quic-pcap"


def test_cli_inspect_pcap_writes_the_protocols(tmp_path, fixture_pcap):
    import argparse

    from memdiver.cli.pipeline import _cmd_inspect_pcap

    out = tmp_path / "protocols.json"
    assert _cmd_inspect_pcap(argparse.Namespace(
        pcap=fixture_pcap, pcap_max_records=None, pcap_max_challenges=None,
        fields=False, protocols=True, output=str(out),
    )) == 0
    payload = json.loads(out.read_text())
    assert payload["protocols"][0]["protocol"] == "tls"


def test_cli_handlers_tolerate_a_namespace_without_the_new_flags(tmp_path,
                                                                fixture_pcap):
    """The handlers are also driven with hand-built Namespaces (the convention
    in ``tests/test_cli.py``), so every new flag is read with a defaulted
    ``getattr`` rather than an attribute access that would break them."""
    import argparse

    from memdiver.cli.pipeline import _cmd_inspect_pcap

    out = tmp_path / "lean.json"
    assert _cmd_inspect_pcap(argparse.Namespace(
        pcap=fixture_pcap, pcap_max_records=None, pcap_max_challenges=None,
        output=str(out),
    )) == 0
    assert "protocols" not in json.loads(out.read_text())


def test_web_route_defaults_to_no_detection_and_opts_in_on_request(fixture_pcap):
    """``ValidatePcapRequest.detect_protocols`` defaults False, so the arm
    request the UI has always sent keeps its exact response."""
    from fastapi.testclient import TestClient

    from memdiver.api.main import create_app
    from memdiver.api.routers.pcaps import ValidatePcapRequest

    assert ValidatePcapRequest(pcap_path="x.pcap").detect_protocols is False

    with TestClient(create_app()) as client:
        lean = client.post("/api/pcaps/validate", json={"pcap_path": fixture_pcap})
        assert lean.status_code == 200
        assert "protocols" not in lean.json()

        rich = client.post(
            "/api/pcaps/validate",
            json={"pcap_path": fixture_pcap, "detect_protocols": True},
        )
        assert rich.status_code == 200
        assert rich.json()["protocols"][0]["protocol"] == "tls"


def test_library_surface_carries_the_new_parameters():
    """``services.py`` re-exports the FUNCTION OBJECTS, so the library surface
    gets all three with no edit there — this pins that."""
    import inspect as inspect_module

    from memdiver import services

    assert "detect_protocols" in inspect_module.signature(
        services.inspect_pcap).parameters
    assert "resource_type" in inspect_module.signature(
        services.brute_force).parameters


# ---------------------------------------------------------------------------
# The extracted flow reader: the shim must not change what the TLS parser sees
# ---------------------------------------------------------------------------


def test_the_read_flows_shim_returns_exactly_what_the_method_did(fixture_pcap):
    """``_read_flows`` is now a thin shim over the module-level ``read_flows``.

    Detection reads a capture through the SAME grouping the TLS parser uses, so
    a report can never describe a different capture than the one that failed.
    This pins the two answers identical — if they drift, the report is about
    something else.
    """
    from memdiver.engine.resources.tls_pcap import TlsPcapResource, read_flows

    resource = TlsPcapResource(fixture_pcap)
    assert resource._read_flows() == read_flows(fixture_pcap)


def test_read_flows_funnels_a_missing_capture_to_pcap_parse_error(tmp_path):
    """The message the extraction had to preserve, distinct from 'unreadable'."""
    from memdiver.engine.resources.tls_pcap import PcapParseError, read_flows

    missing = str(tmp_path / "nope.pcap")
    with pytest.raises(PcapParseError) as excinfo:
        read_flows(missing)
    assert "capture not found" in str(excinfo.value)


def test_read_flows_ignores_udp_exactly_as_before(tmp_path):
    """The hazard, pinned: the TLS flow reader must keep dropping datagrams.

    ``_extract_tcp`` was deliberately NOT widened for QUIC/DTLS detection —
    doing so would feed non-TCP payloads into the reassembler behind real
    challenge generation. This test fails if someone later 'fixes' it.
    """
    from memdiver.engine.resources.tls_pcap import read_flows

    path = _write_pcap(tmp_path / "udp.pcap", [
        _udp_frame(CLIENT_IP, SERVER_IP, CLIENT_PORT, 443, _QUIC_INITIAL),
    ])
    assert read_flows(path) == {}
