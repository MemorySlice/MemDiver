"""What protocol is this capture, actually? — detection that reports, never guesses.

``TlsPcapResource`` answers exactly one question ("give me the TLS challenges in
this capture") and, when the answer is no, says so in four words: *no complete
TLS handshake found*. For a user who handed MemDiver a QUIC capture, a
cleartext HTTP capture, or a capture of the wrong connection entirely, that
sentence is true and useless — it describes what was *looked for*, not what is
*there*.

This module supplies the missing half. It reads the same capture through the
same flow grouping the TLS parser uses (:func:`~memdiver.engine.resources
.tls_pcap.read_flows`), plus a UDP peek the TLS path deliberately does not have,
and reports one :class:`ProtocolCandidate` per protocol it can name. The caller
(``app.tools_pipeline``) turns that into an error that says what was found and
whether anything installed can decrypt it — and, when *several* things can,
refuses to pick one.

Three properties are load-bearing:

* **It never raises.** A garbage file, a truncated capture, a capture of ARP
  frames only — every one of those answers with an empty tuple. This runs on the
  failure path, so a detector that threw would replace a bad-but-true error
  message with a traceback about the diagnostic itself.
* **``decryptable`` is read from the LIVE registry**
  (``builtin_oracle.RESOURCE_FACTORIES``, via
  :func:`~memdiver.engine.resources.builtin_oracle.is_registered_resource_type`),
  never from a list written here. The registry is extensible out-of-tree through
  the ``memdiver.oracles`` entry-point group, so a third-party QUIC oracle makes
  ``quic`` report ``decryptable=True`` with no edit to this file. A hardcoded
  answer would tell that user their capture cannot be handled while the code to
  handle it is installed and registered.
* **It does not touch the TLS parsing path.** ``_extract_tcp`` drops UDP (it
  gates on ``isinstance(tcp, dpkt.tcp.TCP)``), which is why QUIC/DTLS detection
  below runs its own reader pass rather than widening that function. Widening it
  would put non-TCP payloads into the stream reassembler that feeds real
  challenge generation — a change to *verification* in service of a *diagnostic*.

Layering: pure engine. Imports nothing from ``app/`` or ``api/`` (the ratchets
in ``tests/test_architecture_invariants.py`` enforce that). Unlike
``protocol_fields.py`` it *does* use dpkt, because unlike that module it reads
files rather than being handed bytes.

Detection is intentionally shallow — a header sniff per connection, not a
dissector. It has to be right about "this is not TLS, it is QUIC"; it does not
have to be right about which HTTP version. Anything it cannot name is reported
as opaque ``tcp``/``udp`` rather than guessed at.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from memdiver.engine.resources.tls_pcap import (
    HAS_PCAP,
    PcapParseError,
    _ip_str,
    _link_payload,
    _open_reader,
    _parse_records,
    _reassemble,
    read_flows,
)

try:
    import dpkt
except ImportError:  # pragma: no cover - dpkt is a base dependency
    # Mirrors ``tls_pcap``'s availability model: the module still imports, and
    # :func:`detect_protocols` short-circuits on ``HAS_PCAP`` before anything
    # here is dereferenced.
    dpkt = None  # type: ignore[assignment]

logger = logging.getLogger("memdiver.engine.resources.protocol_detect")

__all__ = [
    "ProtocolCandidate",
    "PROTOCOL_RESOURCE_TYPES",
    "detect_protocols",
]

#: Protocol name -> the ``resource_type`` a verification resource for it would
#: register under. This is a NAMING CONVENTION, not a capability claim: whether
#: any of these can be built is answered by the registry at report time. Only
#: ``"tls-pcap"`` ships in-tree today; the rest are the names an out-of-tree
#: oracle should choose so that detection can point a user at it.
#:
#: An empty string means "no resource type could name this" — a cleartext or
#: unidentified protocol. Those are always non-decryptable, and saying so with
#: ``""`` rather than inventing ``"http-pcap"`` keeps the report from implying
#: that a decryptor for cleartext HTTP would make sense.
PROTOCOL_RESOURCE_TYPES: Dict[str, str] = {
    "tls": "tls-pcap",
    "dtls": "dtls-pcap",
    "quic": "quic-pcap",
    "ssh": "ssh-pcap",
    "http": "",
    "tcp": "",
    "udp": "",
}

#: One-line description per protocol, taking the connection count. Kept beside
#: the resource-type table so a new protocol cannot be added to one and
#: forgotten in the other.
_PROTOCOL_DETAILS: Dict[str, str] = {
    "tls": "TLS record layer on {n} connection(s)",
    "dtls": "DTLS record layer on {n} UDP association(s)",
    "quic": "QUIC long-header packets on {n} UDP association(s)",
    "ssh": "SSH transport banner on {n} connection(s)",
    "http": "cleartext HTTP on {n} connection(s) — there is nothing to decrypt",
    "tcp": "{n} TCP connection(s) carrying no protocol MemDiver recognises",
    "udp": "{n} UDP association(s) carrying no protocol MemDiver recognises",
}

#: How many per-connection evidence lines a candidate carries. Bounded because
#: this ends up inside an error message: a capture of 4,000 flows must produce a
#: readable refusal, not a wall of endpoints.
_MAX_EVIDENCE = 4

#: HTTP/1.x request methods and the response prefix. Sniffed as a first-line
#: prefix only — enough to distinguish "cleartext HTTP" from "opaque TCP", which
#: is the entire decision being made.
_HTTP_PREFIXES: Tuple[bytes, ...] = (
    b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ",
    b"PATCH ", b"TRACE ", b"CONNECT ", b"HTTP/1.",
)

#: The SSH identification string every SSH transport opens with (RFC 4253 §4.2).
_SSH_PREFIX = b"SSH-"

#: DTLS record-layer versions (RFC 6347 / RFC 9147): the 1's-complement
#: encodings 1.0, 1.2 and 1.3.
_DTLS_VERSIONS: Tuple[bytes, ...] = (b"\xfe\xff", b"\xfe\xfd", b"\xfe\xfc")

#: Valid DTLS/TLS record content types (change_cipher_spec .. heartbeat).
_RECORD_CONTENT_TYPES = range(20, 26)

#: DTLS record header: type(1) || version(2) || epoch(2) || seq(6) || length(2).
_DTLS_HEADER_LEN = 13

#: QUIC versions we are willing to name from a long header: version negotiation
#: (0), QUIC v1 (RFC 9000), QUIC v2 (RFC 9369), and the ``ff0000XX`` IETF drafts.
_QUIC_VERSIONS = frozenset({0x00000000, 0x00000001, 0x6B3343CF})
_QUIC_DRAFT_PREFIX = 0xFF0000

#: RFC 9287 version grease: any version of the form ``?a?a?a?a``.
_QUIC_GREASE_MASK = 0x0F0F0F0F
_QUIC_GREASE_VALUE = 0x0A0A0A0A


@dataclass(frozen=True)
class ProtocolCandidate:
    """One protocol a capture was found to carry, and whether we can decrypt it.

    ``flows`` counts distinct CONNECTIONS, a bidirectional pair counted once —
    the same de-duplication ``TlsPcapResource._parse_sessions`` applies — so one
    TLS connection reports 1 and not 2. (``describe_capture``'s ``flow_count``
    is the *directional* count; the two are different numbers on purpose and
    live under different names.)

    ``resource_type`` is the registry name a verification resource for this
    protocol would carry, or ``""`` when none could (cleartext / unidentified);
    ``decryptable`` is whether that name resolves in the live registry right
    now. ``detail`` is the one-line human summary, and ``evidence`` names up to
    :data:`_MAX_EVIDENCE` of the connections it was read from, so a user can
    check the report against their own capture instead of trusting it.
    """

    protocol: str
    resource_type: str
    decryptable: bool
    flows: int
    detail: str
    evidence: Tuple[str, ...] = ()

    def as_dict(self) -> Dict[str, Any]:
        """A JSON-friendly dict — the shape every surface renders."""
        return {
            "protocol": self.protocol,
            "resource_type": self.resource_type,
            "decryptable": self.decryptable,
            "flows": self.flows,
            "detail": self.detail,
            "evidence": list(self.evidence),
        }

    def describe(self) -> str:
        """A compact one-liner for an error message listing several candidates."""
        suffix = (
            f", decryptable by resource_type={self.resource_type!r}"
            if self.decryptable
            else ", no registered resource can decrypt it"
        )
        return f"{self.protocol} ({self.detail}){suffix}"


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #


def detect_protocols(pcap_path: Any) -> Tuple[ProtocolCandidate, ...]:
    """Report every protocol *pcap_path* was found to carry.

    Returns candidates ordered decryptable-first, then by descending connection
    count, then by name — a stable order, so a caller can render the tuple
    without re-sorting and a test can assert on position.

    NEVER raises. An unreadable file, a capture with no IP traffic, or a missing
    dpkt all answer with an empty tuple: this function exists to *explain* a
    failure, so a failure of its own must not replace the explanation.
    """
    if not HAS_PCAP:
        # dpkt is a base dependency; if it is genuinely absent the caller has
        # already reported that (``inspect_pcap`` raises UNSUPPORTED), and there
        # is nothing this can add.
        return ()

    tcp_connections = _group_tcp_connections(pcap_path)
    udp_connections = _group_udp_connections(pcap_path)

    # protocol -> [evidence line, ...]; the list length IS the connection count.
    found: Dict[str, List[str]] = {}
    for endpoints, streams in tcp_connections.items():
        protocol, note = _classify_tcp(streams)
        found.setdefault(protocol, []).append(_evidence_line(endpoints, note))
    for endpoints, payloads in udp_connections.items():
        protocol, note = _classify_udp(payloads)
        found.setdefault(protocol, []).append(_evidence_line(endpoints, note))

    candidates = [_candidate(protocol, lines) for protocol, lines in found.items()]
    return tuple(
        sorted(candidates, key=lambda c: (not c.decryptable, -c.flows, c.protocol))
    )


def _candidate(protocol: str, evidence: List[str]) -> ProtocolCandidate:
    """Build one candidate, asking the LIVE registry whether it is decryptable.

    The registry import is local so this module stays importable (and testable)
    without triggering out-of-tree entry-point discovery, which
    :func:`is_registered_resource_type` performs on first call.
    """
    from memdiver.engine.resources.builtin_oracle import is_registered_resource_type

    resource_type = PROTOCOL_RESOURCE_TYPES.get(protocol, "")
    return ProtocolCandidate(
        protocol=protocol,
        resource_type=resource_type,
        # ``""`` never resolves, so cleartext/unidentified protocols answer
        # False without a special case here.
        decryptable=bool(resource_type) and is_registered_resource_type(resource_type),
        flows=len(evidence),
        detail=_PROTOCOL_DETAILS.get(protocol, "{n} connection(s)").format(
            n=len(evidence)
        ),
        evidence=_bounded(evidence),
    )


def _bounded(evidence: List[str]) -> Tuple[str, ...]:
    """The first :data:`_MAX_EVIDENCE` lines, with a count of what was elided.

    Sorted first so the sample is deterministic: flow dicts are insertion-
    ordered by packet arrival, and an error message that names two different
    connections on two runs of the same capture is not evidence of anything.
    """
    ordered = sorted(evidence)
    if len(ordered) <= _MAX_EVIDENCE:
        return tuple(ordered)
    remaining = len(ordered) - _MAX_EVIDENCE
    return (*ordered[:_MAX_EVIDENCE], f"... and {remaining} more")


def _evidence_line(endpoints: Tuple[Tuple[str, int], ...], note: str) -> str:
    """Render one connection plus why it was classified the way it was."""
    (a_ip, a_port), (b_ip, b_port) = endpoints
    return f"{a_ip}:{a_port} <-> {b_ip}:{b_port} ({note})"


# --------------------------------------------------------------------------- #
# Grouping: directional flows -> bidirectional connections
# --------------------------------------------------------------------------- #


def _connection_key(
    flow_key: Tuple[str, int, str, int]
) -> Tuple[Tuple[str, int], ...]:
    """Canonicalise a directional 4-tuple so both directions hash the same.

    Sorting the endpoint pair is what makes the two directions of one connection
    collapse. Doing it by SORT rather than by "client first" is deliberate: which
    side is the client is a TLS-handshake fact, and this module classifies
    captures whose handshake did not parse.
    """
    src_ip, src_port, dst_ip, dst_port = flow_key
    return tuple(sorted(((src_ip, src_port), (dst_ip, dst_port))))


def _group_tcp_connections(
    pcap_path: Any,
) -> Dict[Tuple[Tuple[str, int], ...], List[bytes]]:
    """Reassembled TCP payloads per connection: key -> [direction bytes, ...].

    Reuses :func:`read_flows` and :func:`_reassemble` — the exact pair the TLS
    parser uses — so the bytes classified here are the bytes that failed to
    parse, not a second reading of the file.
    """
    try:
        flows = read_flows(pcap_path)
    except PcapParseError as exc:
        # The capture is unreadable. The caller's own error already says so
        # (``could not read capture ...``); detection has nothing to add and
        # must not raise on top of it.
        logger.debug("protocol detection: capture unreadable: %s", exc)
        return {}
    except Exception as exc:  # pragma: no cover - read_flows funnels everything
        logger.debug("protocol detection: unexpected TCP read failure: %s", exc)
        return {}

    connections: Dict[Tuple[Tuple[str, int], ...], List[bytes]] = {}
    for flow_key, segments in flows.items():
        raw = _reassemble(segments)
        if raw:
            connections.setdefault(_connection_key(flow_key), []).append(raw)
    return connections


def _group_udp_connections(
    pcap_path: Any,
) -> Dict[Tuple[Tuple[str, int], ...], List[bytes]]:
    """UDP datagram payloads per association: key -> [datagram, ...].

    The UDP peek ``tls_pcap`` does not have. ``_extract_tcp`` gates on
    ``isinstance(tcp, dpkt.tcp.TCP)`` and so drops every datagram, which is
    correct for a TLS-over-TCP parser and fatal for QUIC/DTLS detection. This
    reads the capture again rather than widening that function, because widening
    it would feed non-TCP payloads into the reassembler behind real challenge
    generation.

    Datagrams are NOT reassembled: UDP has no stream to reassemble, and every
    sniff below reads a single datagram's header.
    """
    connections: Dict[Tuple[Tuple[str, int], ...], List[bytes]] = {}
    try:
        with open(pcap_path, "rb") as handle:
            reader = _open_reader(handle)
            datalink = reader.datalink()
            for _ts, buf in reader:
                entry = _extract_udp(datalink, buf)
                if entry is None:
                    continue
                flow_key, payload = entry
                connections.setdefault(_connection_key(flow_key), []).append(payload)
    except Exception as exc:
        # Same contract as the TCP half: a truncated or non-capture file yields
        # no UDP evidence rather than an exception. Whatever was collected before
        # the failure is dropped along with it, so a partial read can never
        # report a protocol it only half saw.
        logger.debug("protocol detection: UDP read failed: %s", exc)
        return {}
    return connections


def _extract_udp(
    datalink: int, buf: bytes
) -> Optional[Tuple[Tuple[str, int, str, int], bytes]]:
    """Peel link/IP/UDP, returning (flow_key, datagram payload) or None.

    The UDP mirror of :func:`~memdiver.engine.resources.tls_pcap._extract_tcp`,
    reusing that module's ``_link_payload`` so both halves agree about link
    types (Ethernet, BSD loopback, Linux SLL) — a capture taken on ``lo`` is the
    common case for a locally-generated QUIC session, and getting its link layer
    wrong would report zero UDP for a capture full of it.
    """
    try:
        ip = _link_payload(datalink, buf)
        if ip is None:
            return None
        udp = ip.data
        if not isinstance(udp, dpkt.udp.UDP):
            return None
        payload = bytes(udp.data)
        if not payload:
            return None
        key = (_ip_str(ip.src), udp.sport, _ip_str(ip.dst), udp.dport)
        return key, payload
    except (dpkt.dpkt.UnpackError, AttributeError, KeyError):
        return None


# --------------------------------------------------------------------------- #
# Classification: bytes -> protocol name + why
# --------------------------------------------------------------------------- #


def _classify_tcp(streams: Iterable[bytes]) -> Tuple[str, str]:
    """Name the protocol on a TCP connection: ``(protocol, note)``.

    Either direction is enough to name the connection — a capture that lost the
    client's flight still shows TLS records coming back from the server — so the
    first direction that answers wins and the rest are not consulted.

    TLS is tested with :func:`_parse_records`, the very function the resource
    uses, rather than a hand-rolled header check: dpkt rejects a bad record
    version outright (``SSL3Exception``), which ``_parse_records`` turns into an
    empty list, so "records parsed" is exactly "the TLS parser can read this".
    Using the same predicate is what makes a ``tls``/``decryptable`` verdict on
    a capture the TLS parser then refuses a statement about the HANDSHAKE and
    not about the record layer.
    """
    for raw in streams:
        records = _parse_records(raw)
        if records:
            return "tls", f"TLS records ({len(records)} parsed)"
    for raw in streams:
        if raw.startswith(_SSH_PREFIX):
            return "ssh", "SSH identification string"
        if raw.startswith(_HTTP_PREFIXES):
            return "http", "HTTP/1.x start line"
    return "tcp", "opaque payload"


def _classify_udp(payloads: Iterable[bytes]) -> Tuple[str, str]:
    """Name the protocol on a UDP association: ``(protocol, note)``.

    Every datagram is examined, not just the first: a QUIC association is named
    by its long-header Initial packet, and a capture that starts mid-connection
    shows only short-header packets — which carry no version and cannot be told
    from arbitrary UDP without connection state. Reporting such a capture as
    opaque ``udp`` is the honest answer; guessing "QUIC because port 443" is
    exactly the guessing this module exists to avoid.
    """
    for raw in payloads:
        if _looks_like_dtls(raw):
            return "dtls", "DTLS record header"
        version = _quic_long_header_version(raw)
        if version is not None:
            return "quic", f"QUIC long header, version 0x{version:08x}"
    return "udp", "opaque datagram"


def _looks_like_dtls(raw: bytes) -> bool:
    """A DTLS record header: a valid content type over a 1's-complement version."""
    return (
        len(raw) >= _DTLS_HEADER_LEN
        and raw[0] in _RECORD_CONTENT_TYPES
        and raw[1:3] in _DTLS_VERSIONS
    )


def _quic_long_header_version(raw: bytes) -> Optional[int]:
    """The version of a QUIC long-header packet, or None if this isn't one.

    A long header sets both the header-form bit (0x80) and the fixed bit (0x40),
    then carries a 4-byte version. Only versions we can NAME are accepted —
    v1 (RFC 9000), v2 (RFC 9369), version negotiation (0), the ``ff0000XX``
    IETF drafts, and RFC 9287 grease — because the bit test alone matches one
    byte in four of arbitrary UDP, and a false "QUIC" would send the user
    looking for a QUIC oracle they never needed.
    """
    if len(raw) < 5 or raw[0] & 0xC0 != 0xC0:
        return None
    version = int.from_bytes(raw[1:5], "big")
    if (
        version in _QUIC_VERSIONS
        or version >> 8 == _QUIC_DRAFT_PREFIX
        or version & _QUIC_GREASE_MASK == _QUIC_GREASE_VALUE
    ):
        return version
    return None
