"""TlsPcapResource — turn a captured TLS session into DecryptionChallenges.

A user hands MemDiver a ``.pcap``/``.pcapng`` of a real TLS session; this
resource reassembles each TCP flow, parses the consecutive TLS records, mines
the handshake for the per-session facts a record key derivation needs
(ClientHello.random, ServerHello.random, the negotiated cipher suite, and the
protocol version), then emits one :class:`DecryptionChallenge` per encrypted
application-data record. A
:class:`~memdiver.engine.resources.oracle.ResourceOracle` consumes those
challenges unchanged: it derives the concrete record key from a memory-recovered
candidate secret and confirms it decrypts the captured bytes.

Only the parser lives here — key derivation, verifiers, and the AEAD/CBC/MAC
checks are entirely the oracle's job (see ``oracle.py``). This module's single
responsibility is: capture bytes in, correctly-shaped challenges out.

Sequence-number rule (documented; the oracle rebuilds AEAD nonces / CBC MACs
from ``DerivationContext.seq_num``):
  * **TLS 1.2** — precise. A direction's record sequence counts from 0 at the
    first record *after that direction's ChangeCipherSpec*. The encrypted
    Finished (a handshake record under the new keys) is therefore seq 0, the
    first application-data record seq 1, and so on (RFC 5246).
  * **TLS 1.3** — the record epoch changes from the handshake-traffic secret to
    the application-traffic secret at each side's (encrypted, unparseable)
    Finished, and *both* epochs number their records from 0 (RFC 8446 §5.3).
    Because that transition is invisible on the wire (every protected record is
    content_type application_data), we cannot count precisely. We number the
    application_data records of a direction from 0 and, for robustness against
    the undetectable handshake→application offset, emit a small window of
    sequence numbers ``[max(0, n - _TLS13_SEQ_WINDOW), n]`` per record. The
    oracle confirms if any lands, so a wider net only costs a few extra tries.

Optional dependency: parsing needs ``dpkt`` (the ``[pcap]`` extra). When it is
absent the class imports fine but :meth:`TlsPcapResource.challenges` raises a
clear, actionable error (mirrors the availability model in ``msl/crypto.py``).
"""

from __future__ import annotations

import logging
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from memdiver.core.kdf_tls import (
    TLS12_CIPHER_SUITES,
    TLS13_CIPHER_SUITES,
    Tls12SuiteParams,
)
from memdiver.engine.resources.challenge import DecryptionChallenge, DerivationContext

logger = logging.getLogger("memdiver.engine.resources.tls_pcap")

try:
    import dpkt

    HAS_PCAP = True
    # dpkt's own exception hierarchy is rooted at ``dpkt.dpkt.Error`` (a bare
    # ``Exception`` subclass), NOT at ``OSError``/``ValueError``. A truncated or
    # malformed capture surfaces as ``dpkt.dpkt.NeedData`` (an ``Error``), so the
    # capture-read funnel must catch this base to map it to ``PcapParseError``.
    _DpktError: tuple = (dpkt.dpkt.Error,)
except ImportError:
    HAS_PCAP = False
    _DpktError = ()  # empty tuple → an ``except`` that matches nothing

_PCAP_MISSING = (
    "dpkt not installed; install the pcap extra to parse captures: "
    "pip install memdiver[pcap]"
)

# TLS record content types (RFC 5246 / RFC 8446).
_CT_CHANGE_CIPHER_SPEC = 20
_CT_HANDSHAKE = 22
_CT_APPLICATION_DATA = 23

# Handshake message types.
_HS_CLIENT_HELLO = 1
_HS_SERVER_HELLO = 2

# The record header prefix (opaque_type=application_data || legacy_version=0x0303)
# that both the TLS 1.2 AEAD additional-data and the TLS 1.3 record AAD begin
# with, and that the TLS 1.2 CBC record MAC covers.
_APPLICATION_DATA_HEADER = b"\x17\x03\x03"

_AEAD_TAG_LEN = 16          # every TLS AEAD suite here uses a 16-byte tag
_CBC_EXPLICIT_IV_LEN = 16   # AES block size = TLS 1.2 CBC explicit record IV

# How far below the wire application_data index to also probe for TLS 1.3 — see
# the module docstring's sequence-number rule.
_TLS13_SEQ_WINDOW = 8


class PcapParseError(Exception):
    """Raised when a capture cannot be read or contains no usable TLS session."""


class _TlsSession:
    """One TLS session recovered from a paired pair of TCP flows.

    ``client_records`` are the records the ClientHello sender emitted (the
    client->server direction); ``server_records`` the reverse.
    """

    __slots__ = (
        "client_random",
        "server_random",
        "cipher_code",
        "version",
        "client_records",
        "server_records",
    )

    def __init__(
        self,
        client_random: bytes,
        server_random: bytes,
        cipher_code: int,
        version: str,
        client_records: list,
        server_records: list,
    ) -> None:
        self.client_random = client_random
        self.server_random = server_random
        self.cipher_code = cipher_code
        self.version = version
        self.client_records = client_records
        self.server_records = server_records


class TlsPcapResource:
    """A :class:`~memdiver.engine.resources.base.VerificationResource` over a pcap.

    Parsing is lazy: the constructor only stores inputs, so a bad path or a
    capture with no TLS session surfaces as a :class:`PcapParseError` from
    :meth:`challenges`, not at construction time.
    """

    def __init__(
        self,
        pcap_path,
        *,
        client_random: Optional[bytes] = None,
        max_records_per_direction: int = 16,
    ) -> None:
        self.pcap_path = str(pcap_path)
        self.client_random = client_random
        self.max_records_per_direction = max_records_per_direction

    @property
    def protocol(self) -> str:
        return "TLS"

    def challenges(self) -> Iterator[DecryptionChallenge]:
        """Parse the capture and yield one challenge per encrypted record."""
        if not HAS_PCAP:
            raise PcapParseError(_PCAP_MISSING)
        sessions = self._parse_sessions()
        if not sessions:
            raise PcapParseError(
                f"no complete TLS handshake found in {self.pcap_path!r} "
                "(need a ClientHello + ServerHello on one TCP connection)"
            )
        emitted = False
        matched = False
        for session in sessions:
            if (
                self.client_random is not None
                and session.client_random != self.client_random
            ):
                continue
            matched = True
            for challenge in self._session_challenges(session):
                emitted = True
                yield challenge
        if not emitted and self.client_random is not None:
            if matched:
                raise PcapParseError(
                    "the TLS session matching the supplied client_random has no "
                    "application-data records to verify against"
                )
            raise PcapParseError(
                "no TLS session in the capture matched the supplied client_random"
            )

    def describe_sessions(self) -> List[dict]:
        """Summarise each parsed TLS session without emitting any challenge.

        The read-only companion to :meth:`challenges`: it reuses the very same
        :meth:`_parse_sessions` handshake mining but, instead of yielding one
        :class:`DecryptionChallenge` per encrypted record, returns one plain,
        JSON-friendly dict per recovered session — the handshake facts plus a
        per-direction application_data record count. Parsing behaviour is
        unchanged and nothing here mutates session state; it only reads what
        :meth:`_parse_sessions` already produced.

        Each dict has ``client_random``/``server_random`` (hex), ``version``
        (``"12"``/``"13"``), ``cipher_suite`` (the IANA code, int),
        ``cipher_name`` (the IANA suite name, or the code's ``str`` when
        unknown), ``client_app_records``/``server_app_records`` (ints), and
        ``has_app_records`` (bool: whether either direction carries at least one
        encrypted application-data record — the oracle can only verify against a
        session that does).
        """
        if not HAS_PCAP:
            raise PcapParseError(_PCAP_MISSING)
        summaries: List[dict] = []
        for session in self._parse_sessions():
            client_app_records = _count_app_data(session.client_records)
            server_app_records = _count_app_data(session.server_records)
            summaries.append(
                {
                    "client_random": session.client_random.hex(),
                    "server_random": session.server_random.hex(),
                    "version": session.version,
                    "cipher_suite": session.cipher_code,
                    "cipher_name": _cipher_name(session.cipher_code, session.version),
                    "client_app_records": client_app_records,
                    "server_app_records": server_app_records,
                    # The oracle can only USE a session that carries encrypted
                    # application-data records; a 0-record session is parseable
                    # but not verifiable (the frontend disables such rows).
                    "has_app_records": bool(
                        client_app_records + server_app_records > 0
                    ),
                }
            )
        return summaries

    # -- capture -> TCP flows --------------------------------------------- #

    def _parse_sessions(self) -> List[_TlsSession]:
        """Read the capture, reassemble flows, and build one session per pair."""
        streams = self._read_flows()
        sessions: List[_TlsSession] = []
        seen: set = set()
        for key, segments in streams.items():
            reverse = (key[2], key[3], key[0], key[1])
            if key in seen or reverse in seen:
                continue
            seen.add(key)
            seen.add(reverse)
            forward_bytes = _reassemble(segments)
            reverse_bytes = _reassemble(streams.get(reverse, []))
            session = self._build_session(
                key, forward_bytes, reverse, reverse_bytes
            )
            if session is not None:
                sessions.append(session)
        return sessions

    def _read_flows(self) -> Dict[Tuple[str, int, str, int], List[Tuple[int, bytes]]]:
        """Group TCP payloads by directional 4-tuple: key -> [(seq, payload)]."""
        streams: Dict[Tuple[str, int, str, int], List[Tuple[int, bytes]]] = {}
        try:
            with open(self.pcap_path, "rb") as handle:
                reader = _open_reader(handle)
                datalink = reader.datalink()
                for _ts, buf in reader:
                    endpoints = _extract_tcp(datalink, buf)
                    if endpoints is None:
                        continue
                    key, seq, payload = endpoints
                    if payload:
                        streams.setdefault(key, []).append((seq, payload))
        except FileNotFoundError as exc:
            raise PcapParseError(f"capture not found: {self.pcap_path!r}") from exc
        except (OSError, ValueError, *_DpktError) as exc:
            raise PcapParseError(
                f"could not read capture {self.pcap_path!r}: {exc}"
            ) from exc
        return streams

    # -- TCP stream -> TLS session ---------------------------------------- #

    def _build_session(
        self,
        forward_key: Tuple[str, int, str, int],
        forward_bytes: bytes,
        reverse_key: Tuple[str, int, str, int],
        reverse_bytes: bytes,
    ) -> Optional[_TlsSession]:
        """Parse both directions' records and mine the handshake facts."""
        forward_records = _parse_records(forward_bytes)
        reverse_records = _parse_records(reverse_bytes)

        client_hello = _find_hello(forward_records, _HS_CLIENT_HELLO)
        if client_hello is not None:
            client_records, server_records = forward_records, reverse_records
        else:
            client_hello = _find_hello(reverse_records, _HS_CLIENT_HELLO)
            if client_hello is None:
                return None
            client_records, server_records = reverse_records, forward_records

        server_hello = _find_hello(server_records, _HS_SERVER_HELLO)
        if server_hello is None:
            return None

        client_random = bytes(getattr(client_hello, "random", b""))
        server_random = bytes(getattr(server_hello, "random", b""))
        cipher_code = _server_hello_cipher_code(server_hello)
        if len(client_random) != 32 or len(server_random) != 32 or cipher_code is None:
            return None

        version = _negotiated_version(server_hello, cipher_code)
        if version is None:
            logger.debug("unsupported cipher suite 0x%04x — skipping session", cipher_code)
            return None

        return _TlsSession(
            client_random=client_random,
            server_random=server_random,
            cipher_code=cipher_code,
            version=version,
            client_records=client_records,
            server_records=server_records,
        )

    # -- TLS session -> challenges ---------------------------------------- #

    def _session_challenges(self, session: _TlsSession) -> Iterator[DecryptionChallenge]:
        directions = (
            ("client", session.client_records),
            ("server", session.server_records),
        )
        if session.version == "12":
            suite = TLS12_CIPHER_SUITES[session.cipher_code]
            for name, records in directions:
                yield from self._tls12_direction(session, suite, name, records)
        else:  # "13"
            for name, records in directions:
                yield from self._tls13_direction(session, name, records)

    def _tls12_direction(
        self,
        session: _TlsSession,
        suite: Tls12SuiteParams,
        direction: str,
        records: list,
    ) -> Iterator[DecryptionChallenge]:
        """Emit TLS 1.2 challenges with precise post-ChangeCipherSpec sequencing."""
        seq = 0
        encrypted = False
        emitted = 0
        for record in records:
            if not encrypted:
                if record.type == _CT_CHANGE_CIPHER_SPEC:
                    encrypted = True  # records that FOLLOW are seq 0, 1, ...
                continue
            if (
                record.type == _CT_APPLICATION_DATA
                and emitted < self.max_records_per_direction
            ):
                yield self._build_tls12(
                    session, suite, direction, bytes(record.data), seq, emitted
                )
                emitted += 1
            seq += 1

    def _tls13_direction(
        self,
        session: _TlsSession,
        direction: str,
        records: list,
    ) -> Iterator[DecryptionChallenge]:
        """Emit TLS 1.3 challenges over a small sequence window (see docstring)."""
        index = 0
        emitted = 0
        for record in records:
            if record.type != _CT_APPLICATION_DATA:
                continue  # ChangeCipherSpec / cleartext ServerHello are not counted
            if emitted < self.max_records_per_direction:
                frag = bytes(record.data)
                for seq in range(max(0, index - _TLS13_SEQ_WINDOW), index + 1):
                    yield self._build_tls13(session, direction, frag, seq, index)
                emitted += 1
            index += 1

    # -- challenge builders ----------------------------------------------- #

    def _build_tls12(
        self,
        session: _TlsSession,
        suite: Tls12SuiteParams,
        direction: str,
        frag: bytes,
        seq: int,
        record_number: int,
    ) -> DecryptionChallenge:
        label = f"tls12 {suite.name} {direction} rec#{record_number}"
        if suite.aead:
            if suite.record_iv_len:  # AES-GCM: explicit 8-byte nonce leads the record
                record_iv = frag[: suite.record_iv_len]
                ciphertext = frag[suite.record_iv_len :]
            else:                    # ChaCha20-Poly1305: nonce is implicit (iv XOR seq)
                record_iv = b""
                ciphertext = frag
            plaintext_len = len(ciphertext) - _AEAD_TAG_LEN
            aad = (
                seq.to_bytes(8, "big")
                + _APPLICATION_DATA_HEADER
                + max(plaintext_len, 0).to_bytes(2, "big")
            )
            derivation = DerivationContext(
                protocol="TLS",
                version="12",
                client_random=session.client_random,
                server_random=session.server_random,
                cipher_suite=session.cipher_code,
                record_iv=record_iv,
                seq_num=seq,
            )
            return DecryptionChallenge(
                cipher=suite.verifier,
                ciphertext=ciphertext,
                tag=None,
                aad=aad,
                derivation=derivation,
                label=label,
            )

        # CBC: explicit 16-byte IV leads the record; aad is only the 3-byte
        # type||version prefix — the oracle assembles the full MAC input.
        record_iv = frag[:_CBC_EXPLICIT_IV_LEN]
        ciphertext = frag[_CBC_EXPLICIT_IV_LEN:]
        derivation = DerivationContext(
            protocol="TLS",
            version="12",
            client_random=session.client_random,
            server_random=session.server_random,
            cipher_suite=session.cipher_code,
            record_iv=record_iv,
            seq_num=seq,
        )
        return DecryptionChallenge(
            cipher=suite.verifier,
            ciphertext=ciphertext,
            tag=None,
            aad=_APPLICATION_DATA_HEADER,
            derivation=derivation,
            label=label,
        )

    def _build_tls13(
        self,
        session: _TlsSession,
        direction: str,
        frag: bytes,
        seq: int,
        record_number: int,
    ) -> DecryptionChallenge:
        suite = TLS13_CIPHER_SUITES[session.cipher_code]
        aad = _APPLICATION_DATA_HEADER + len(frag).to_bytes(2, "big")
        derivation = DerivationContext(
            protocol="TLS",
            version="13",
            cipher_suite=session.cipher_code,
            seq_num=seq,
        )
        return DecryptionChallenge(
            cipher=suite.verifier,
            ciphertext=frag,          # includes the trailing 16-byte AEAD tag
            tag=None,
            aad=aad,
            derivation=derivation,
            label=f"tls13 {suite.name} {direction} rec#{record_number} seq{seq}",
        )


# --------------------------------------------------------------------------- #
# Module-level parsing helpers (kept free of instance state so they stay unit-
# testable and read as straight data transforms).
# --------------------------------------------------------------------------- #


def _open_reader(handle):
    """Return a dpkt pcap or pcapng reader by sniffing the file's magic."""
    magic = handle.read(4)
    handle.seek(0)
    # pcapng Section Header Block magic; everything else is classic pcap.
    if magic == b"\x0a\x0d\x0d\x0a":
        return dpkt.pcapng.Reader(handle)
    return dpkt.pcap.Reader(handle)


def _extract_tcp(
    datalink: int, buf: bytes
) -> Optional[Tuple[Tuple[str, int, str, int], int, bytes]]:
    """Peel link/IP/TCP layers, returning (flow_key, tcp_seq, payload) or None."""
    try:
        ip = _link_payload(datalink, buf)
        if ip is None:
            return None
        tcp = ip.data
        if not isinstance(tcp, dpkt.tcp.TCP):
            return None
        src = _ip_str(ip.src)
        dst = _ip_str(ip.dst)
        key = (src, tcp.sport, dst, tcp.dport)
        return key, tcp.seq, bytes(tcp.data)
    except (dpkt.dpkt.UnpackError, AttributeError, KeyError):
        return None


def _link_payload(datalink: int, buf: bytes):
    """Return the IP layer for the link type, or None if it isn't IP-over-TCP."""
    if datalink == dpkt.pcap.DLT_EN10MB:
        layer = dpkt.ethernet.Ethernet(buf).data
    elif datalink in (dpkt.pcap.DLT_NULL, getattr(dpkt.pcap, "DLT_LOOP", -1)):
        # BSD loopback: 4-byte host-order address family, then the IP packet.
        layer = dpkt.ip.IP(buf[4:])
    elif datalink == getattr(dpkt.pcap, "DLT_LINUX_SLL", -1):
        layer = dpkt.sll.SLL(buf).data
    else:
        # Best effort: assume Ethernet, the overwhelmingly common case.
        layer = dpkt.ethernet.Ethernet(buf).data
    if isinstance(layer, (dpkt.ip.IP, dpkt.ip6.IP6)):
        return layer
    return None


def _ip_str(raw: bytes) -> str:
    """Render a packed IPv4/IPv6 address for use as a flow-key component."""
    import socket

    family = socket.AF_INET if len(raw) == 4 else socket.AF_INET6
    return socket.inet_ntop(family, raw)


def _reassemble(segments: List[Tuple[int, bytes]]) -> bytes:
    """Order TCP segments by sequence number and concatenate, trimming overlaps.

    A simple, gap-tolerant reassembler: segments are sorted by seq, then laid
    down from the lowest seq; a segment that overlaps already-written bytes is
    trimmed, a segment past the current end starts a fresh contiguous run. Good
    enough for the small, retransmission-free captures this resource targets.
    """
    if not segments:
        return b""
    ordered = sorted(segments, key=lambda item: item[0])
    buffer = bytearray()
    expected = ordered[0][0]
    for seq, data in ordered:
        if seq < expected:
            overlap = expected - seq
            if overlap >= len(data):
                continue  # wholly-duplicate segment
            data = data[overlap:]
            seq = expected
        buffer.extend(data)
        expected = seq + len(data)
    return bytes(buffer)


def _parse_records(raw: bytes) -> list:
    """Parse a reassembled byte stream into consecutive TLS records."""
    if not raw:
        return []
    try:
        records, _consumed = dpkt.ssl.tls_multi_factory(raw)
    except dpkt.ssl.SSL3Exception:
        return []
    return records


def _find_hello(records: list, hs_type: int):
    """Return the first ClientHello/ServerHello body across handshake records."""
    for record in records:
        if record.type != _CT_HANDSHAKE:
            continue
        for message in _iter_handshake_messages(bytes(record.data)):
            if message.type == hs_type:
                return message.data
    return None


def _iter_handshake_messages(body: bytes) -> Iterable:
    """Yield each TLSHandshake message packed in one handshake record's fragment."""
    while body:
        try:
            message = dpkt.ssl.TLSHandshake(body)
        except (dpkt.dpkt.UnpackError, dpkt.dpkt.NeedData, dpkt.ssl.SSL3Exception):
            return
        consumed = len(message)
        if consumed <= 0 or consumed > len(body):
            return
        yield message
        body = body[consumed:]


def _server_hello_cipher_code(server_hello) -> Optional[int]:
    """Read the negotiated IANA suite code from a parsed ServerHello."""
    suite = getattr(server_hello, "ciphersuite", None)
    if suite is None:
        suite = getattr(server_hello, "cipher_suite", None)  # older dpkt name
    if suite is None:
        return None
    code = getattr(suite, "code", suite)
    return int(code) if isinstance(code, int) else None


def _negotiated_version(server_hello, cipher_code: int) -> Optional[str]:
    """Decide "12" vs "13" for a session.

    dpkt does not expose parsed ServerHello extensions, so TLS 1.3's
    supported_versions signal is not directly available. We therefore rely on
    the (fully reliable) fact that the TLS 1.3 IANA suite codes (0x1301-0x1303)
    are disjoint from the TLS 1.2 codes: membership alone determines the
    version. A defensive extensions probe is kept for future dpkt versions.
    """
    extensions = getattr(server_hello, "extensions", None)
    if extensions:
        try:
            for ext_type, ext_data in extensions:
                if ext_type == 43 and b"\x03\x04" in bytes(ext_data):
                    return "13"
        except (TypeError, ValueError):
            pass
    if cipher_code in TLS13_CIPHER_SUITES:
        return "13"
    if cipher_code in TLS12_CIPHER_SUITES:
        return "12"
    return None


def _count_app_data(records: list) -> int:
    """Count the application_data records in one direction's record list."""
    return sum(1 for record in records if record.type == _CT_APPLICATION_DATA)


def _cipher_name(cipher_code: int, version: str) -> str:
    """Resolve the IANA suite name for a code, or its ``str`` when unknown."""
    table = TLS13_CIPHER_SUITES if version == "13" else TLS12_CIPHER_SUITES
    suite = table.get(cipher_code)
    return suite.name if suite is not None else str(cipher_code)
