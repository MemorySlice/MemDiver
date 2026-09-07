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

Dependency: parsing needs ``dpkt``, which ships in the base install. When it is
absent — a force-uninstall or a broken environment — the class still imports
but :meth:`TlsPcapResource.challenges` raises a clear, actionable error
(mirrors the availability model in ``msl/crypto.py``).
"""

from __future__ import annotations

import logging
from typing import (
    Any,
    Dict,
    Iterable,
    Iterator,
    List,
    Mapping,
    NamedTuple,
    Optional,
    Sequence,
    Tuple,
)

from memdiver.core.install_hints import missing_package_message
from memdiver.core.kdf_tls import (
    TLS12_CIPHER_SUITES,
    TLS13_CIPHER_SUITES,
    Tls12SuiteParams,
)
from memdiver.engine.resources.challenge import DecryptionChallenge, DerivationContext
from memdiver.engine.resources.protocol_fields import (
    ProtocolField,
    absent_certificate_note,
    certificate_fields,
    client_hello_fields,
    missing_sni_note,
    parse_certificate_list,
    parse_hello_layout,
    parse_server_name_list,
    record_seq_field,
    server_hello_fields,
    tls13_certificate_note,
    truncated_hello_note,
)

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

_PCAP_MISSING = missing_package_message("dpkt (capture parsing)")

# TLS record content types (RFC 5246 / RFC 8446).
_CT_CHANGE_CIPHER_SPEC = 20
_CT_HANDSHAKE = 22
_CT_APPLICATION_DATA = 23

# Handshake message types.
_HS_CLIENT_HELLO = 1
_HS_SERVER_HELLO = 2
# Certificate (RFC 5246 s7.4.2). Cleartext in TLS 1.2 only -- RFC 8446 moved it
# inside the protected handshake epoch, so a TLS 1.3 capture never yields one.
_HS_CERTIFICATE = 11

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


# The record-header size the whole module counts in: content_type(1) ||
# version(2) || length(2). Named because the cumulative offset walk and the
# provenance arithmetic must agree on it, and a bare `5` in two places is how
# they stop agreeing.
_RECORD_HEADER_LEN = 5

# The handshake message header the hello/certificate bodies sit behind:
# msg_type(1) || length(3).
_HANDSHAKE_HEADER_LEN = 4


class _MessageLocation(NamedTuple):
    """Where one handshake message body sits, in both frames of reference.

    Produced by :func:`_find_hello_with_offset` / :func:`_find_certificate_with_offset`
    and consumed by the field extractors, which need *offsets* and not only
    values -- see ``protocol_fields`` for why. Deliberately a plain NamedTuple:
    it is a coordinate, and it must stay cheap enough to build on every parse.

    ``fragment_base`` is the body's offset inside the record fragment (the
    message's position in the fragment plus its 4-byte header), which is what a
    field's ``record_offset`` is measured from. ``record_header_offset`` is where
    the enclosing record's 5-byte header starts in the reassembled direction
    stream.
    """

    direction: str          #: ``"client"`` or ``"server"``
    record_index: int       #: index into that direction's record list
    record_header_offset: int
    fragment_base: int
    raw: bytes              #: the message body, WITHOUT its handshake header
    parsed: Any = None      #: dpkt's parse of the same body, when it produced one


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
        # -- C1 protocol-field locations ---------------------------------- #
        # Byte coordinates for the handshake messages the field extractor
        # reads, filled by :meth:`TlsPcapResource._build_session` because that
        # is where the messages are already in hand. KEYWORD-ONLY WITH
        # DEFAULTS on purpose: tests (and any library caller) construct
        # ``_TlsSession`` positionally with the original six arguments, so a
        # required seventh would break them. A ``None`` here means "nobody
        # recorded a location", and :func:`session_fields` re-derives from the
        # record lists rather than silently reporting no fields.
        "client_hello",
        "server_hello",
        "certificates",
    )

    def __init__(
        self,
        client_random: bytes,
        server_random: bytes,
        cipher_code: int,
        version: str,
        client_records: list,
        server_records: list,
        *,
        client_hello: Optional[_MessageLocation] = None,
        server_hello: Optional[_MessageLocation] = None,
        certificates: Optional[_MessageLocation] = None,
    ) -> None:
        self.client_random = client_random
        self.server_random = server_random
        self.cipher_code = cipher_code
        self.version = version
        self.client_records = client_records
        self.server_records = server_records
        self.client_hello = client_hello
        self.server_hello = server_hello
        self.certificates = certificates


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
        max_challenges: Optional[int] = None,
    ) -> None:
        # Imported inside the constructor so the import edge stays one-way: the
        # parser must not pull the oracle loader (and, through it,
        # ``ResourceOracle``) in merely to be importable.
        from memdiver.engine.resources.builtin_oracle import _require_positive_cap

        self.pcap_path = str(pcap_path)
        self.client_random = client_random
        # Validated HERE as well as at the oracle-loader entry point, because a
        # direct construction -- a library caller, a test, a future factory --
        # reaches this constructor without passing through either that loader or
        # the producer layer's ``_validate_pcap_caps``. A record cap below 1
        # emits no challenges at all, so it reports a genuine key as
        # "0 confirmed" from a run that looks successful. ``None`` still means
        # "no cap supplied" and passes through untouched.
        # ``allow_none=False``: this parameter is annotated ``int`` with a
        # default of 16, so an explicit ``None`` is not "uncapped" -- it would
        # reach ``emitted < self.max_records_per_direction`` below and raise an
        # unrelated TypeError mid-emission.
        self.max_records_per_direction = _require_positive_cap(
            "max_records_per_direction", max_records_per_direction, allow_none=False
        )
        # Reported here, ENFORCED by the consumer: the total-challenge cap slices
        # the flat challenge list (see ``ResourceOracle``), so it truncates
        # ACROSS sessions and cannot be applied per direction. Carrying it lets
        # :meth:`describe_capture` report the caps actually in force; without it
        # a run with ``max_challenges=1`` reported full coverage. It is
        # validated by the same helper where it is enforced (``build_oracle``),
        # not here, so this stays a pure reporting copy.
        self.max_challenges = max_challenges
        # Parse-time accounting, refreshed on every ``_parse_sessions`` call and
        # reported by ``describe_capture``. Without it a session the parser has
        # to drop vanishes silently, so any corpus-wide number computed over
        # this resource understates itself with no trace of the loss.
        self._skipped: List[dict] = []
        self._flow_count: int = 0

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
            if self._excluded_by_filter(session):
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
        return [_summarise_session(s) for s in self._parse_sessions()]

    def describe_capture(self) -> dict:
        """Report the whole capture: the sessions kept AND the work dropped.

        The reportable superset of :meth:`describe_sessions`, whose return shape
        is frozen (the web router and the React frontend read it). This method is
        built *around* that one — it reports the very same per-session dicts and
        then adds the accounting :meth:`_parse_sessions` gathered on the side:
        every session the parser had to drop, with a machine-readable ``reason``,
        plus the caps that bound how much of a *kept* session is actually
        verified.

        Why it exists: a corpus sweep aggregates thousands of captures, and both
        a silently-dropped session and a cap silently clipping verification work
        make the aggregate understate itself with nothing in the output to say
        so. Every drop this resource makes is reportable here.

        Coverage numbers come from the *same gate the emitter uses*
        (:meth:`_tls12_gated` / :meth:`_tls13_gated`), never from re-deriving
        them out of the summary counts. That matters: TLS 1.2 records are only
        decryptable *after* their direction's ChangeCipherSpec, so a capture
        that starts mid-session (or drops the CCS packet) carries application
        data the challenge stream cannot cover at all. Counting raw records
        there reported full coverage for a session that verified nothing.

        Returns ``{"sessions": [...], "skipped": [...], "flow_count": int,
        "caps": {...}, "records_truncated": bool, "challenges_available": int,
        "challenges_returned": int, "challenges_truncated": bool}``:

        * ``sessions`` — each :meth:`describe_sessions` dict plus four additive
          accounting keys: ``app_records_seen`` (application-data records the
          parser saw across both directions), ``records_returned`` (how many of
          those the challenge stream actually covers, after the record cap, the
          TLS 1.2 ChangeCipherSpec gate, and whatever is left of the
          challenge budget), ``challenges_available`` (challenges this session
          would contribute uncapped — more than one per record for TLS 1.3,
          which probes a small sequence window) and ``challenges_returned``.
        * ``skipped`` — one dict per piece of work the parser could not use,
          carrying a machine-readable ``reason``, the ``flow`` it was seen on,
          and any reason-specific context. Reachable reasons:
          ``"no_client_hello"``, ``"no_server_hello"``,
          ``"unsupported_cipher_suite"`` (each drops a whole session),
          ``"client_random_mismatch"`` (parsed, but this resource is pinned to
          another session, so the stream skips it — it carries the session's
          ``client_random``) and ``"no_change_cipher_spec"`` (the session is
          kept, but one direction's application data is unreachable — it carries
          ``direction`` and that direction's ``app_records_seen``). Two further reasons,
          ``"no_cipher_suite"`` and ``"short_random"``, guard ServerHello shapes
          the bundled dpkt cannot produce (it always yields a 32-byte random and
          an int suite code, and rejects a short random outright — which
          surfaces as ``"no_server_hello"``); they are kept as defence against
          another dpkt version, so a caller should tolerate them but must not
          expect them.
        * ``flow_count`` — directional TCP flows the capture yielded.
        * ``caps`` — the caps in force: ``max_records_per_direction`` (int) and
          ``max_challenges`` (int, or ``None`` for no cap).
        * ``records_truncated`` — True whenever some session returns fewer
          records than it saw, whatever the cause (record cap, missing
          ChangeCipherSpec, or an exhausted challenge budget).
        * ``challenges_available`` / ``challenges_returned`` /
          ``challenges_truncated`` — the challenge stream the oracle will see.
          ``max_challenges`` truncates that flat stream ACROSS sessions, so
          these are capture-level: a session whose sequence-window burst is only
          partly emitted still counts as a returned record, and
          ``challenges_returned < challenges_available`` is the signal that some
          records got only part of their window.
        """
        if not HAS_PCAP:
            raise PcapParseError(_PCAP_MISSING)
        parsed = self._parse_sessions()
        remaining = self.max_challenges
        sessions: List[dict] = []
        challenges_available = 0
        challenges_returned = 0
        records_truncated = False
        for session in parsed:
            summary = _summarise_session(session)
            bursts = self._challenge_bursts(session)
            available = sum(bursts)
            covered, returned, remaining = _spend_challenge_budget(bursts, remaining)
            seen = summary["client_app_records"] + summary["server_app_records"]
            records_truncated = records_truncated or covered < seen
            challenges_available += available
            challenges_returned += returned
            sessions.append(
                {
                    **summary,
                    "app_records_seen": seen,
                    "records_returned": covered,
                    "challenges_available": available,
                    "challenges_returned": returned,
                }
            )
        return {
            "sessions": sessions,
            "skipped": list(self._skipped),
            "flow_count": self._flow_count,
            "caps": {
                "max_records_per_direction": self.max_records_per_direction,
                "max_challenges": self.max_challenges,
            },
            "records_truncated": records_truncated,
            "challenges_available": challenges_available,
            "challenges_returned": challenges_returned,
            "challenges_truncated": challenges_returned < challenges_available,
        }

    def describe_fields(self) -> List[dict]:
        """Report the byte-addressable protocol fields of every parsed session.

        The third read-only companion to :meth:`challenges`, alongside
        :meth:`describe_sessions` (what session is this?) and
        :meth:`describe_capture` (what did the parser have to drop?). This one
        answers "which bytes of this handshake could I go looking for in a
        memory dump, and where on the wire did each come from?" -- see
        ``protocol_fields`` for why that is a different question.

        It is a NEW method rather than an extra key on ``describe_sessions``
        because that dict's key set is a frozen contract the web router and the
        React frontend read; adding to it fails the build by design. Nothing
        here mutates state or changes what either existing method returns.

        Returns one dict per session::

            {"client_random": <hex>,      # the session's identity, as elsewhere
             "session_index": <int>,      # position in the parse order
             "fields": [<ProtocolField.as_dict()>, ...],
             "notes": [{"code", "detail"}, ...]}

        ``notes`` explains every field a caller might reasonably expect and not
        find -- most importantly that TLS 1.3 encrypts the Certificate message,
        so its absence is by design and not a parse failure.
        """
        if not HAS_PCAP:
            raise PcapParseError(_PCAP_MISSING)
        return [
            {
                "client_random": session.client_random.hex(),
                "session_index": index,
                "fields": [
                    field.as_dict()
                    for field in session_fields(
                        session, record_sequences=self._record_sequences(session)
                    )
                ],
                "notes": session_notes(session),
            }
            for index, session in enumerate(self._parse_sessions())
        ]

    def _record_sequences(self, session: _TlsSession) -> Dict[str, List[int]]:
        """The record sequence numbers each direction's challenges will carry.

        Read straight out of the emitter's own gates -- never re-derived from
        record counts -- for exactly the reason :meth:`describe_capture`'s
        coverage numbers are: the gates encode the TLS 1.2 ChangeCipherSpec
        condition and the per-direction cap, so any independent derivation
        eventually disagrees with the stream it claims to describe.

        For TLS 1.2 these are true sequence numbers (position in the post-CCS
        run). For TLS 1.3 they are the *wire indices* the gate reports, which the
        module docstring's sequence rule makes an upper bound on the true
        sequence number rather than the number itself -- the handshake-to-
        application epoch change is invisible, so the challenge stream probes a
        window below each one.
        """
        sequences: Dict[str, List[int]] = {}
        for direction, records in _directions(session):
            if session.version == "12":
                sequences[direction] = [seq for _rec, seq, _n in self._tls12_gated(records)]
            else:  # "13" -- wire indices; see the docstring
                sequences[direction] = [index for _rec, index in self._tls13_gated(records)]
        return sequences

    def _excluded_by_filter(self, session: _TlsSession) -> bool:
        """True when ``client_random`` restricts this run to a different session.

        THE session filter — shared by :meth:`challenges` and the honesty report
        so a session the stream skips can never be reported as covered.
        """
        return (
            self.client_random is not None
            and session.client_random != self.client_random
        )

    def _challenge_bursts(self, session: _TlsSession) -> List[int]:
        """How many challenges each covered record contributes, in emit order.

        One entry per record the challenge stream really reaches — so
        ``len(...)`` is the honest ``records_returned`` and ``sum(...)`` the
        honest challenge count. Both directions are walked through the exact
        gates :meth:`_session_challenges` emits from, which is what keeps the
        report and the stream from drifting apart.
        """
        if self._excluded_by_filter(session):
            return []  # the stream skips this session entirely
        bursts: List[int] = []
        for _direction, records in _directions(session):
            if session.version == "12":
                bursts.extend(1 for _gated in self._tls12_gated(records))
            else:  # "13" — each record probes a small sequence window
                bursts.extend(
                    len(_tls13_seq_window(index))
                    for _record, index in self._tls13_gated(records)
                )
        return bursts

    def _note_skipped(
        self,
        reason: str,
        flow_key: Tuple[str, int, str, int],
        **context: Any,
    ) -> None:
        """Log one piece of dropped work for :meth:`describe_capture` to report.

        Most reasons drop a whole session; ``"no_change_cipher_spec"`` keeps the
        session but records that one direction's application data is unreachable.
        """
        entry: Dict[str, Any] = {"reason": reason, "flow": _flow_label(flow_key)}
        entry.update(context)
        self._skipped.append(entry)

    # -- capture -> TCP flows --------------------------------------------- #

    def _parse_sessions(self) -> List[_TlsSession]:
        """Read the capture, reassemble flows, and build one session per pair."""
        streams = self._read_flows()
        # A fresh parse means fresh accounting: the drop log describes THIS pass,
        # never an accumulation across repeated calls.
        self._skipped = []
        self._flow_count = len(streams)
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
        """Group TCP payloads by directional 4-tuple: key -> [(seq, payload)].

        A thin shim over the module-level :func:`read_flows`, which is where the
        reader loop actually lives. The split is deliberate: protocol DETECTION
        (``protocol_detect.py``) needs the very same flow grouping for a capture
        it has no resource for, and duplicating the loop there would mean a
        capture whose flows the detector reads differently from the ones the TLS
        parse reads -- i.e. a report about a different capture than the one that
        failed. The method stays because every caller in this class spells it
        this way and it carries the instance's path.
        """
        return read_flows(self.pcap_path)

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
            client_key = forward_key
        else:
            client_hello = _find_hello(reverse_records, _HS_CLIENT_HELLO)
            if client_hello is None:
                self._note_skipped("no_client_hello", forward_key)
                return None
            client_records, server_records = reverse_records, forward_records
            client_key = reverse_key

        server_hello = _find_hello(server_records, _HS_SERVER_HELLO)
        if server_hello is None:
            self._note_skipped("no_server_hello", client_key)
            return None

        client_random = bytes(getattr(client_hello, "random", b""))
        server_random = bytes(getattr(server_hello, "random", b""))
        cipher_code = _server_hello_cipher_code(server_hello)
        # Same three drops as before, split so each reports its own reason.
        if cipher_code is None:
            self._note_skipped("no_cipher_suite", client_key)
            return None
        if len(client_random) != 32 or len(server_random) != 32:
            self._note_skipped(
                "short_random",
                client_key,
                client_random_len=len(client_random),
                server_random_len=len(server_random),
            )
            return None

        version = _negotiated_version(server_hello, cipher_code)
        if version is None:
            # INFO, not DEBUG: an out-of-table suite drops an entire TLS session,
            # which at default log levels used to leave no trace at all.
            logger.info("unsupported cipher suite 0x%04x — skipping session", cipher_code)
            self._note_skipped(
                "unsupported_cipher_suite", client_key, cipher_suite=cipher_code
            )
            return None

        session = _TlsSession(
            client_random=client_random,
            server_random=server_random,
            cipher_code=cipher_code,
            version=version,
            client_records=client_records,
            server_records=server_records,
            # Coordinates only -- the hello BODIES are not parsed into fields
            # here. Locating is a cheap walk over already-parsed records,
            # whereas the field walk is only ever wanted by
            # :meth:`describe_fields`; doing it here would tax every
            # ``challenges()`` call for nothing.
            #
            # These locate a SECOND time rather than reusing the
            # ``_find_hello`` calls above, deliberately. The value path above is
            # left exactly as it was -- byte for byte, including being the seam
            # existing tests monkeypatch ``_find_hello`` at -- so nothing about
            # how a session is *built* changed when the field model arrived. The
            # cost is one extra pass over a record list a handful of entries
            # long, which is not worth buying back with a behaviour change.
            client_hello=_hello_location("client", client_records, _HS_CLIENT_HELLO),
            server_hello=_hello_location("server", server_records, _HS_SERVER_HELLO),
            certificates=_certificate_location("server", server_records),
        )
        if self._excluded_by_filter(session):
            # Parsed fine, but this run is pinned to another session, so nothing
            # in it will be verified. Reported for the same reason every other
            # drop is: an unexplained zero is indistinguishable from a failure.
            self._note_skipped(
                "client_random_mismatch",
                client_key,
                client_random=session.client_random.hex(),
            )
        else:
            self._note_unreachable_directions(client_key, session)
        return session

    def _note_unreachable_directions(
        self,
        client_key: Tuple[str, int, str, int],
        session: _TlsSession,
    ) -> None:
        """Report a TLS 1.2 direction whose app data no ChangeCipherSpec unlocks.

        TLS 1.2 record keys only take effect *after* a direction's
        ChangeCipherSpec, so application data with no preceding CCS in the
        capture — a truncated capture start, a dropped packet, a one-sided CCS —
        can never be turned into a challenge. Kept as a ``skipped`` entry so an
        operator reading a zero-confirmation result learns *why* the session
        verified nothing instead of seeing an unexplained zero. TLS 1.3 needs no
        CCS (its records are protected from the handshake onward), so the check
        applies to TLS 1.2 only.
        """
        if session.version != "12":
            return
        for direction, records in _directions(session):
            app_records = _count_app_data(records)
            if not app_records or _has_change_cipher_spec(records):
                continue
            logger.info(
                "no ChangeCipherSpec on the %s direction — %d application-data "
                "record(s) cannot be verified",
                direction, app_records,
            )
            self._note_skipped(
                "no_change_cipher_spec",
                client_key,
                direction=direction,
                app_records_seen=app_records,
            )

    # -- TLS session -> challenges ---------------------------------------- #

    def _session_challenges(self, session: _TlsSession) -> Iterator[DecryptionChallenge]:
        directions = _directions(session)
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
        for record, seq, number in self._tls12_gated(records):
            yield self._build_tls12(
                session, suite, direction, bytes(record.data), seq, number
            )

    def _tls12_gated(self, records: list) -> Iterator[Tuple[Any, int, int]]:
        """Yield ``(record, seq_num, record_number)`` for every coverable record.

        THE TLS 1.2 gate — the single place that decides which application-data
        records the challenge stream reaches, shared by the emitter
        (:meth:`_tls12_direction`) and the honesty report
        (:meth:`_challenge_bursts`). Keeping one gate is the point: when
        ``describe_capture`` re-derived its counts from the raw record totals
        instead, a capture with no ChangeCipherSpec reported full coverage while
        the stream carried zero challenges.

        Only records *after* this direction's ChangeCipherSpec are encrypted
        under the negotiated keys; ``seq`` counts from 0 at the first such record
        (the encrypted Finished), so an application-data record's sequence number
        is its position in that post-CCS run, not its position among the
        application-data records.
        """
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
                yield record, seq, emitted
                emitted += 1
            seq += 1

    def _tls13_direction(
        self,
        session: _TlsSession,
        direction: str,
        records: list,
    ) -> Iterator[DecryptionChallenge]:
        """Emit TLS 1.3 challenges over a small sequence window (see docstring)."""
        for record, index in self._tls13_gated(records):
            frag = bytes(record.data)
            for seq in _tls13_seq_window(index):
                yield self._build_tls13(session, direction, frag, seq, index)

    def _tls13_gated(self, records: list) -> Iterator[Tuple[Any, int]]:
        """Yield ``(record, record_index)`` for every coverable record.

        THE TLS 1.3 gate, shared by :meth:`_tls13_direction` and
        :meth:`_challenge_bursts` for the same reason its TLS 1.2 sibling is.
        Every protected TLS 1.3 record is application_data, so there is no CCS
        condition here — only the per-direction record cap. ``index`` keeps
        counting past the cap so a record's index still reflects its position on
        the wire.
        """
        index = 0
        emitted = 0
        for record in records:
            if record.type != _CT_APPLICATION_DATA:
                continue  # ChangeCipherSpec / cleartext ServerHello are not counted
            if emitted < self.max_records_per_direction:
                yield record, index
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


def read_flows(
    pcap_path: Any,
) -> Dict[Tuple[str, int, str, int], List[Tuple[int, bytes]]]:
    """Group a capture's TCP payloads by directional 4-tuple: key -> [(seq, payload)].

    The capture-reading half of :meth:`TlsPcapResource._read_flows`, lifted to
    module level so a caller that has no resource -- protocol detection, which
    runs precisely when building one has already failed -- reads the capture
    through the SAME loop rather than a second copy of it.

    Every read failure is funnelled to :class:`PcapParseError`, including dpkt's
    own ``dpkt.dpkt.Error`` hierarchy (see :data:`_DpktError`); a missing file
    keeps its own distinct message because "not found" and "unreadable" call for
    different fixes. UDP is not here by design: :func:`_extract_tcp` drops it,
    and this function exists to be reused, not to change what the TLS parser
    sees.
    """
    streams: Dict[Tuple[str, int, str, int], List[Tuple[int, bytes]]] = {}
    try:
        with open(pcap_path, "rb") as handle:
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
        raise PcapParseError(f"capture not found: {pcap_path!r}") from exc
    except (OSError, ValueError, *_DpktError) as exc:
        raise PcapParseError(
            f"could not read capture {pcap_path!r}: {exc}"
        ) from exc
    return streams


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
    """Return the first ClientHello/ServerHello body across handshake records.

    A thin wrapper over :func:`_find_hello_with_offset`, kept because it is the
    long-standing spelling every existing caller uses and its value-only answer
    is all they need. The two can never disagree: this one simply drops the
    coordinates the other reports.
    """
    return _find_hello_with_offset(records, hs_type)[0]


def _find_hello_with_offset(
    records: list, hs_type: int
) -> Tuple[Any, int, int, bytes]:
    """:func:`_find_hello`, plus *where* the hello was.

    Returns ``(body, record_index, stream_offset, raw)``:

    * ``body`` -- dpkt's parse of the message (a ``TLSClientHello`` /
      ``TLSServerHello``), exactly what :func:`_find_hello` returns;
    * ``record_index`` -- index of the carrying record in ``records``;
    * ``stream_offset`` -- the byte offset of the message *body* in the
      reassembled direction stream, derived from a cumulative walk of
      ``_RECORD_HEADER_LEN + record.length`` over the preceding records plus the
      message's position inside this record's fragment and its 4-byte handshake
      header;
    * ``raw`` -- the message body bytes, without that handshake header.

    ``(None, -1, -1, b"")`` when no such message is present -- a sentinel rather
    than ``None`` so the wrapper above stays a one-liner and callers that only
    want the body are unaffected.

    Offsets exist because a field value without a wire position cannot be
    cross-checked against a hit in a memory dump; see ``protocol_fields``.
    """
    record_header_offset = 0
    for index, record in enumerate(records):
        if record.type == _CT_HANDSHAKE:
            fragment = bytes(record.data)
            for message, message_offset in _iter_handshake_messages_with_offset(fragment):
                if message.type != hs_type:
                    continue
                body_start = message_offset + _HANDSHAKE_HEADER_LEN
                return (
                    message.data,
                    index,
                    record_header_offset + _RECORD_HEADER_LEN + body_start,
                    fragment[body_start : body_start + _message_body_len(message)],
                )
        record_header_offset += _RECORD_HEADER_LEN + _record_length(record)
    return None, -1, -1, b""


def _find_certificate_with_offset(records: list) -> Tuple[int, int, bytes]:
    """Locate the cleartext Certificate handshake message, if the capture has one.

    Returns ``(record_index, stream_offset, raw)`` with the same meaning as
    :func:`_find_hello_with_offset`, or ``(-1, -1, b"")`` when there is none.
    Absence is the *normal* TLS 1.3 outcome (RFC 8446 encrypts this message), so
    this must never be treated as a parse failure -- ``session_notes`` reports it
    instead. It is also the normal outcome for a TLS 1.2 capture that starts
    after the server's flight.
    """
    record_header_offset = 0
    for index, record in enumerate(records):
        if record.type == _CT_HANDSHAKE:
            fragment = bytes(record.data)
            for message, message_offset in _iter_handshake_messages_with_offset(fragment):
                if message.type != _HS_CERTIFICATE:
                    continue
                body_start = message_offset + _HANDSHAKE_HEADER_LEN
                return (
                    index,
                    record_header_offset + _RECORD_HEADER_LEN + body_start,
                    fragment[body_start : body_start + _message_body_len(message)],
                )
        record_header_offset += _RECORD_HEADER_LEN + _record_length(record)
    return -1, -1, b""


def _record_length(record) -> int:
    """The record's fragment length, as the offset walk must count it.

    Reads dpkt's parsed ``length`` header field, falling back to the fragment it
    actually produced. The fallback matters for the same reason every other
    ``getattr`` in this module does: the attribute exists only after a
    successful unpack, and an offset walk that raises would take the whole
    field extraction down over one odd record.
    """
    length = getattr(record, "length", None)
    if isinstance(length, int):
        return length
    return len(bytes(getattr(record, "data", b"")))


def _message_body_len(message) -> int:
    """A handshake message's declared body length (``length``), defensively read."""
    length = getattr(message, "length", None)
    if isinstance(length, int):
        return length
    return max(0, len(message) - _HANDSHAKE_HEADER_LEN)


def _iter_handshake_messages(body: bytes) -> Iterable:
    """Yield each TLSHandshake message packed in one handshake record's fragment.

    A thin wrapper over :func:`_iter_handshake_messages_with_offset`, kept for
    the callers that only need the messages.
    """
    for message, _offset in _iter_handshake_messages_with_offset(body):
        yield message


def _iter_handshake_messages_with_offset(body: bytes) -> Iterator[Tuple[Any, int]]:
    """Yield ``(message, offset_in_fragment)`` for each packed handshake message.

    Several handshake messages may share one record fragment (a server's
    ServerHello + Certificate + ServerKeyExchange flight routinely does), so a
    message's byte position is its offset within the fragment -- not zero. That
    offset is the missing half of every field coordinate this module reports,
    which is why the offset-carrying form is the real implementation and the
    value-only one above is the wrapper.
    """
    offset = 0
    while body:
        try:
            message = dpkt.ssl.TLSHandshake(body)
        except (dpkt.dpkt.UnpackError, dpkt.dpkt.NeedData, dpkt.ssl.SSL3Exception):
            return
        consumed = len(message)
        if consumed <= 0 or consumed > len(body):
            return
        yield message, offset
        offset += consumed
        body = body[consumed:]


def _record_header_offset(records: list, record_index: int) -> int:
    """Where record ``record_index``'s 5-byte header starts in the direction stream.

    The cumulative ``_RECORD_HEADER_LEN + record.length`` walk, stated once. The
    locators above walk it as they search; this recovers it for a record whose
    index is already known, which is how ``fragment_base`` is separated back out
    of the ``stream_offset`` the locators return (see :func:`_message_location`).
    """
    return sum(
        _RECORD_HEADER_LEN + _record_length(record)
        for record in records[:record_index]
    )


def _message_location(
    direction: str, records: list, found: Tuple[Any, int, int, bytes]
) -> Optional[_MessageLocation]:
    """Turn a :func:`_find_hello_with_offset` result into a full coordinate.

    ``found`` reports the body's ``stream_offset``; a field's ``record_offset``
    is measured from the *fragment*, so the two are separated here using the
    identity the record header defines::

        fragment_base = stream_offset - record_header_offset - _RECORD_HEADER_LEN

    Doing it in one place -- rather than at each of the three call sites that
    need a coordinate -- is what keeps an off-by-five from existing in only one
    of them. ``None`` when the message was not found.
    """
    body, record_index, stream_offset, raw = found
    if record_index < 0:
        return None
    header_offset = _record_header_offset(records, record_index)
    return _MessageLocation(
        direction=direction,
        record_index=record_index,
        record_header_offset=header_offset,
        fragment_base=stream_offset - header_offset - _RECORD_HEADER_LEN,
        raw=raw,
        parsed=body,
    )


def _hello_location(
    direction: str, records: list, hs_type: int
) -> Optional[_MessageLocation]:
    """:func:`_message_location` for a ClientHello/ServerHello, or ``None``."""
    return _message_location(
        direction, records, _find_hello_with_offset(records, hs_type)
    )


def _certificate_location(
    direction: str, records: list
) -> Optional[_MessageLocation]:
    """:func:`_message_location` for the Certificate message, or ``None``.

    ``None`` is the expected TLS 1.3 answer and a legitimate TLS 1.2 one; see
    :func:`_find_certificate_with_offset`.
    """
    record_index, stream_offset, raw = _find_certificate_with_offset(records)
    return _message_location(direction, records, (None, record_index, stream_offset, raw))


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


def _flow_label(flow_key: Tuple[str, int, str, int]) -> str:
    """Render a directional flow key for a human-readable drop report."""
    src, sport, dst, dport = flow_key
    return f"{src}:{sport} -> {dst}:{dport}"


def _count_app_data(records: list) -> int:
    """Count the application_data records in one direction's record list."""
    return sum(1 for record in records if record.type == _CT_APPLICATION_DATA)


def _has_change_cipher_spec(records: list) -> bool:
    """True when this direction sent a ChangeCipherSpec (TLS 1.2 key switch)."""
    return any(record.type == _CT_CHANGE_CIPHER_SPEC for record in records)


def _directions(session: _TlsSession) -> Tuple[Tuple[str, list], Tuple[str, list]]:
    """The session's two directions in the exact order challenges are emitted."""
    return (("client", session.client_records), ("server", session.server_records))


def _tls13_seq_window(index: int) -> range:
    """The sequence numbers a TLS 1.3 record at *index* is probed with.

    The undetectable handshake->application epoch change (see the module
    docstring) means the true sequence number is at or below the wire index, so
    each record contributes a small window of candidates. Shared by the emitter
    and the honesty report so ``challenges_available`` counts exactly what the
    stream yields.
    """
    return range(max(0, index - _TLS13_SEQ_WINDOW), index + 1)


def _spend_challenge_budget(
    bursts: List[int], remaining: Optional[int]
) -> Tuple[int, int, Optional[int]]:
    """Apply the cross-session challenge budget to one session's record bursts.

    ``ResourceOracle`` caps by slicing the *flat* challenge list, so the budget
    is consumed session by session in emission order — that is what this walk
    reproduces. Returns ``(records_covered, challenges_returned, remaining)``;
    ``remaining=None`` means no cap. A record whose burst is only partially
    emitted still counts as covered, which is why ``challenges_returned`` is
    reported alongside it.
    """
    if remaining is None:
        return len(bursts), sum(bursts), None
    covered = 0
    returned = 0
    for burst in bursts:
        if remaining <= 0:
            break
        taken = min(burst, remaining)
        covered += 1
        returned += taken
        remaining -= taken
    return covered, returned, remaining


def _summarise_session(session: _TlsSession) -> dict:
    """Render one parsed session as the frozen ``describe_sessions`` dict.

    Extracted so :meth:`TlsPcapResource.describe_capture` can report the very
    same per-session shape from an already-parsed session list — reading the
    capture once instead of parsing it a second time — without either surface
    being able to drift from the other.
    """
    client_app_records = _count_app_data(session.client_records)
    server_app_records = _count_app_data(session.server_records)
    return {
        "client_random": session.client_random.hex(),
        "server_random": session.server_random.hex(),
        "version": session.version,
        "cipher_suite": session.cipher_code,
        "cipher_name": _cipher_name(session.cipher_code, session.version),
        "client_app_records": client_app_records,
        "server_app_records": server_app_records,
        # The oracle can only USE a session that carries encrypted
        # application-data records; a 0-record session is parseable but not
        # verifiable (the frontend disables such rows).
        "has_app_records": bool(client_app_records + server_app_records > 0),
    }


# --------------------------------------------------------------------------- #
# C1 protocol field model -- the byte-addressed view of a parsed session.
#
# Deliberately NOT folded into ``_summarise_session`` above. That dict's key set
# is a frozen contract (``tests/test_tls_pcap_resource.py``
# ::test_describe_sessions_shape_is_unchanged asserts it exactly, because the web
# router and the React frontend read it), so a ``fields`` key there would fail
# the build. Fields ride on their own function and their own method instead, and
# ``describe_sessions`` / ``describe_capture`` output is byte-identical to what
# it was before this model existed.
# --------------------------------------------------------------------------- #


def session_fields(
    session: _TlsSession,
    *,
    record_sequences: Optional[Mapping[str, Sequence[int]]] = None,
) -> Tuple[ProtocolField, ...]:
    """Every :class:`ProtocolField` a parsed session yields.

    Ordered by source -- ClientHello fields, then ServerHello, then the
    certificate chain, then the record layer -- with each hello's extensions in
    wire order inside its group. Grouped rather than strictly wire-ordered
    because that is the order a reader scans them in, and because the record-seq
    fields have no wire position to be ordered by at all.

    Handshake fields are read from the locations :meth:`_build_session` recorded;
    when a session was constructed without them (a positional construction in a
    test, or a library caller building one by hand) the locations are re-derived
    from the record lists, so this function is total rather than silently empty.

    ``record_sequences`` is the one thing this function will not derive itself.
    Record sequence numbers come out of the emitter's own gates
    (:meth:`TlsPcapResource._tls12_gated` / :meth:`_tls13_gated`), which depend
    on the resource's ``max_records_per_direction`` cap -- so re-deriving them
    here would produce a list the challenge stream does not actually use. That
    is precisely the drift ``describe_capture`` was rewritten to eliminate, so
    the numbers are *passed in* by :meth:`TlsPcapResource.describe_fields` or
    omitted. Map keys are ``"client"`` / ``"server"``.
    """
    fields: List[ProtocolField] = []

    client = _client_hello_location(session)
    if client is not None:
        fields.extend(
            client_hello_fields(
                parse_hello_layout(client.raw, is_client=True),
                record_index=client.record_index,
                record_header_offset=client.record_header_offset,
                fragment_base=client.fragment_base,
                direction=client.direction,
            )
        )

    server = _server_hello_location(session)
    if server is not None:
        fields.extend(
            server_hello_fields(
                parse_hello_layout(server.raw, is_client=False),
                record_index=server.record_index,
                record_header_offset=server.record_header_offset,
                fragment_base=server.fragment_base,
                # The suite code the CHALLENGE STREAM uses, read through
                # ``_server_hello_cipher_code``'s defensive dpkt path, not the
                # hand-rolled one -- so the field and the derivation can never
                # report different suites for one session.
                negotiated_cipher=session.cipher_code,
                direction=server.direction,
            )
        )

    certificates = _certificate_message_location(session)
    if certificates is not None:
        fields.extend(
            certificate_fields(
                parse_certificate_list(certificates.raw),
                record_index=certificates.record_index,
                record_header_offset=certificates.record_header_offset,
                fragment_base=certificates.fragment_base,
                direction=certificates.direction,
            )
        )

    for direction, _records in _directions(session):
        sequences = None if record_sequences is None else record_sequences.get(direction)
        if sequences is not None:
            fields.append(record_seq_field(direction, sequences))
    return tuple(fields)


def session_notes(session: _TlsSession) -> List[dict]:
    """Why a field a caller expected is legitimately absent from this session.

    The same discipline as ``describe_capture``'s ``skipped`` list: an
    unexplained absence is indistinguishable from a bug to the person least able
    to tell the difference. Each entry is ``{"code", "detail"}`` -- machine
    readable first, human readable second.
    """
    notes: List[dict] = []
    client = _client_hello_location(session)
    if client is not None:
        layout = parse_hello_layout(client.raw, is_client=True)
        if layout.truncated:
            notes.append(truncated_hello_note("ClientHello"))
        # Asked of the LAYOUT, not of ``session_fields``: re-running the whole
        # extraction just to look for one field id would double the work of
        # ``describe_fields``, and the question ("did the ClientHello carry a
        # non-empty server_name list?") is answerable right here.
        if not _has_server_name(layout):
            notes.append(missing_sni_note())

    if session.version == "13":
        # Unconditional for TLS 1.3, and NOT contingent on having looked:
        # RFC 8446 encrypts the Certificate message, so no TLS 1.3 capture can
        # ever carry one. Saying so is the whole point -- an empty
        # ``certificate.0`` would imply a parse that failed.
        notes.append(tls13_certificate_note())
    elif _certificate_message_location(session) is None:
        notes.append(absent_certificate_note())
    return notes


def _has_server_name(layout) -> bool:
    """True when a hello layout carries a non-empty SNI host_name entry."""
    return any(
        ext_type == 0x0000 and parse_server_name_list(ext_data) is not None
        for ext_type, ext_data, _offset in layout.extensions
    )


def _client_hello_location(session: _TlsSession) -> Optional[_MessageLocation]:
    """The session's recorded ClientHello coordinate, re-derived if absent.

    The three ``_*_location`` helpers exist so the "use the cache, else walk the
    records" fallback is written once. That fallback is what makes
    :func:`session_fields` total for a ``_TlsSession`` built positionally --
    which existing tests and library callers do, and which leaves the new
    keyword-only slots at ``None``.
    """
    if session.client_hello is not None:
        return session.client_hello
    return _hello_location("client", session.client_records, _HS_CLIENT_HELLO)


def _server_hello_location(session: _TlsSession) -> Optional[_MessageLocation]:
    """The session's recorded ServerHello coordinate, re-derived if absent."""
    if session.server_hello is not None:
        return session.server_hello
    return _hello_location("server", session.server_records, _HS_SERVER_HELLO)


def _certificate_message_location(session: _TlsSession) -> Optional[_MessageLocation]:
    """The session's recorded Certificate coordinate, re-derived if absent.

    ``None`` means "this capture has no cleartext Certificate message" in both
    the cached and the re-derived case, which is why the caller turns it into a
    note rather than an error.
    """
    if session.certificates is not None:
        return session.certificates
    return _certificate_location("server", session.server_records)


def _cipher_name(cipher_code: int, version: str) -> str:
    """Resolve the IANA suite name for a code, or its ``str`` when unknown."""
    table = TLS13_CIPHER_SUITES if version == "13" else TLS12_CIPHER_SUITES
    suite = table.get(cipher_code)
    return suite.name if suite is not None else str(cipher_code)
