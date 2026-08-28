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
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from memdiver.core.install_hints import missing_package_message
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

_PCAP_MISSING = missing_package_message("dpkt (capture parsing)")

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


def _cipher_name(cipher_code: int, version: str) -> str:
    """Resolve the IANA suite name for a code, or its ``str`` when unknown."""
    table = TLS13_CIPHER_SUITES if version == "13" else TLS12_CIPHER_SUITES
    suite = table.get(cipher_code)
    return suite.name if suite is not None else str(cipher_code)
