"""Corpus-scale key proof: the pure aggregation half.

WHAT THIS MODULE IS
-------------------
The survival sweep (:mod:`engine.survival_scan`) answers *"were the keylog's
bytes still in memory?"*. This module is the other half of the claim: *"and did
that recovered key actually decrypt the traffic THIS RUN captured?"* — the
end-to-end proof, per run, against the run's own
``run_data/traffic.pcap``.

It holds only the data model, the per-run locator and the aggregation +
rendering. Everything that spends time — arming a capture with ``inspect_pcap``
and confirming a key with ``brute_force`` — lives in
:mod:`app.pipeline.corpus_pcap_runner`, because those are ``app`` producers and
``engine`` may never import ``app`` (pinned by
``tests/test_architecture_invariants.py::test_engine_layer_never_imports_up_into_app``).

THE PER-RUN TRIPLE IS ATOMIC
----------------------------
A run's ``traffic.pcap`` only ever matches THAT RUN'S session. There is exactly
one TLS session per run in the measured corpus (tshark-verified on
libretls/openssl/matrixssl/mbedtls ``run_13_1``), so a capture from a different
run shares no ``client_random`` with this run's keylog.
:func:`pairing_check` asserts that intersection LOUDLY. Without it a
mis-scanned directory — one capture accidentally paired with 2,598 runs —
produces 2,598 zero-hit rows that read as *"the key does not survive"*. It is
:data:`SKIP_PAIRING_MISMATCH` in a sweep and a
:class:`core.service_errors.CapabilityError` (``PRECONDITION``) for a single
deliberate run.

EVERY FAILURE IS A TYPED ROW, NEVER A SILENT DROP
-------------------------------------------------
:data:`SKIP_REASONS` is the closed vocabulary. A run that cannot be proven
still emits one :class:`SecretProof` per keylog secret carrying the reason, so
``len(run.proofs) == run.secrets_total`` whenever the keylog was readable and
the denominator can never be deflated by a run quietly disappearing.

TWO DENOMINATORS, NEVER COLLAPSED
---------------------------------
:class:`ProofTotals` reports both and refuses to combine them:

* ``confirmed / secrets_located`` — "when the secret WAS in memory, how often
  did it decrypt its own capture". This is the *engine's* claim.
* ``confirmed / secrets_total`` — "of every secret the keylog says existed, how
  many were proven end to end". This is the *paper's* claim.

**The gap between them IS the survival result.** :func:`render_markdown`
therefore always ends with a mandatory ``## Not counted`` section listing every
:data:`SKIP_REASONS` member with its count and example run paths, plus the
:data:`BUCKET_NOT_CONFIRMED` bucket, so the difference between the numerator
and the corpus total is always on the page.

WHY ``describe_capture()`` AND NOT ``describe_sessions()``
----------------------------------------------------------
:class:`CaptureFacts` is built from the ``inspect_pcap`` payload, which reads
:meth:`engine.resources.tls_pcap.TlsPcapResource.describe_capture`. Three
silent-loss sites exist in the parse — ``max_records_per_direction=16``,
``max_challenges``, and ``_build_session`` returning ``None`` for an
out-of-table suite behind a bare ``logger.debug`` — and ``describe_sessions``
reports none of them. A 2,598-run number that silently understates is worse
than no number. ``describe_sessions`` stays frozen for the web UI;
``describe_capture`` is the reporting superset.

WHY THE PHASE AXIS IS CANONICAL
-------------------------------
The raw phase vocabulary is ragged **per run**, not merely per library, so raw
phases cannot be compared across the corpus. :attr:`SecretProof.canonical_phase`
carries the :class:`core.phase_normalizer.PhaseNormalizer` label and
:attr:`SecretProof.raw_phase` is retained beside it for traceability.

WHY THIS DOES NOT REUSE ``engine.survival_scan.scan_dump_unit``
---------------------------------------------------------------
That worker probes ONE dump and groups by ``secret_type``, keeping only the
first offset per type and discarding WHICH secret matched. The proof needs the
individual secret (its ``client_random`` pins the pcap session and its length
derives ``key_sizes``) and it needs the FIRST DUMP IN THE RUN that carries it.
The shapes do not fit, so :func:`locate_secret` here makes the same calls under
the same rules — :func:`core.dump_source.find_first_in`, never ``read_all()``
(absent from the ``DumpSource`` contract on gcore and the regioned sources) and
never :class:`core.dump_io.DumpReader` directly (``mmap.find`` defaults its
start to the CURRENT FILE POSITION).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from memdiver.core.dump_source import find_first_in, open_dump

logger = logging.getLogger("memdiver.engine.corpus_proof")

#: Version of the on-disk ``outcomes.json`` record shape. A sweep of the full
#: corpus takes hours; the runner writes its outcomes so a report can be
#: re-rendered without re-running, and this is what tells a reader whether the
#: file on disk means what the current code thinks it means. BUMP IT whenever a
#: field is added to, removed from, or re-interpreted in any dataclass here.
PROOF_RECORD_VERSION: int = 1

# -- the closed skip vocabulary -------------------------------------------- #
#
# Read these as "why this secret was not proven". They are ordered below the
# way :func:`app.pipeline.corpus_pcap_runner.prove_run` evaluates them, and
# that order is load-bearing: the cheapest, most-general reason wins, so a run
# with no capture is never also reported as a pairing mismatch.

#: The run has no ``run_data/traffic.pcap`` at all. There is nothing to prove
#: the key against; this is not evidence about the key.
SKIP_NO_CAPTURE = "no_capture"

#: A capture file exists but is zero-byte, un-stat-able, or not parseable as a
#: capture. Distinct from :data:`SKIP_NO_CAPTURE` so a truncated file never
#: deflates the corpus denominator as if it had never existed.
SKIP_UNREADABLE_CAPTURE = "unreadable_capture"

#: The run's ``keylog.csv`` is missing or unparseable, so there is no ground
#: truth and NO DENOMINATOR. ``core.keylog`` swallows every exception and
#: returns ``[]``; without this reason that zero is indistinguishable from a
#: session that genuinely logged nothing.
SKIP_NO_KEYLOG = "no_keylog"

#: The keylog's ``client_random`` set and the capture's share nothing. The
#: triple has been broken — some other run's capture is being scanned against
#: this run's keylog. LOUD by design; see the module docstring.
SKIP_PAIRING_MISMATCH = "pairing_mismatch"

#: The capture parsed but yielded no complete TLS handshake (no ClientHello +
#: ServerHello on one TCP connection).
SKIP_NO_TLS_SESSION = "no_tls_session"

#: A session was recovered but carries no encrypted application-data records,
#: so the oracle has nothing to decrypt. Parseable is not verifiable.
SKIP_NO_APP_RECORDS = "no_app_records"

#: The capture's cipher suite is outside the verifier's table, so
#: ``_build_session`` dropped the session. Reported rather than invisible: this
#: is the reason ``inspect_pcap``'s ``skipped_sessions`` is armed before any
#: brute force is spent.
SKIP_UNSUPPORTED_SUITE = "unsupported_suite"

#: The secret's verbatim keylog bytes were not found in ANY of the run's dumps.
#: The only reason here that is a genuine statement about the key.
SKIP_SECRET_ABSENT = "secret_absent"  # nosec B105 - a report label, not a credential

#: This particular secret's ``client_random`` names a session the capture does
#: not contain, even though the run as a whole paired. Per-secret sibling of
#: :data:`SKIP_PAIRING_MISMATCH`.
SKIP_CLIENT_RANDOM_MISMATCH = "client_random_mismatch"

#: The capture's session exists and has records, but the challenge stream the
#: oracle would see is empty after the TLS 1.2 ChangeCipherSpec gate and the
#: caps. Detected at arm time so nothing is spent proving against zero work.
SKIP_ORACLE_NO_CHALLENGES = "oracle_no_challenges"

#: The run directory holds ZERO dumps. DELIBERATE ADDITION to the plan's
#: ten-reason vocabulary, and the reason it is not folded into
#: :data:`SKIP_SECRET_ABSENT`: 33 run directories in the measured corpus contain
#: no ``.dump`` file at all and 31 of those carry a complete ``keylog.csv`` and
#: a non-empty ``traffic.pcap``. Calling their secrets "absent" would be a
#: positive claim of absence over bytes that were never searched — exactly the
#: failure this taxonomy exists to prevent — while dropping them would delete 31
#: runs from the denominator.
SKIP_NO_DUMPS = "no_dumps"

#: The closed vocabulary, in evaluation order.
SKIP_REASONS: Tuple[str, ...] = (
    SKIP_NO_KEYLOG,
    SKIP_NO_CAPTURE,
    SKIP_UNREADABLE_CAPTURE,
    SKIP_NO_TLS_SESSION,
    SKIP_UNSUPPORTED_SUITE,
    SKIP_NO_APP_RECORDS,
    SKIP_ORACLE_NO_CHALLENGES,
    SKIP_PAIRING_MISMATCH,
    SKIP_CLIENT_RANDOM_MISMATCH,
    SKIP_NO_DUMPS,
    SKIP_SECRET_ABSENT,
)

#: NOT a skip reason: the secret WAS located and the oracle WAS given real
#: challenges, and the key still did not decrypt. That is a result, not a
#: failure of the harness — and it is where ``_reassemble``'s documented
#: retransmission-naivety lands across thousands of real captures. It shares
#: the ``## Not counted`` table with the skip reasons because it too separates
#: the numerator from the corpus total, but it is labelled apart so the two are
#: never read as the same fact.
BUCKET_NOT_CONFIRMED = "not_confirmed"

#: Every bucket the ``## Not counted`` section renders, in table order.
NOT_COUNTED_BUCKETS: Tuple[str, ...] = SKIP_REASONS + (BUCKET_NOT_CONFIRMED,)

#: How many example run paths each ``## Not counted`` row carries.
MAX_EXAMPLES: int = 3


def derive_key_sizes(secret_value: bytes) -> Tuple[int, ...]:
    """The ``key_sizes`` grid for ONE secret: exactly its own length.

    DERIVED, never hardcoded. The pcap oracle gates on candidate length before
    it derives anything — 48 bytes for a TLS 1.2 ``CLIENT_RANDOM`` master
    secret, 32 for every TLS 1.3 traffic/handshake secret — so a hardcoded
    ``(32,)`` silently proves nothing at all on the whole TLS 1.2 half of the
    corpus.

    Raises:
        ValueError: for an empty secret. An empty needle cannot be located and
            must never be reported as absent (see
            ``engine.survival_scan._searchable_groups`` for the same rule).
    """
    if not secret_value:
        raise ValueError(
            "cannot derive key_sizes from an empty secret; an empty needle is"
            " unsearchable and no absence may be claimed for it")
    return (len(secret_value),)


@dataclass(frozen=True)
class PairingResult:
    """The verdict of the per-run triple assertion.

    ``ok`` is True only when the keylog and the capture share at least one
    ``client_random``. ``keylog_only`` / ``pcap_only`` are kept so a mismatch
    report can name both sides instead of just saying "no".
    """

    ok: bool
    shared: Tuple[str, ...] = ()
    keylog_only: Tuple[str, ...] = ()
    pcap_only: Tuple[str, ...] = ()

    @property
    def detail(self) -> str:
        """A one-line human explanation, safe to embed in a report."""
        if self.ok:
            return (
                str(len(self.shared)) + " shared client_random(s): "
                + ", ".join(self.shared))
        return (
            "keylog client_random(s) " + (", ".join(self.keylog_only) or "<none>")
            + " share nothing with capture client_random(s) "
            + (", ".join(self.pcap_only) or "<none>"))


def pairing_check(
    keylog_client_randoms: Iterable[str],
    pcap_client_randoms: Iterable[str],
) -> PairingResult:
    """Assert that a keylog and a capture describe the SAME session.

    Both sides are normalised to lowercase hex before comparison, because the
    keylog carries raw hex text and the capture carries ``bytes.hex()``.

    Verified exact and non-vacuous on the real corpus for openssl ``run_12_1``,
    openssl ``run_13_1`` and rustls ``run_13_7``: the two sets are EQUAL, as a
    singleton. So this is a genuine equality test on the corpus, not a
    permissive "any overlap" gesture — the weaker intersection rule is kept only
    so a future multi-session capture is not rejected outright.
    """
    left = {c.lower() for c in keylog_client_randoms if c}
    right = {c.lower() for c in pcap_client_randoms if c}
    shared = tuple(sorted(left & right))
    return PairingResult(
        ok=bool(shared),
        shared=shared,
        keylog_only=tuple(sorted(left - right)),
        pcap_only=tuple(sorted(right - left)),
    )


@dataclass(frozen=True)
class CaptureFacts:
    """Everything the arm step learned about one run's capture.

    Recorded for EVERY run, proven or not. That is the point: ``_reassemble``
    in :mod:`engine.resources.tls_pcap` is retransmission-naive by design, so
    across 2,598 real captures there will be non-confirmations no aggregate can
    explain. Each one has to carry its own capture's facts, or the reader is
    left guessing whether the key died or the parse did.

    Built from the :func:`app.tools_pipeline.inspect_pcap` payload, which reads
    ``describe_capture`` — never ``describe_sessions``.
    """

    session_count: int = 0
    flow_count: int = 0
    client_randoms: Tuple[str, ...] = ()
    cipher_names: Tuple[str, ...] = ()
    versions: Tuple[str, ...] = ()
    sessions_with_app_records: int = 0
    app_records_seen: int = 0
    records_returned: int = 0
    records_truncated: bool = False
    challenges_available: int = 0
    challenges_returned: int = 0
    challenges_truncated: bool = False
    skipped_reasons: Tuple[Tuple[str, int], ...] = ()
    max_records_per_direction: int = 0
    max_challenges: Optional[int] = None

    @property
    def has_app_records(self) -> bool:
        """True when at least one kept session carries application data."""
        return self.sessions_with_app_records > 0

    @property
    def has_unsupported_suite(self) -> bool:
        """True when the parser dropped a session for an out-of-table suite."""
        return any(
            reason == "unsupported_cipher_suite" and count > 0
            for reason, count in self.skipped_reasons
        )

    @classmethod
    def from_inspect(cls, payload: Mapping[str, Any]) -> "CaptureFacts":
        """Build from one :func:`app.tools_pipeline.inspect_pcap` result dict.

        Reads only keys that producer documents. ``app_records_seen`` /
        ``records_returned`` are the additive accounting keys ``describe_capture``
        adds to each session dict; they are absent from a plain
        ``describe_sessions`` dict, and default to 0 rather than raising so a
        caller that passed the frozen shape degrades visibly instead of
        crashing a multi-hour sweep.
        """
        sessions: Sequence[Mapping[str, Any]] = payload.get("sessions") or ()
        skipped: Sequence[Mapping[str, Any]] = payload.get("skipped_sessions") or ()
        reasons: Dict[str, int] = {}
        for entry in skipped:
            reason = str(entry.get("reason", "unknown"))
            reasons[reason] = reasons.get(reason, 0) + 1
        caps: Mapping[str, Any] = payload.get("caps") or {}
        max_challenges = caps.get("max_challenges")
        return cls(
            session_count=int(payload.get("session_count", len(sessions))),
            flow_count=int(payload.get("flow_count", 0)),
            client_randoms=tuple(
                str(s.get("client_random", "")).lower() for s in sessions),
            cipher_names=tuple(str(s.get("cipher_name", "")) for s in sessions),
            versions=tuple(str(s.get("version", "")) for s in sessions),
            sessions_with_app_records=sum(
                1 for s in sessions if s.get("has_app_records")),
            app_records_seen=sum(int(s.get("app_records_seen", 0)) for s in sessions),
            records_returned=sum(int(s.get("records_returned", 0)) for s in sessions),
            records_truncated=bool(payload.get("records_truncated", False)),
            challenges_available=int(payload.get("challenges_available", 0)),
            challenges_returned=int(payload.get("challenges_returned", 0)),
            challenges_truncated=bool(payload.get("challenges_truncated", False)),
            skipped_reasons=tuple(sorted(reasons.items())),
            max_records_per_direction=int(caps.get("max_records_per_direction", 0)),
            max_challenges=None if max_challenges is None else int(max_challenges),
        )

    def to_dict(self) -> Dict[str, Any]:
        """JSON-serialisable view (``outcomes.json``)."""
        return {
            "session_count": self.session_count,
            "flow_count": self.flow_count,
            "client_randoms": list(self.client_randoms),
            "cipher_names": list(self.cipher_names),
            "versions": list(self.versions),
            "sessions_with_app_records": self.sessions_with_app_records,
            "app_records_seen": self.app_records_seen,
            "records_returned": self.records_returned,
            "records_truncated": self.records_truncated,
            "challenges_available": self.challenges_available,
            "challenges_returned": self.challenges_returned,
            "challenges_truncated": self.challenges_truncated,
            "skipped_reasons": [list(pair) for pair in self.skipped_reasons],
            "max_records_per_direction": self.max_records_per_direction,
            "max_challenges": self.max_challenges,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "CaptureFacts":
        """Inverse of :meth:`to_dict`."""
        max_challenges = payload.get("max_challenges")
        return cls(
            session_count=int(payload.get("session_count", 0)),
            flow_count=int(payload.get("flow_count", 0)),
            client_randoms=tuple(payload.get("client_randoms") or ()),
            cipher_names=tuple(payload.get("cipher_names") or ()),
            versions=tuple(payload.get("versions") or ()),
            sessions_with_app_records=int(payload.get("sessions_with_app_records", 0)),
            app_records_seen=int(payload.get("app_records_seen", 0)),
            records_returned=int(payload.get("records_returned", 0)),
            records_truncated=bool(payload.get("records_truncated", False)),
            challenges_available=int(payload.get("challenges_available", 0)),
            challenges_returned=int(payload.get("challenges_returned", 0)),
            challenges_truncated=bool(payload.get("challenges_truncated", False)),
            skipped_reasons=tuple(
                (str(r), int(c)) for r, c in payload.get("skipped_reasons") or ()),
            max_records_per_direction=int(payload.get("max_records_per_direction", 0)),
            max_challenges=None if max_challenges is None else int(max_challenges),
        )


@dataclass(frozen=True)
class SecretProof:
    """One ``(run, keylog secret)`` cell — the grain of both denominators.

    ``located`` feeds ``secrets_located``; ``confirmed`` feeds the numerator.
    A row is never dropped: when it cannot be proven it carries a
    :data:`SKIP_REASONS` member instead, so the two denominators stay
    reconcilable by construction (see :meth:`ProofTotals.reconciles`).

    ``raw_phase`` and ``canonical_phase`` both travel — canonical because the
    raw vocabulary is ragged per run and cannot be compared across the corpus,
    raw because a canonical label is derived positionally and a reader
    auditing one cell needs the filename it came from.
    """

    secret_type: str = ""
    client_random: str = ""
    secret_len: int = 0
    located: bool = False
    first_offset: Optional[int] = None
    dump_path: str = ""
    raw_phase: str = ""
    canonical_phase: str = ""
    dumps_searched: int = 0
    confirmed: bool = False
    confirmed_by: str = ""
    skip_reason: str = ""
    detail: str = ""

    def __post_init__(self) -> None:
        """Reject shapes no consumer could interpret.

        ``ValueError`` and not :class:`core.service_errors.CapabilityError`:
        every guard here catches a WRITER bug, not caller input.
        """
        if self.skip_reason and self.skip_reason not in SKIP_REASONS:
            raise ValueError(
                "unknown skip_reason " + repr(self.skip_reason) + "; expected"
                " one of " + ", ".join(repr(r) for r in SKIP_REASONS))
        if self.located != (self.first_offset is not None):
            raise ValueError(
                "located " + repr(self.located) + " contradicts first_offset "
                + repr(self.first_offset) + " for " + repr(self.secret_type))
        if self.confirmed and not self.located:
            raise ValueError(
                "a confirmed secret must also be located: " + repr(self.secret_type))
        if self.confirmed and self.skip_reason:
            raise ValueError(
                "a confirmed secret cannot carry skip_reason "
                + repr(self.skip_reason) + " for " + repr(self.secret_type))
        if self.confirmed and not self.confirmed_by:
            raise ValueError(
                "a confirmed secret must name its confirming oracle: "
                + repr(self.secret_type))

    @property
    def bucket(self) -> str:
        """Which ``## Not counted`` row this cell falls in, or ``""``.

        A confirmed cell belongs to no bucket — it is the numerator.
        """
        if self.confirmed:
            return ""
        return self.skip_reason or BUCKET_NOT_CONFIRMED

    def to_dict(self) -> Dict[str, Any]:
        """JSON-serialisable view (``outcomes.json``)."""
        return {
            "secret_type": self.secret_type,
            "client_random": self.client_random,
            "secret_len": self.secret_len,
            "located": self.located,
            "first_offset": self.first_offset,
            "dump_path": self.dump_path,
            "raw_phase": self.raw_phase,
            "canonical_phase": self.canonical_phase,
            "dumps_searched": self.dumps_searched,
            "confirmed": self.confirmed,
            "confirmed_by": self.confirmed_by,
            "skip_reason": self.skip_reason,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "SecretProof":
        """Inverse of :meth:`to_dict`."""
        offset = payload.get("first_offset")
        return cls(
            secret_type=str(payload.get("secret_type", "")),
            client_random=str(payload.get("client_random", "")),
            secret_len=int(payload.get("secret_len", 0)),
            located=bool(payload.get("located", False)),
            first_offset=None if offset is None else int(offset),
            dump_path=str(payload.get("dump_path", "")),
            raw_phase=str(payload.get("raw_phase", "")),
            canonical_phase=str(payload.get("canonical_phase", "")),
            dumps_searched=int(payload.get("dumps_searched", 0)),
            confirmed=bool(payload.get("confirmed", False)),
            confirmed_by=str(payload.get("confirmed_by", "")),
            skip_reason=str(payload.get("skip_reason", "")),
            detail=str(payload.get("detail", "")),
        )


@dataclass(frozen=True)
class RunProof:
    """One run's whole verdict — its triple, its capture facts, its cells.

    ``secrets_total`` is the SECOND denominator's per-run contribution: every
    secret the keylog said existed, whether or not anything could be done with
    it. It is 0 only when the keylog itself could not be read
    (:data:`SKIP_NO_KEYLOG`), which is precisely the case where the denominator
    is unknown rather than zero.
    """

    run_dir: str = ""
    library: str = ""
    protocol_version: str = ""
    scenario: str = ""
    run_number: int = 0
    keylog_status: str = ""
    secrets_total: int = 0
    dumps_in_run: int = 0
    capture_path: str = ""
    capture_status: str = "absent"
    capture: Optional[CaptureFacts] = None
    keylog_client_randoms: Tuple[str, ...] = ()
    pairing_ok: bool = False
    pairing_detail: str = ""
    skip_reason: str = ""
    detail: str = ""
    proofs: Tuple[SecretProof, ...] = ()

    def __post_init__(self) -> None:
        if self.skip_reason and self.skip_reason not in SKIP_REASONS:
            raise ValueError(
                "unknown run skip_reason " + repr(self.skip_reason))
        if self.skip_reason != SKIP_NO_KEYLOG and len(self.proofs) != self.secrets_total:
            raise ValueError(
                "run " + repr(self.run_dir) + " has " + str(len(self.proofs))
                + " proof row(s) for " + str(self.secrets_total) + " keylog"
                " secret(s); every secret must carry a row so the denominator"
                " cannot be deflated by a silent drop")

    @property
    def confirmed(self) -> int:
        """Cells proven end to end against this run's own capture."""
        return sum(1 for p in self.proofs if p.confirmed)

    @property
    def located(self) -> int:
        """Cells whose keylog bytes were found in one of this run's dumps."""
        return sum(1 for p in self.proofs if p.located)

    def to_dict(self) -> Dict[str, Any]:
        """JSON-serialisable view — one ``outcomes.json`` run record."""
        return {
            "run_dir": self.run_dir,
            "library": self.library,
            "protocol_version": self.protocol_version,
            "scenario": self.scenario,
            "run_number": self.run_number,
            "keylog_status": self.keylog_status,
            "secrets_total": self.secrets_total,
            "dumps_in_run": self.dumps_in_run,
            "capture_path": self.capture_path,
            "capture_status": self.capture_status,
            "capture": None if self.capture is None else self.capture.to_dict(),
            "keylog_client_randoms": list(self.keylog_client_randoms),
            "pairing_ok": self.pairing_ok,
            "pairing_detail": self.pairing_detail,
            "skip_reason": self.skip_reason,
            "detail": self.detail,
            "proofs": [p.to_dict() for p in self.proofs],
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "RunProof":
        """Inverse of :meth:`to_dict`."""
        capture = payload.get("capture")
        return cls(
            run_dir=str(payload.get("run_dir", "")),
            library=str(payload.get("library", "")),
            protocol_version=str(payload.get("protocol_version", "")),
            scenario=str(payload.get("scenario", "")),
            run_number=int(payload.get("run_number", 0)),
            keylog_status=str(payload.get("keylog_status", "")),
            secrets_total=int(payload.get("secrets_total", 0)),
            dumps_in_run=int(payload.get("dumps_in_run", 0)),
            capture_path=str(payload.get("capture_path", "")),
            capture_status=str(payload.get("capture_status", "absent")),
            capture=None if capture is None else CaptureFacts.from_dict(capture),
            keylog_client_randoms=tuple(payload.get("keylog_client_randoms") or ()),
            pairing_ok=bool(payload.get("pairing_ok", False)),
            pairing_detail=str(payload.get("pairing_detail", "")),
            skip_reason=str(payload.get("skip_reason", "")),
            detail=str(payload.get("detail", "")),
            proofs=tuple(
                SecretProof.from_dict(p) for p in payload.get("proofs") or ()),
        )


@dataclass(frozen=True)
class ProofTotals:
    """The aggregate — and the ONE place the two denominators are kept apart.

    :attr:`rate_over_located` and :attr:`rate_over_total` are separate
    properties returning ``Optional[float]``; there is deliberately no single
    "success rate" attribute, because the only way to collapse the two is to
    pick one and hide the other, and the gap between them IS the survival
    result this whole phase exists to measure.
    """

    runs: int = 0
    runs_with_capture: int = 0
    runs_paired: int = 0
    secrets_total: int = 0
    secrets_located: int = 0
    confirmed: int = 0
    buckets: Tuple[Tuple[str, int], ...] = ()
    run_buckets: Tuple[Tuple[str, int], ...] = ()
    examples: Tuple[Tuple[str, Tuple[str, ...]], ...] = ()

    def __post_init__(self) -> None:
        if not self.confirmed <= self.secrets_located <= self.secrets_total:
            raise ValueError(
                "denominator invariant violated: confirmed " + str(self.confirmed)
                + " <= secrets_located " + str(self.secrets_located)
                + " <= secrets_total " + str(self.secrets_total))

    @property
    def bucket_counts(self) -> Dict[str, int]:
        """Bucket -> secret count, for every bucket including the zeros."""
        counts = dict.fromkeys(NOT_COUNTED_BUCKETS, 0)
        counts.update(dict(self.buckets))
        return counts

    @property
    def run_bucket_counts(self) -> Dict[str, int]:
        """Bucket -> RUN count. A run-level reason hits every secret in the
        run, so the secret count alone would over-state how much of the corpus
        the reason actually touched."""
        counts = dict.fromkeys(NOT_COUNTED_BUCKETS, 0)
        counts.update(dict(self.run_buckets))
        return counts

    @property
    def example_paths(self) -> Dict[str, Tuple[str, ...]]:
        """Bucket -> up to :data:`MAX_EXAMPLES` run paths."""
        return dict(self.examples)

    @property
    def not_counted(self) -> int:
        """Secrets in the denominator that were not proven."""
        return self.secrets_total - self.confirmed

    @property
    def rate_over_located(self) -> Optional[float]:
        """THE ENGINE'S CLAIM: ``confirmed / secrets_located``.

        "When the secret was in memory, how often did it decrypt its own
        capture." ``None`` — never ``0.0`` — when nothing was located, because
        a rate over an empty denominator is not zero, it is undefined.
        """
        if self.secrets_located <= 0:
            return None
        return self.confirmed / self.secrets_located

    @property
    def rate_over_total(self) -> Optional[float]:
        """THE PAPER'S CLAIM: ``confirmed / secrets_total``.

        "Of every secret the keylog says existed, how many were proven end to
        end." ``None`` when the corpus yielded no readable keylog at all.
        """
        if self.secrets_total <= 0:
            return None
        return self.confirmed / self.secrets_total

    def reconciles(self) -> bool:
        """``secrets_total == confirmed + sum(every bucket)``.

        The arithmetic guarantee behind the ``## Not counted`` section: if this
        holds, the page accounts for every secret in the denominator.
        """
        return self.secrets_total == self.confirmed + sum(
            self.bucket_counts.values())

    def to_dict(self) -> Dict[str, Any]:
        """JSON-serialisable view (``outcomes.json``)."""
        return {
            "runs": self.runs,
            "runs_with_capture": self.runs_with_capture,
            "runs_paired": self.runs_paired,
            "secrets_total": self.secrets_total,
            "secrets_located": self.secrets_located,
            "confirmed": self.confirmed,
            "buckets": [list(pair) for pair in self.buckets],
            "run_buckets": [list(pair) for pair in self.run_buckets],
            "examples": [[name, list(paths)] for name, paths in self.examples],
            "rate_over_located": self.rate_over_located,
            "rate_over_total": self.rate_over_total,
        }


@dataclass(frozen=True)
class CorpusProofReport:
    """A whole sweep: what was asked for, what happened, and the aggregate.

    Serialised to ``outcomes.json`` by
    :mod:`app.pipeline.corpus_pcap_runner` so a multi-hour sweep can be
    re-rendered — or re-analysed under a different presentation — without
    re-running a byte of it.
    """

    record_version: int = PROOF_RECORD_VERSION
    root: str = ""
    max_runs_per_library: int = 0
    runs: Tuple[RunProof, ...] = ()
    totals: ProofTotals = field(default_factory=ProofTotals)

    def to_dict(self) -> Dict[str, Any]:
        """JSON-serialisable view — the whole ``outcomes.json`` payload."""
        return {
            "record_version": self.record_version,
            "root": self.root,
            "max_runs_per_library": self.max_runs_per_library,
            "runs": [r.to_dict() for r in self.runs],
            "totals": self.totals.to_dict(),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "CorpusProofReport":
        """Rebuild a report from ``outcomes.json``.

        The totals are RECOMPUTED from the run records rather than trusted from
        the file: the rows are the evidence, the aggregate is a view of them,
        and a hand-edited (or older-version) totals block must never be able to
        contradict the rows it claims to summarise.
        """
        runs = tuple(RunProof.from_dict(r) for r in payload.get("runs") or ())
        return cls(
            record_version=int(payload.get("record_version", 0)),
            root=str(payload.get("root", "")),
            max_runs_per_library=int(payload.get("max_runs_per_library", 0)),
            runs=runs,
            totals=aggregate(runs),
        )


def aggregate(runs: Sequence[RunProof]) -> ProofTotals:
    """Fold run verdicts into the two denominators and the bucket table.

    Every non-confirmed cell lands in exactly one bucket, so
    :meth:`ProofTotals.reconciles` holds by construction. A run whose keylog
    could not be read contributes no secrets but IS counted under
    :data:`SKIP_NO_KEYLOG` in ``run_buckets``, which is how 31 dumpless-yet-
    complete runs (and any unreadable keylog) stay visible instead of vanishing.
    """
    buckets: Dict[str, int] = {}
    run_buckets: Dict[str, int] = {}
    examples: Dict[str, List[str]] = {}

    def note(bucket: str, run_dir: str) -> None:
        paths = examples.setdefault(bucket, [])
        if run_dir and run_dir not in paths and len(paths) < MAX_EXAMPLES:
            paths.append(run_dir)

    secrets_total = 0
    secrets_located = 0
    confirmed = 0
    runs_with_capture = 0
    runs_paired = 0
    for run in runs:
        secrets_total += run.secrets_total
        secrets_located += run.located
        confirmed += run.confirmed
        if run.capture_status == "present":
            runs_with_capture += 1
        if run.pairing_ok:
            runs_paired += 1
        run_seen: set = set()
        for proof in run.proofs:
            bucket = proof.bucket
            if not bucket:
                continue
            buckets[bucket] = buckets.get(bucket, 0) + 1
            note(bucket, run.run_dir)
            run_seen.add(bucket)
        if run.skip_reason == SKIP_NO_KEYLOG:
            # No secrets, therefore no cells — but the run must not vanish.
            run_seen.add(SKIP_NO_KEYLOG)
            note(SKIP_NO_KEYLOG, run.run_dir)
        for bucket in run_seen:
            run_buckets[bucket] = run_buckets.get(bucket, 0) + 1

    return ProofTotals(
        runs=len(runs),
        runs_with_capture=runs_with_capture,
        runs_paired=runs_paired,
        secrets_total=secrets_total,
        secrets_located=secrets_located,
        confirmed=confirmed,
        buckets=tuple(sorted(buckets.items())),
        run_buckets=tuple(sorted(run_buckets.items())),
        examples=tuple(
            (name, tuple(paths)) for name, paths in sorted(examples.items())),
    )


def build_report(
    runs: Sequence[RunProof],
    *,
    root: str = "",
    max_runs_per_library: int = 0,
) -> CorpusProofReport:
    """Wrap run verdicts with their freshly-computed aggregate."""
    ordered = tuple(runs)
    return CorpusProofReport(
        root=root,
        max_runs_per_library=max_runs_per_library,
        runs=ordered,
        totals=aggregate(ordered),
    )


@dataclass(frozen=True)
class LocatedSecret:
    """Where a secret's verbatim bytes were first found inside a run."""

    dump_path: str
    offset: int


def locate_secret(
    dump_paths: Sequence[Path],
    needle: bytes,
    *,
    view: Optional[str] = None,
) -> Optional[LocatedSecret]:
    """First dump in *dump_paths* containing *needle*, or ``None``.

    ONE :func:`core.dump_source.find_first_in` per dump, stopping at the first
    hit: this is a presence probe feeding a proof, not an occurrence census.

    Why these calls and no others (the same rules
    :mod:`engine.survival_scan` documents at length):

    * ``find_first_in``, never ``source.read_all().find(...)``. ``read_all`` is
      NOT part of the :class:`core.dump_source.DumpSource` contract — the gcore
      and regioned-raw sources omit it deliberately — so a ``read_all``-based
      locator crashes on exactly the sources a mixed corpus would introduce,
      and materialises up to 85 MB per dump on the ones where it works.
    * Never :class:`core.dump_io.DumpReader` directly: ``mmap.find(sub)``
      defaults its start to the mapping's CURRENT FILE POSITION, which reports
      a present secret as absent (measured on a real corpus dump at offset
      585148). Only :func:`core.dump_io.find_first_offset` handles that, and
      ``find_first_in`` routes through it.
    * *view* is forwarded only when supplied, so every source keeps its own
      default (``"raw"`` for :class:`core.dump_source.RawDumpSource`, ``"vas"``
      for ``MslDumpSource``); passing ``"raw"`` blindly would silently switch an
      ``.msl`` from its VAS projection to container bytes.

    An unreadable dump is logged and skipped rather than raised: one bad file
    in a 2,598-run sweep must not claim the secret is absent, and must not kill
    the sweep either. The caller distinguishes the two through the run's own
    :attr:`RunProof.dumps_in_run`.

    Raises:
        ValueError: for an empty needle — unsearchable, and no absence may be
            claimed for it.
    """
    if not needle:
        raise ValueError(
            "cannot locate an empty secret; no absence may be claimed for it")
    for dump_path in dump_paths:
        try:
            with open_dump(Path(dump_path)) as source:
                offset = find_first_in(source, needle, view=view)
        except (OSError, ValueError) as exc:
            logger.warning(
                "%s: unreadable while locating a secret (%s); skipping this"
                " dump, claiming nothing about the secret.", dump_path, exc)
            continue
        if offset is not None:
            return LocatedSecret(dump_path=str(dump_path), offset=offset)
    return None


# -- rendering ------------------------------------------------------------- #


def _pct(value: Optional[float]) -> str:
    """Render a rate as a percentage, or ``n/a`` for an undefined one."""
    return "n/a" if value is None else "{:.1f}%".format(100.0 * value)


def render_markdown(report: CorpusProofReport) -> str:
    """Render a report, ending in the MANDATORY ``## Not counted`` section.

    The two denominators are printed as two separate rows with their two
    separate meanings spelled out, and the section that follows accounts for
    every secret between the numerator and the corpus total. That section is
    emitted unconditionally and lists EVERY bucket — the zeros included — so a
    reader can see which failure modes did not occur rather than having to
    infer it from an absence.
    """
    totals = report.totals
    lines: List[str] = []
    lines.append("# Corpus key proof")
    lines.append("")
    lines.append(
        "Each run was proven against ITS OWN `run_data/traffic.pcap`; the"
        " keylog/capture `client_random` pairing was asserted per run.")
    lines.append("")
    lines.append("- root: `" + (report.root or "<unset>") + "`")
    lines.append(
        "- max_runs_per_library: "
        + ("all" if report.max_runs_per_library <= 0
           else str(report.max_runs_per_library)))
    lines.append("- record_version: " + str(report.record_version))
    lines.append("")
    lines.append("## Result")
    lines.append("")
    lines.append("| measure | value | meaning |")
    lines.append("| --- | --- | --- |")
    lines.append(
        "| runs | " + str(totals.runs)
        + " | run directories examined |")
    lines.append(
        "| runs with a capture | " + str(totals.runs_with_capture)
        + " | had a readable `traffic.pcap` |")
    lines.append(
        "| runs paired | " + str(totals.runs_paired)
        + " | keylog and capture share a `client_random` |")
    lines.append(
        "| confirmed | " + str(totals.confirmed)
        + " | keys proven to decrypt their own capture |")
    lines.append(
        "| secrets located | " + str(totals.secrets_located)
        + " | keylog bytes found in one of the run's dumps |")
    lines.append(
        "| secrets total | " + str(totals.secrets_total)
        + " | every secret the keylogs say existed |")
    lines.append("")
    lines.append("**Two denominators. They are not interchangeable.**")
    lines.append("")
    lines.append("| rate | value | claim |")
    lines.append("| --- | --- | --- |")
    lines.append(
        "| confirmed / secrets_located | " + _pct(totals.rate_over_located)
        + " | when the secret was in memory, how often it decrypted its own"
          " capture (the engine's claim) |")
    lines.append(
        "| confirmed / secrets_total | " + _pct(totals.rate_over_total)
        + " | of every secret the keylog says existed, how many were proven"
          " end to end (the paper's claim) |")
    lines.append("")
    lines.append(
        "The gap between those two rows is the survival result. Do not collapse"
        " them into one number.")
    lines.append("")
    lines.extend(_render_not_counted(totals))
    return "\n".join(lines) + "\n"


def _render_not_counted(totals: ProofTotals) -> List[str]:
    """The mandatory ``## Not counted`` section.

    Every bucket, its secret count, how many RUNS it touched, and up to
    :data:`MAX_EXAMPLES` example run paths — so the difference between the
    numerator and the corpus total is always on the page and always traceable
    back to real directories on disk.
    """
    counts = totals.bucket_counts
    run_counts = totals.run_bucket_counts
    examples = totals.example_paths
    lines: List[str] = ["## Not counted", ""]
    lines.append(
        "`secrets_total` (" + str(totals.secrets_total) + ") = `confirmed` ("
        + str(totals.confirmed) + ") + the rows below (" + str(totals.not_counted)
        + ").")
    if not totals.reconciles():
        lines.append("")
        lines.append(
            "> **WARNING** the rows below do NOT reconcile with the"
            " denominator; treat every number on this page as unproven.")
    lines.append("")
    lines.append("| reason | secrets | runs | examples |")
    lines.append("| --- | ---: | ---: | --- |")
    for bucket in NOT_COUNTED_BUCKETS:
        paths = examples.get(bucket, ())
        lines.append(
            "| `" + bucket + "` | " + str(counts.get(bucket, 0)) + " | "
            + str(run_counts.get(bucket, 0)) + " | "
            + (", ".join("`" + p + "`" for p in paths) or "—") + " |")
    lines.append("")
    lines.append(
        "`" + BUCKET_NOT_CONFIRMED + "` is not a skip: those secrets WERE"
        " located and the oracle WAS given real challenges, and the key still"
        " did not decrypt. `engine.resources.tls_pcap._reassemble` is"
        " retransmission-naive by design, and TLS 1.3 exporter/resumption"
        " secrets protect no application data at all — each such row carries"
        " its own capture's facts in `outcomes.json`.")
    return lines


__all__ = [
    "BUCKET_NOT_CONFIRMED",
    "MAX_EXAMPLES",
    "NOT_COUNTED_BUCKETS",
    "PROOF_RECORD_VERSION",
    "SKIP_CLIENT_RANDOM_MISMATCH",
    "SKIP_NO_APP_RECORDS",
    "SKIP_NO_CAPTURE",
    "SKIP_NO_DUMPS",
    "SKIP_NO_KEYLOG",
    "SKIP_NO_TLS_SESSION",
    "SKIP_ORACLE_NO_CHALLENGES",
    "SKIP_PAIRING_MISMATCH",
    "SKIP_REASONS",
    "SKIP_SECRET_ABSENT",
    "SKIP_UNREADABLE_CAPTURE",
    "SKIP_UNSUPPORTED_SUITE",
    "CaptureFacts",
    "CorpusProofReport",
    "LocatedSecret",
    "PairingResult",
    "ProofTotals",
    "RunProof",
    "SecretProof",
    "aggregate",
    "build_report",
    "derive_key_sizes",
    "locate_secret",
    "pairing_check",
    "render_markdown",
]
