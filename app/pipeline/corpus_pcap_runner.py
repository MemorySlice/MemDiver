"""Corpus-scale key proof: the orchestration half.

For each run this drives the run's OWN triple —
``(dumps, keylog.csv, run_data/traffic.pcap)`` — through four ordered steps:

1. read the run's keylog with a TYPED parse status (never a swallowed ``[]``);
2. **arm** the capture with :func:`app.tools_pipeline.inspect_pcap` BEFORE
   anything is spent, so an unsupported suite, a session-less capture or an
   empty challenge stream becomes a *reported* skip instead of an invisible one;
3. assert the keylog/capture ``client_random`` pairing LOUDLY
   (:func:`engine.corpus_proof.pairing_check`);
4. locate each secret with :func:`engine.corpus_proof.locate_secret` and prove
   it with :func:`app.tools_pipeline.brute_force` against that same capture.

It lives in ``app/`` and not in ``engine/`` for one reason: it calls
``app.tools_pipeline``, and ``engine`` may never import ``app`` (pinned by
``tests/test_architecture_invariants.py::test_engine_layer_never_imports_up_into_app``).
The data model, the aggregation and the rendering are all in the pure
:mod:`engine.corpus_proof`.

THE SETTINGS THAT ARE NOT NEGOTIABLE
------------------------------------
``stride=1``. A stride-4 grid is not a cheaper approximation, it is a wrong
answer: measured TLS 1.2 master-secret offsets include boringssl **113858**
(``≡ 2 mod 4``) and wolfssl **30933** (``≡ 1 mod 4``), both of which a stride-4
grid misses entirely — the run then ends "successfully" with zero hits and the
key is recorded as not surviving. Here the grid is a single window anyway (see
:func:`_confirm_secret`), so stride only has to be a divisor of nothing; it is
pinned at 1 so a future widening of the region cannot silently reintroduce the
bug.

``key_sizes`` is DERIVED from the secret's own length via
:func:`engine.corpus_proof.derive_key_sizes` — 48 for a TLS 1.2
``CLIENT_RANDOM`` master secret, 32 for the TLS 1.3 secrets. The oracle gates
on candidate length before it derives anything, so a hardcoded ``(32,)`` proves
nothing at all across the whole TLS 1.2 half of the corpus.

``max_runs_per_library`` defaults to :data:`DEFAULT_MAX_RUNS_PER_LIBRARY` (5).
A full-corpus pass is hours of work and has to be an explicit choice, not
something a caller trips over.

RE-ANALYSABLE WITHOUT RE-RUNNING
--------------------------------
:func:`write_outcomes` persists every run record to ``outcomes.json`` and
:func:`report_from_outcomes` rebuilds a report from it, so the markdown (or any
other view) can be regenerated from a finished sweep without touching a byte of
the corpus again. The totals are always recomputed from the rows.

WHAT KEYLOGS DO NOT CONTAIN
---------------------------
Keylogs never record post-KeyUpdate secrets — only ``*_TRAFFIC_SECRET_0``, in
1298/1298 TLS 1.3 runs of the measured corpus. A ``post_server_key_update``
dump therefore has NO GROUND TRUTH for the rotated key. There is nothing to
locate and nothing to prove, so no row is invented for it: this module only
ever proves secrets the keylog actually logged. That absence is *not observed*,
never a failed proof.
"""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from memdiver.core.corpus_axes import KEYLOG_FILENAME, axes_from_run_dir
from memdiver.core.discovery import RunDiscovery
from memdiver.core.keylog import KEYLOG_STATUS_MISSING, KEYLOG_STATUS_UNREADABLE
from memdiver.core.models import CryptoSecret, DumpFile, RunDirectory
from memdiver.core.phase_normalizer import PhaseNormalizer, parse_phase_timestamp
from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.engine.corpus_proof import (
    SKIP_CLIENT_RANDOM_MISMATCH,
    SKIP_NO_APP_RECORDS,
    SKIP_NO_CAPTURE,
    SKIP_NO_DUMPS,
    SKIP_NO_KEYLOG,
    SKIP_NO_TLS_SESSION,
    SKIP_ORACLE_NO_CHALLENGES,
    SKIP_PAIRING_MISMATCH,
    SKIP_SECRET_ABSENT,
    SKIP_UNREADABLE_CAPTURE,
    SKIP_UNSUPPORTED_SUITE,
    CaptureFacts,
    CorpusProofReport,
    LocatedSecret,
    RunProof,
    SecretProof,
    build_report,
    derive_key_sizes,
    locate_secret,
    pairing_check,
    render_markdown,
)
from memdiver.engine.truth_labels import keylog_secrets_for_run

logger = logging.getLogger("memdiver.app.pipeline.corpus_pcap_runner")

#: Runs per library a sweep touches unless the caller says otherwise. A full
#: 2,598-run pass is an EXPLICIT choice (``max_runs_per_library=0``), never a
#: default a caller can fall into.
DEFAULT_MAX_RUNS_PER_LIBRARY: int = 5

#: The candidate grid stride. See the module docstring: this is a correctness
#: constant, not a performance knob.
PROOF_STRIDE: int = 1

#: ``jobs=1`` keeps ``run_brute_force`` on its serial path. This function can
#: run inside a TaskManager worker process, and nesting a ProcessPool there
#: under macOS spawn is the documented failure mode
#: :mod:`app.pipeline.batch_task_runner` forces ``use_processes=False`` for.
#: The grid is one window per secret anyway, so there is nothing to parallelise.
PROOF_JOBS: int = 1

#: Filename of the re-analysable sweep record.
OUTCOMES_FILENAME: str = "outcomes.json"

#: Filename of the rendered report.
REPORT_FILENAME: str = "corpus_proof.md"

# Substrings of the ``PcapParseError`` messages ``brute_force`` funnels into a
# ``CapabilityError``. The oracle raises these EAGERLY from
# ``ResourceOracle.__init__`` when a pinned ``client_random`` finds no work, and
# a funnelled error carries no structured code, so this is the only seam
# available. Anything that does not match falls through to
# ``SKIP_UNREADABLE_CAPTURE`` WITH THE FULL MESSAGE in ``detail`` — an
# unrecognised failure is reported verbatim, never guessed at.
_ORACLE_ERROR_MARKERS: Tuple[Tuple[str, str], ...] = (
    ("matched the supplied client_random", SKIP_CLIENT_RANDOM_MISMATCH),
    ("no application-data records to verify", SKIP_ORACLE_NO_CHALLENGES),
    ("no complete TLS handshake", SKIP_NO_TLS_SESSION),
)


def _classify_oracle_error(message: str) -> Tuple[str, str]:
    """Map a funnelled oracle error to ``(skip_reason, detail)``."""
    for marker, reason in _ORACLE_ERROR_MARKERS:
        if marker in message:
            return reason, message
    return SKIP_UNREADABLE_CAPTURE, message


def _canonical_phases(run: RunDirectory) -> Dict[str, str]:
    """``raw full_phase -> canonical_phase`` for one run.

    The canonical label is what the report groups on: the RAW vocabulary is
    ragged per RUN (gotls TLS 1.3 alone has three distinct per-run sets), so raw
    phases cannot be compared across the corpus. A dump whose raw phase the
    normalizer did not map keeps its raw label, never a guessed canonical one.
    """
    return {
        raw: mapping.canonical_phase
        for raw, mapping in PhaseNormalizer().normalize_run(run).items()
    }


def _ordered_dumps(run: RunDirectory) -> List[DumpFile]:
    """This run's dumps in chronological order.

    :func:`core.phase_normalizer.parse_phase_timestamp` and not the raw
    timestamp string: ``core.discovery.DUMP_PATTERN`` allows a variable-width
    microsecond field, and a five-digit one sorts wrong as text. Chronological
    order makes "the first dump carrying this secret" a stable, meaningful
    answer rather than an artefact of ``sorted(iterdir())``.
    """
    return sorted(run.dumps, key=lambda d: parse_phase_timestamp(d.timestamp))


def _run_axes(run_dir: Path, run: RunDirectory) -> Dict[str, Any]:
    """Corpus axes for one run, degrading to the run directory's own facts."""
    axes = axes_from_run_dir(run_dir)
    if axes is None:
        return {
            "library": run.library,
            "protocol_version": run.protocol_version,
            "scenario": "",
            "run_number": run.run_number,
        }
    return {
        "library": axes.library,
        "protocol_version": axes.protocol_version,
        "scenario": axes.scenario,
        "run_number": axes.run_number,
    }


def _skip_all(
    secrets: Sequence[CryptoSecret],
    reason: str,
    detail: str,
    dumps_in_run: int,
) -> Tuple[SecretProof, ...]:
    """One typed row per keylog secret, all carrying the same run-level reason.

    A run-level failure must not collapse into a single row: the SECOND
    denominator counts secrets, so every secret the keylog declared has to stay
    in it with the reason it could not be proven.
    """
    return tuple(
        SecretProof(
            secret_type=s.secret_type,
            client_random=s.identifier.hex(),
            secret_len=len(s.secret_value),
            dumps_searched=dumps_in_run,
            skip_reason=reason,
            detail=detail,
        )
        for s in secrets
    )


def _arm_capture(
    capture_path: Path,
    *,
    pcap_max_records: Optional[int],
    pcap_max_challenges: Optional[int],
) -> Tuple[Optional[CaptureFacts], str, str]:
    """Arm the capture. Returns ``(facts, skip_reason, detail)``.

    ``inspect_pcap`` reads ``describe_capture`` — the reporting superset — so
    the caps in force, the sessions the parser DROPPED (with their reasons) and
    the challenge stream the oracle will actually see are all known before a
    single candidate is tested. ``describe_sessions`` reports none of that and
    is frozen for the web UI; using it here would let a 2,598-run aggregate
    silently understate itself.
    """
    from memdiver.app.tools_pipeline import inspect_pcap

    try:
        payload = inspect_pcap(
            pcap_path=str(capture_path),
            pcap_max_records=pcap_max_records,
            pcap_max_challenges=pcap_max_challenges,
        )
    except CapabilityError as exc:
        if exc.category is ErrorCategory.UNSUPPORTED:
            # dpkt is missing: nothing about this corpus can be proven, and
            # calling that a per-run skip would bury an environment problem in
            # 2,598 identical rows.
            raise
        return None, SKIP_UNREADABLE_CAPTURE, str(exc)

    facts = CaptureFacts.from_inspect(payload)
    if facts.session_count == 0:
        if facts.has_unsupported_suite:
            return facts, SKIP_UNSUPPORTED_SUITE, "cipher suite outside the verifier table"
        return facts, SKIP_NO_TLS_SESSION, "no complete TLS handshake in the capture"
    if not facts.has_app_records:
        return facts, SKIP_NO_APP_RECORDS, "no encrypted application-data records"
    if facts.challenges_returned == 0:
        return facts, SKIP_ORACLE_NO_CHALLENGES, "the oracle's challenge stream is empty"
    return facts, "", ""


def _confirm_secret(
    dump_path: str,
    offset: int,
    secret: CryptoSecret,
    capture_path: Path,
    output_dir: Path,
    *,
    pcap_max_records: Optional[int],
    pcap_max_challenges: Optional[int],
) -> Tuple[bool, str, str, str]:
    """Prove ONE located secret against the capture.

    Returns ``(confirmed, confirmed_by, skip_reason, detail)``.

    The candidate grid is a SINGLE window: the region is exactly
    ``[offset, offset + len(secret))`` and ``key_sizes`` is exactly that length,
    so ``iter_candidate_slices`` yields one candidate — the located bytes
    themselves. That is what makes a corpus-scale proof affordable at
    ``stride=1``: the expensive part of a brute force is the grid, and here the
    grid has already been collapsed by :func:`engine.corpus_proof.locate_secret`.

    ``tls_client_random`` pins the oracle to THIS secret's session, so a
    multi-session capture can never confirm a key against traffic it did not
    protect.
    """
    from memdiver.app.tools_pipeline import brute_force

    key_sizes = derive_key_sizes(secret.secret_value)
    candidates_path = output_dir / "candidates.json"
    candidates_path.write_text(json.dumps(
        {"regions": [{"offset": offset, "length": key_sizes[0]}]}))
    try:
        result = brute_force(
            candidates_path=str(candidates_path),
            reference_path=dump_path,
            output_dir=str(output_dir),
            pcap_path=str(capture_path),
            tls_client_random=secret.identifier.hex(),
            pcap_max_records=pcap_max_records,
            pcap_max_challenges=pcap_max_challenges,
            key_sizes=key_sizes,
            stride=PROOF_STRIDE,
            jobs=PROOF_JOBS,
        )
    except CapabilityError as exc:
        reason, detail = _classify_oracle_error(str(exc))
        return False, "", reason, detail

    hits: Sequence[Dict[str, Any]] = result.get("hits") or ()
    if not hits:
        return False, "", "", (
            "the located key did not decrypt this run's own capture"
            " (candidates_tested=" + str(result.get("candidates_tested", 0)) + ")")
    confirmed_by = str(hits[0].get("confirmed_by", ""))
    return True, confirmed_by, "", ""


def prove_run(
    run_dir: Path,
    *,
    keylog_filename: str = KEYLOG_FILENAME,
    work_dir: Optional[Path] = None,
    pcap_max_records: Optional[int] = None,
    pcap_max_challenges: Optional[int] = None,
    strict_pairing: bool = False,
    view: Optional[str] = None,
) -> RunProof:
    """Prove one run's keylog secrets against that run's OWN capture.

    Args:
        run_dir: The run directory holding the triple.
        keylog_filename: Overridable for a non-default corpus.
        work_dir: Scratch directory for the per-secret ``candidates.json`` /
            ``hits.json``. Defaults to ``run_dir`` is DELIBERATELY NOT done —
            a proof must never write into the corpus — so a caller that omits
            it gets a temporary directory.
        pcap_max_records / pcap_max_challenges: The two caps, passed to BOTH
            the arm step and the proof so the caps reported are the caps used.
        strict_pairing: Raise instead of recording a skip when the keylog and
            the capture share no ``client_random``. For a single deliberate run
            a broken triple is a PRECONDITION error the caller must see; in a
            sweep it is a typed row (see :data:`engine.corpus_proof.SKIP_PAIRING_MISMATCH`).
        view: Byte view forwarded to the locator; unset lets each source keep
            its own default.

    Returns:
        A :class:`engine.corpus_proof.RunProof`. It ALWAYS carries one
        :class:`engine.corpus_proof.SecretProof` per keylog secret, whatever
        went wrong — the only exception being an unreadable keylog, where the
        number of secrets is by definition unknown.

    Raises:
        CapabilityError: ``PRECONDITION`` when *strict_pairing* is set and the
            triple is broken; ``UNSUPPORTED`` when ``dpkt`` is not installed.
    """
    from memdiver.app.artifact_cache import reference_cache_scope

    run_dir = Path(run_dir)
    run = RunDiscovery.load_run_directory(
        run_dir, keylog_filename, extract_secrets=False)
    if run is None:
        raise CapabilityError(
            "not a corpus run directory: " + str(run_dir),
            category=ErrorCategory.INVALID_INPUT,
        )

    axes = _run_axes(run_dir, run)
    dumps = _ordered_dumps(run)
    capture_path = run.capture_path
    base: Dict[str, Any] = {
        "run_dir": str(run_dir),
        "dumps_in_run": len(dumps),
        "capture_path": "" if capture_path is None else str(capture_path),
        "capture_status": run.capture_status,
        **axes,
    }

    secrets, keylog_status = keylog_secrets_for_run(
        run_dir, keylog_filename=keylog_filename)
    if keylog_status in (KEYLOG_STATUS_MISSING, KEYLOG_STATUS_UNREADABLE):
        # No truth, therefore NO DENOMINATOR. This is the one shape with no
        # per-secret rows -- and the reason it is a run-level skip rather than
        # a zero: ``core.keylog`` swallows every exception and returns ``[]``.
        return RunProof(
            keylog_status=keylog_status, secrets_total=0,
            skip_reason=SKIP_NO_KEYLOG,
            detail="keylog status " + keylog_status, **base)

    base["keylog_status"] = keylog_status
    base["secrets_total"] = len(secrets)
    keylog_crs = tuple(sorted({s.identifier.hex() for s in secrets if s.identifier}))
    base["keylog_client_randoms"] = keylog_crs

    if capture_path is None or run.capture_status != "present":
        reason = (SKIP_NO_CAPTURE if run.capture_status == "absent"
                  else SKIP_UNREADABLE_CAPTURE)
        detail = "capture status " + run.capture_status
        return RunProof(
            skip_reason=reason, detail=detail,
            proofs=_skip_all(secrets, reason, detail, len(dumps)), **base)

    facts, arm_reason, arm_detail = _arm_capture(
        capture_path,
        pcap_max_records=pcap_max_records,
        pcap_max_challenges=pcap_max_challenges,
    )
    base["capture"] = facts
    if arm_reason or facts is None:
        reason = arm_reason or SKIP_UNREADABLE_CAPTURE
        return RunProof(
            skip_reason=reason, detail=arm_detail,
            proofs=_skip_all(secrets, reason, arm_detail, len(dumps)), **base)

    pairing = pairing_check(keylog_crs, facts.client_randoms)
    base["pairing_ok"] = pairing.ok
    base["pairing_detail"] = pairing.detail
    if not pairing.ok:
        # LOUD. A silently mis-paired directory turns into thousands of
        # zero-hit rows that read as "the key does not survive".
        logger.error(
            "%s: BROKEN TRIPLE -- %s. The capture does not belong to this run;"
            " no absence may be inferred from it.", run_dir, pairing.detail)
        if strict_pairing:
            raise CapabilityError(
                "run " + str(run_dir) + " is not paired with its capture: "
                + pairing.detail,
                category=ErrorCategory.PRECONDITION,
            )
        return RunProof(
            skip_reason=SKIP_PAIRING_MISMATCH, detail=pairing.detail,
            proofs=_skip_all(
                secrets, SKIP_PAIRING_MISMATCH, pairing.detail, len(dumps)),
            **base)

    canonical = _canonical_phases(run)
    session_crs = set(facts.client_randoms)
    proofs: List[SecretProof] = []
    with tempfile.TemporaryDirectory(prefix="memdiver-proof-") as tmp:
        out_root = Path(work_dir) if work_dir is not None else Path(tmp)
        out_root.mkdir(parents=True, exist_ok=True)
        # One reference-bytes cache per RUN, never per sweep: every secret in a
        # run tends to land in the same dump, so this collapses N reads of an
        # ~11 MB dump into one, while a sweep-wide scope would retain a blob per
        # dump across 18,917 of them.
        with reference_cache_scope():
            for index, secret in enumerate(secrets):
                proofs.append(_prove_secret(
                    secret, index, dumps, canonical, session_crs,
                    capture_path=capture_path, out_root=out_root,
                    pcap_max_records=pcap_max_records,
                    pcap_max_challenges=pcap_max_challenges,
                    view=view,
                ))
    return RunProof(proofs=tuple(proofs), **base)


def _prove_secret(
    secret: CryptoSecret,
    index: int,
    dumps: Sequence[DumpFile],
    canonical: Dict[str, str],
    session_crs: Set[str],
    *,
    capture_path: Path,
    out_root: Path,
    pcap_max_records: Optional[int],
    pcap_max_challenges: Optional[int],
    view: Optional[str],
) -> SecretProof:
    """Locate then prove ONE secret. Always returns a row, never ``None``."""
    client_random = secret.identifier.hex()
    cell: Dict[str, Any] = {
        "secret_type": secret.secret_type,
        "client_random": client_random,
        "secret_len": len(secret.secret_value),
        "dumps_searched": len(dumps),
    }
    if not secret.secret_value:
        # An empty needle is unsearchable, so no absence may be claimed for it.
        return SecretProof(
            skip_reason=SKIP_SECRET_ABSENT,
            detail="empty secret value; nothing was searched for", **cell)
    if client_random not in session_crs:
        return SecretProof(
            skip_reason=SKIP_CLIENT_RANDOM_MISMATCH,
            detail="client_random " + client_random
            + " names no session in this run's capture", **cell)
    if not dumps:
        # 33 corpus run directories hold zero dumps and 31 of those have a
        # complete keylog AND a non-empty capture. Claiming "absent" here would
        # be a positive claim over bytes that were never read.
        return SecretProof(
            skip_reason=SKIP_NO_DUMPS,
            detail="run directory holds no dumps; nothing was searched", **cell)

    located: Optional[LocatedSecret] = locate_secret(
        [d.path for d in dumps], secret.secret_value, view=view)
    if located is None:
        return SecretProof(
            skip_reason=SKIP_SECRET_ABSENT,
            detail="not present in any of this run's " + str(len(dumps))
            + " dump(s)", **cell)

    raw_phase = ""
    for dump in dumps:
        if str(dump.path) == located.dump_path:
            raw_phase = dump.full_phase
            break
    out_dir = out_root / ("secret_" + str(index))
    out_dir.mkdir(parents=True, exist_ok=True)
    confirmed, confirmed_by, skip_reason, detail = _confirm_secret(
        located.dump_path, located.offset, secret, capture_path, out_dir,
        pcap_max_records=pcap_max_records,
        pcap_max_challenges=pcap_max_challenges,
    )
    return SecretProof(
        located=True,
        first_offset=located.offset,
        dump_path=located.dump_path,
        raw_phase=raw_phase,
        canonical_phase=canonical.get(raw_phase, raw_phase),
        confirmed=confirmed,
        confirmed_by=confirmed_by,
        skip_reason=skip_reason,
        detail=detail,
        **cell)


def iter_run_dirs(
    root: Path,
    *,
    libraries: Optional[Sequence[str]] = None,
    protocol_versions: Optional[Sequence[str]] = None,
    max_runs_per_library: int = DEFAULT_MAX_RUNS_PER_LIBRARY,
) -> Iterator[Path]:
    """Yield corpus run directories, deterministically and bounded.

    Walks ``<root>/<protocol>/<scenario>/<library>/<run>`` and, per library
    directory, keeps the first *max_runs_per_library* runs BY RUN NUMBER (0 =
    all). Bounding per library rather than globally is what keeps a CI slice
    representative: a global cap would spend its whole budget inside the first
    library and report nothing about the other twelve.

    Directories that do not parse as corpus runs are skipped silently — this is
    an enumerator, not a validator; a run that parses but cannot be proven is
    :func:`prove_run`'s business, and it emits a typed row for it.
    """
    wanted_libraries = None if libraries is None else {lib for lib in libraries}
    wanted_versions = None if protocol_versions is None else {
        str(v) for v in protocol_versions}
    root = Path(root)
    if not root.is_dir():
        return
    for protocol_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        for scenario_dir in sorted(p for p in protocol_dir.iterdir() if p.is_dir()):
            for library_dir in sorted(p for p in scenario_dir.iterdir() if p.is_dir()):
                if wanted_libraries is not None and library_dir.name not in wanted_libraries:
                    continue
                candidates: List[Tuple[int, Path]] = []
                for entry in sorted(p for p in library_dir.iterdir() if p.is_dir()):
                    parsed = RunDiscovery.parse_run_dirname(entry.name)
                    if parsed is None:
                        continue
                    _library, version, run_number = parsed
                    if wanted_versions is not None and version not in wanted_versions:
                        continue
                    candidates.append((run_number, entry))
                candidates.sort(key=lambda pair: pair[0])
                if max_runs_per_library > 0:
                    candidates = candidates[:max_runs_per_library]
                for _run_number, entry in candidates:
                    yield entry


def sweep_corpus(
    root: Path,
    *,
    libraries: Optional[Sequence[str]] = None,
    protocol_versions: Optional[Sequence[str]] = None,
    max_runs_per_library: int = DEFAULT_MAX_RUNS_PER_LIBRARY,
    keylog_filename: str = KEYLOG_FILENAME,
    pcap_max_records: Optional[int] = None,
    pcap_max_challenges: Optional[int] = None,
    view: Optional[str] = None,
    on_run: Optional[Callable[[int, int, RunProof], None]] = None,
    is_cancelled: Optional[Callable[[], bool]] = None,
) -> CorpusProofReport:
    """Prove every selected run and fold the verdicts into a report.

    ``strict_pairing`` is deliberately NOT exposed here: in a sweep a broken
    triple is a typed row (and a ``logger.error``), because one mis-scanned
    directory must not abort a multi-hour pass over the other 2,597 runs.

    *on_run* — when given — is called as ``on_run(index, total_so_far, run_proof)``
    after each run, so a surface can report progress without this function
    importing any progress machinery. *is_cancelled* is polled between runs; a
    cancelled sweep returns the runs it DID complete rather than raising, which
    is what makes a partial sweep still worth its ``outcomes.json``.
    """
    runs: List[RunProof] = []
    for index, run_dir in enumerate(iter_run_dirs(
        root,
        libraries=libraries,
        protocol_versions=protocol_versions,
        max_runs_per_library=max_runs_per_library,
    )):
        if is_cancelled is not None and is_cancelled():
            logger.info("corpus proof cancelled after %d run(s)", len(runs))
            break
        proof = prove_run(
            run_dir,
            keylog_filename=keylog_filename,
            pcap_max_records=pcap_max_records,
            pcap_max_challenges=pcap_max_challenges,
            view=view,
        )
        runs.append(proof)
        if on_run is not None:
            on_run(index, len(runs), proof)
    return build_report(
        runs, root=str(root), max_runs_per_library=max_runs_per_library)


def write_outcomes(report: CorpusProofReport, path: Path) -> Path:
    """Persist a report as ``outcomes.json`` so it can be re-analysed.

    A full-corpus pass is hours of work; throwing away the rows and keeping
    only a rendered percentage would mean re-running the corpus to ask a second
    question of it.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_dict(), indent=2))
    return path


def report_from_outcomes(path: Path) -> CorpusProofReport:
    """Rebuild a report from an ``outcomes.json`` written by a previous sweep.

    The totals are recomputed from the rows (see
    :meth:`engine.corpus_proof.CorpusProofReport.from_dict`), so a stale or
    hand-edited aggregate cannot contradict the evidence it summarises.
    """
    return CorpusProofReport.from_dict(json.loads(Path(path).read_text()))


def run_corpus_proof(params: Dict[str, Any], ctx: Any) -> Dict[str, Any]:
    """TaskManager worker entry — the house ``run_batch(params, ctx)`` shape.

    Mirrors :func:`app.pipeline.batch_task_runner.run_batch`: a top-level
    picklable function, artifacts resolved through
    :func:`app.pipeline.artifact_paths.resolve_artifact_dir`, progress through
    ``ctx.emit``, and a ``{"artifacts", "summary"}`` return.

    ``params`` keys: ``root`` (required), ``libraries``, ``protocol_versions``,
    ``max_runs_per_library`` (default :data:`DEFAULT_MAX_RUNS_PER_LIBRARY`),
    ``keylog_filename``, ``pcap_max_records``, ``pcap_max_challenges``, plus the
    usual ``task_root`` / ``artifact_dir``.

    Writes two artifacts: ``outcomes.json`` (every row, re-analysable) and
    ``corpus_proof.md`` (the rendered report, ``## Not counted`` included).
    The summary carries BOTH denominators and never a single collapsed rate.
    """
    from memdiver.app.pipeline.artifact_paths import resolve_artifact_dir
    from memdiver.core.artifact_util import register_artifact

    artifact_dir = resolve_artifact_dir(params, ctx)
    root = params.get("root")
    if not root:
        raise ValueError("corpus proof params: 'root' is required")
    max_runs = int(params.get(
        "max_runs_per_library", DEFAULT_MAX_RUNS_PER_LIBRARY))

    ctx.emit("stage_start", stage="corpus_proof", pct=0.0,
             msg="proving runs under " + str(root))

    def _on_run(index: int, done: int, proof: RunProof) -> None:
        ctx.emit(
            "progress", stage="corpus_proof", pct=None,
            msg=proof.run_dir,
            extra={"completed": done, "confirmed": proof.confirmed,
                   "located": proof.located,
                   "skip_reason": proof.skip_reason},
        )

    report = sweep_corpus(
        Path(root),
        libraries=params.get("libraries"),
        protocol_versions=params.get("protocol_versions"),
        max_runs_per_library=max_runs,
        keylog_filename=params.get("keylog_filename", KEYLOG_FILENAME),
        pcap_max_records=params.get("pcap_max_records"),
        pcap_max_challenges=params.get("pcap_max_challenges"),
        on_run=_on_run,
        is_cancelled=getattr(ctx, "is_cancelled", None),
    )

    write_outcomes(report, artifact_dir / OUTCOMES_FILENAME)
    (artifact_dir / REPORT_FILENAME).write_text(render_markdown(report))

    artifacts: List[Dict[str, Any]] = []
    register_artifact(artifacts, artifact_dir, name="corpus_proof_outcomes",
                      relpath=OUTCOMES_FILENAME, media_type="application/json")
    register_artifact(artifacts, artifact_dir, name="corpus_proof_report",
                      relpath=REPORT_FILENAME, media_type="text/markdown")

    totals = report.totals
    summary: Dict[str, Any] = {
        "runs": totals.runs,
        "runs_with_capture": totals.runs_with_capture,
        "runs_paired": totals.runs_paired,
        "confirmed": totals.confirmed,
        "secrets_located": totals.secrets_located,
        "secrets_total": totals.secrets_total,
        # BOTH rates travel, always. There is no single "success rate" key by
        # design: the gap between these two IS the survival result.
        "rate_over_located": totals.rate_over_located,
        "rate_over_total": totals.rate_over_total,
        "not_counted": totals.bucket_counts,
        "max_runs_per_library": max_runs,
    }
    ctx.emit("stage_end", stage="corpus_proof", pct=1.0,
             msg=(str(totals.confirmed) + " confirmed / "
                  + str(totals.secrets_located) + " located / "
                  + str(totals.secrets_total) + " total"),
             extra=summary)
    return {"artifacts": artifacts, "summary": summary}


__all__ = [
    "DEFAULT_MAX_RUNS_PER_LIBRARY",
    "OUTCOMES_FILENAME",
    "PROOF_JOBS",
    "PROOF_STRIDE",
    "REPORT_FILENAME",
    "iter_run_dirs",
    "prove_run",
    "report_from_outcomes",
    "run_corpus_proof",
    "sweep_corpus",
    "write_outcomes",
]
