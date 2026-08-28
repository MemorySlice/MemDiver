"""AnalysisPipeline - orchestrate the analysis workflow."""

import logging
from pathlib import Path
from typing import Dict, List, Optional

from memdiver.core.discovery import RunDiscovery
from memdiver.core.input_schemas import AnalyzeRequest
from memdiver.core.keylog import KeylogParser
from memdiver.core.keylog_templates import get_template
from memdiver.core.models import CryptoSecret
from memdiver.core.phase_normalizer import PhaseNormalizer
from .consensus import ConsensusVector
from .correlator import SearchCorrelator
from .derived_keys import DerivedKeyExpander
from .diff_store import DiffStore
from .results import AnalysisResult, LibraryReport, SecretHit

try:
    from .project_db import METHOD_CONSENSUS_SEARCH, ProjectDB, _finding_row_from_hit
    _HAS_PROJECT_DB = True
except ImportError:
    _HAS_PROJECT_DB = False
    METHOD_CONSENSUS_SEARCH = "consensus_search"

logger = logging.getLogger("memdiver.engine.pipeline")

#: What a run whose path does not conform to the corpus layout resolves to.
#: Every value is the DEFAULT of the column it lands in (see
#: ``engine.project_db._ADDED_COLUMNS``) AND of the matching
#: :class:`engine.results.LibraryReport` field, so an ad-hoc directory keeps
#: persisting exactly what it persisted before the axes existed. Named once
#: here because two places need it: the resolver below and the check that
#: decides whether a report was ever stamped.
_AXIS_FALLBACK = {
    "library_version": "unknown",
    "version_axis": "protocol_version",
    "scenario": "",
    "protocol": "",
}


def _resolve_dump(run, phase: str, normalize: bool):
    """Get the dump for *phase*, falling back to canonical matching."""
    dump = run.get_dump_for_phase(phase)
    if dump is None and normalize:
        dump = next((d for d in run.dumps if d.canonical_or_raw == phase), None)
    return dump


class AnalysisPipeline:
    """Orchestrate the full analysis workflow.

    Flow: Load dumps -> Build ConsensusVector -> Expand derived keys
    -> Search (mmap) -> Feed DiffStore (Polars) -> Package results.
    """

    def __init__(self, project_db=None, auto_persist: bool = True):
        self.consensus = ConsensusVector()
        self.correlator = SearchCorrelator()
        self.expander = DerivedKeyExpander()
        self.diff_store = DiffStore()
        self._normalizer = PhaseNormalizer()
        self._project_db = project_db
        self._auto_persist = auto_persist

    def analyze_library(
        self,
        library_dir: Path,
        phase: str,
        protocol_version: str,
        keylog_filename: str = "keylog.csv",
        max_runs: int = 10,
        expand_keys: bool = True,
        template=None,
        normalize: bool = False,
        algorithms: Optional[List[str]] = None,
        align_candidates: bool = False,
        verify_decryption: bool = False,
    ) -> LibraryReport:
        """Run full analysis on one library at one phase."""
        runs = RunDiscovery.discover_library_runs(
            library_dir, max_runs=max_runs,
            keylog_filename=keylog_filename, template=template,
        )
        if not runs:
            logger.warning("No runs found in %s", library_dir)
            return LibraryReport(
                library=library_dir.name, protocol_version=protocol_version,
                phase=phase, num_runs=0,
                # No run resolved, so there is nothing to resolve axes FROM.
                # `_resolve_axes(())` is the single place that spells out what
                # an unresolvable run yields, so going through it keeps this
                # report and the one built below from ever describing the same
                # corpus with two different vocabularies.
                **self._resolve_axes(()),
            )

        library_name = runs[0].library
        logger.info("Analyzing %s: %d runs, phase=%s", library_name, len(runs), phase)

        # Apply phase normalization if requested
        if normalize:
            for run in runs:
                mappings = self._normalizer.normalize_run(run)
                for raw_phase, mapping in mappings.items():
                    mapping.dump_file.canonical_phase = mapping.canonical_phase

        # Resolve dump for each run (with optional canonical fallback)
        run_dumps = []
        for run in runs:
            dump = _resolve_dump(run, phase, normalize)
            if dump:
                run_dumps.append((run, dump))

        # num_runs reflects what was actually analyzed, not merely discovered.
        # When the requested phase exists in no run, run_dumps is empty: report
        # 0 analyzed runs so a phase typo isn't masked as a clean "no secrets".
        num_runs_analyzed = len(run_dumps)
        if runs and not run_dumps:
            logger.warning("Phase '%s' not found in any of %d discovered runs for %s — "
                           "0 dumps analyzed (check the phase name)",
                           phase, len(runs), library_name)

        # Build consensus matrix (DumpSource-aware for MSL ASLR alignment)
        from memdiver.core.dump_source import open_dump
        _sources = []
        if len(run_dumps) >= 2:
            try:
                for _, _d in run_dumps:
                    _src = open_dump(_d.path)
                    _src.open()
                    _sources.append(_src)
                self.consensus.build_from_sources(_sources)
            finally:
                for _src in _sources:
                    _src.close()
            self.correlator = SearchCorrelator(self.consensus)

        # Resolve secrets
        secrets = runs[0].secrets if runs else []

        # Expand derived keys
        all_secrets = list(secrets)
        if expand_keys:
            derived = self.expander.expand_secrets(secrets)
            all_secrets.extend(derived)

        # Determine output phase name (canonical if normalizing)
        phase_out = phase
        if normalize and run_dumps:
            phase_out = run_dumps[0][1].canonical_or_raw

        # Search each dump (skip exact_match if not in requested algorithms)
        all_hits: List[SecretHit] = []
        run_exact_match = algorithms is None or "exact_match" in algorithms
        if run_exact_match:
            for run, dump in run_dumps:
                hits = self.correlator.search_all(
                    dump.path, all_secrets,
                    library=library_name, phase=phase_out, run_id=run.run_number,
                    # The hit's canonical phase is a property of ITS OWN dump,
                    # which only this loop knows: the correlator is handed one
                    # dump at a time and `_persist_report_rows` only has the
                    # run-wide fallback (the FIRST analysed dump's canonical
                    # phase, which is wrong for every other dump). Stamping it
                    # here makes the per-dump value the single source and
                    # leaves that fallback for producers other than this one.
                    canonical_phase=getattr(dump, "canonical_phase", "") or "",
                )
                all_hits.extend(hits)

        # Feed to DiffStore
        self.diff_store.ingest_hits(all_hits)

        # The corpus axes, resolved ONCE. `_persist_report` reads them back
        # off the report rather than resolving a second time, so the report a
        # caller reads and the row written to the project database cannot
        # disagree about which corpus cell this run belongs to.
        axes = self._resolve_axes(run_dumps)

        # Build report
        report = LibraryReport(
            library=library_name,
            protocol_version=protocol_version,
            phase=phase_out,
            num_runs=num_runs_analyzed,
            hits=all_hits,
            static_regions=self.consensus.get_static_regions() if self.consensus.size > 0 else [],
            metadata={
                "consensus": self.consensus.classification_counts() if self.consensus.size > 0 else {},
                "diff_summary": self.diff_store.summary_stats(),
                "total_secrets": len(all_secrets),
                "derived_count": len(all_secrets) - len(secrets),
            },
            canonical_phase=self._canonical_phase(run_dumps),
            # Splatted rather than listed so a new axis added to
            # `_resolve_axes` without a matching `LibraryReport` field fails
            # loudly here instead of being silently dropped again.
            **axes,
        )
        # Optional: alignment-filtered candidates
        if align_candidates and self.consensus.size > 0:
            aligned = self.consensus.get_aligned_candidates()
            report.metadata["aligned_candidates"] = [
                {"start": r.start, "end": r.end, "length": r.length,
                 "mean_variance": r.mean_variance}
                for r in aligned
            ]

        if verify_decryption and all_hits and secrets:
            self._verify_hits(all_hits, secrets)

        logger.info("Report: %d hits across %d analyzed runs", len(all_hits), num_runs_analyzed)

        # Persist findings to ProjectDB if available and auto_persist enabled
        if self._auto_persist and self._project_db and getattr(self._project_db, '_available', False):
            try:
                self._persist_report(report, all_hits, library_dir, run_dumps,
                                     keylog_filename=keylog_filename)
            except Exception as e:
                logger.warning("ProjectDB persistence failed: %s", e)

        return report

    def _verify_hits(self, all_hits, secrets):
        """Mark hits whose bytes decrypt a known ciphertext under the first matching secret.

        A confirmed hit is also stamped with the EVIDENCE behind the
        confirmation -- see :meth:`_stamp_proof`.
        """
        try:
            from .verification import AesCbcVerifier, VERIFICATION_IV, VERIFICATION_PLAINTEXT
        except ImportError:
            logger.debug("cryptography not available, skipping verification")
            return

        from collections import defaultdict
        from memdiver.core.dump_source import open_dump

        verifier = AesCbcVerifier()
        key_len = verifier.key_length

        secret = next((s for s in secrets if len(s.secret_value) == key_len), None)
        if secret is None:
            return
        ciphertext = verifier.create_ciphertext(
            secret.secret_value, VERIFICATION_PLAINTEXT, VERIFICATION_IV,
        )

        hits_by_path = defaultdict(list)
        for hit in all_hits:
            if hit.length == key_len:
                hits_by_path[str(hit.dump_path)].append(hit)

        for path_str, path_hits in hits_by_path.items():
            try:
                with open_dump(Path(path_str)) as source:
                    for hit in path_hits:
                        candidate = source.read_range(hit.offset, key_len)
                        hit.verified = verifier.verify(
                            candidate, ciphertext, VERIFICATION_IV, VERIFICATION_PLAINTEXT,
                        )
                        if hit.verified:
                            self._stamp_proof(hit, candidate, verifier)
            except FileNotFoundError:
                logger.debug("dump missing during verification: %s", path_str)

    @staticmethod
    def _stamp_proof(hit, candidate: bytes, verifier) -> None:
        """Record on *hit* the evidence behind a successful verification.

        This loop already HELD the bytes it decrypted with and threw them
        away, setting only ``hit.verified``. Every downstream writer reads the
        proof off the hit -- :meth:`_persist_report_rows`,
        :func:`engine.serializer.serialize_hit`,
        :meth:`engine.project_db.ProjectDB.persist_ground_truth` -- and
        ``SecretHit.value_hex`` had no producer at all, so the W5 proof ledger
        filled with rows whose ``key_hex`` / ``value_hex`` were empty: the row
        count looked healthy and the evidence was not in it.

        ``cipher`` is the VERIFIER's own name, not a guess at the cipher suite
        the library negotiated. What was proven is exactly "these bytes
        decrypt this ciphertext under this verifier", and that is what is
        recorded; ``setdefault`` leaves a richer label (a real suite name from
        the pcap oracle, say) alone.

        ``confirmed_by`` is deliberately NOT stamped:
        :func:`engine.project_db._confirmed_by` already resolves an unlabelled
        verified hit to ``"verifier"``, which is precisely this provenance.
        Writing a second spelling of it here would give the two a way to
        drift.
        """
        hit.value_hex = candidate.hex()
        metadata = getattr(hit, "metadata", None)
        if metadata is None:
            hit.metadata = metadata = {}
        metadata.setdefault("cipher", verifier.cipher_name)

    def _persist_report(self, report, hits, library_dir, run_dumps=(), *,
                        keylog_filename: str = ""):
        """Write analysis results to ProjectDB, corpus axes included.

        *run_dumps* is the ``[(run, dump), ...]`` list :meth:`analyze_library`
        already built. It is what lets this method write real ``dumps`` rows
        (the table had no production caller at all) with real ``run_number``s
        and per-run sidecar paths, instead of persisting a run with no dumps
        attached.

        *keylog_filename* is the sidecar name the CALLER asked discovery for.
        It has to be threaded through: probing the built-in default instead
        persists ``keylog_path = ""`` for every corpus that names its keylog
        anything else, while discovery happily read the real file. Empty means
        "use the built-in default", which is what a direct caller gets.

        Grain: ONE ``analysis_runs`` row per (library, phase) invocation — that
        is what an "analysis run" is, and re-graining it would silently change
        what ``project_timeline`` reports. Per-corpus-run resolution lives in
        the ``dumps`` rows written here (and later in ``survival``), each of
        which carries ``run_number`` and points back via ``dumps.run_id``.

        The whole write is ONE TRANSACTION, matching
        :meth:`engine.project_db.ProjectDB.persist_report`. Without it a
        failure part-way through left a project and a run row with only some of
        their dumps and none of their findings — and :meth:`analyze_library`
        swallows the exception, so that half-written state was the silent
        outcome rather than a visible error.

        It borrows the database's OWN
        :meth:`engine.project_db.ProjectDB._transaction` rather than issuing a
        raw ``BEGIN`` on ``db._conn``. The hand-rolled version swallowed a
        failing ``ROLLBACK``, which left the connection inside an open
        transaction: every later ``_persist_report`` then died on ``BEGIN``,
        :meth:`analyze_library` swallowed that too, and the process lost ALL
        persistence from that point on behind a single ``logger.warning``.
        There is no nesting hazard — nothing :meth:`_persist_report_rows`
        calls opens a transaction of its own.
        """
        db = self._project_db
        conn = getattr(db, "_conn", None)
        transaction = getattr(db, "_transaction", None)
        if conn is None or transaction is None:
            # A stand-in project DB with no connection to transact on: write
            # straight through, exactly as this method always has.
            self._persist_report_rows(db, report, hits, library_dir, run_dumps,
                                      keylog_filename)
            return
        with transaction():
            self._persist_report_rows(db, report, hits, library_dir, run_dumps,
                                      keylog_filename)

    def _persist_report_rows(self, db, report, hits, library_dir, run_dumps,
                             keylog_filename):
        """The body of :meth:`_persist_report`, inside its transaction."""
        axes = self._persisted_axes(report, run_dumps)
        # FROZEN name format — see ProjectDB.persist_report.
        project_name = f"{report.library}_{report.protocol_version}"
        pid = db.create_project(
            project_name, description=str(library_dir),
            library=report.library,
            protocol_version=report.protocol_version,
            library_version=axes["library_version"],
            version_axis=axes["version_axis"],
            scenario=axes["scenario"],
            protocol=axes["protocol"],
        )
        # run_dir / keylog_path / pcap_path / run_number are per-corpus-run, so
        # they are only filled in when this invocation covered exactly one run.
        # Claiming one run's sidecars for a row that spans ten would be a lie.
        single = run_dumps[0] if len(run_dumps) == 1 else None
        canonical_phase = (getattr(report, "canonical_phase", "")
                           or self._canonical_phase(run_dumps))
        rid = db.start_run(pid, config={
            "phase": report.phase, "num_runs": report.num_runs,
            "protocol_version": report.protocol_version,
        },
            phase=report.phase,
            canonical_phase=canonical_phase,
            library=report.library,
            protocol_version=report.protocol_version,
            library_version=axes["library_version"],
            scenario=axes["scenario"],
            run_number=single[0].run_number if single else 0,
            run_dir=str(single[0].path) if single else "",
            keylog_path=(self._keylog_path(single[0], keylog_filename)
                         if single else ""),
            pcap_path=str(single[0].capture_path or "") if single else "",
        )
        # `analysis_runs.dump_id` stays empty on purpose: this row's grain spans
        # every dump of the phase. `dumps.run_id` (written below) is the
        # authoritative dump -> run link, and populating it here would need an
        # UPDATE, which this append-only table deliberately avoids.
        #
        # `add_dump` returns the `dump_id` it minted and this loop used to throw
        # it away, so a finding or a ground-truth label had no way back to its
        # dump row except by re-joining on the path string. Keeping the mapping
        # is what lets `dump_id` be stamped on the rows written below.
        dump_ids: Dict[str, str] = {}
        for run, dump in run_dumps:
            did = db.add_dump(
                pid, dump.path, getattr(dump, "kind", "raw"),
                phase=dump.full_phase,
                canonical_phase=dump.canonical_phase or "",
                run_number=run.run_number,
                library=report.library,
                run_id=rid,
            )
            dump_ids[str(dump.path)] = did
        # Every `getattr(hit, ..., default)` below is KEPT VERBATIM: this path
        # is fed by producers other than SearchCorrelator, and the fallbacks are
        # what stop a hit missing one attribute from failing the whole write.
        hit_dicts = []
        for hit in hits:
            hit_meta = getattr(hit, "metadata", None) or {}
            hit_dicts.append({
                "secret_type": hit.secret_type,
                "offset": hit.offset,
                "length": hit.length,
                "value_hex": getattr(hit, "value_hex", None),
                "verified": getattr(hit, "verified", None),
                "confirmed_by": hit_meta.get("confirmed_by"),
                "cipher": hit_meta.get("cipher"),
                "confidence": getattr(hit, "confidence", 1.0),
                # Labels the SecretHit has always carried and this path used to
                # drop on the floor.
                "dump_path": getattr(hit, "dump_path", ""),
                "phase": getattr(hit, "phase", "") or report.phase,
                "library": getattr(hit, "library", "") or report.library,
                # `SecretHit.run_id` is the CORPUS RUN NUMBER; `findings` grew a
                # `run_number` column for it, and this path was still building
                # its hit dict without the key, so every finding it wrote
                # recorded run 0. Same story for `canonical_phase`, which falls
                # back to the analysed dumps' canonical phase.
                "run_id": getattr(hit, "run_id", 0),
                # The same corpus run number under the name `ground_truth`
                # (and `dumps`, and `survival`) spells it.
                "run_number": getattr(hit, "run_id", 0),
                "canonical_phase": (getattr(hit, "canonical_phase", "")
                                    or canonical_phase),
                "dump_id": dump_ids.get(str(getattr(hit, "dump_path", "")), ""),
            })
        db.add_findings_batch(
            rid,
            [_finding_row_from_hit(h, method=METHOD_CONSENSUS_SEARCH)
             for h in hit_dicts],
        )
        # The W5 proof ledger. `verify_decryption` marks hits `verified`, and
        # this method wrote no `ground_truth` row at all, so the one path that
        # produces proven key locations never reached the ledger that exists to
        # record them. Only already-confirmed hits are written, exactly as
        # `ProjectDB.persist_report` does it, so the ordinary (unverified)
        # analysis path adds zero rows.
        confirmed = [h for h in hit_dicts if h.get("verified")]
        if confirmed:
            db.persist_ground_truth(
                rid, confirmed,
                library=report.library,
                version=report.protocol_version,
                library_version=axes["library_version"],
                scenario=axes["scenario"],
                phase=report.phase,
                canonical_phase=canonical_phase,
                run_number=single[0].run_number if single else 0,
                method=METHOD_CONSENSUS_SEARCH,
            )
        db.finish_run(rid)

    @staticmethod
    def _canonical_phase(run_dumps) -> str:
        """Canonical phase of the analysed dumps, or ``""`` if not normalized."""
        for _run, dump in run_dumps:
            if dump.canonical_phase:
                return dump.canonical_phase
        return ""

    @staticmethod
    def _keylog_path(run, keylog_filename: str = "") -> str:
        """The run's keylog sidecar path as a string, or ``""`` when absent.

        *keylog_filename* is the name :meth:`analyze_library` was asked to
        discover with. Hard-coding :data:`core.corpus_axes.KEYLOG_FILENAME`
        here meant a corpus using any other sidecar name persisted
        ``keylog_path = ""`` even though discovery had just read the file.
        Empty falls back to the built-in default, which is what the parameter
        itself defaults to.
        """
        from memdiver.core.corpus_axes import KEYLOG_FILENAME
        candidate = Path(run.path) / (keylog_filename or KEYLOG_FILENAME)
        return str(candidate) if candidate.is_file() else ""

    @classmethod
    def _persisted_axes(cls, report, run_dumps) -> Dict[str, str]:
        """The axes to WRITE: the report's own, else resolved from *run_dumps*.

        :meth:`analyze_library` resolves the axes once and stamps them on the
        report it returns, so the report a caller reads and the row written
        here cannot disagree about which corpus cell a run belongs to.

        A report carrying nothing but :data:`_AXIS_FALLBACK` was either
        hand-built by a direct caller or produced before the fields existed;
        for those the axes are resolved from *run_dumps*, exactly as this
        method used to do unconditionally. The two answers can never conflict:
        when the stamped axes ARE the fallback, resolving either reproduces
        them or improves on them.
        """
        stamped = {name: getattr(report, name, default)
                   for name, default in _AXIS_FALLBACK.items()}
        if stamped != _AXIS_FALLBACK:
            return stamped
        return cls._resolve_axes(run_dumps)

    @staticmethod
    def _resolve_axes(run_dumps) -> Dict[str, str]:
        """Corpus axes shared by the analysed runs, with safe fallbacks.

        Delegates to :mod:`core.corpus_axes` — the single source of truth for
        how a dump path decomposes into axes — rather than re-deriving them
        here with a second spelling. A path that does not conform to the corpus
        layout yields the column defaults instead of raising, because the
        pipeline must keep working on ad-hoc directories.
        """
        fallback = dict(_AXIS_FALLBACK)
        if not run_dumps:
            return fallback
        try:
            from memdiver.core.corpus_axes import axes_from_run_dir
        except ImportError:  # pragma: no cover - corpus_axes is a base module
            return fallback
        resolved = axes_from_run_dir(run_dumps[0][0].path)
        if resolved is None:
            return fallback
        return {
            "library_version": resolved.library_version,
            "version_axis": resolved.version_axis,
            "scenario": resolved.scenario,
            "protocol": resolved.protocol,
        }

    def run(self, request: AnalyzeRequest) -> AnalysisResult:
        """Run analysis across multiple libraries."""
        template = request.template or get_template(request.template_name)
        result = AnalysisResult()
        for lib_dir in request.library_dirs:
            report = self.analyze_library(
                lib_dir, request.phase, request.protocol_version,
                keylog_filename=request.keylog_filename,
                max_runs=request.max_runs,
                expand_keys=request.expand_keys,
                template=template,
                normalize=request.normalize,
                algorithms=request.algorithms,
            )
            result.libraries.append(report)
        result.metadata = {"diff_summary": self.diff_store.summary_stats()}
        return result
