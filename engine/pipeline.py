"""AnalysisPipeline - orchestrate the analysis workflow."""

import logging
from pathlib import Path
from typing import Dict, List, Optional

from core.discovery import RunDiscovery
from core.input_schemas import AnalyzeRequest
from core.keylog import KeylogParser
from core.keylog_templates import get_template
from core.models import CryptoSecret
from core.phase_normalizer import PhaseNormalizer
from .consensus import ConsensusVector
from .correlator import SearchCorrelator
from .derived_keys import DerivedKeyExpander
from .diff_store import DiffStore
from .results import AnalysisResult, LibraryReport, SecretHit

try:
    from .project_db import ProjectDB
    _HAS_PROJECT_DB = True
except ImportError:
    _HAS_PROJECT_DB = False

logger = logging.getLogger("memdiver.engine.pipeline")


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

        if runs and not run_dumps:
            logger.warning("Phase '%s' not found in any of %d runs for %s", phase, len(runs), library_name)

        # Build consensus matrix (DumpSource-aware for MSL ASLR alignment)
        from core.dump_source import open_dump
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
                )
                all_hits.extend(hits)

        # Feed to DiffStore
        self.diff_store.ingest_hits(all_hits)

        # Build report
        report = LibraryReport(
            library=library_name,
            protocol_version=protocol_version,
            phase=phase_out,
            num_runs=len(runs),
            hits=all_hits,
            static_regions=self.consensus.get_static_regions() if self.consensus.size > 0 else [],
            metadata={
                "consensus": self.consensus.classification_counts() if self.consensus.size > 0 else {},
                "diff_summary": self.diff_store.summary_stats(),
                "total_secrets": len(all_secrets),
                "derived_count": len(all_secrets) - len(secrets),
            },
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

        logger.info("Report: %d hits across %d runs", len(all_hits), len(runs))

        # Persist findings to ProjectDB if available and auto_persist enabled
        if self._auto_persist and self._project_db and getattr(self._project_db, '_available', False):
            try:
                self._persist_report(report, all_hits, library_dir)
            except Exception as e:
                logger.warning("ProjectDB persistence failed: %s", e)

        return report

    def _verify_hits(self, all_hits, secrets):
        """Mark hits whose bytes decrypt a known ciphertext under the first matching secret."""
        try:
            from .verification import AesCbcVerifier, VERIFICATION_IV, VERIFICATION_PLAINTEXT
        except ImportError:
            logger.debug("cryptography not available, skipping verification")
            return

        from collections import defaultdict
        from core.dump_source import open_dump

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
            except FileNotFoundError:
                logger.debug("dump missing during verification: %s", path_str)

    def _persist_report(self, report, hits, library_dir):
        """Write analysis results to ProjectDB."""
        db = self._project_db
        project_name = f"{report.library}_{report.protocol_version}"
        pid = db.create_project(project_name, description=str(library_dir))
        rid = db.start_run(pid, config={
            "phase": report.phase, "num_runs": report.num_runs,
            "protocol_version": report.protocol_version,
        })
        for hit in hits:
            db.add_finding(
                rid, finding_type=hit.secret_type,
                offset=hit.offset, length=hit.length,
                value_hex=hit.value_hex if hasattr(hit, 'value_hex') else None,
                confidence=1.0,
            )
        db.finish_run(rid)

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
