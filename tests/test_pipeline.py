"""Tests for engine.pipeline module."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from engine.pipeline import AnalysisPipeline
from engine.results import AnalysisResult, LibraryReport


def test_analysis_result_get_library():
    result = AnalysisResult()
    report = LibraryReport(library="test", tls_version="13", phase="pre_abort", num_runs=3)
    result.libraries.append(report)
    assert result.get_library("test") is report
    assert result.get_library("missing") is None


def test_analysis_result_total_hits():
    result = AnalysisResult()
    assert result.total_hits == 0


def test_pipeline_init():
    pipeline = AnalysisPipeline()
    assert pipeline.consensus is not None
    assert pipeline.correlator is not None
    assert pipeline.expander is not None
    assert pipeline.diff_store is not None
