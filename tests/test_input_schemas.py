"""Tests for core.input_schemas module."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.input_schemas import AnalyzeRequest, BatchRequest, ScanRequest


def test_analyze_request_valid(tmp_path):
    lib_dir = tmp_path / "lib1"
    lib_dir.mkdir()
    req = AnalyzeRequest(
        library_dirs=[lib_dir],
        phase="pre_abort",
        protocol_version="13",
    )
    assert req.library_dirs == [lib_dir]
    assert req.phase == "pre_abort"


def test_analyze_request_empty_dirs():
    with pytest.raises(ValueError, match="must not be empty"):
        AnalyzeRequest(library_dirs=[], phase="pre_abort", protocol_version="13")


def test_analyze_request_nonexistent_dir_rejected(tmp_path):
    bad = tmp_path / "nonexistent"
    with pytest.raises(ValueError, match="does not exist"):
        AnalyzeRequest(library_dirs=[bad], phase="pre_abort", protocol_version="13")


def test_analyze_request_empty_phase(tmp_path):
    lib_dir = tmp_path / "lib1"
    lib_dir.mkdir()
    with pytest.raises(ValueError, match="phase must not be empty"):
        AnalyzeRequest(library_dirs=[lib_dir], phase="", protocol_version="13")


def test_analyze_request_empty_protocol_version(tmp_path):
    lib_dir = tmp_path / "lib1"
    lib_dir.mkdir()
    with pytest.raises(ValueError, match="protocol_version must not be empty"):
        AnalyzeRequest(library_dirs=[lib_dir], phase="pre_abort", protocol_version="")


def test_scan_request_valid(tmp_path):
    req = ScanRequest(dataset_root=tmp_path)
    assert req.dataset_root == tmp_path


def test_scan_request_nonexistent(tmp_path):
    bad = tmp_path / "nonexistent"
    with pytest.raises(ValueError, match="not a directory"):
        ScanRequest(dataset_root=bad)


def test_scan_request_not_a_dir(tmp_path):
    f = tmp_path / "file.txt"
    f.write_text("hi")
    with pytest.raises(ValueError, match="not a directory"):
        ScanRequest(dataset_root=f)


def test_batch_request_valid(tmp_path):
    lib_dir = tmp_path / "lib1"
    lib_dir.mkdir()
    job = AnalyzeRequest(library_dirs=[lib_dir], phase="pre_abort", protocol_version="13")
    batch = BatchRequest(jobs=[job])
    assert len(batch.jobs) == 1


def test_batch_request_empty_jobs():
    with pytest.raises(ValueError, match="at least one job"):
        BatchRequest(jobs=[])


def test_batch_request_bad_format(tmp_path):
    lib_dir = tmp_path / "lib1"
    lib_dir.mkdir()
    job = AnalyzeRequest(library_dirs=[lib_dir], phase="pre_abort", protocol_version="13")
    with pytest.raises(ValueError, match="output_format"):
        BatchRequest(jobs=[job], output_format="xml")
