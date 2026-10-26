"""Mid-stage cancel of the ISF probe / try jobs on REAL images (gated on MEMDIVER_IMAGE_CORPUS).

Run with ``-s`` to see the measured latencies.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from memdiver.analysis.record_store import AnalysisRecord
from memdiver.app import tools_isf as T
from memdiver.core.image.context import file_sha256
from memdiver.core.service_errors import CapabilityError

CORPUS = os.environ.get("MEMDIVER_IMAGE_CORPUS")
DEBIAN = "debian-12_6.1.0-28-arm64"
ARISTA = "arista-eos-4.36.1F_5.10.165.Ar-48367454.4361F"


def _need(*names_exts):
    ok = bool(CORPUS) and all((Path(CORPUS) / f"{n}{e}").is_file() for n, e in names_exts)
    return pytest.mark.skipif(not ok, reason="MEMDIVER_IMAGE_CORPUS lacks the needed files")


def _flip_after(seconds):
    start = time.monotonic()
    return lambda: time.monotonic() - start > seconds


@_need((DEBIAN, ".lime"))
def test_kallsyms_probe_cancels_mid_stage(tmp_path):
    image = Path(CORPUS) / f"{DEBIAN}.lime"
    case_dir, capture = str(tmp_path / "case"), file_sha256(image)
    T.isf_draft_create_result(case_dir, capture, "d", "aarch64")
    start = time.monotonic()
    with pytest.raises(CapabilityError) as info:
        T.isf_probe_result(str(image), "kallsyms", arch="aarch64", case_dir=case_dir,
                           draft="d", cancel=_flip_after(2.0))
    elapsed = time.monotonic() - start
    print(f"[cancel] debian kallsyms cancel after 2 s -> raised after {elapsed:.2f}s")
    assert info.value.code == "cancelled" and elapsed < 4.0   # ~76 s uncancelled
    assert T.isf_draft_get_result(case_dir, capture, "d").payload["counts"]["symbols"] == 0


@_need((ARISTA, ".lime"))
def test_kallsyms_job_path_matches_in_process_counts():
    image = str(Path(CORPUS) / f"{ARISTA}.lime")
    t0 = time.monotonic()
    direct = T.isf_probe_result(image, "kallsyms", arch="x86_64").payload
    t1 = time.monotonic()
    job = T.isf_probe_result(image, "kallsyms", arch="x86_64", cancel=lambda: False).payload
    t2 = time.monotonic()
    print(f"[job] arista kallsyms in-process {t1 - t0:.2f}s, job path {t2 - t1:.2f}s "
          f"(overhead {t2 - t1 - (t1 - t0):+.2f}s), counts {job['counts']}")
    assert job["counts"] == direct["counts"] and job["counts"]["symbols"] == 108_206
    assert job["rows"] == direct["rows"] and job["capture_id"] == direct["capture_id"]


@_need((ARISTA, ".lime"), (ARISTA, ".isf.json"))
def test_try_cancels_mid_run_and_records_nothing(tmp_path):
    image = Path(CORPUS) / f"{ARISTA}.lime"
    shipped = str(Path(CORPUS) / f"{ARISTA}.isf.json")
    case_dir, capture = str(tmp_path / "case"), file_sha256(image)
    T.isf_draft_create_result(case_dir, capture, "d", "x86_64")
    T.isf_draft_import_result(case_dir, capture, "d", shipped)
    stages = []
    start = time.monotonic()
    with pytest.raises(CapabilityError) as info:
        T.isf_try_result(str(image), case_dir=case_dir, draft="d", plugin="linux.psscan",
                         cancel=_flip_after(3.0),
                         progress=lambda stage, elapsed: stages.append(stage))
    elapsed = time.monotonic() - start
    print(f"[cancel] arista psscan try cancel after 3 s -> raised after {elapsed:.2f}s")
    assert info.value.code == "cancelled" and elapsed < 5.0   # ~30 s uncancelled
    assert AnalysisRecord(T._case_root(case_dir)).entries(capture, T.ISF_TRY_KIND) == []
