"""Real-image proof for ``.mdview`` views (LiME + ground-truth ISF), gated on a corpus.

Set ``MEMDIVER_IMAGE_CORPUS`` to the pakunoda ``dumps/acquired`` directory. Like
``requires_dataset``/``requires_vol3`` this is a CONDITIONAL gate (clean skip
without the corpus), not a ``slow`` cost gate; with the corpus it takes ~15 s.
"""

import json
import os
from pathlib import Path

import pytest

from memdiver.core.dump_source import open_dump
from memdiver.core.image.adapters import ProcessAdapter
from memdiver.core.image.context import get_image_context
from memdiver.core.image.view_descriptor import ProfileRef, ViewDescriptor, ViewKind

ALMA9 = "alma-9_5.14.0-427.el9"
ALMA8 = "alma-8_4.18.0-553.16.1.el8_10"
# Distinct per image: the process-wide ImageContext cache is keyed on these.
SHA = {ALMA9: "c9" * 32, ALMA8: "c8" * 32}
_ROOT = os.environ.get("MEMDIVER_IMAGE_CORPUS", "")
CORPUS = Path(_ROOT) if _ROOT else None


def _has(stem):
    return CORPUS is not None and all(
        (CORPUS / f"{stem}{ext}").is_file() for ext in (".lime", ".gt.isf.json"))


pytestmark = pytest.mark.skipif(
    not (_has(ALMA9) and _has(ALMA8)),
    reason="set MEMDIVER_IMAGE_CORPUS to a dir with the alma-8/alma-9 .lime + .gt.isf.json")


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "home"))


def _view(tmp_path, stem, kind, pid=None):
    profile = None if kind is ViewKind.PHYSICAL else ProfileRef(
        str(CORPUS / f"{stem}.gt.isf.json"), sha256=SHA[stem], origin="pakunoda")
    desc = ViewDescriptor(str(CORPUS / f"{stem}.lime"), SHA[stem], kind, pid=pid, profile=profile)
    return desc.write(tmp_path / f"{stem}-{kind.value}{pid or ''}.mdview")


def _banner_va(stem, aslr_shift):
    isf = json.loads((CORPUS / f"{stem}.gt.isf.json").read_text())
    return isf["symbols"]["linux_banner"]["address"] + aslr_shift


def test_alma9_kernel_view_is_la57_and_reads_the_banner(tmp_path):
    with open_dump(_view(tmp_path, ALMA9, ViewKind.KERNEL)) as src:
        kernel = src.metadata()["layer"]["kernel"]
        assert kernel["va_bits"] == 57
        assert kernel["rejected"] == []
        assert kernel["la57_symbol"] == 1
        result = src.read_location(_banner_va(ALMA9, kernel["aslr_shift"]), 64)
        assert result.data.startswith(b"Linux version 5.14.0-611")
        assert result.coverage.captured == result.coverage.requested == 64
        assert not result.coverage.gaps


def test_alma9_process_view_has_the_known_captured_size_and_a_heap(tmp_path):
    with open_dump(_view(tmp_path, ALMA9, ViewKind.PROCESS, pid=22176)) as src:
        assert sum(length for _, length, _ in src.captured_runs()) == 7823360
        assert src.metadata()["layer"]["view"] == "process"
        assert src.metadata()["layer"]["pid"] == 22176
        assert src.metadata()["layer"]["vma_count"] > 0
        assert src.size_for("vas") == 7823360


def test_alma9_process_view_contains_a_heap_vma(tmp_path):
    desc_path = _view(tmp_path, ALMA9, ViewKind.PROCESS, pid=22176)
    desc = ViewDescriptor.read(desc_path)
    image_ctx = get_image_context(desc.image_path(desc_path), SHA[ALMA9],
                                   desc.isf_path(desc_path), SHA[ALMA9])
    heaps = [v for v in ProcessAdapter(image_ctx, 22176).vmas() if v.is_heap]
    assert heaps and all(v.name == "[heap]" for v in heaps)


def test_alma8_kernel_view_is_four_level_with_a_rejected_57_bit_candidate(tmp_path):
    with open_dump(_view(tmp_path, ALMA8, ViewKind.KERNEL)) as src:
        kernel = src.metadata()["layer"]["kernel"]
        assert kernel["va_bits"] == 48
        assert any(r.startswith("57-bit") for r in kernel["rejected"])
        assert kernel["la57_symbol"] == 0
        banner = src.read_location(_banner_va(ALMA8, kernel["aslr_shift"]), 13)
        assert banner.data == b"Linux version"
