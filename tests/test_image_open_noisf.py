"""Review regressions for image_open_view_result: no-ISF paging depth and draft resolution."""

import pytest

from memdiver.app import tools_image as ti
from memdiver.core.service_errors import CapabilityError, ErrorCategory

pytest.importorskip("pakunoda")
CAP_BYTES = b"not a real image"


@pytest.fixture
def image(tmp_path):
    path = tmp_path / "img.lime"
    path.write_bytes(CAP_BYTES)
    return path


def test_explicit_pgd_and_arch_without_va_bits_is_refused(image):
    with pytest.raises(CapabilityError) as e:
        ti.image_open_view_result(str(image), "kernel", no_profile=True,
                                  paging={"pgd_phys": 0x1000, "arch": "x86_64"})
    assert e.value.code == "paging_va_bits_required"
    assert e.value.category is ErrorCategory.INVALID_INPUT


def test_explicit_va_bits_is_accepted(image, tmp_path):
    out = ti.image_open_view_result(str(image), "kernel", no_profile=True,
                                    out_path=str(tmp_path / "v.mdview"),
                                    paging={"pgd_phys": 0x1000, "arch": "x86_64",
                                            "va_bits": 57}).payload
    assert out["descriptor"]["paging"]["va_bits"] == 57


def test_unresolvable_draft_raises_before_any_extraction(image, tmp_path, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("the chain must not run for an unusable draft")
    monkeypatch.setattr(ti, "default_chain", boom)
    with pytest.raises(CapabilityError) as e:
        ti.image_open_view_result(str(image), "kernel", case_dir=str(tmp_path / "case"),
                                  draft="missing")
    assert e.value.code == "draft_unusable"
    assert "no draft" in e.value.message


def test_isf_and_draft_together_is_a_conflict(image, tmp_path):
    isf = tmp_path / "x.isf.json"
    isf.write_text("{}")
    with pytest.raises(CapabilityError) as e:
        ti.image_open_view_result(str(image), "kernel", isf=str(isf),
                                  case_dir=str(tmp_path / "case"), draft="d")
    assert e.value.code == "profile_conflict"
