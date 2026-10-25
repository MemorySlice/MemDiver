"""Tests for core/image/view_descriptor.py: ``.mdview`` descriptors."""

from pathlib import Path

import pytest

from memdiver.core.image.view_descriptor import (
    MAGIC,
    PagingSpec,
    ProfileRef,
    ViewDescriptor,
    ViewKind,
    is_view_descriptor,
)

SHA = "ab" * 32


def _process(**kw):
    base = dict(image="img.lime", image_sha256=SHA, view=ViewKind.PROCESS,
                pid=22176, profile=ProfileRef("prof.json.xz", "cd" * 32, "pakunoda"))
    base.update(kw)
    return ViewDescriptor(**base)


def test_magic_constant():
    assert MAGIC == "MEMDIVER-VIEW/1"


def test_write_read_round_trip(tmp_path):
    desc = _process(paging=PagingSpec(0x1000, "x86_64", 48))
    path = desc.write(tmp_path / "p.mdview")
    assert path == tmp_path / "p.mdview"
    assert ViewDescriptor.read(path) == desc


def test_round_trip_physical_without_optionals(tmp_path):
    desc = ViewDescriptor("img.lime", SHA, ViewKind.PHYSICAL)
    assert ViewDescriptor.read(desc.write(tmp_path / "x.mdview")) == desc


def test_first_line_is_exactly_the_magic(tmp_path):
    path = _process().write(tmp_path / "p.mdview")
    assert path.read_text(encoding="utf-8").split("\n", 1)[0] == "MEMDIVER-VIEW/1"
    assert path.read_bytes().startswith(b"MEMDIVER-VIEW/1\n")


def test_read_of_non_descriptor_raises_value_error(tmp_path):
    path = tmp_path / "not.mdview"
    path.write_text("{\"image\": \"x\"}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not a"):
        ViewDescriptor.read(path)


def test_process_view_requires_pid_and_profile():
    with pytest.raises(ValueError, match="pid"):
        _process(pid=None)
    with pytest.raises(ValueError, match="profile"):
        _process(profile=None)


@pytest.mark.parametrize("kind", [ViewKind.PHYSICAL, ViewKind.KERNEL])
def test_non_process_views_refuse_pid(kind):
    with pytest.raises(ValueError, match="pid"):
        ViewDescriptor("i", SHA, kind, pid=1, profile=ProfileRef("p"))


def test_kernel_view_needs_profile_or_paging():
    with pytest.raises(ValueError, match="kernel"):
        ViewDescriptor("i", SHA, ViewKind.KERNEL)
    ViewDescriptor("i", SHA, ViewKind.KERNEL, profile=ProfileRef("p"))
    ViewDescriptor("i", SHA, ViewKind.KERNEL, paging=PagingSpec(arch="x86_64"))


def test_view_must_be_a_viewkind():
    with pytest.raises(TypeError):
        ViewDescriptor("i", SHA, "physical")


def test_relative_image_and_isf_resolve_against_descriptor_dir(tmp_path):
    desc = _process(image="sub/img.lime", profile=ProfileRef("isf/p.json"))
    dpath = tmp_path / "case" / "p.mdview"
    assert desc.image_path(dpath) == (tmp_path / "case" / "sub" / "img.lime").resolve()
    assert desc.isf_path(dpath) == (tmp_path / "case" / "isf" / "p.json").resolve()


def test_absolute_paths_stay_absolute(tmp_path):
    abs_img = tmp_path / "elsewhere" / "img.lime"
    desc = _process(image=str(abs_img), profile=ProfileRef(str(tmp_path / "p.json")))
    dpath = tmp_path / "case" / "p.mdview"
    assert desc.image_path(dpath) == abs_img
    assert desc.isf_path(dpath) == tmp_path / "p.json"


def test_isf_path_is_none_without_profile():
    desc = ViewDescriptor("i", SHA, ViewKind.PHYSICAL)
    assert desc.isf_path(Path("/x/y.mdview")) is None


def test_is_view_descriptor_true_and_false(tmp_path):
    path = _process().write(tmp_path / "p.mdview")
    assert is_view_descriptor(path.read_bytes()[:64])
    assert not is_view_descriptor(b"MEMDIVER-VIEW/2\n{}")
    assert not is_view_descriptor(b"MEMDIVER-VIEW/1")  # no newline
    assert not is_view_descriptor(b"\x7fELF")
    assert not is_view_descriptor(b"")


def test_capture_id_is_image_sha256():
    assert _process().capture_id == SHA


def test_to_dict_omits_unset_optionals():
    assert ViewDescriptor("i", SHA, ViewKind.PHYSICAL).to_dict() == {
        "image": "i", "image_sha256": SHA, "view": "physical"}


def test_profile_and_paging_dict_round_trip():
    p = ProfileRef("a.json", None, "cache")
    assert ProfileRef.from_dict(p.to_dict()) == p
    g = PagingSpec(0x10, "aarch64", None, 16384)
    assert PagingSpec.from_dict(g.to_dict()) == g
