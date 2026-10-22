"""End-to-end checks on a memslicer-written Android capture.

``tests/fixtures/android/memslicer_android.msl`` is produced by memslicer's
``tests/tools/make_android_fixture.py``: a live (non-imported) capture with a
VAS_MAP carrying Android mapping names, ``os_type`` Android, and a 32-byte
key planted in ``[anon:scudo:primary]`` at VA ``0x7a00000340``.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

from memdiver.core.region_view_filter import stored_region_infos
from memdiver.msl.import_preview import (PLATFORM_SOURCE_HEADER,
                                         preview_import)
from memdiver.msl.reader import MslReader
from memdiver.msl.region_select import (DEFAULT_INTERACTIVE_CATEGORIES,
                                        RegionCategory, RegionSelection)

_FIXTURES = Path(__file__).resolve().parent / "fixtures"
FIXTURE = _FIXTURES / "android" / "memslicer_android.msl"
VECTORS = _FIXTURES / "region_name_vectors.json"

# Mirrors memslicer tests/tools/make_android_fixture.py (KEY_SEED, KEY_OFFSET).
KEY = random.Random(0x4B455931).randbytes(32)
KEY_VA = 0x7A00000340
KEY_REGION_NAME = "[anon:scudo:primary]"


@pytest.fixture(scope="module")
def preview():
    return preview_import(FIXTURE)


@pytest.fixture(scope="module")
def vectors():
    return {v["name"]: v["memdiver_category"]
            for v in json.loads(VECTORS.read_text(encoding="utf-8"))}


def _assert_matches_vectors(regions, vectors):
    named = [r for r in regions if r.name in vectors]
    assert named, "fixture names should be covered by the shared vectors"
    for region in named:
        expected = vectors[region.name]
        if expected is None:  # no name override: never runtime
            assert region.category is not RegionCategory.RUNTIME, region.name
        else:
            assert region.category.value == expected, region.name


def test_every_region_is_named(preview):
    assert preview.regions and all(r.name for r in preview.regions)


def test_preview_categories_match_shared_vectors(preview, vectors):
    _assert_matches_vectors(preview.regions, vectors)


def test_stored_region_infos_match_shared_vectors(vectors):
    with MslReader(FIXTURE) as reader:
        infos = stored_region_infos(reader)
    _assert_matches_vectors(infos, vectors)


def test_preview_and_stored_infos_agree(preview):
    with MslReader(FIXTURE) as reader:
        stored = {(i.base_addr, i.category) for i in stored_region_infos(reader)}
    assert {(r.base_addr, r.category) for r in preview.regions} == stored


def test_platform_is_android_from_header(preview):
    assert preview.platform == "android"
    assert preview.platform_source == PLATFORM_SOURCE_HEADER


def test_runtime_regions_reported(preview):
    assert preview.runtime_count > 0
    assert preview.runtime_bytes > 0
    assert RegionCategory.RUNTIME not in DEFAULT_INTERACTIVE_CATEGORIES
    assert any("'runtime'" in note for note in preview.notes)


def _key_region(regions):
    return next(r for r in regions
                if r.base_addr <= KEY_VA < r.base_addr + r.size)


def test_default_selection_keeps_key_region_and_drops_runtime(preview):
    default = RegionSelection.default_interactive()
    region = _key_region(preview.regions)
    assert region.name == KEY_REGION_NAME
    assert region.category is RegionCategory.HEAP
    assert default.includes(region)
    assert not any(default.includes(r) for r in preview.regions
                   if r.category is RegionCategory.RUNTIME)


def _read_va(reader: MslReader, va: int, length: int) -> bytes:
    for run in reader.captured_run_index().by_va:
        if run.va_start <= va and va + length <= run.va_start + run.length:
            return bytes(reader.run_view(run, va - run.va_start, length))
    raise AssertionError(f"VA 0x{va:x} not captured")


def test_key_bytes_readable_at_planted_va():
    with MslReader(FIXTURE) as reader:
        assert _read_va(reader, KEY_VA, len(KEY)) == KEY
