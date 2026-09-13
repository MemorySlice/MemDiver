"""``class_regions_from_vector`` — every occurrence of a class, and how to JUMP there.

The producer behind "the analyst clicks *Key candidate* and gets every
occurrence, then clicks a row to scroll the hex viewer there". Two things can
go wrong, and this module separates them:

* **the LIST** — which runs are regions at all. That is class-union grouping
  plus the length filters plus the pagination cursor, and it is asserted on a
  hand-built class profile so every expected offset is derivable by reading
  this file.
* **the JUMP** — ``anchor_offset``, the argument ``scrollToOffset`` takes. That
  is slab -> VA -> navigable-offset, and it is asserted on a REAL aligned
  ``.msl`` pair, because the properties that matter (a VA span that starts at
  one region and a second region megabytes away, a region crossing a layout-row
  boundary) do not exist in a fabricated layout.

The fixture is therefore a hybrid: a real two-region ASLR pair, really built,
with its variance/classification arrays REPLACED by a profile chosen so each
case below is a single readable assertion. The layout, the dump paths and the
sources on disk stay real, so every coordinate answer is computed the same way
production computes it.

THE DOMAIN FACT THE DEFAULTS ENCODE. Real key material is class-MIXED: a
measured 48-byte TLS 1.2 secret classifies as 22 KEY_CANDIDATE + 18 POINTER +
8 STRUCTURAL bytes. ``_SECRET`` below is exactly that shape, and
``test_union_keeps_a_mixed_class_secret_in_one_region`` is the reason
``classes=None`` defaults to the non-invariant union rather than to
``key_candidate``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.core.service_errors import (  # noqa: E402
    CapabilityError,
    FileNotFoundServiceError,
)
from memdiver.core.variance import ByteClass, classify_variance  # noqa: E402
from memdiver.app.tools_consensus import (  # noqa: E402
    MAX_REGIONS_PER_PAGE,
    NON_INVARIANT_CLASSES,
    class_regions_from_vector,
    class_regions_result,
)
from memdiver.app.composition import build_tool_session  # noqa: E402
from memdiver.engine.consensus_service import build_consensus  # noqa: E402
from tests.fixtures.generate_msl_aslr_fixtures import (  # noqa: E402
    EXTRA_BASE_RUN1,
    EXTRA_BASE_RUN2,
    HEAP_BASE_RUN1,
    generate_aslr_msl_pair,
)

# -- variance values, one per band (see core.variance's 0 / 200 / 3000 bands) --
_INVARIANT = 0.0
_STRUCTURAL = 100.0
_POINTER = 2500.0
_KEY = 9000.0

#: The real pair's slab: two 4096-byte layout rows. Row 0 is the extra region
#: (VA base 0x10000000, which is ALSO the "va" view's span start, so a row-0
#: slab offset and its "va" offset coincide); row 1 is the heap page, 0x7fff...
#: away — the gap that makes a region crossing 4096 non-contiguous in "va".
_ROW_SIZE = 4096
_SLAB = 8192

#: Regions planted in the profile, in slab order. Each is one CONTIGUOUS
#: non-invariant run; the invariant bytes between them are what separates them.
_STRUCTURAL_RUN = (100, 120)      # 20 bytes, pure STRUCTURAL
_POINTER_RUN = (200, 210)         # 10 bytes, pure POINTER
_SECRET = (1000, 1048)            # 48 bytes: 8 STRUCTURAL + 18 POINTER + 22 KEY
_SECRET_KEY_PART = (1026, 1048)   # the 22 KEY_CANDIDATE bytes inside it
_CROSSING = (4090, 4106)          # 16 bytes KEY, straddling the row boundary
#: Every non-invariant union region, in offset order.
_UNION_REGIONS = [_STRUCTURAL_RUN, _POINTER_RUN, _SECRET, _CROSSING]


def _profile() -> np.ndarray:
    variance = np.full(_SLAB, _INVARIANT, dtype=np.float32)
    variance[slice(*_STRUCTURAL_RUN)] = _STRUCTURAL
    variance[slice(*_POINTER_RUN)] = _POINTER
    variance[1000:1008] = _STRUCTURAL
    variance[1008:1026] = _POINTER
    variance[slice(*_SECRET_KEY_PART)] = _KEY
    variance[slice(*_CROSSING)] = _KEY
    return variance


@pytest.fixture(scope="module")
def aslr_pair(tmp_path_factory):
    """Two ASLR-shifted ``.msl`` runs with TWO differently-shifted regions."""
    root = tmp_path_factory.mktemp("class_regions")
    run1, run2 = generate_aslr_msl_pair(extra_region=True)
    first, second = root / "run_1.msl", root / "run_2.msl"
    first.write_bytes(run1)
    second.write_bytes(run2)
    return str(first), str(second)


@pytest.fixture
def aligned(aslr_pair):
    """A REAL aligned consensus wearing a hand-built class profile."""
    consensus = build_consensus(list(aslr_pair))
    assert consensus.msl_layout == [
        (0, _ROW_SIZE, [EXTRA_BASE_RUN1, EXTRA_BASE_RUN2]),
        (_ROW_SIZE, _ROW_SIZE, [HEAP_BASE_RUN1, 0x7FFF10000000]),
    ], consensus.msl_layout
    consensus.variance = _profile()
    consensus.classifications = classify_variance(consensus.variance)
    return consensus


@pytest.fixture
def flat_pair(tmp_path_factory):
    """Two plain ``.dump`` files — a flat (``file_offset``) build."""
    root = tmp_path_factory.mktemp("flat_regions")
    first, second = root / "a.dump", root / "b.dump"
    first.write_bytes(bytes(range(256)) * 4)
    second.write_bytes(bytes([(b * 7) % 256 for b in range(256)]) * 4)
    return str(first), str(second)


def _spans(payload) -> list:
    return [(r["slab_start"], r["slab_end"]) for r in payload["regions"]]


# ---------------------------------------------------------------------------
# The class query: names, raw codes, and the union alias
# ---------------------------------------------------------------------------


def test_classes_accepts_names_and_raw_integer_codes(aligned):
    """The surfaces speak names; an agent or a script may speak codes."""
    by_name = class_regions_from_vector(
        aligned, classes=["key_candidate"], min_length=1)
    by_code = class_regions_from_vector(
        aligned, classes=[int(ByteClass.KEY_CANDIDATE)], min_length=1)

    assert by_name["regions"] == by_code["regions"]
    assert by_name["classes"] == ["key_candidate"]
    assert _spans(by_name) == [_SECRET_KEY_PART, _CROSSING]


def test_non_invariant_alias_is_the_three_class_union(aligned):
    """The alias exists so a caller that PASSES classes can still say "the
    union" without spelling three names and getting one of them wrong."""
    aliased = class_regions_from_vector(
        aligned, classes=["non_invariant"], min_length=1)
    spelled = class_regions_from_vector(
        aligned, classes=["structural", "pointer", "key_candidate"],
        min_length=1)

    assert aliased["regions"] == spelled["regions"]
    assert aliased["classes"] == ["structural", "pointer", "key_candidate"]
    assert aliased["union"] is True


def test_omitting_classes_is_the_non_invariant_union(aligned):
    """The DEFAULT, and the domain fact behind it — see the module docstring."""
    default = class_regions_from_vector(aligned, min_length=1)

    assert default["classes"] == [
        klass.name.lower() for klass in NON_INVARIANT_CLASSES]
    assert _spans(default) == _UNION_REGIONS


def test_a_single_class_query_is_not_a_union(aligned):
    page = class_regions_from_vector(aligned, classes=["pointer"], min_length=1)
    assert page["union"] is False
    assert page["classes"] == ["pointer"]


def test_an_unknown_class_is_a_capability_error_naming_the_alias(aligned):
    with pytest.raises(CapabilityError) as exc:
        class_regions_from_vector(aligned, classes=["keycandidate"])
    assert "non_invariant" in str(exc.value)


def test_an_empty_class_list_is_refused_rather_than_defaulted(aligned):
    """Defaulting an EXPLICIT empty list to the union would answer a question
    nobody asked; ``classes=None`` is how the union is requested."""
    with pytest.raises(CapabilityError, match="at least one"):
        class_regions_from_vector(aligned, classes=[])


# ---------------------------------------------------------------------------
# THE domain case: a union keeps a class-MIXED secret in ONE region
# ---------------------------------------------------------------------------


def test_union_keeps_a_mixed_class_secret_in_one_region(aligned):
    """22 KEY_CANDIDATE + 18 POINTER + 8 STRUCTURAL is ONE 48-byte row.

    Mirrors ``test_get_regions_multi_class_query_merges_adjacent_runs`` at the
    producer level, and is the whole justification for the default: the same
    bytes queried as ``key_candidate`` alone are a 22-byte FRAGMENT of the
    secret, and at any realistic ``min_length`` they vanish entirely.
    """
    union = class_regions_from_vector(aligned, min_length=48)
    (secret,) = union["regions"]

    assert (secret["slab_start"], secret["slab_end"]) == _SECRET
    assert secret["length"] == 48
    # Labelled by the most volatile class it contains, and carrying the MIX.
    assert secret["classification"] == "key_candidate"
    assert secret["class_counts"] == {
        "structural": 8, "pointer": 18, "key_candidate": 22}

    narrow = class_regions_from_vector(
        aligned, classes=["key_candidate"], min_length=48)
    assert narrow["regions"] == [], "the naive query loses the secret entirely"


def test_class_counts_are_union_only_and_omit_empty_classes(aligned):
    """A single-class query already answers this with ``length``, so it stays
    ``{}`` rather than restating it."""
    single = class_regions_from_vector(
        aligned, classes=["key_candidate"], min_length=1)
    assert all(r["class_counts"] == {} for r in single["regions"])

    union = class_regions_from_vector(aligned, min_length=1)
    by_span = {(r["slab_start"], r["slab_end"]): r["class_counts"]
               for r in union["regions"]}
    assert by_span[_STRUCTURAL_RUN] == {"structural": 20}
    assert by_span[_CROSSING] == {"key_candidate": 16}


# ---------------------------------------------------------------------------
# Length filters
# ---------------------------------------------------------------------------


def test_min_length_filters_the_page_and_the_total(aligned):
    page = class_regions_from_vector(aligned, min_length=16)
    assert _spans(page) == [_STRUCTURAL_RUN, _SECRET, _CROSSING]
    assert page["total"] == 3, "the total sizes the FILTERED set, not the slab"
    assert page["min_length"] == 16


def test_max_length_bounds_the_page(aligned):
    page = class_regions_from_vector(aligned, min_length=1, max_length=20)
    assert _spans(page) == [_STRUCTURAL_RUN, _POINTER_RUN, _CROSSING]
    assert page["max_length"] == 20


def test_max_length_zero_is_unbounded(aligned):
    bounded = class_regions_from_vector(aligned, min_length=1, max_length=0)
    assert _spans(bounded) == _UNION_REGIONS


# ---------------------------------------------------------------------------
# Pagination: total / next_after / truncated
# ---------------------------------------------------------------------------


def test_pagination_walks_the_whole_set_with_no_gaps_or_repeats(aligned):
    """The cursor contract. Two pages of two must reproduce all four regions in
    order, exactly once each — the property a page-number scheme loses the
    moment the underlying set shifts."""
    first = class_regions_from_vector(aligned, min_length=1, limit=2)
    assert _spans(first) == _UNION_REGIONS[:2]
    assert first["total"] == 4
    assert first["returned"] == 2
    assert first["truncated"] is True
    assert first["after"] == -1
    assert first["next_after"] == _POINTER_RUN[0]

    second = class_regions_from_vector(
        aligned, min_length=1, limit=2, after=first["next_after"])
    assert _spans(second) == _UNION_REGIONS[2:]
    assert second["total"] == 4, "the total is the whole set on every page"
    assert second["truncated"] is False
    assert second["next_after"] == -1

    assert _spans(first) + _spans(second) == _UNION_REGIONS


def test_a_page_that_exactly_fits_is_not_truncated(aligned):
    """``returned == limit`` is not itself evidence of a next page — the
    producer looks one region past the page rather than guessing."""
    page = class_regions_from_vector(aligned, min_length=1, limit=4)
    assert page["returned"] == 4
    assert page["truncated"] is False
    assert page["next_after"] == -1


def test_a_cursor_past_the_last_region_returns_an_empty_page(aligned):
    page = class_regions_from_vector(aligned, min_length=1, after=_CROSSING[0])
    assert page["regions"] == []
    assert page["returned"] == 0
    assert page["truncated"] is False
    assert page["next_after"] == -1
    assert page["total"] == 4, "an empty PAGE is not an empty result set"


def test_limit_is_clamped_to_the_page_cap(aligned):
    page = class_regions_from_vector(
        aligned, min_length=1, limit=MAX_REGIONS_PER_PAGE * 10)
    assert page["returned"] == 4


# ---------------------------------------------------------------------------
# The envelope
# ---------------------------------------------------------------------------


def test_envelope_carries_the_whole_build_histogram_and_alignment(aligned):
    """``counts`` is the WHOLE build, not the page: the chip counts beside the
    list arrive with the first page instead of a second round trip."""
    page = class_regions_from_vector(aligned, min_length=1, limit=1)

    assert page["counts"] == {
        "invariant": _SLAB - 20 - 10 - 48 - 16,
        "structural": 20 + 8,
        "pointer": 10 + 18,
        "key_candidate": 22 + 16,
    }
    assert page["coordinate"] == "aligned"
    assert page["alignment"]["method"] == "module_offset"
    assert page["consensus_id"] is None


def test_an_unfinalized_vector_is_refused_rather_than_answered(aligned):
    """A vector with no classifications would answer every class with nothing
    while claiming to have looked — the silent lie ``_require_classified``
    exists to prevent."""
    from memdiver.engine.consensus import ConsensusVector

    live = ConsensusVector()
    live.build_incremental(64)
    with pytest.raises(CapabilityError) as exc:
        class_regions_from_vector(live)
    assert exc.value.status == 409


# ---------------------------------------------------------------------------
# THE JUMP: anchor_offset in both navigable views
# ---------------------------------------------------------------------------


def test_anchor_offset_is_navigable_in_the_va_view(aligned, aslr_pair):
    """``anchor_offset`` is what ``scrollToOffset`` takes — not a VA.

    Row 0's VA base IS the "va" view's span start, so a row-0 region's offset
    equals its slab offset. Asserted against the VA too, so a producer that
    returned the VA in the offset field fails loudly rather than plausibly.
    """
    first, _second = aslr_pair
    page = class_regions_from_vector(
        aligned, min_length=1, anchor_path=first, anchor_view="va")

    assert page["anchor"] == {
        "dump_path": first, "dump_index": 0, "view": "va", "jumpable": True}
    row = page["regions"][0]
    assert (row["slab_start"], row["slab_end"]) == _STRUCTURAL_RUN
    assert row["anchor_va"] == EXTRA_BASE_RUN1 + _STRUCTURAL_RUN[0]
    assert row["anchor_offset"] == _STRUCTURAL_RUN[0]
    assert row["anchor_offset_end"] == _STRUCTURAL_RUN[1]
    assert row["anchor_contiguous"] is True


def test_anchor_offset_is_navigable_in_the_vas_view(aligned, aslr_pair):
    """The overlay navigates in "vas", the single viewer in "va" — the producer
    answers in whichever the caller asked for, which is precisely the
    translation a VA-only response would push back onto the client."""
    first, _second = aslr_pair
    page = class_regions_from_vector(
        aligned, min_length=1, anchor_path=first, anchor_view="vas")

    assert page["anchor"]["jumpable"] is True
    row = page["regions"][0]
    assert row["anchor_va"] == EXTRA_BASE_RUN1 + _STRUCTURAL_RUN[0]
    # The extra region is the FIRST captured run, so its VAS offsets start at 0.
    assert row["anchor_offset"] == _STRUCTURAL_RUN[0]


def test_the_second_dump_anchors_on_its_OWN_base(aligned, aslr_pair):
    """The same slab region, a different dump, a different VA — and the same
    offset, because each dump's span starts at its own base. A producer that
    cached one dump's delta would return run 1's address here."""
    _first, second = aslr_pair
    page = class_regions_from_vector(
        aligned, min_length=1, anchor_path=second, anchor_view="va")

    assert page["anchor"]["dump_index"] == 1
    row = page["regions"][0]
    assert row["anchor_va"] == EXTRA_BASE_RUN2 + _STRUCTURAL_RUN[0]
    assert row["anchor_va"] != EXTRA_BASE_RUN1 + _STRUCTURAL_RUN[0]
    assert row["anchor_offset"] == _STRUCTURAL_RUN[0]


def test_a_region_crossing_a_layout_row_is_not_contiguous_in_va(
    aligned, aslr_pair,
):
    """THE contiguity caveat. A region is contiguous in SLAB space, but
    ``msl_layout`` rows are per page and ``slab_to_va`` is linear only within a
    row — so the 16 bytes at 4090..4106 are two runs 0x7fee-something apart in
    the anchor's VA view. ``anchor_contiguous`` is what stops a caller
    highlighting ``[offset, offset + length)`` and painting the wrong bytes.
    """
    first, _second = aslr_pair
    page = class_regions_from_vector(
        aligned, min_length=1, anchor_path=first, anchor_view="va")
    crossing = page["regions"][-1]

    assert (crossing["slab_start"], crossing["slab_end"]) == _CROSSING
    assert crossing["anchor_offset"] == _CROSSING[0]
    # The END is resolved from the region's LAST byte, which lives in row 1.
    assert crossing["anchor_offset_end"] == (
        HEAP_BASE_RUN1 - EXTRA_BASE_RUN1 + (_CROSSING[1] - 1 - _ROW_SIZE) + 1)
    assert crossing["anchor_offset_end"] - crossing["anchor_offset"] != 16
    assert crossing["anchor_contiguous"] is False


def test_the_same_crossing_region_IS_contiguous_in_the_dense_vas_view(
    aligned, aslr_pair,
):
    """The contrast that proves ``anchor_contiguous`` is measured, not assumed:
    "vas" is the DENSE stream of captured bytes, so the two layout rows sit
    back to back and the very same region is one run."""
    first, _second = aslr_pair
    page = class_regions_from_vector(
        aligned, min_length=1, anchor_path=first, anchor_view="vas")
    crossing = page["regions"][-1]

    assert crossing["anchor_offset"] == _CROSSING[0]
    assert crossing["anchor_offset_end"] == _CROSSING[1]
    assert crossing["anchor_contiguous"] is True


def test_no_anchor_means_slab_coordinates_only(aligned):
    """Without an anchor there is no dump to be navigable IN, so every offset
    is ``-1`` and ``jumpable`` says so once for the page."""
    page = class_regions_from_vector(aligned, min_length=1)

    assert page["anchor"] == {
        "dump_path": None, "dump_index": -1, "view": "va", "jumpable": False}
    assert all(r["anchor_offset"] == -1 for r in page["regions"])
    assert all(r["anchor_va"] == -1 for r in page["regions"])
    assert all(r["anchor_contiguous"] is False for r in page["regions"])
    # The LIST is unaffected — the regions are read from the consensus.
    assert _spans(page) == _UNION_REGIONS


def test_include_anchor_offsets_false_skips_the_open_entirely(aligned, aslr_pair):
    """The cheap path for a caller that only wants counts: the anchor is still
    resolved to an index, but nothing is opened and nothing is jumpable."""
    first, _second = aslr_pair
    page = class_regions_from_vector(
        aligned, min_length=1, anchor_path=first, include_anchor_offsets=False)

    assert page["anchor"]["dump_index"] == 0
    assert page["anchor"]["jumpable"] is False
    assert all(r["anchor_offset"] == -1 for r in page["regions"])


def test_an_anchor_outside_the_build_is_not_found(aligned, tmp_path):
    stranger = tmp_path / "stranger.msl"
    stranger.write_bytes(b"\x00" * 16)
    with pytest.raises(FileNotFoundServiceError):
        class_regions_from_vector(aligned, anchor_path=str(stranger))


def test_an_unknown_anchor_view_is_refused(aligned, aslr_pair):
    first, _second = aslr_pair
    with pytest.raises(CapabilityError, match="Unknown view"):
        class_regions_from_vector(aligned, anchor_path=first, anchor_view="slab")


# ---------------------------------------------------------------------------
# The three "-1" cases
# ---------------------------------------------------------------------------


def test_a_flat_build_queried_in_va_is_not_jumpable(flat_pair):
    """A ``file_offset`` build has no virtual addresses at all, so there is no
    honest "va" offset — ``-1``, never a plausible number."""
    consensus = build_consensus(list(flat_pair))
    assert consensus.msl_layout is None

    page = class_regions_from_vector(
        consensus, min_length=1, anchor_path=flat_pair[0], anchor_view="va")

    assert page["coordinate"] == "flat"
    assert page["anchor"]["jumpable"] is False
    assert page["regions"], "the LIST is still served"
    assert all(r["anchor_offset"] == -1 for r in page["regions"])
    assert all(r["anchor_va"] == -1 for r in page["regions"])


def test_a_flat_build_IS_jumpable_in_the_stream_the_build_compared(flat_pair):
    """The flat slab offset IS every dump's offset in the very stream the build
    compared, so the raw view answers — and answers with the slab offset."""
    consensus = build_consensus(list(flat_pair))
    page = class_regions_from_vector(
        consensus, min_length=1, anchor_path=flat_pair[0], anchor_view="raw")

    assert page["anchor"]["jumpable"] is True
    row = page["regions"][0]
    assert row["anchor_offset"] == row["slab_start"]
    assert row["anchor_offset_end"] == row["slab_end"]
    assert row["anchor_contiguous"] is True
    assert row["anchor_va"] == -1, "a flat build has no virtual addresses"


def test_a_locked_anchor_is_reported_and_NEVER_raises(tmp_path):
    """Unlike the aligned window — which measures every coordinate through the
    anchor and so cannot proceed — a region page reads NOTHING through the
    anchor. A missing key costs the jump offsets and nothing else, so refusing
    the whole page would throw away an answer the caller can still use.
    """
    from memdiver.msl import crypto
    from memdiver.msl.enums import EncAlgo

    if not crypto.cipher_is_available(EncAlgo.AES_256_GCM):
        pytest.skip("AES-256-GCM backend not installed")

    from memdiver.msl.writer import MslEncryptionConfig, MslWriter

    key = os.urandom(32)
    paths = []
    for name, fill in (("enc_a.msl", 0xA1), ("enc_b.msl", 0xB2)):
        path = tmp_path / name
        writer = MslWriter(str(path), pid=7, imported=False,
                           encryption=MslEncryptionConfig(raw_key=key))
        writer.add_process_identity(exe_path="/proc")
        writer.add_memory_region(0x1000, bytes([fill]) * 4096)
        writer.add_end_of_capture()
        writer.write()
        paths.append(str(path))

    consensus = build_consensus(paths, key_material={"key": key})
    assert consensus.msl_layout is not None

    # No key_material_by_path: the anchor opens LOCKED.
    page = class_regions_from_vector(
        consensus, min_length=1, anchor_path=paths[0], anchor_view="va")

    assert page["anchor"]["dump_index"] == 0
    assert page["anchor"]["jumpable"] is False
    assert all(r["anchor_offset"] == -1 for r in page["regions"])

    # With the key, the very same request IS jumpable — so the -1 above is the
    # lock talking and not a broken locator.
    unlocked = class_regions_from_vector(
        consensus, min_length=1, anchor_path=paths[0], anchor_view="va",
        key_material_by_path={paths[0]: {"key": key}})
    assert unlocked["anchor"]["jumpable"] is True


# ---------------------------------------------------------------------------
# class_regions_result — the build-one-now half of the pair
# ---------------------------------------------------------------------------


def test_result_builds_a_consensus_and_serves_the_same_shape(aslr_pair):
    from memdiver.core.service_result import Resolution

    result = class_regions_result(
        build_tool_session(), dump_paths=list(aslr_pair), min_length=1,
        anchor_path=aslr_pair[0])

    assert result.status.resolution is Resolution.OK
    assert result.payload["coordinate"] == "aligned"
    assert result.payload["anchor"]["jumpable"] is True
    assert result.payload["total"] == result.payload["returned"]


def test_result_reports_an_unanswerable_anchor_as_PARTIAL(flat_pair):
    """The rows are complete but carry no navigable offsets — "answered, but
    not fully" is exactly what the status block is for."""
    from memdiver.core.service_result import Resolution

    result = class_regions_result(
        build_tool_session(), dump_paths=list(flat_pair), min_length=1,
        anchor_path=flat_pair[0], anchor_view="va")

    assert result.status.resolution is Resolution.PARTIAL
    assert result.payload["anchor"]["jumpable"] is False


def test_result_needs_at_least_two_dumps(aslr_pair):
    with pytest.raises(CapabilityError, match="at least 2 dumps"):
        class_regions_result(
            build_tool_session(), dump_paths=[aslr_pair[0]])
