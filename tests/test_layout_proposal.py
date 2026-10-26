"""propose_layout: field kinds, bounds from allocator chunks, to_structure."""

import numpy as np
import pytest

from memdiver.core.structure_defs import FieldType
from memdiver.engine.anchor_consensus import Anchor, InstanceWindow, anchor_consensus
from memdiver.engine.layout_proposal import propose_layout

N = 4
LENGTH = 256
DELTA_START = -128          # anchor at window offset 128
ANCHOR_LEN = 16
CONST_DELTA, VERIFIED_DELTA, POINTER_DELTA, SMALL_DELTA = -64, -40, 32, 64
HOLE = (20, 24)             # window offsets, uncaptured in instance 2
CONST = bytes(range(0x21, 0x31))


def _rand(seed: int, n: int) -> bytes:
    return bytes(np.random.default_rng(seed).integers(1, 255, n, dtype=np.uint8).tolist())


def _va(i: int) -> int:
    return 0x7F0000 + i * 0x10000


def _runs(i: int):
    return [(0x500000 + i * 0x1000, 0x100)]


def _verified(i: int) -> bytes:
    return _rand(100 + i, 32)


def _window(i: int, mutate=None) -> InstanceWindow:
    data = bytearray((i * 50 + o * 7) % 256 for o in range(LENGTH))  # 4 distinct values each
    off = lambda d: d - DELTA_START  # noqa: E731
    data[off(0):off(0) + ANCHOR_LEN] = _rand(i, ANCHOR_LEN)
    data[off(CONST_DELTA):off(CONST_DELTA) + 16] = CONST
    data[off(VERIFIED_DELTA):off(VERIFIED_DELTA) + 32] = _verified(i)
    ptr = (0x500000 + i * 0x1000 + 0x20).to_bytes(8, "little")
    data[off(POINTER_DELTA):off(POINTER_DELTA) + 8] = ptr
    data[off(SMALL_DELTA)] = 0x10 if i % 2 else 0x90
    captured = np.ones(LENGTH, dtype=bool)
    if i == 2:
        captured[HOLE[0]:HOLE[1]] = False
    if mutate:
        mutate(i, data, captured)
    anchor = Anchor(dump_path=f"d{i}", offset=1000 + i, view="va", va=_va(i))
    return InstanceWindow(anchor=anchor, data=bytes(data), captured=captured)


def _consensus(mutate=None):
    return anchor_consensus([_window(i, mutate) for i in range(N)], delta_start=DELTA_START)


def _by_kind(proposal, kind):
    return [f for f in proposal.fields if f.kind == kind]


def _at(proposal, delta):
    return next(f for f in proposal.fields if f.delta == delta)


def _needles():
    return {"client_random": [_verified(i) for i in range(N)]}


def _full(**kw):
    kw.setdefault("related", _needles())
    kw.setdefault("captured_runs_of", _runs)
    return propose_layout(_consensus(), anchor_length=ANCHOR_LEN, **kw)


def test_anchor_field_covers_anchor_length_at_delta_zero():
    f = _by_kind(_full(), "anchor")
    assert [(x.delta, x.length) for x in f] == [(0, ANCHOR_LEN)]


def test_constant_block_is_proposed_as_constant():
    f = _at(_full(), CONST_DELTA)
    assert (f.kind, f.length) == ("constant", 16)


def test_verified_field_found_at_same_delta_in_every_instance():
    f = _at(_full(), VERIFIED_DELTA)
    assert (f.kind, f.length, f.name) == ("verified_field", 32, "client_random")
    assert "4/4" in f.evidence[0]


def test_verified_needle_missing_in_one_instance_not_claimed():
    needles = _needles()
    needles["client_random"][1] = None
    assert not _by_kind(_full(related=needles), "verified_field")


def test_verified_needle_at_different_delta_in_one_instance_not_claimed():
    def move(i, data, captured):
        if i == 1:
            old = _verified(1)
            at = bytes(data).find(old)
            data[at:at + 32] = bytes(32 * [0x42])
            data[200:232] = old
    proposal = propose_layout(_consensus(move), anchor_length=ANCHOR_LEN, related=_needles())
    assert not _by_kind(proposal, "verified_field")


def test_verified_needle_appearing_twice_in_window_not_claimed():
    def duplicate(i, data, captured):
        if i == 3:
            data[200:232] = _verified(3)
    proposal = propose_layout(_consensus(duplicate), anchor_length=ANCHOR_LEN, related=_needles())
    assert not _by_kind(proposal, "verified_field")


def test_verified_needle_over_uncaptured_bytes_not_claimed():
    def uncapture(i, data, captured):
        if i == 0:
            captured[88:92] = False
    proposal = propose_layout(_consensus(uncapture), anchor_length=ANCHOR_LEN, related=_needles())
    assert not _by_kind(proposal, "verified_field")


def test_pointer_into_captured_run_in_all_instances_is_proposed():
    f = _at(_full(), POINTER_DELTA)
    assert (f.kind, f.length) == ("pointer", 8)
    assert "4/4" in f.evidence[0]


def test_pointer_requires_quorum_of_instances():
    runs_two = lambda i: _runs(i) if i < 2 else []  # noqa: E731
    assert not _by_kind(_full(captured_runs_of=runs_two), "pointer")
    assert [p.delta for p in _by_kind(_full(captured_runs_of=runs_two, pointer_quorum=2), "pointer")] == [POINTER_DELTA]


def test_value_outside_captured_runs_is_not_a_pointer():
    assert not _by_kind(_full(captured_runs_of=lambda i: [(0x900000, 0x10)]), "pointer")


def test_no_pointers_without_captured_runs_callable():
    assert not _by_kind(propose_layout(_consensus(), anchor_length=ANCHOR_LEN), "pointer")


def test_small_set_byte_is_proposed_as_small_set():
    f = _at(_full(), SMALL_DELTA)
    assert (f.kind, f.length) == ("small_set", 1)


def test_four_distinct_values_are_variable_and_wide_run_lists_alternative():
    f = _at(_full(), DELTA_START)  # window start, nothing special there
    assert f.kind == "variable"
    assert any("several adjacent fields" in a for a in f.alternatives)


def test_hole_in_one_instance_is_undetermined():
    undetermined = _by_kind(_full(), "undetermined")
    assert [(f.delta, f.length) for f in undetermined] == [(HOLE[0] + DELTA_START, HOLE[1] - HOLE[0])]


def test_fields_are_sorted_and_non_overlapping():
    fields = _full().fields
    assert [f.delta for f in fields] == sorted(f.delta for f in fields)
    assert all(a.delta + a.length <= b.delta for a, b in zip(fields, fields[1:]))


def test_fields_tile_the_whole_window():
    fields = _full().fields
    assert sum(f.length for f in fields) == LENGTH


def _chunk_agree(i, va):
    return (va - 80, 0x200)


def test_agreeing_chunks_propose_object_bounds():
    p = _full(chunk_of=_chunk_agree)
    assert (p.base_delta, p.total_size) == (-80, 0x200)
    assert "4/4" in p.bounds_evidence[0] and not p.warnings


def test_disagreeing_chunks_warn_and_propose_no_bounds():
    p = _full(chunk_of=lambda i, va: (va - 80, 0x200 if i else 0x300))
    assert p.base_delta is None and p.total_size is None
    assert len(p.warnings) == 1 and "disagree" in p.warnings[0]


def test_chunk_missing_in_one_instance_warns_and_proposes_no_bounds():
    p = _full(chunk_of=lambda i, va: None if i == 2 else (va - 80, 0x200))
    assert p.base_delta is None and "no allocator chunk" in p.warnings[0]


def test_to_structure_rebases_offsets_to_base_delta_and_drops_undetermined():
    s = _full(chunk_of=_chunk_agree).to_structure("obj", library="lib")
    assert (s.name, s.total_size, s.library, s.stability) == ("obj", 0x200, "lib", "experimental")
    assert s.field_by_name("anchor").offset == 80
    assert s.field_by_name("client_random").offset == VERIFIED_DELTA + 80
    assert not [f for f in s.fields if f.name.startswith("undetermined")]


def test_to_structure_drops_fields_outside_object_bounds():
    s = _full(chunk_of=lambda i, va: (va - 8, 0x40)).to_structure("obj")
    assert s.total_size == 0x40
    assert all(0 <= f.offset and f.offset + f.size <= 0x40 for f in s.fields)
    assert s.field_by_name("client_random") is None


def test_to_structure_types_and_constraints():
    s = _full(chunk_of=_chunk_agree).to_structure("obj")
    assert s.field_by_name("anchor").constraints == {"not_zero": True}
    assert s.field_by_name("client_random").constraints == {"not_zero": True}
    pointer = next(f for f in s.fields if f.field_type is FieldType.POINTER)
    assert pointer.offset == POINTER_DELTA + 80 and pointer.constraints == {}


def test_to_structure_without_bounds_uses_window_as_structure():
    p = _full()
    s = p.to_structure("obj")
    assert s.total_size == LENGTH
    assert s.field_by_name("anchor").offset == -DELTA_START
    assert len(s.fields) == len(p.fields) - len(_by_kind(p, "undetermined"))


def test_default_names_encode_signed_delta():
    p = _full()
    assert _at(p, CONST_DELTA).to_dict()["name"] == "constant_m40"
    assert _at(p, POINTER_DELTA).to_dict()["name"] == "pointer_p20"


def test_proposal_to_dict_is_json_shaped():
    d = _full(chunk_of=_chunk_agree).to_dict()
    assert d["base_delta"] == -80 and d["fields"][0]["delta"] == DELTA_START


def test_window_not_containing_the_anchor_is_refused():
    cons = anchor_consensus([_window(i) for i in range(N)], delta_start=DELTA_START)
    shifted = anchor_consensus([_window(i) for i in range(N)], delta_start=8)
    with pytest.raises(ValueError, match="contain the anchor"):
        propose_layout(shifted, anchor_length=ANCHOR_LEN)
    short = anchor_consensus([_window(i) for i in range(N)], delta_start=DELTA_START)
    with pytest.raises(ValueError, match="contain the anchor"):
        propose_layout(short, anchor_length=LENGTH - DELTA_START + 1)
    assert propose_layout(cons, anchor_length=ANCHOR_LEN).fields


def test_claim_never_clamps_silently():
    from memdiver.engine.layout_proposal import _claim

    cons = _consensus()
    claimed = np.zeros(cons.length, dtype=bool)
    with pytest.raises(ValueError, match="outside the window"):
        _claim(cons, claimed, DELTA_START - 4, 8, "pointer", "", [])
    assert not claimed.any()


def _pointer_deltas(vas, quorum=2):
    # words hold a pointer at window offsets aligned for the instance's own VA
    def mutate(i, data, captured):
        phase = (-(vas[i] + DELTA_START)) % 8
        start = 192 + 16 * i + phase
        data[start:start + 8] = (0x500000 + i * 0x1000 + 0x20).to_bytes(8, "little")

    wins = []
    for i in range(2):
        w = _window(i, lambda j, d, c, i=i: mutate(i, d, c))
        wins.append(InstanceWindow(
            anchor=Anchor(f"d{i}", 1000 + i, "va", vas[i]), data=w.data, captured=w.captured))
    cons = anchor_consensus(wins, delta_start=DELTA_START)
    return propose_layout(cons, anchor_length=ANCHOR_LEN, captured_runs_of=_runs,
                          pointer_quorum=quorum)


def test_pointer_alignment_is_per_instance_with_warning():
    # instance 1's anchor VA is 4 mod 8: its aligned words sit 4 bytes later.
    proposal = _pointer_deltas([0x7F0000, 0x7F0004], quorum=1)
    ptrs = [f for f in proposal.fields if f.kind == "pointer"]
    assert {p.delta for p in ptrs} - {POINTER_DELTA} == {64, 84}      # one per instance's own phase
    assert all("1/2" in p.evidence[0] for p in ptrs)
    assert any("differ mod 8" in w for w in proposal.warnings)
    aligned = _pointer_deltas([0x7F0000, 0x7F0000])
    assert not any("differ mod 8" in w for w in aligned.warnings)
