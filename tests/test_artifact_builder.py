"""select_prefilter and build_structure_model."""

import numpy as np
import pytest

from memdiver.architect.artifact_model import Applicability, Evidence
from memdiver.engine.anchor_consensus import Anchor, InstanceWindow, anchor_consensus
from memdiver.engine.artifact_builder import FieldMeaning, build_structure_model, select_prefilter
from memdiver.engine.layout_proposal import propose_layout

N = 4
LENGTH = 256
DELTA_START = -128
ANCHOR_LEN = 16
CONST = bytes(range(0x21, 0x31))


def _rand(seed: int, n: int) -> bytes:
    return bytes(np.random.default_rng(seed).integers(1, 255, n, dtype=np.uint8).tolist())


def _windows(invariants, delta_start=DELTA_START, length=LENGTH):
    """*invariants*: {window_offset: bytes} written identically into every instance;
    everything else varies per instance (4 distinct values per position)."""
    out = []
    for i in range(N):
        data = bytearray((i * 50 + o * 7) % 256 for o in range(length))
        for off, blob in invariants.items():
            data[off:off + len(blob)] = blob
        anchor = Anchor(dump_path=f"d{i}", offset=1000, view="va", va=0x10000 * (i + 1))
        out.append(InstanceWindow(anchor, bytes(data), np.ones(length, dtype=bool)))
    return anchor_consensus(out, delta_start=delta_start)


def _zero_and_random():
    return _windows({0: bytes(100), 150: _rand(1, 32), 20: _rand(2, 20)})


def test_random_invariant_run_beats_longer_zero_run():
    c = _windows({0: bytes(100), 150: _rand(1, 32)})
    pf = select_prefilter(c, anchor_length=ANCHOR_LEN)
    start = pf.delta - DELTA_START
    assert start <= 150 and start + pf.length >= 182
    assert pf.informative_bytes == 32


def test_ff_run_is_also_uninformative():
    c = _windows({0: b"\xff" * 100, 150: _rand(1, 32)})
    assert select_prefilter(c, anchor_length=ANCHOR_LEN).informative_bytes == 32


def test_within_restricts_the_search_span():
    c = _zero_and_random()
    pf = select_prefilter(c, anchor_length=ANCHOR_LEN, within=(DELTA_START, DELTA_START + 100))
    assert pf.informative_bytes == 20
    start = pf.delta - DELTA_START
    assert 0 <= start and start + pf.length <= 100 and start <= 20 and start + pf.length >= 40


def test_raises_when_nothing_informative():
    with pytest.raises(ValueError, match="no window holds an informative"):
        select_prefilter(_windows({0: bytes(100)}), anchor_length=ANCHOR_LEN)


def test_raises_when_span_shorter_than_prefilter():
    with pytest.raises(ValueError, match="shorter than"):
        select_prefilter(_zero_and_random(), anchor_length=ANCHOR_LEN,
                         within=(DELTA_START, DELTA_START + 10))


def test_raises_when_prefilter_longer_than_window():
    with pytest.raises(ValueError, match="shorter than"):
        select_prefilter(_zero_and_random(), anchor_length=ANCHOR_LEN, length=LENGTH + 1)


def test_key_offset_is_anchor_position_relative_to_window_start():
    pf = select_prefilter(_zero_and_random(), anchor_length=ANCHOR_LEN, name="n")
    assert pf.pattern["key_offset"] == -pf.delta
    assert pf.pattern["key_length"] == ANCHOR_LEN and pf.pattern["name"] == "n"


def test_pattern_wildcards_variable_bytes_and_counts_static():
    pf = select_prefilter(_zero_and_random(), anchor_length=ANCHOR_LEN)
    tokens = pf.pattern["wildcard_pattern"].split()
    assert len(tokens) == pf.length
    assert pf.pattern["static_count"] == sum(t != "??" for t in tokens)
    assert pf.pattern["static_count"] + pf.pattern["volatile_count"] == pf.length
    assert len(pf.pattern["hex_pattern"].split()) == pf.length


# -- build_structure_model ------------------------------------------------------

def _fixture():
    data_needles = [_rand(100 + i, 32) for i in range(N)]
    windows = []
    for i in range(N):
        data = bytearray((i * 50 + o * 7) % 256 for o in range(LENGTH))
        data[64:80] = CONST
        data[88:120] = data_needles[i]
        data[128:144] = _rand(i, 16)
        anchor = Anchor(f"d{i}", 1000, "va", va=0x10000 * (i + 1))
        windows.append(InstanceWindow(anchor, bytes(data), np.ones(LENGTH, dtype=bool)))
    consensus = anchor_consensus(windows, delta_start=DELTA_START)
    proposal = propose_layout(consensus, anchor_length=ANCHOR_LEN,
                              related={"client_random": data_needles},
                              chunk_of=lambda i, va: (va - 80, 0x200))
    return consensus, proposal


def _build(**kw):
    consensus, proposal = _fixture()
    kw.setdefault("meanings", [FieldMeaning("client_random", "TLS client_random", "CR",
                                            (Evidence("experiment", "e1"),))])
    return build_structure_model(consensus, proposal, name="tls", anchor_length=ANCHOR_LEN, **kw)


def test_model_is_a_valid_structure_locator_anchored_on_anchor_field():
    m = _build()
    assert m.check() == []
    assert (m.locator.kind, m.locator.anchor_field) == ("structure", "anchor")
    assert m.layout.total_size == 0x200


def test_assertions_carry_meaning_label_and_support():
    (a,) = _build().assertions
    assert (a.field, a.meaning, a.label, a.support) == (
        "client_random", "TLS client_random", "CR", (Evidence("experiment", "e1"),))


def test_relationship_delta_and_support_come_from_the_proposal():
    m = _build(relationships=[("owned_by", "anchor", "client_random")])
    (r,) = m.relationships
    assert (r.kind, r.source, r.target, r.delta) == ("owned_by", "anchor", "client_random", -40)
    assert "-0x28" in r.description and "4 instances" in r.description
    assert all(e.kind == "consensus" for e in r.support) and len(r.support) == 2
    assert any("client_random found" in e.ref for e in r.support)


def test_learned_on_lists_every_instance_dump():
    assert _build().validation.learned_on == ("d0", "d1", "d2", "d3")
    assert _build().validation.verdict == "untested"


def test_applicability_is_kept_and_sets_layout_library():
    m = _build(applicability=Applicability(library="openssl", arch="x86_64"))
    assert m.applicability.arch == "x86_64" and m.layout.library == "openssl"


def test_prefilter_is_searched_inside_the_object_bounds():
    m = _build()
    assert m.locator.pattern["static_count"] >= 16
    assert "informative bytes" in m.description


def test_unknown_relationship_field_raises():
    with pytest.raises(ValueError, match="unproposed field"):
        _build(relationships=[("owned_by", "anchor", "ghost")])


def test_unknown_relationship_kind_raises_inconsistent_model():
    with pytest.raises(ValueError, match="inconsistent artifact model"):
        _build(relationships=[("friend", "anchor", "client_random")])


def test_assertion_on_unknown_field_raises_inconsistent_model():
    with pytest.raises(ValueError, match="inconsistent artifact model"):
        _build(meanings=[FieldMeaning("ghost", "x")])


def test_select_prefilter_never_matches_excluded_pointer_bytes_literally():
    """A pointer can be invariant only because the platform's address space is
    (aarch64 heap 0xaaaa...); excluded spans must become wildcards."""
    import numpy as np
    from memdiver.engine.anchor_consensus import Anchor, InstanceWindow, anchor_consensus
    from memdiver.engine.artifact_builder import select_prefilter
    body = bytes(range(1, 65))
    wins = [InstanceWindow(Anchor(f"d{i}", 64, va=0x1000 + 64), body + bytes([i * 7 % 251]) * 16,
                           np.ones(80, dtype=bool)) for i in range(4)]
    c = anchor_consensus(wins, delta_start=-64)
    plain = select_prefilter(c, anchor_length=16, length=32)
    hardened = select_prefilter(c, anchor_length=16, length=32, exclude=[(plain.delta, 8)])
    tokens = hardened.pattern["wildcard_pattern"].split()
    covered = range(plain.delta - hardened.delta, plain.delta - hardened.delta + 8)
    assert all(tokens[i] == "??" for i in covered if 0 <= i < len(tokens))
    assert hardened.informative_bytes <= plain.informative_bytes
