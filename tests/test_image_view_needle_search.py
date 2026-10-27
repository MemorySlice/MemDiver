"""Needle search, presence and VA reads over an image view (``Vol3LayerSource``).

Regressions: ``search_needles`` passed ``limit=`` to a ``find_all`` that had no
such parameter (TypeError on every needle search over an ``.mdview``), and
``heap.memory.VaMemory`` -- which keys VA support on ``va_to_vas_offset`` --
treated an image view as a flat file and read the IMAGE at ``offset = va``.
"""

from contextlib import ExitStack

import pytest

import memdiver.core.dump_search as dump_search
from memdiver.core.dump_search import present_needles
from memdiver.core.dump_source import find_all_in, find_first_in
from memdiver.core.image.run_index import LayerRun, RunState
from memdiver.core.image.sources import Vol3LayerSource
from memdiver.core.image.view_descriptor import ProfileRef, ViewDescriptor, ViewKind
from memdiver.engine.anchor_consensus import search_needles
from memdiver.heap.memory import VaMemory

C, N = RunState.CAPTURED, RunState.NOT_RESIDENT
SHA = "ab" * 32
#: two captured runs separated by a non-resident gap; span starts at 0x10000
RUNS = [LayerRun(0x10000, 0x2000, C), LayerRun(0x12000, 0x1000, N),
        LayerRun(0x13000, 0x1000, C)]
NEEDLE = b"SECRET-NEEDLE-0123456789abcdef!!"  # 32 bytes


class _Adapter:
    def __init__(self, memory):
        self.memory = memory

    def runs(self):
        return RUNS

    def read(self, address, length):
        assert any(r.state is C and r.start <= address and address + length <= r.end
                   for r in RUNS), f"read outside a captured run: {address:#x}"
        return bytes(self.memory[address:address + length])

    def describe(self):
        return {"layer": "fake"}

    def close(self):
        pass


def _memory(plants=()):
    mem = bytearray(0x14000)
    for run in RUNS:
        if run.state is C:
            for i in range(run.start, run.end):
                mem[i] = (i * 13 + 5) % 251 + 1
    for va, data in plants:
        mem[va:va + len(data)] = data
    return mem


def _source(tmp_path, plants=()):
    # The IMAGE file is deliberately different from the view's bytes, so a read
    # that goes to the image instead of through the layer is detectable.
    (tmp_path / "img.bin").write_bytes(b"\xee" * 0x20000)
    desc = ViewDescriptor("img.bin", SHA, ViewKind.PROCESS, pid=7, profile=ProfileRef("p.json"))
    path = desc.write(tmp_path / "v.mdview")
    adapter = _Adapter(_memory(plants))
    src = Vol3LayerSource(path, adapter_factory=lambda d, p: adapter)
    src.open()
    return src


@pytest.fixture
def three_hits(tmp_path):
    plants = [(0x10100, NEEDLE), (0x11800, NEEDLE), (0x13010, NEEDLE)]
    src = _source(tmp_path, plants)
    yield src
    src.close()


# ---------------------------------------------------------------- item 1

def test_find_all_honours_limit(three_hits):
    assert three_hits.find_all(NEEDLE, view="va") == [0x100, 0x1800, 0x3010]
    assert three_hits.find_all(NEEDLE, view="va", limit=2) == [0x100, 0x1800]
    assert three_hits.find_all(NEEDLE, view="vas", limit=1) == [0x100]
    assert three_hits.find_all(NEEDLE, view="va", limit=0) == [0x100, 0x1800, 0x3010]
    assert find_all_in(three_hits, NEEDLE, "vas", limit=5) == [0x100, 0x1800, 0x2010]


@pytest.mark.parametrize("view", ["va", "vas"])
def test_search_needles_over_image_view(three_hits, view):
    full = search_needles({"d": three_hits}, {"d": NEEDLE}, view=view, max_hits=10)["d"]
    assert not full.truncated and len(full.anchors) == 3
    capped = search_needles({"d": three_hits}, {"d": NEEDLE}, view=view, max_hits=2)["d"]
    assert capped.truncated and [a.offset for a in capped.anchors] == [
        a.offset for a in full.anchors[:2]]
    if view == "va":
        assert [a.va for a in full.anchors] == [0x10100, 0x11800, 0x13010]


def test_keylog_and_semantic_presence_over_image_view(three_hits):
    from memdiver.app.tools_semantic import _present_in, _present_many
    from memdiver.engine.keylog_anchors import _present, _present_set

    other = b"Z" * 32
    assert _present(three_hits, "d", NEEDLE, "va") and not _present(three_hits, "d", other, "va")
    assert _present_set(three_hits, "d", [NEEDLE, other], "va") == {NEEDLE}
    assert _present_in(three_hits, "va", NEEDLE)
    assert _present_many(three_hits, "va", [NEEDLE, other]) == {NEEDLE}


# ------------------------------------------------- present_needles strategy

def _per_needle(src, needles, view):
    return {n for n in needles if find_first_in(src, n, view) is not None}


@pytest.mark.parametrize("view", ["va", "vas"])
def test_present_needles_matches_per_needle_search(tmp_path, monkeypatch, view):
    monkeypatch.setattr(dump_search, "_PRESENCE_WINDOW", 0x100)  # many windows
    across_window = b"W" * 40
    straddles_gap = b"G" * 16
    plants = [(0x100f0, across_window),            # crosses a 0x100 window boundary
              (0x11ff8, straddles_gap[:8]),        # end of run 1 ...
              (0x13000, straddles_gap[8:]),        # ... start of run 2 (packed: adjacent)
              (0x13ff0, NEEDLE[:16])]              # tail of the last run
    src = _source(tmp_path, plants)
    try:
        needles = [across_window, straddles_gap, NEEDLE[:16], NEEDLE, b"\x00" * 8]
        expected = _per_needle(src, needles, view)
        assert across_window in expected and NEEDLE[:16] in expected
        assert straddles_gap not in expected  # never matched across a gap
        assert present_needles(src, needles, view, lambda n: pytest.fail("fallback")) \
            == expected
    finally:
        src.close()


# ---------------------------------------------------------------- items 2 + 3

def test_va_to_vas_offset(three_hits):
    assert three_hits.va_to_vas_offset(0x10000) == 0
    assert three_hits.va_to_vas_offset(0x13010) == 0x2010
    assert three_hits.va_to_vas_offset(0x12800) is None   # not resident
    assert three_hits.va_to_vas_offset(0x9000) is None    # unmapped
    assert three_hits.va_to_vas_offset(0x14000) is None   # past the end


def test_va_memory_reads_the_view_not_the_image_file(three_hits):
    memory = VaMemory(three_hits)
    assert memory.base_va is None  # VA-mapped, not flat mode over the image file
    assert memory.read(0x13010, len(NEEDLE)) == NEEDLE
    assert memory.read(0x10100, 8) == NEEDLE[:8]
    assert memory.read(0x12000, 8) is None          # not-resident gap
    assert memory.read(0x11ffc, 8) is None          # range runs into the gap
    assert memory.va_to_view_offset(0x13010, "vas") == 0x2010
    assert memory.view_offset_to_va(0x2010, "vas") == 0x13010


# ---------------------------------------------------------------- item 4

class _Session:
    def __init__(self, client_random, secrets):
        self.client_random, self.secrets = client_random, secrets


def test_shared_expected_is_one_presence_pass_with_same_answer(three_hits, monkeypatch):
    import memdiver.app.tools_semantic as sem

    cr_present, cr_absent = NEEDLE[::-1], b"R" * 32
    sessions = [_Session(b"A" * 32, {"L": NEEDLE}),      # secret present
                _Session(cr_absent, {"L": b"S" * 32}),   # nothing present
                _Session(cr_present, {"L": b"T" * 32})]  # only client_random present
    calls = []
    real = sem._present_many
    monkeypatch.setattr(sem, "_present_many",
                        lambda o, v, n: calls.append(list(n)) or real(o, v, n))
    # plant the present client_random
    three_hits._adapter.memory[0x10400:0x10420] = cr_present
    note = []
    out = sem._shared_expected(sessions, three_hits, ["L"], note)
    assert len(calls) == 1
    assert out == {("L", (b"A" * 32).hex(), NEEDLE.hex())}
    assert note == [cr_present.hex()]


def test_score_one_checks_va_precondition_before_scanning(monkeypatch):
    import memdiver.app.tools_consensus as tc
    import memdiver.app.tools_semantic as sem
    from memdiver.core.service_errors import CapabilityError

    class _NoVa:
        format_name, path = "raw", "x"

        def va_span_start(self):
            return None

    monkeypatch.setattr(tc, "_open_one", lambda stack, path, km: _NoVa())
    monkeypatch.setattr(sem, "_expected_triples",
                        lambda *a, **k: pytest.fail("scanned a refused capture"))
    monkeypatch.setattr(sem, "_no_va_view_message", lambda *a: "no va view")
    with ExitStack() as stack, pytest.raises(CapabilityError) as exc:
        sem._score_one(stack, "src", {"dump_path": "/tmp/x.dump"}, ["L"], 16)
    assert exc.value.code == "semantic.no_va_view"
