"""Exporters (analysis/exporters.py): producers -> case tables, queried back."""

import pytest

import memdiver.core.image.context as image_context
from memdiver.analysis.capture_id import capture_id_for
from memdiver.analysis.case import Case
from memdiver.analysis.context import locate_context
from memdiver.analysis import exporters
from memdiver.core.image.adapters import Vma
from memdiver.core.image.run_index import LayerRun, RunState
from memdiver.core.image.sources import Vol3LayerSource
from memdiver.core.image.view_descriptor import ProfileRef, ViewDescriptor, ViewKind
from memdiver.core.location import AddressSpace, Location
from memdiver.engine.yara_scan import RuleMatch
from memdiver.msl.enums import ArchType, OSType, PageState
from memdiver.msl.types import MslVasEntry
from memdiver.msl.writer import MslWriter
from tests.fixtures import synth_heap as sh

SHA = "ab" * 32
PAGE = 0x1000
C, F = PageState.CAPTURED, PageState.FAILED


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    return Case.init(tmp_path / "case")


def _rows(case, sql):
    return case.query(sql).table.to_pylist()


def _write_msl(path, states=(C, F, C)):
    writer = MslWriter(str(path), pid=7, imported=False)
    writer.add_process_identity(exe_path="/proc")
    captured = sum(1 for s in states if s == C)
    writer.add_memory_region(0x10000, b"\xaa" * PAGE * captured, page_states=list(states))
    writer.add_vas_map([MslVasEntry(0x10000, PAGE * len(states), 0x03, 0, "[heap]")])
    writer.add_end_of_capture()
    writer.write()
    return str(path)


# ------------------------------------------------------------- capture_id

def test_capture_id_mdview(tmp_path):
    (tmp_path / "i.bin").write_bytes(b"x")
    path = ViewDescriptor("i.bin", SHA, ViewKind.PHYSICAL).write(tmp_path / "v.mdview")
    assert capture_id_for(path) == SHA


def test_capture_id_msl_uses_stored_hash_without_rehash(tmp_path, monkeypatch):
    path = _write_msl(tmp_path / "a.msl")

    def boom(_p):
        raise AssertionError("file was re-hashed")

    monkeypatch.setattr(image_context, "_hash_file", boom)
    cid = capture_id_for(path)
    from memdiver.msl.reader import MslReader
    with MslReader(__import__("pathlib").Path(path)) as r:
        assert cid == r.collect_end_of_capture()[-1].file_hash.hex()
    assert len(cid) == 64 and cid != "0" * 64


def test_capture_id_plain_file(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    f = tmp_path / "x.bin"
    f.write_bytes(b"hello")
    import hashlib
    assert capture_id_for(f) == hashlib.sha256(b"hello").hexdigest()


# ------------------------------------------------------------- view regions

class _Adapter:
    def __init__(self, runs, vmas):
        self._runs, self._vmas = runs, vmas

    def runs(self):
        return self._runs

    def vmas(self):
        return self._vmas

    def read(self, a, n):
        return bytes(n)

    def describe(self):
        return {}

    def close(self):
        pass


def _source(tmp_path, kind, adapter):
    (tmp_path / "img.bin").write_bytes(b"\0" * 64)
    kw = dict(pid=42, profile=ProfileRef("p.json")) if kind is ViewKind.PROCESS else {}
    path = ViewDescriptor("img.bin", SHA, kind, **kw).write(tmp_path / "v.mdview")
    return Vol3LayerSource(path, adapter_factory=lambda d, p: adapter)


RUNS = [LayerRun(0x1000, 0x2000, RunState.CAPTURED),
        LayerRun(0x3000, 0x1000, RunState.NOT_RESIDENT)]
VMAS = [Vma(0x1000, 0x3000, "[heap]", "rw-", True), Vma(0x3000, 0x4000, "lib", "r-x", False)]


def test_export_view_regions_process(case, tmp_path):
    with _source(tmp_path, ViewKind.PROCESS, _Adapter(RUNS, VMAS)) as src:
        ref = exporters.export_view_regions(case, src, run_id="r1")
    assert ref.name == "view_runs"
    assert _rows(case, "SELECT count(*) AS n FROM view_runs")[0]["n"] == 2
    row = _rows(case, "SELECT pid, space, capture_id, image_sha256, state FROM view_runs "
                      "ORDER BY addr")[1]
    assert (row["pid"], row["space"], row["capture_id"], row["state"]) == (
        42, "process_va", SHA, "not_resident")
    assert _rows(case, "SELECT count(*) AS n FROM proc_maps")[0]["n"] == 2
    loc = Location(AddressSpace.PROCESS_VA, 0x2000, capture_id=SHA, pid=42)
    stack = locate_context(case, loc)
    assert {l.name for l in stack.layers} >= {"view_runs", "proc_maps"}


def test_export_view_regions_physical_has_no_proc_maps(case, tmp_path):
    adapter = _Adapter(RUNS, VMAS)
    del_adapter = type("A", (), {k: getattr(adapter, k) for k in
                                 ("runs", "read", "describe", "close")})()
    with _source(tmp_path, ViewKind.PHYSICAL, del_adapter) as src:
        exporters.export_view_regions(case, src)
    assert "proc_maps" not in case.tables()
    assert _rows(case, "SELECT DISTINCT space FROM view_runs")[0]["space"] == "physical"


# ------------------------------------------------------------- msl

def test_export_msl_regions_and_page_states(case, tmp_path):
    path = _write_msl(tmp_path / "a.msl")
    exporters.export_msl_regions(case, path)
    exporters.export_page_state_runs(case, path)
    row = _rows(case, "SELECT addr, size, space, pid, mapped_path FROM msl_regions")[0]
    assert (row["addr"], row["size"], row["space"], row["pid"]) == (0x10000, 3 * PAGE, "msl_va", 7)
    assert _rows(case, "SELECT count(*) AS n FROM msl_page_states")[0]["n"] >= 1
    failed = _rows(case, "SELECT addr, size FROM msl_page_states WHERE state='FAILED'")[0]
    assert (failed["addr"], failed["size"]) == (0x11000, PAGE)
    cid = capture_id_for(path)
    stack = locate_context(case, Location(AddressSpace.MSL_VA, 0x11800, capture_id=cid, pid=7))
    assert {l.name for l in stack.layers} == {"msl_regions", "msl_page_states"}


# ------------------------------------------------------------- heap

def test_export_heap_chunks(case, tmp_path):
    heap = sh.glibc_heap()
    path = tmp_path / "h.msl"
    writer = MslWriter(str(path), os_type=OSType.LINUX, arch_type=ArchType.X86_64, imported=True)
    vas = []
    for idx, (va, size, name) in enumerate(heap.regions):
        writer.add_memory_region(va, heap.region_bytes(idx), protection=0x03)
        vas.append(MslVasEntry(va, size, 0x03, 0, name))
    writer.add_vas_map(vas)
    writer.add_end_of_capture()
    writer.write()
    ref = exporters.export_heap_chunks(case, str(path))
    assert ref.name == "heap_chunks"
    n = _rows(case, "SELECT count(*) AS n FROM heap_chunks")[0]["n"]
    assert n > 0 and _rows(case, "SELECT DISTINCT space FROM heap_chunks")[0]["space"] == "msl_va"
    first = _rows(case, "SELECT addr FROM heap_chunks ORDER BY addr LIMIT 1")[0]["addr"]
    stack = locate_context(case, Location(AddressSpace.MSL_VA, first, capture_id=capture_id_for(path)))
    assert [l.name for l in stack.layers] == ["heap_chunks"]


# ------------------------------------------------------------- yara

def test_export_yara_matches(case):
    ms = [RuleMatch("r1", ("a", "b"), "$s", 0x500, 16, "00", 4, 8),
          RuleMatch("r2", (), "$t", 0x900, 4, "00", None, None)]
    exporters.export_yara_matches(case, ms, capture_id="cap1", space="process_va", pid=3)
    rows = _rows(case, "SELECT rule, addr, size, pid, tags, key_offset FROM yara_hits ORDER BY addr")
    assert [(r["rule"], r["addr"], r["size"], r["pid"]) for r in rows] == [
        ("r1", 0x500, 16, 3), ("r2", 0x900, 4, 3)]
    assert rows[0]["tags"] == "a,b" and rows[1]["key_offset"] is None
    stack = locate_context(case, Location(AddressSpace.PROCESS_VA, 0x505, capture_id="cap1", pid=3))
    assert [l.name for l in stack.layers] == ["yara_hits"]
