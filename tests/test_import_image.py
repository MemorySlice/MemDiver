"""Process-from-image extraction to .msl (msl/image_extract.py)."""

import json
import os
from pathlib import Path

import pytest

from memdiver.app.tools_inspect import vas_regions_result
from memdiver.mcp_server.session import ToolSession
from memdiver.core.dump_source import open_dump
from memdiver.core.image.adapters import Vma
from memdiver.core.image.run_index import LayerRun, RunState
from memdiver.core.image.sources import Vol3LayerSource
from memdiver.core.image.view_descriptor import ProfileRef, ViewDescriptor, ViewKind
from memdiver.msl.enums import (PageState, RegionType, SourceFormat, VasNameSource)
from memdiver.msl.image_extract import extract_process_to_msl
from memdiver.msl.reader import MslReader
from memdiver.msl.types import PhysicalRange
from memdiver.msl.writer import CapBit

C, F, N = RunState.CAPTURED, RunState.FAILED, RunState.NOT_RESIDENT
P = 0x1000
BASE = 0x400000
# libc image mapping: C C | F ; heap: C N N C ; stack: N ; anon: C
VMAS = [Vma(BASE, BASE + 3 * P, "/usr/lib/libc.so.6", "r-x", False, True),
        Vma(BASE + 0x10000, BASE + 0x14000, "[heap]", "rw-", True, False),
        Vma(BASE + 0x20000, BASE + 0x21000, "[stack]", "rw-", False, False),
        Vma(BASE + 0x30000, BASE + 0x31000, "", "rw-", False, False),
        Vma(BASE + 0x40000, BASE + 0x41000, "/etc/data.bin", "r--", False, True)]
RUNS = [LayerRun(BASE, 2 * P, C), LayerRun(BASE + 2 * P, P, F),
        LayerRun(BASE + 0x10000, P, C), LayerRun(BASE + 0x11000, 2 * P, N),
        LayerRun(BASE + 0x13000, P, C), LayerRun(BASE + 0x20000, P, N),
        LayerRun(BASE + 0x30000, P, C), LayerRun(BASE + 0x40000, P, C)]


def _byte(addr):
    return (addr // P * 31 + addr) % 250 + 1


class FakeProcAdapter:
    def __init__(self):
        self.reads = []

    def runs(self):
        return RUNS

    def vmas(self):
        return VMAS

    def read(self, address, length):
        assert any(r.state is C and r.start <= address and address + length <= r.end
                   for r in RUNS), f"non-captured read {address:#x}+{length:#x}"
        self.reads.append((address, length))
        return bytes(_byte(a) for a in range(address, address + length)) \
            if length < 64 else bytes(_byte(address + i) for i in range(length))

    def describe(self):
        return {"view": "process", "pid": 4242, "comm": "victim", "process_dtb": 0x1234000}

    def close(self):
        pass


@pytest.fixture
def source(tmp_path):
    (tmp_path / "img.lime").write_bytes(b"\x00" * 5000)
    desc = ViewDescriptor("img.lime", "ab" * 32, ViewKind.PROCESS, pid=4242,
                          profile=ProfileRef("p.json"))
    path = desc.write(tmp_path / "v.mdview")
    adapter = FakeProcAdapter()
    src = Vol3LayerSource(path, adapter_factory=lambda d, p: adapter)
    src.open()
    yield src
    src.close()


def _extract(source, tmp_path, **kw):
    out = tmp_path / "proc.msl"
    res = extract_process_to_msl(source, out, note_fields={"image_sha256": "ab" * 32}, **kw)
    return out, res


def test_states_bytes_and_result(source, tmp_path):
    out, res = _extract(source, tmp_path)
    assert res.pid == 4242 and res.regions_written == 5
    assert res.captured_bytes == 6 * P
    assert res.state_bytes == {"captured": 6 * P, "failed": P, "not_resident": 3 * P}
    with MslReader(out) as r:
        regions = {g.base_addr: g for g in r.collect_regions()}
        libc = regions[BASE]
        assert [int(s) for s in libc.page_states] == [0, 0, 1]
        heap = regions[BASE + 0x10000]
        assert [int(s) for s in heap.page_states] == [0, 3, 3, 0]
        assert int(regions[BASE + 0x20000].page_states[0]) == int(PageState.NOT_RESIDENT)
        assert int(heap.region_type) == RegionType.HEAP
        assert int(libc.region_type) == RegionType.IMAGE
        assert int(regions[BASE + 0x20000].region_type) == RegionType.STACK
        assert int(regions[BASE + 0x30000].region_type) == RegionType.ANONYMOUS
        assert int(regions[BASE + 0x40000].region_type) == RegionType.MAPPED_FILE
        assert r.file_header.pid == 4242 and r.file_header.imported
        assert r.file_header.cap_bitmap & CapBit.PAGE_STATES_INFERRED


def test_captured_bytes_equal_memory_and_never_read_noncaptured(source, tmp_path):
    out, _ = _extract(source, tmp_path)
    with open_dump(out) as d:
        data = d.read_all("vas")
    expected = b"".join(bytes(_byte(a) for a in range(r.start, r.end))
                        for r in RUNS if r.state is C)
    assert data == expected  # FakeProcAdapter.read asserts on non-captured reads


def test_vas_names_modules_and_provenance(source, tmp_path):
    out, _ = _extract(source, tmp_path, physical_ranges=[PhysicalRange(0, 0xFFFFF, "System RAM")])
    with MslReader(out) as r:
        entries = r.effective_vas_map().entries
        assert [e.mapped_path for e in entries] == [v.name for v in VMAS]
        assert all(e.name_source == VasNameSource.SOURCE_METADATA for e in entries)
        prov = r.collect_import_provenance()[0]
        assert prov.source_format == 0xFFFF == SourceFormat.OTHER
        assert prov.tool_name == "memdiver" and prov.orig_file_size == 5000
        assert prov.note == ("physical-image extraction; image_sha256=" + "ab" * 32 +
                             "; pid=4242; comm=victim; dtb=0x1234000")
        assert [m.path for m in r.collect_modules()] == ["/usr/lib/libc.so.6", "/etc/data.bin"]
        assert r.collect_physical_memory_map()[0].rows[0].label == "System RAM"


def test_open_dump_and_vas_regions_result(source, tmp_path):
    out, _ = _extract(source, tmp_path)
    with open_dump(out) as d:
        assert d.size > 0
    res = vas_regions_result(ToolSession(), str(out))
    names = [e["mapped_path"] for e in res.payload["vas_entries"]]
    assert names == [v.name for v in VMAS]


# -- real data (gated) ---------------------------------------------------------------

_ROOT = os.environ.get("MEMDIVER_IMAGE_CORPUS", "")
_STEM = "alma-9_5.14.0-427.el9"


@pytest.mark.skipif(
    not (_ROOT and all((Path(_ROOT) / f"{_STEM}{e}").is_file() for e in (".lime", ".gt.isf.json"))),
    reason="set MEMDIVER_IMAGE_CORPUS to a dir with the alma-9 .lime + .gt.isf.json")
def test_alma9_pid_22176_extraction(tmp_path, monkeypatch):
    from memdiver.app.tools_heap import heap_detect_result
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "home"))
    corpus = Path(_ROOT)
    sha = "c9" * 32
    desc = ViewDescriptor(str(corpus / f"{_STEM}.lime"), sha, ViewKind.PROCESS, pid=22176,
                          profile=ProfileRef(str(corpus / f"{_STEM}.gt.isf.json"),
                                             sha256=sha, origin="pakunoda"))
    view = desc.write(tmp_path / "p.mdview")
    out = tmp_path / "p22176.msl"
    with open_dump(view) as src:
        res = extract_process_to_msl(src, out, note_fields={"image_sha256": sha})
    assert res.captured_bytes == 7823360
    assert res.state_bytes["failed"] == 13193216
    assert res.state_bytes["not_resident"] == 626688
    payload = heap_detect_result(ToolSession(), str(out)).payload
    assert payload["best"] == "ptmalloc2"
