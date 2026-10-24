"""Cross-repo integrity interop between memslicer and MemDiver.

memslicer-written files must pass MemDiver's ``verify_chain`` (spec §4.4:
Block 0 PrevHash = hash of the file header; §4.5: EoC FileHash and
BlockCount; §4.6: extension segments), and MemDiver-written files with an
extension segment must pass memslicer's ``verify_slice``.

Skipped when the sibling ``memslicer`` package is not importable or too old.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

pytest.importorskip("blake3")
pytest.importorskip("memslicer.msl.writer")

try:
    from memslicer.msl.constants import CompAlgo, PageState, VasNameSource  # noqa: E402
    from memslicer.msl.types import (FileHeader, MemoryRegion, ProcessIdentity,  # noqa: E402
                                     RelatedDump, VasEntry)
    from memslicer.msl.verify import verify_slice  # noqa: E402
    from memslicer.msl.writer import MSLWriter  # noqa: E402
except ImportError as exc:
    pytest.skip(f"installed memslicer predates this interop (needs >= 0.5): {exc}",
                allow_module_level=True)

from memdiver.msl.enums import BlockType  # noqa: E402
from memdiver.msl.hashing import hash_bytes  # noqa: E402
from memdiver.msl.integrity import verify_chain  # noqa: E402
from memdiver.msl.reader import MslReader  # noqa: E402
from memdiver.msl.types import MslPointerGraphEdge, MslPointerGraphNode  # noqa: E402
from memdiver.msl.writer import MslWriter  # noqa: E402

_PRODUCER = "memslicer-interop-test/1"

_REPO = Path(__file__).resolve().parent.parent
_FIXTURE = _REPO / "tests" / "fixtures" / "android" / "memslicer_android.msl"
_FIXTURE_TOOL = _REPO.parent / "memslicer" / "tests" / "tools" / "make_android_fixture.py"


def _write_memslicer(path: Path, comp_algo: CompAlgo, *,
                     extension: bool = False) -> Path:
    """Process identity, one region, a VAS map, EoC; optionally one
    extension segment (a RelatedDump block) closed by End-of-Extension."""
    with path.open("wb") as f:
        w = MSLWriter(f, FileHeader(pid=4242), comp_algo=comp_algo)
        w.write_process_identity(ProcessIdentity(ppid=1, exe_path="/bin/x", cmd_line="x"))
        w.write_memory_region(MemoryRegion(
            base_addr=0x10000, region_size=8192, protection=3,
            page_states=[PageState.CAPTURED, PageState.CAPTURED],
            page_data_chunks=[b"\x41" * 4096, b"\x42" * 4096],
        ))
        w.write_vas_map([VasEntry(base_addr=0x10000, region_size=8192, protection=3,
                                  mapped_path="/bin/x", name_source=VasNameSource.LIVE)])
        w.finalize()
        if extension:
            w.begin_extension()
            w.write_related_dump(RelatedDump(related_dump_uuid=b"\x07" * 16,
                                             related_pid=1, relationship=0x0001))
            w.finalize_extension(_PRODUCER)
    return path


def _report(path: Path):
    with MslReader(path) as reader:
        return verify_chain(reader)


def _assert_chain_ok(path: Path, min_blocks: int = 3):
    raw = path.read_bytes()
    hs = raw[9]
    assert raw[hs + 0x30:hs + 0x50] == hash_bytes(raw[:hs]), "Block 0 != hash(header)"
    report = _report(path)
    assert report.valid, report.errors
    assert report.block_count >= min_blocks
    return report


def _assert_eoc_counts_and_hash(report) -> None:
    """A current memslicer writer records a 48-byte EoC with the exact
    capture-segment count and a FileHash MemDiver can recompute."""
    assert report.eoc_block_count == report.block_count, (
        report.eoc_block_count, report.block_count)
    assert report.block_count_ok
    assert report.file_hash_ok is True, report.warnings


@pytest.mark.parametrize("comp_algo", [CompAlgo.NONE, CompAlgo.ZSTD, CompAlgo.LZ4])
def test_memslicer_writer_passes_verify_chain(tmp_path, comp_algo):
    if comp_algo == CompAlgo.ZSTD:
        pytest.importorskip("zstandard")
    if comp_algo == CompAlgo.LZ4:
        pytest.importorskip("lz4")
    report = _assert_chain_ok(
        _write_memslicer(tmp_path / f"ms_{comp_algo.name}.msl", comp_algo))
    _assert_eoc_counts_and_hash(report)
    assert report.segments == [] and report.trailing_bytes == 0


def test_memslicer_vas_map_name_source_roundtrips(tmp_path):
    path = _write_memslicer(tmp_path / "vas.msl", CompAlgo.NONE)
    with MslReader(path) as reader:
        entries = reader.collect_vas_map()[0].entries
    assert [e.mapped_path for e in entries] == ["/bin/x"]
    assert entries[0].name_source == int(VasNameSource.LIVE)


def test_memslicer_extension_segment_passes_verify_chain(tmp_path):
    """One memslicer extension segment (spec 4.6) verifies in MemDiver:
    chained from H(EoC), SegmentHash and BlockCount exact, producer kept."""
    path = _write_memslicer(tmp_path / "ms_ext.msl", CompAlgo.NONE, extension=True)
    report = _assert_chain_ok(path)
    _assert_eoc_counts_and_hash(report)
    assert len(report.segments) == 1
    seg = report.segments[0]
    assert seg.verified, seg.errors
    assert seg.producer == _PRODUCER
    assert seg.block_count == 2  # RelatedDump + End-of-Extension
    assert report.trailing_bytes == 0
    assert report.warnings == []
    with MslReader(path) as reader:
        types = [h.block_type for h, _ in reader.iter_extension_blocks()]
        assert types == [BlockType.RELATED_DUMP, BlockType.END_OF_EXTENSION]
        eoe = reader.collect_end_of_extension()
        assert len(eoe) == 1 and eoe[0].producer == _PRODUCER
        assert eoe[0].block_count == 2
    # memslicer's own verifier agrees on its own output.
    with path.open("rb") as f:
        ms_report = verify_slice(f)
    assert ms_report.valid, ms_report.errors
    assert len(ms_report.segments) == 1 and ms_report.segments[0].verified


def test_memdiver_pointer_graph_segment_passes_memslicer_verify(tmp_path):
    """A MemDiver-written file with a pointer-graph segment verifies in
    memslicer: chain, FileHash, counts and the one extension segment."""
    path = tmp_path / "md_pg.msl"
    w = MslWriter(path, pid=7)
    w.add_memory_region(0x1000, b"\x11" * 4096)
    w.add_pointer_graph([MslPointerGraphNode(1, 0x1040, "n")],
                        [MslPointerGraphEdge(0, 0, 1, "self")],
                        producer="memdiver-interop-test/1")
    w.add_end_of_capture()
    w.write()
    with path.open("rb") as f:
        report = verify_slice(f)
    assert report.valid, report.errors
    assert report.errors == [] and report.warnings == []
    assert report.capture_ok and report.chain_ok
    assert report.file_hash_ok is True
    assert report.block_count == 2
    assert report.eoc_block_count == 2 and report.block_count_ok
    assert len(report.segments) == 1
    seg = report.segments[0]
    assert seg.verified
    assert seg.producer == "memdiver-interop-test/1"
    assert seg.block_count == seg.declared_block_count == 2
    assert report.trailing_bytes == 0


def test_checked_in_android_fixture_passes_verify_chain():
    if not _FIXTURE.exists():
        pytest.skip("memslicer_android.msl fixture not present")
    _assert_chain_ok(_FIXTURE)


def test_checked_in_android_fixture_has_eoc_count_and_live_vas_names():
    """Needs the fixture regenerated by a current memslicer: 48-byte EoC
    with BlockCount and VAS NameSource == LIVE."""
    if not _FIXTURE.exists():
        pytest.skip("memslicer_android.msl fixture not present")
    report = _assert_chain_ok(_FIXTURE)
    _assert_eoc_counts_and_hash(report)
    with MslReader(_FIXTURE) as reader:
        entries = reader.collect_vas_map()[0].entries
    assert entries and all(e.name_source == int(VasNameSource.LIVE) for e in entries)


def test_fixture_tool_output_passes_verify_chain(tmp_path):
    if not _FIXTURE_TOOL.exists():
        pytest.skip("memslicer fixture tool not checked out alongside")
    spec = importlib.util.spec_from_file_location("make_android_fixture", _FIXTURE_TOOL)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve annotations via sys.modules
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    out = tmp_path / "android.msl"
    module.build_android_fixture(out)
    _assert_eoc_counts_and_hash(_assert_chain_ok(out))
