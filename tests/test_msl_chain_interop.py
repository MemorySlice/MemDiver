"""Cross-repo PrevHash chain interop: memslicer-written files must pass
MemDiver's ``verify_chain`` (spec §4.4: Block 0 PrevHash = hash of the file
header, all HeaderSize bytes as stored on disk).

Skipped when the sibling ``memslicer`` package is not importable.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

pytest.importorskip("blake3")
pytest.importorskip("memslicer.msl.writer")

from memslicer.msl.constants import CompAlgo, PageState  # noqa: E402
from memslicer.msl.types import FileHeader, MemoryRegion, ProcessIdentity  # noqa: E402
from memslicer.msl.writer import MSLWriter  # noqa: E402

from memdiver.msl.hashing import hash_bytes  # noqa: E402
from memdiver.msl.integrity import verify_chain  # noqa: E402
from memdiver.msl.reader import MslReader  # noqa: E402

_REPO = Path(__file__).resolve().parent.parent
_FIXTURE = _REPO / "tests" / "fixtures" / "android" / "memslicer_android.msl"
_FIXTURE_TOOL = _REPO.parent / "memslicer" / "tests" / "tools" / "make_android_fixture.py"


def _write_memslicer(path: Path, comp_algo: CompAlgo) -> Path:
    with path.open("wb") as f:
        w = MSLWriter(f, FileHeader(pid=4242), comp_algo=comp_algo)
        w.write_process_identity(ProcessIdentity(ppid=1, exe_path="/bin/x", cmd_line="x"))
        w.write_memory_region(MemoryRegion(
            base_addr=0x10000, region_size=8192, protection=3,
            page_states=[PageState.CAPTURED, PageState.CAPTURED],
            page_data_chunks=[b"\x41" * 4096, b"\x42" * 4096],
        ))
        w.finalize()
    return path


def _assert_chain_ok(path: Path, min_blocks: int = 3) -> None:
    raw = path.read_bytes()
    hs = raw[9]
    assert raw[hs + 0x30:hs + 0x50] == hash_bytes(raw[:hs]), "Block 0 != hash(header)"
    with MslReader(path) as reader:
        report = verify_chain(reader)
    assert report.valid, report.errors
    assert report.block_count >= min_blocks


@pytest.mark.parametrize("comp_algo", [CompAlgo.NONE, CompAlgo.ZSTD, CompAlgo.LZ4])
def test_memslicer_writer_passes_verify_chain(tmp_path, comp_algo):
    if comp_algo == CompAlgo.ZSTD:
        pytest.importorskip("zstandard")
    if comp_algo == CompAlgo.LZ4:
        pytest.importorskip("lz4")
    _assert_chain_ok(_write_memslicer(tmp_path / f"ms_{comp_algo.name}.msl", comp_algo))


def test_checked_in_android_fixture_passes_verify_chain():
    if not _FIXTURE.exists():
        pytest.skip("memslicer_android.msl fixture not present")
    _assert_chain_ok(_FIXTURE)


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
    _assert_chain_ok(out)
