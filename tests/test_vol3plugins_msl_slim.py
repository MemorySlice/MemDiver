"""The standard-library ``.msl`` reader ``vol3plugins/msl_slim.py`` (MemDiver-less fallback).

Claim C-SLIM1: on every capture both readers can open, the slim reader and MemDiver's reader
give ``msl_layer`` identical regions, page states, VAs, stream offsets, metadata, region
maps and bytes, so the layers stacked on a ``.msl`` look the same to a plugin whichever
reader is behind them. Checked on the small fixtures, a synthetic slice with every page
state, every run of the gocryptfs corpus (structure plus sampled windows) and a sample of
runs byte for byte.

Also: features the slim reader cannot serve (encryption, zstd/lz4) fail with one line naming
``pip install memdiver``; corrupt and truncated input fails cleanly and fast; and the slim
reader is chosen only when ``import memdiver`` fails.
"""

import ast
import hashlib
import json
import os
import random
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

pytest.importorskip("volatility3")

from volatility3.framework import exceptions  # noqa: E402

from memdiver.core.dump_source import open_dump  # noqa: E402
from memdiver.msl.enums import CompAlgo  # noqa: E402
from memdiver.msl.page_map import decode_page_intervals  # noqa: E402
from memdiver.msl.reader import MslReader  # noqa: E402
from memdiver.msl.writer import MslEncryptionConfig  # noqa: E402
from memdiver.vol3plugins import memdiver_stackers, msl_layer, msl_slim  # noqa: E402
from tests._oracle_gocryptfs_fixtures import GOCRYPTFS_CORPUS, RUN_0001_MASTER_HEX  # noqa: E402
from tests.test_vol3plugins_msl_layer import (  # noqa: E402
    C, NR, PAGE, RAW_KEY, REGION_A, STATES_A, _file_context, _write_slice)

FIXTURES = Path(__file__).parent / "fixtures"
FIXTURE_SLICES = [FIXTURES / "android" / "memslicer_android.msl",
                  FIXTURES / "dataset" / "msl" / "test_capture.msl"]
CHROME_MIN = FIXTURES / "real_samples" / "chrome_min.msl"
CORPUS_RUNS = sorted(GOCRYPTFS_CORPUS.glob("run_*/memslicer.msl"))
needs_corpus = pytest.mark.skipif(not CORPUS_RUNS, reason=f"corpus absent: {GOCRYPTFS_CORPUS}")
#: Every 12th run is compared byte for byte (8 of 95 runs, ~1.7 GB per reader).
BYTE_SAMPLE = CORPUS_RUNS[::12]
#: Where the run_0001 master key sits in the captured process (proven by the gocryptfs plugin).
RUN_0001_KEY_VA = 0xC0000BC220
PLUGIN_DIR = Path(msl_layer.__file__).resolve().parent


@pytest.fixture(autouse=True)
def _fresh_layer_cache():
    yield
    msl_layer.close_slices()


@pytest.fixture
def memdiver_blocked(monkeypatch):
    """``import memdiver`` raises ImportError, as in a Python without MemDiver."""
    monkeypatch.setitem(sys.modules, "memdiver", None)


@pytest.fixture
def all_states_slice(tmp_path):
    path = tmp_path / "all_states.msl"
    return path, _write_slice(path)


# ------------------------------------------------------------------------ helpers


def _memdiver_slice(path: Path) -> msl_layer.MslSlice:
    source = open_dump(path)
    source.open()
    return msl_layer.MslSlice(source)


def _slim_slice(path: Path) -> msl_layer.MslSlice:
    return msl_layer.MslSlice(msl_slim.MslSlimSource(str(path)).open())


def _region_rows(reader):
    return [(r.base_addr, r.region_size, r.protection, r.region_type, r.page_size,
             r.num_pages, [(i.start_page, i.count, int(i.state)) for i in r.page_intervals])
            for r in reader.collect_regions()]


def _structure(opened: msl_layer.MslSlice) -> dict:
    """Everything ``msl_layer`` derives from a reader, except page bytes."""
    meta = opened.describe()
    meta["msl_path"] = os.path.normpath(meta["msl_path"])
    return {
        "regions": _region_rows(opened.reader),
        "runs": [tuple(run[:5]) for run in opened.runs],
        "spans": opened.spans, "vas_starts": opened.vas_starts, "holes": opened.holes,
        "vas_size": opened.vas_size, "zero_size": opened.zero_size,
        "va_segments": opened.va_segments, "describe": meta,
        "region_map": opened.region_map(),
    }


def _read_pieces(opened: msl_layer.MslSlice, position: int, end: int):
    """``[(data or None, size)]``: what ``MslVasLayer.read`` sees between two offsets."""
    pieces = []
    while position < end:
        data, size = opened.piece(position, end)
        pieces.append((data, size))
        position += size
    return pieces


def _random_windows(opened: msl_layer.MslSlice, seed: int, count: int = 64):
    rng = random.Random(seed)
    limit = opened.stream_size + PAGE
    for _ in range(count):
        start = rng.randrange(-16, limit)
        yield start, start + rng.choice((1, 16, 64, PAGE, 3 * PAGE + 7))
    for va, mapped, length in opened.va_segments:  # every segment edge, both sides
        yield mapped - 8, mapped + 8
        yield mapped + length - 8, mapped + length + 8


def _assert_same(path: Path, seed: int = 0) -> int:
    """C-SLIM1 on ``path`` (structure + windows); returns the number of regions compared."""
    md, slim = _memdiver_slice(path), _slim_slice(path)
    try:
        assert type(slim.reader) is msl_slim.MslSlimReader
        assert _structure(slim) == _structure(md)
        for start, end in _random_windows(md, seed):
            assert _read_pieces(slim, start, end) == _read_pieces(md, start, end), (start, end)
            assert slim.is_readable(start, end) == md.is_readable(start, end)
        return len(md.reader.collect_regions())
    finally:
        md.close()
        slim.close()


def _segment_digests(opened: msl_layer.MslSlice):
    digests = []
    for _va, mapped, length in opened.va_segments:
        digest = hashlib.sha256()
        for data, _size in _read_pieces(opened, mapped, mapped + length):
            digest.update(b"\xff" if data is None else data)
        digests.append(digest.hexdigest())
    return digests


def _twin_stacks(path: Path, monkeypatch):
    """``(memdiver MslLayer, slim MslLayer)`` stacked the vol way on the same file."""
    md_ctx = _file_context(path)
    md_top = memdiver_stackers.MslStacker.stack(md_ctx, "FileLayer")
    msl_layer._open_slices.clear()  # md_top keeps its open slice; the next open is new
    with monkeypatch.context() as patch:
        patch.setitem(sys.modules, "memdiver", None)
        slim_ctx = _file_context(path)
        slim_top = memdiver_stackers.MslStacker.stack(slim_ctx, "FileLayer")
    md_vas = md_ctx.layers[md_top.config["base_layer"]]
    slim_vas = slim_ctx.layers[slim_top.config["base_layer"]]
    assert type(md_vas.reader) is MslReader
    assert type(slim_vas.reader) is msl_slim.MslSlimReader
    return md_top, slim_top, md_vas


# ------------------------------------------------------------- (a) differential


@pytest.mark.parametrize("path", FIXTURE_SLICES, ids=lambda p: p.name)
def test_slim_matches_memdiver_on_fixture_slices(path):
    assert _assert_same(path) >= 1


def test_slim_matches_memdiver_on_every_page_state(all_states_slice):
    path, _data = all_states_slice
    assert _assert_same(path) == 3
    md, slim = _memdiver_slice(path), _slim_slice(path)
    assert _segment_digests(slim) == _segment_digests(md)
    md.close()
    slim.close()


def test_slim_matches_memdiver_on_vas_map_and_identity(tmp_path):
    from memdiver.msl.enums import ArchType, OSType
    from memdiver.msl.types import MslVasEntry
    from memdiver.msl.writer import MslWriter

    path = tmp_path / "vasmap.msl"
    writer = MslWriter(path, pid=7, os_type=OSType.ANDROID, arch_type=ArchType.ARM64,
                       imported=False)  # live capture: Process Identity is block 0
    writer.add_memory_region(0x7000, bytes(range(256)) * (PAGE // 256))
    writer.add_vas_map([MslVasEntry(0x7000, PAGE, 0x5, 0x02, "/system/lib64/libz.so"),
                        MslVasEntry(0x1000, PAGE, 0x1, 0x00, "")])
    writer.add_process_identity(ppid=3, session_id=0, start_time_ns=1,
                                exe_path="/system/bin/app", cmd_line="app --flag")
    writer.add_end_of_capture()
    writer.write()
    assert _assert_same(path) == 1
    slim = _slim_slice(path)
    assert [row.path for row in slim.region_map()] == ["", "/system/lib64/libz.so"]
    assert slim.describe()["msl_exe_path"] == "/system/bin/app"
    slim.close()


def test_no_decodable_pages_fails_the_same_way(caplog, memdiver_blocked):
    with pytest.raises(msl_layer.MslLayerException, match="no captured or NotResident pages"):
        msl_layer.open_slice(str(CHROME_MIN))
    assert "Skipping malformed MEMORY_REGION" in caplog.text  # as MemDiver logs it


@needs_corpus
@pytest.mark.parametrize("path", CORPUS_RUNS, ids=lambda p: p.parent.name)
def test_slim_matches_memdiver_on_corpus_run(path):
    assert _assert_same(path, seed=hash(path.parent.name) & 0xFFFF) > 0


@needs_corpus
@pytest.mark.parametrize("path", BYTE_SAMPLE, ids=lambda p: p.parent.name)
def test_slim_serves_corpus_run_bytes_identically(path):
    md, slim = _memdiver_slice(path), _slim_slice(path)
    try:
        assert _segment_digests(slim) == _segment_digests(md)
    finally:
        md.close()
        slim.close()


@needs_corpus
def test_slim_layers_equal_memdiver_layers_on_run_0001(monkeypatch):
    path = GOCRYPTFS_CORPUS / "run_0001" / "memslicer.msl"
    md_top, slim_top, md_vas = _twin_stacks(path, monkeypatch)
    assert dict(slim_top.metadata) == dict(md_top.metadata)
    assert "os" not in slim_top.metadata
    assert list(slim_top.mapping(0, 1 << 48, ignore_errors=True)) == list(
        md_top.mapping(0, 1 << 48, ignore_errors=True))
    assert slim_top.read(RUN_0001_KEY_VA, 32).hex() == RUN_0001_MASTER_HEX
    with MslReader(path) as reader:
        failed = list(msl_layer._page_spans(reader.collect_regions(), 0b01))
    assert failed
    for va, _length in failed:
        for top in (slim_top, md_top):
            assert not top.is_valid(va)
            with pytest.raises(exceptions.InvalidAddressException):
                top.read(va, 1)
    md_vas._capture.close()


def test_page_intervals_match_memdiver_decoder():
    rng = random.Random(7)
    for _ in range(300):
        num_pages = rng.randrange(0, 70)
        data = bytes(rng.choice((0x00, 0x55, 0xAA, 0xFF, rng.randrange(256)))
                     for _ in range(rng.randrange(0, 20)))
        expected = [(i.start_page, i.count, int(i.state))
                    for i in decode_page_intervals(data, num_pages)]
        assert [(i.start_page, i.count, i.state)
                for i in msl_slim.decode_page_intervals(data, num_pages)] == expected


# --------------------------------------------------- (b) unsupported features


def test_encrypted_slice_names_the_install_and_reads_no_key(tmp_path, caplog, monkeypatch,
                                                            memdiver_blocked):
    path = tmp_path / "locked.msl"
    _write_slice(path, encryption=MslEncryptionConfig(raw_key=RAW_KEY))
    monkeypatch.setattr(msl_layer, "_key_material",
                        lambda config: pytest.fail("key material read without MemDiver"))
    with pytest.raises(msl_layer.MslLayerException) as excinfo:
        memdiver_stackers.MslStacker.stack(_file_context(path), "FileLayer")
    message = str(excinfo.value)
    assert "\n" not in message and "encrypted" in message
    assert "pip install memdiver" in message and message in caplog.text


@pytest.mark.parametrize("algo", [CompAlgo.ZSTD, CompAlgo.LZ4], ids=lambda a: a.name)
def test_compressed_slice_names_the_install(tmp_path, algo, memdiver_blocked):
    path = tmp_path / f"{algo.name}.msl"
    _write_slice(path, compression=algo)
    with pytest.raises(msl_layer.MslLayerException,
                       match=f"compressed \\({algo.name.lower()}\\).*pip install memdiver"):
        msl_layer.open_slice(str(path))


# ------------------------------------------------ (c) corrupt and truncated input


def _open_outcome(path: Path):
    """``"ok"`` / ``"error"``; anything but a clean ``MslSlimError`` fails the test."""
    try:
        with msl_slim.MslSlimReader(str(path)) as reader:
            reader.captured_run_index()
            reader.collect_process_identity()
            reader.effective_vas_map()
        return "ok"
    except msl_slim.MslSlimError:
        return "error"


def test_truncated_files_fail_cleanly_or_agree_with_memdiver(all_states_slice, tmp_path):
    path, _data = all_states_slice
    blob = path.read_bytes()
    cut = tmp_path / "cut.msl"
    outcomes = set()
    for size in sorted(set(range(0, 400, 7)) | set(range(0, len(blob), 997)) | {len(blob) - 1}):
        cut.write_bytes(blob[:size])
        outcome = _open_outcome(cut)
        outcomes.add(outcome)
        if outcome == "ok":
            with MslReader(cut) as md, msl_slim.MslSlimReader(str(cut)) as slim:
                assert _region_rows(slim) == _region_rows(md), size
                md_runs = [tuple(r[:5]) for r in md.captured_run_index().runs]
                assert [tuple(r[:5]) for r in slim.captured_run_index().runs] == md_runs
    assert outcomes == {"ok", "error"}


def test_random_corruption_never_escapes_as_another_error(all_states_slice, tmp_path):
    path, _data = all_states_slice
    blob = path.read_bytes()
    mutant = tmp_path / "mutant.msl"
    rng = random.Random(11)
    for _ in range(300):
        data = bytearray(blob)
        for _flip in range(rng.randrange(1, 6)):
            data[rng.randrange(min(len(data), 1024))] = rng.randrange(256)
        mutant.write_bytes(bytes(data))
        _open_outcome(mutant)


def test_garbage_and_empty_files_are_clean_errors(tmp_path, memdiver_blocked):
    for name, content in (("empty.msl", b""), ("short.msl", b"MEMSLICE"),
                          ("wrong.msl", b"NOTSLICE" + bytes(200)),
                          ("bigendian.msl", b"MEMSLICE\x02" + bytes(200))):
        path = tmp_path / name
        path.write_bytes(content)
        with pytest.raises(msl_layer.MslLayerException, match="cannot open .msl"):
            msl_layer.open_slice(str(path))


@pytest.mark.timeout(30)
def test_huge_region_size_does_not_hang(all_states_slice, tmp_path):
    """A crafted RegionSize of ~2**63 means 2**51 pages; the map walk must not visit them."""
    path, _data = all_states_slice
    blob = bytearray(path.read_bytes())
    header_size = blob[9]
    region_payload = header_size + msl_slim.BLOCK_HEADER_SIZE
    blob[region_payload + 8:region_payload + 16] = (1 << 63).to_bytes(8, "little")
    crafted = tmp_path / "huge.msl"
    crafted.write_bytes(bytes(blob))
    start = time.perf_counter()
    with msl_slim.MslSlimReader(str(crafted)) as reader:
        region = next(r for r in reader.collect_regions() if r.region_size == 1 << 63)
        assert region.page_intervals[-1].state == msl_slim.FAILED
    assert time.perf_counter() - start < 5


# ------------------------------------------------------ (d) reader selection


def test_memdiver_reader_is_used_while_memdiver_imports(all_states_slice, caplog):
    path, _data = all_states_slice
    caplog.set_level("INFO")
    top = memdiver_stackers.MslStacker.stack(_file_context(path), "FileLayer")
    assert type(top.reader) is MslReader
    assert "MSL reader: MemDiver" in caplog.text and "msl_slim" not in caplog.text


def test_slim_reader_is_used_when_memdiver_import_fails(all_states_slice, caplog,
                                                        memdiver_blocked):
    path, data = all_states_slice
    caplog.set_level("INFO")
    top = memdiver_stackers.MslStacker.stack(_file_context(path), "FileLayer")
    assert type(top.reader) is msl_slim.MslSlimReader
    assert caplog.text.count("MSL reader: msl_slim") == 1
    assert top.read(REGION_A, PAGE) == data["a"][:PAGE]
    assert top.read(REGION_A + 2 * PAGE, PAGE) == bytes(PAGE)  # NotResident
    with pytest.raises(exceptions.InvalidAddressException):
        top.read(REGION_A + STATES_A.index(0b01) * PAGE, 1)  # Failed


_NO_MEMDIVER_PROBE = textwrap.dedent("""
    import importlib, json, sys
    sys.modules["memdiver"] = None  # a Python where memdiver is not installed
    import volatility3.plugins
    from volatility3.framework import constants, contexts
    from volatility3.framework.configuration import requirements
    from volatility3.framework.layers import physical

    volatility3.plugins.__path__ = [sys.argv[1]] + constants.PLUGINS_PATH
    stackers = importlib.import_module("volatility3.plugins.memdiver_stackers")
    ctx = contexts.Context()
    ctx.config["FileLayer.location"] = requirements.URIRequirement.location_from_file(sys.argv[2])
    ctx.add_layer(physical.FileLayer(ctx, "FileLayer", "FileLayer"))
    top = stackers.MslStacker.stack(ctx, "FileLayer")
    print(json.dumps({
        "layer": type(top).__name__, "class_path": type(top).__module__,
        "reader": type(top.reader).__name__, "pid": top.metadata["pid"],
        "memdiver_modules": sorted(m for m in sys.modules
                                   if m.split(".")[0] == "memdiver" and sys.modules[m]),
    }))
""")


def test_stock_vol_without_memdiver_stacks_with_the_slim_reader(all_states_slice, tmp_path):
    path, _data = all_states_slice
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    result = subprocess.run(
        [sys.executable, "-c", _NO_MEMDIVER_PROBE, str(PLUGIN_DIR), str(path)],
        capture_output=True, text=True, cwd=tmp_path, env=env, timeout=120, check=True)
    assert json.loads(result.stdout.strip().splitlines()[-1]) == {
        "layer": "MslLayer", "class_path": "volatility3.plugins.msl_layer",
        "reader": "MslSlimReader", "pid": 4242, "memdiver_modules": []}


def test_slim_module_imports_only_the_standard_library():
    """Stricter than the vol3plugins rule: not even volatility3, so it stands alone."""
    tree = ast.parse(Path(msl_slim.__file__).read_text(encoding="utf-8"))
    names = {alias.name.split(".")[0] for node in ast.walk(tree)
             if isinstance(node, ast.Import) for alias in node.names}
    names |= {node.module.split(".")[0] for node in ast.walk(tree)
              if isinstance(node, ast.ImportFrom) and node.module}
    assert names <= {"dataclasses", "enum", "hashlib", "logging", "mmap", "os", "struct",
                     "typing", "uuid"}, names


@pytest.fixture
def msl_info():
    """``vol3plugins.msl.info``, imported BEFORE ``memdiver_blocked`` (list it first)."""
    from memdiver.vol3plugins.msl import info

    return info


def test_msl_info_plugins_say_they_need_memdiver(caplog, msl_info, memdiver_blocked):
    info = msl_info
    assert info.memdiver_missing("msl.info")
    assert "msl.info needs MemDiver" in caplog.text and "pip install memdiver" in caplog.text


def test_msl_info_plugins_run_while_memdiver_imports():
    from memdiver.vol3plugins.msl import info

    assert not info.memdiver_missing("msl.info")


def test_msl_reader_or_report_no_longer_needs_memdiver(caplog, msl_info, memdiver_blocked):
    """Without MemDiver the plugins read the slim reader: only a non-MSL layer is refused."""
    from types import SimpleNamespace

    info = msl_info
    reader = object()
    layer = SimpleNamespace(region_map=lambda: [], reader=reader)
    context = SimpleNamespace(layers={"primary": object(), "msl": layer})
    assert info.msl_reader_or_report(context, "msl", "msl.vasmap") is reader
    assert "needs MemDiver" not in caplog.text
    assert info.msl_reader_or_report(context, "primary", "msl.vasmap") is None
    assert "not an MSL capture layer" in caplog.text


def test_msl_reader_or_report_refuses_a_non_msl_layer(caplog):
    from types import SimpleNamespace

    from memdiver.vol3plugins.msl import info

    reader = object()
    msl_layer = SimpleNamespace(region_map=lambda: [], reader=reader)
    context = SimpleNamespace(layers={"primary": object(), "msl": msl_layer})
    assert info.msl_reader_or_report(context, "primary", "msl.vasmap") is None
    assert ("msl.vasmap: the primary layer is not an MSL capture layer; run it on a .msl "
            "file (vol -p <vol3plugins dir> -f x.msl msl.vasmap)") in caplog.text
    assert info.msl_reader_or_report(context, "msl", "msl.info") is reader


# ============================================================================
# C-MSL4 support: the slim reader decodes the table blocks and verifies the chain
# ============================================================================

import dataclasses  # noqa: E402
import gzip  # noqa: E402
import hashlib  # noqa: E402
import struct  # noqa: E402
from uuid import uuid4  # noqa: E402

from memdiver.msl import enums as md_enums  # noqa: E402
from memdiver.msl.integrity import verify_chain  # noqa: E402
from memdiver.msl.types import MslThreadRegister  # noqa: E402
from memdiver.msl.writer import ExtensionBlock, MslWriter, ModuleEntrySpec  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
SAMPLE_GZ = sorted((REPO / "samples").glob("*.msl.gz"))
TABLE_COLLECTORS = ("collect_modules", "collect_module_list_index", "collect_key_hints",
                    "collect_thread_contexts", "collect_import_provenance",
                    "collect_end_of_capture", "collect_process_identity")
RICH_PAGE_STATES = [C, NR, C]
RICH_BASE = 0x10000
RICH_PID = 777


def _regs(pc: int, sp: int):
    def reg(name, value, flags=0):
        return MslThreadRegister(name=name, width=8, flags=flags,
                                 value=value.to_bytes(8, "little"))
    return [reg("rax", 0xAA), reg("rip", pc, 0x1), reg("rsp", sp, 0x2), reg("rbp", sp + 8, 0x4),
            MslThreadRegister(name="xmm0", width=16, flags=0, value=bytes(range(16)))]


def write_rich_slice(path: Path, extension: bool = False) -> dict:
    """A slice with provenance, identity, modules, two threads, five key hints (one readable
    across two page runs, one in range, one out of range, one for an unknown region, one of
    unknown length). Returns the captured bytes and the hinted region's UUID."""
    data = bytes(random.Random(11).randbytes(2 * PAGE))
    writer = MslWriter(path, pid=RICH_PID, os_type=md_enums.OSType.LINUX,
                       arch_type=md_enums.ArchType.X86_64)
    writer.add_import_provenance(int(md_enums.SourceFormat.ELF_CORE), "rich-importer", 4321,
                                 note="made for the msl.* plugin tests")
    writer.add_process_identity(ppid=1, session_id=2, start_time_ns=1_700_000_000_000_000_000,
                                exe_path="/usr/bin/demo", cmd_line="demo --flag")  # dropped: imported
    writer.add_module_list_index([
        ModuleEntrySpec(0x400000, 0x1000, "/usr/bin/demo", "1.0", disk_hash=bytes([7]) * 32),
        ModuleEntrySpec(0x7F0000000000, 0x2000, "/lib/libx.so")])
    writer.add_thread_context(1001, _regs(0x401000, 0x7FFF0000), flags=0x1,
                              state=md_enums.ThreadState.RUNNING, name="main")
    writer.add_thread_context(1002, _regs(0x402000, 0x7FFE0000), flags=0x4,
                              state=md_enums.ThreadState.SLEEPING, name="")
    region = writer.add_memory_region(RICH_BASE, data, page_states=RICH_PAGE_STATES)
    for offset, length, note in ((PAGE - 4, 8, "spans two runs"), (16, 32, "in the first page"),
                                 (10 * PAGE, 16, "beyond the captured pages"),
                                 (0, 0, "length not recorded")):
        writer.add_key_hint(region, offset, length, md_enums.MslKeyType.SESSION_KEY,
                            md_enums.MslProtocol.SSH, confidence=2, key_state=1, note=note)
    writer.add_key_hint(uuid4(), 0, 16, md_enums.MslKeyType.OTHER, md_enums.MslProtocol.OTHER,
                        note="orphan")
    writer.add_end_of_capture()
    if extension:
        writer.add_extension_segment("rich-test", [ExtensionBlock(0x1003, b"\x01" * 24)])
    writer.write()
    return {"data": data, "region": region}


@pytest.fixture
def rich_slice(tmp_path):
    path = tmp_path / "rich.msl"
    return path, write_rich_slice(path)


@pytest.fixture(scope="module")
def sample_msls(tmp_path_factory):
    """``{name: path}`` of every samples/*.msl.gz unpacked once."""
    out = tmp_path_factory.mktemp("samples")
    paths = {}
    for gz in SAMPLE_GZ:
        target = out / gz.name[:-3]
        with gzip.open(gz, "rb") as src, open(target, "wb") as dst:
            while chunk := src.read(1 << 24):
                dst.write(chunk)
        paths[target.name] = target
    return paths


def _plain(value):
    """MemDiver dataclass / slim NamedTuple -> plain comparable data, minus block headers."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: _plain(getattr(value, f.name)) for f in dataclasses.fields(value)
                if f.name != "block_header"}
    if hasattr(value, "_fields"):
        return {name: _plain(getattr(value, name)) for name in value._fields
                if name != "block_header"}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return int(value) if isinstance(value, int) else value


def _header_key(value):
    hdr = getattr(value, "block_header", None)
    return None if hdr is None else (
        int(hdr.block_type), hdr.file_offset, hdr.block_length, hdr.block_uuid, hdr.parent_uuid,
        int(hdr.flags), bytes(hdr.prev_hash))


def _assert_tables_equal(path: Path) -> int:
    """Every table collector: slim decode == MemDiver decode. Returns blocks compared."""
    compared = 0
    full = MslReader(path)
    full.open()
    try:
        with msl_slim.MslSlimReader(str(path)) as slim:
            for name in TABLE_COLLECTORS:
                try:
                    got = getattr(slim, name)()
                except msl_slim.MslSlimUnsupported:  # compressed table block: refused, not wrong
                    continue
                want = getattr(full, name)()
                if name == "collect_process_identity":  # decoded without a block header here
                    assert [_plain(g) for g in got] == [_plain(w) for w in want], name
                else:
                    assert [(_plain(g), _header_key(g)) for g in got] == \
                        [(_plain(w), _header_key(w)) for w in want], name
                compared += len(want)
    finally:
        full.close()
    return compared


def test_slim_decodes_every_table_block_like_memdiver_synthetic(rich_slice):
    path, _ = rich_slice
    # 2 modules + 1 index, 2 threads, 5 hints, provenance, EoC (identity needs imported=False)
    assert _assert_tables_equal(path) == 12


@pytest.mark.parametrize("name", [p.name[:-3] for p in SAMPLE_GZ])
def test_slim_decodes_every_table_block_like_memdiver_on_samples(sample_msls, name):
    assert _assert_tables_equal(sample_msls[name]) > 0


def test_samples_cover_threads_and_modules(sample_msls):
    """The parity above is not vacuous: threads (ssh) and modules (gocryptfs) are present."""
    with msl_slim.MslSlimReader(str(sample_msls["ssh_libssh_client.msl"])) as slim:
        assert len(slim.collect_thread_contexts()) == 1
        assert slim.collect_thread_contexts()[0].registers
    with msl_slim.MslSlimReader(str(sample_msls["gocryptfs_aes.msl"])) as slim:
        assert len(slim.collect_modules()) == 11


@pytest.mark.parametrize("path", FIXTURE_SLICES + [CHROME_MIN], ids=lambda p: p.name)
def test_slim_decodes_every_table_block_like_memdiver_on_fixtures(path):
    try:
        with msl_slim.MslSlimReader(str(path)):
            pass
    except msl_slim.MslSlimError:
        pytest.skip("compressed fixture: the slim reader refuses it by design")
    _assert_tables_equal(path)


@needs_corpus
@pytest.mark.parametrize("path", CORPUS_RUNS[:3] + CORPUS_RUNS[-2:], ids=lambda p: p.parent.name)
def test_slim_decodes_every_table_block_like_memdiver_on_corpus(path):
    assert _assert_tables_equal(path) > 0


def test_slim_enums_are_a_subset_of_memdiver_enums():
    pairs = [(msl_slim.PageState, md_enums.PageState), (msl_slim.RegionType, md_enums.RegionType),
             (msl_slim.KeyType, md_enums.MslKeyType), (msl_slim.Protocol, md_enums.MslProtocol),
             (msl_slim.Confidence, md_enums.Confidence), (msl_slim.KeyState, md_enums.KeyState),
             (msl_slim.ThreadState, md_enums.ThreadState), (msl_slim.CompAlgo, md_enums.CompAlgo),
             (msl_slim.HashAlgo, md_enums.HashAlgo), (msl_slim.SourceFormat, md_enums.SourceFormat),
             (msl_slim.OSType, md_enums.OSType), (msl_slim.ArchType, md_enums.ArchType)]
    for slim_enum, full_enum in pairs:
        assert {m.name: int(m) for m in slim_enum} == {
            m.name: int(m) for m in full_enum if m.name in slim_enum.__members__}, slim_enum
        assert len(slim_enum) >= len({int(m) for m in full_enum if int(m) <= 0xFFFF}) - 1


def test_slim_block_type_constants_match_memdiver():
    for name in ("MEMORY_REGION", "MODULE_ENTRY", "MODULE_LIST_INDEX", "THREAD_CONTEXT",
                 "KEY_HINT", "IMPORT_PROVENANCE", "PROCESS_IDENTITY", "END_OF_EXTENSION",
                 "END_OF_CAPTURE", "VAS_MAP"):
        assert getattr(msl_slim, name) == int(md_enums.BlockType[name]), name


def test_compressed_table_block_is_unsupported_only_when_collected(tmp_path):
    """A zstd MODULE_ENTRY must not stop a capture stacking, but must not read as 'no modules'."""
    path = tmp_path / "c.msl"
    write_rich_slice(path)
    raw = bytearray(path.read_bytes())
    offset = 64
    while True:
        block_type, = struct.unpack_from("<H", raw, offset + 4)
        length, = struct.unpack_from("<I", raw, offset + 8)
        if block_type == msl_slim.MODULE_ENTRY:
            raw[offset + 6] |= 0x03  # COMPRESSED | COMP_ZSTD
            break
        offset += length
    path.write_bytes(raw)
    with msl_slim.MslSlimReader(str(path)) as slim:
        assert slim.collect_regions()
        with pytest.raises(msl_slim.MslSlimUnsupported, match="pip install memdiver"):
            slim.collect_modules()


# ------------------------------------------------------------------- verification


def _rechain(path: Path, algo: int) -> Path:
    """Rewrite ``path``'s chain and EoC FileHash with HashAlgo ``algo`` (1 sha256, 2 sha512/256)."""
    hasher = ((lambda b: hashlib.sha256(b).digest()) if algo == 1
              else (lambda b: hashlib.new("sha512_256", b).digest()))
    data = bytearray(path.read_bytes())
    data[0x3D] = algo
    offset, prev = 64, hasher(bytes(data[:64]))
    while data[offset:offset + 4] == b"MSLC":
        length, = struct.unpack_from("<I", data, offset + 8)
        data[offset + 0x30:offset + 0x50] = prev
        if struct.unpack_from("<H", data, offset + 4)[0] == msl_slim.END_OF_CAPTURE:
            data[offset + 80:offset + 112] = hasher(bytes(data[:offset]))
            break
        prev = hasher(bytes(data[offset:offset + length]))
        offset += length
    out = path.with_name(f"{path.stem}_algo{algo}.msl")
    out.write_bytes(data)
    return out


def _both_reports(path: Path):
    import blake3

    full = MslReader(path)
    full.open()
    try:
        expected = verify_chain(full)
    finally:
        full.close()
    with msl_slim.MslSlimReader(str(path), allow_compressed=True) as slim:
        return msl_slim.verify_container(slim, blake3), expected


def _assert_same_verdict(path: Path):
    got, want = _both_reports(path)
    assert (got.valid, got.block_count, got.file_hash_ok, got.block_count_ok) == (
        want.valid, want.block_count, want.file_hash_ok, want.block_count_ok), path
    assert got.errors == want.errors and got.warnings == want.warnings
    assert [(s.index, s.start, s.end, s.verified) for s in got.segments] == [
        (s.index, s.start, s.end, s.verified) for s in want.segments]
    assert got.trailing_bytes == want.trailing_bytes
    return got


@pytest.mark.parametrize("name", [p.name[:-3] for p in SAMPLE_GZ])
def test_verify_container_matches_memdiver_on_samples(sample_msls, name):
    assert _assert_same_verdict(sample_msls[name]).valid == ("tampered" not in name)


def test_verify_container_flags_the_tampered_sample_like_memdiver(sample_msls):
    report = _assert_same_verdict(sample_msls["gocryptfs_aes_tampered.msl"])
    assert not report.valid
    assert report.file_hash_ok is False and report.broken_at is not None
    block_types = {c.file_offset: c.block_type for c in report.blocks}
    assert block_types[report.broken_at] == msl_slim.VAS_MAP  # breaks AFTER the region


def test_verify_container_without_blake3_says_needs_memdiver(rich_slice):
    path, _ = rich_slice
    with msl_slim.MslSlimReader(str(path)) as slim:
        with pytest.raises(msl_slim.MslSlimHashUnavailable, match=r"needs memdiver \(BLAKE3"):
            msl_slim.verify_container(slim)


@pytest.mark.parametrize("algo", [1, 2], ids=["sha256", "sha512_256"])
def test_verify_container_checks_stdlib_chains_without_blake3(rich_slice, algo):
    path, _ = rich_slice
    rechained = _rechain(path, algo)
    with msl_slim.MslSlimReader(str(rechained)) as slim:
        report = msl_slim.verify_container(slim)  # no blake3 module handed in
    assert report.valid and report.file_hash_ok is True
    assert len(report.blocks) == report.block_count and all(c.ok for c in report.blocks)
    assert _assert_same_verdict(rechained).valid


@pytest.mark.parametrize("algo", [1, 2], ids=["sha256", "sha512_256"])
def test_verify_container_detects_a_flipped_byte_in_stdlib_chains(rich_slice, algo):
    path, _ = rich_slice
    rechained = _rechain(path, algo)
    raw = bytearray(rechained.read_bytes())
    with msl_slim.MslSlimReader(str(rechained)) as slim:
        region = next(h for h in slim.blocks if h.block_type == msl_slim.MEMORY_REGION)
        after = slim.blocks[slim.blocks.index(region) + 1]
    raw[region.payload_offset + 0x40] ^= 0x01
    rechained.write_bytes(raw)
    with msl_slim.MslSlimReader(str(rechained)) as slim:
        report = msl_slim.verify_container(slim)
    assert not report.valid and report.file_hash_ok is False
    assert report.broken_at == after.file_offset
    assert [c.ok for c in report.blocks].count(False) == 1


def test_verify_container_checks_extension_segments(tmp_path):
    path = tmp_path / "ext.msl"
    write_rich_slice(path, extension=True)
    report = _assert_same_verdict(path)
    assert report.valid and len(report.segments) == 1 and report.segments[0].verified
    raw = bytearray(path.read_bytes())
    raw[report.segments[0].start + 0x50 + 3] ^= 0x01  # inside the segment's block payload
    path.write_bytes(raw)
    broken = _assert_same_verdict(path)
    assert not broken.valid and not broken.segments[0].verified
    assert broken.capture_ok  # the capture segment itself is untouched


def test_verify_container_reports_a_truncated_capture_like_memdiver(rich_slice, tmp_path):
    path, _ = rich_slice
    raw = path.read_bytes()
    cut = tmp_path / "cut.msl"
    cut.write_bytes(raw[:-40])
    got, want = _both_reports(cut)
    assert not got.valid and not want.valid
    assert any("Truncated" in e for e in got.errors) and any("Truncated" in e for e in want.errors)


def test_verify_container_rejects_unknown_hash_algo(rich_slice):
    path, _ = rich_slice
    raw = bytearray(path.read_bytes())
    raw[0x3D] = 0x7E
    path.write_bytes(raw)
    with msl_slim.MslSlimReader(str(path)) as slim:
        with pytest.raises(msl_slim.MslSlimError, match="unsupported HashAlgo"):
            msl_slim.verify_container(slim)


def test_verify_container_hashes_compressed_blocks_as_stored(tmp_path):
    path = tmp_path / "z.msl"
    from tests.test_vol3plugins_msl_layer import _write_slice

    _write_slice(path, compression=CompAlgo.ZSTD)
    with pytest.raises(msl_slim.MslSlimUnsupported):
        msl_slim.MslSlimReader(str(path)).open()
    assert _assert_same_verdict(path).valid  # allow_compressed=True path


# ------------------------------------------------- running msl.* plugins in-process


def _memory_files(store: dict):
    """A vol ``FileHandlerInterface`` that keeps what a plugin ``self.open()``s in ``store``."""
    from volatility3.framework.interfaces.plugins import FileHandlerInterface

    class MemoryFile(FileHandlerInterface):
        def __init__(self, filename):
            super().__init__(filename)
            self._data = bytearray()

        def writable(self):
            return True

        def write(self, data):
            self._data += data
            return len(data)

        def close(self):
            store[self.preferred_filename] = bytes(self._data)
            super().close()

    return MemoryFile


def run_plugin(plugin_cls, path, **config):
    """``(rows, files)`` of ``plugin_cls`` on the ``.msl`` at ``path``, built as vol builds it."""
    from tests.test_vol3plugins_msl_layer import _stack

    ctx, top = _stack(path)
    config_path = "plugins.P"
    ctx.config[f"{config_path}.primary"] = top.name
    for key, value in config.items():
        ctx.config[f"{config_path}.{key}"] = value
    plugin = plugin_cls(ctx, config_path)
    files: dict = {}
    plugin.set_open_method(_memory_files(files))
    rows = []
    plugin.run().populate(lambda node, acc: rows.append(tuple(node.values)) or acc, None)
    return rows, files


def plain_rows(rows):
    """Rows as comparable plain values (absent cells -> ``"N/A"``)."""
    from volatility3.framework import interfaces

    return [tuple("N/A" if isinstance(v, interfaces.renderers.BaseAbsentValue)
                  else int(v) if isinstance(v, int) else v for v in row) for row in rows]


def run_with_both_readers(plugin_cls, path, monkeypatch, **config):
    """``(memdiver rows, slim rows, memdiver files, slim files)``; the slim run blocks
    ``import memdiver`` so ``msl_layer`` opens the capture with ``msl_slim``."""
    full_rows, full_files = run_plugin(plugin_cls, path, **config)
    msl_layer.close_slices()
    monkeypatch.setitem(sys.modules, "memdiver", None)
    slim_rows, slim_files = run_plugin(plugin_cls, path, **config)
    return plain_rows(full_rows), plain_rows(slim_rows), full_files, slim_files
