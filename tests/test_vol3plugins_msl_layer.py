"""The Volatility 3 ``.msl`` layers: ``vol3plugins/msl_layer.py`` + ``memdiver_stackers.py``.

Claim C-MSL1: for every captured run of a ``.msl``, the bytes ``MslLayer`` serves at the
run's virtual address equal the bytes MemDiver's own ``"va"`` and ``"vas"`` views serve,
and ``MslVasLayer`` offsets ARE MemDiver ``"vas"`` offsets. NotResident pages read as zeros;
Failed/Unmapped pages raise ``InvalidAddressException``.

Also covered: the stacker's no-MemDiver fast path (checked in a fresh interpreter),
encrypted containers (locked = one clear line; key file / env var / passphrase open it),
and the canonical class path that lets a config written in-process replay under stock
``vol -p <dir> -c config.json``.
"""

import hashlib
import json
import os
import pickle
import random
import subprocess
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("volatility3")

from volatility3.framework import contexts, exceptions  # noqa: E402
from volatility3.framework.configuration import requirements  # noqa: E402
from volatility3.framework.layers import physical, scanners  # noqa: E402

from memdiver.core.dump_source import open_dump  # noqa: E402
from memdiver.msl import crypto  # noqa: E402
from memdiver.msl.enums import ArchType, CompAlgo, KdfType, OSType, PageState  # noqa: E402
from memdiver.msl.types import MslVasEntry  # noqa: E402
from memdiver.msl.writer import MslEncryptionConfig, MslWriter  # noqa: E402
from memdiver.vol3plugins import memdiver_stackers, msl_layer  # noqa: E402
from tests._oracle_gocryptfs_fixtures import GOCRYPTFS_CORPUS, RUN_0001_MASTER_HEX  # noqa: E402

PLUGIN_DIR = Path(msl_layer.__file__).resolve().parent
CHROME_MIN = Path(__file__).parent / "fixtures" / "real_samples" / "chrome_min.msl"
RUN_0001 = GOCRYPTFS_CORPUS / "run_0001" / "memslicer.msl"
needs_run_0001 = pytest.mark.skipif(not RUN_0001.is_file(), reason=f"corpus absent: {RUN_0001}")

PAGE = 4096
C, F, U, NR = (int(s) for s in (PageState.CAPTURED, PageState.FAILED,
                                PageState.UNMAPPED, PageState.NOT_RESIDENT))
#: Region A: every page state, so a VA walk crosses captured -> NR -> Failed -> Unmapped.
REGION_A, STATES_A = 0x10000, [C, C, NR, F, C, U, C, NR]
#: Region B (compressed when asked) abuts region C in VA: two runs, one contiguous VA range.
REGION_B, REGION_C = 0x40000, 0x43000
NEEDLE = b"MSL-LAYER-NEEDLE"
NEEDLE_VA = REGION_C + PAGE + 0x123
STRADDLE_VA = REGION_C - 5  # needle split across the B/C run boundary
EDGE_HEAD = b"EDGE"
RAW_KEY = bytes(range(32))
#: vol's entry point; the guard matters: spawned workers re-import the main script.
VOL_CLI = "from volatility3.cli import main\n\nif __name__ == \"__main__\":\n    main()\n"
PASSPHRASE = "correct horse battery"


# ------------------------------------------------------------------------- fixtures


@pytest.fixture(autouse=True)
def _fresh_layer_cache(monkeypatch):
    """No cached capture or key variable leaks from one test into the next."""
    for env in (msl_layer.KEY_FILE_ENV, msl_layer.KEM_KEY_FILE_ENV, msl_layer.PASSPHRASE_ENV):
        monkeypatch.delenv(env, raising=False)
    yield
    msl_layer.close_slices()


def _captured_bytes(count: int, seed: int) -> bytearray:
    return bytearray(random.Random(seed).randbytes(count * PAGE))


def _write_slice(path: Path, encryption=None, compression=CompAlgo.NONE) -> dict:
    """A synthetic Linux/x86-64 slice with every page state; returns the captured bytes."""
    data_a = _captured_bytes(STATES_A.count(C), 1)
    data_b = _captured_bytes(3, 2)
    data_c = _captured_bytes(2, 3)
    data_c[PAGE + 0x123:PAGE + 0x123 + len(NEEDLE)] = NEEDLE
    data_b[-5:] = NEEDLE[:5]
    data_a[2 * PAGE - len(EDGE_HEAD):2 * PAGE] = EDGE_HEAD  # captured page 1 -> NR page 2
    data_c[:len(NEEDLE) - 5] = NEEDLE[5:]
    writer = MslWriter(path, pid=4242, os_type=OSType.LINUX, arch_type=ArchType.X86_64,
                       encryption=encryption)
    writer.add_memory_region(REGION_A, bytes(data_a), page_states=STATES_A)
    writer.add_memory_region(REGION_B, bytes(data_b), compression=compression)
    writer.add_memory_region(REGION_C, bytes(data_c))
    writer.add_end_of_capture()
    writer.write()
    return {"a": bytes(data_a), "b": bytes(data_b), "c": bytes(data_c)}



@pytest.fixture
def plain_slice(tmp_path):
    path = tmp_path / "plain.msl"
    return path, _write_slice(path)


def _file_context(path: Path):
    ctx = contexts.Context()
    ctx.config["FileLayer.location"] = requirements.URIRequirement.location_from_file(str(path))
    ctx.add_layer(physical.FileLayer(ctx, "FileLayer", "FileLayer"))
    return ctx


def _stack(path: Path):
    """``(context, MslLayer)`` as vol's LayerStacker builds them for ``-f path``."""
    ctx = _file_context(path)
    top = memdiver_stackers.MslStacker.stack(ctx, "FileLayer")
    ctx.add_layer(top)
    return ctx, top


def _vas_layer(ctx, top):
    return ctx.layers[top.config["base_layer"]]


def _construct(path: Path, **options):
    """Build both layers from config alone, the way ``-c`` replay does (no stacker)."""
    ctx = _file_context(path)
    ctx.config["vas.base_layer"] = "FileLayer"
    for option, value in options.items():
        ctx.config[f"vas.{option}"] = value
    ctx.add_layer(msl_layer.MslVasLayer(ctx, "vas", "vas"))
    ctx.config["top.base_layer"] = "vas"
    top = msl_layer.MslLayer(ctx, "top", "top")
    ctx.add_layer(top)
    return top


def _sample_offsets(length: int):
    return sorted({0, 1, length // 2, max(0, length - 16), length - 1})


def _assert_layer_parity(path: Path) -> int:
    """C-MSL1 for every captured run of ``path``; returns the number of runs checked."""
    ctx, top = _stack(path)
    vas = _vas_layer(ctx, top)
    with open_dump(path) as source:
        span_start = source.va_span_start()
        runs = source.captured_runs()
        assert vas.zero_region_offset == source.size_for("vas")
        for va, length, vas_offset in runs:
            for offset in _sample_offsets(length):
                size = min(64, length - offset)
                expected = source.read_range(vas_offset + offset, size, view="vas")
                assert len(expected) == size
                assert source.read_range(va - span_start + offset, size, view="va") == expected
                assert vas.read(vas_offset + offset, size) == expected
                assert top.read(va + offset, size) == expected
            assert top.is_valid(va) and top.is_valid(va + length - 1)
    return len(runs)


# ------------------------------------------------------------------- (a) VA parity


def test_msl_layer_matches_memdiver_va_and_vas_views_synthetic(plain_slice):
    path, _data = plain_slice
    assert _assert_layer_parity(path) == 5  # A: 3 captured runs, B, C


def test_compressed_region_reads_match_memdiver(tmp_path):
    path = tmp_path / "zstd.msl"
    data = _write_slice(path, compression=CompAlgo.ZSTD)
    _assert_layer_parity(path)
    _ctx, top = _stack(path)
    assert top.read(REGION_B, 3 * PAGE) == data["b"]


@needs_run_0001
def test_msl_layer_matches_memdiver_views_real_gocryptfs():
    assert _assert_layer_parity(RUN_0001) == 109


def test_chrome_min_has_no_decodable_pages_in_either_tool(caplog):
    with open_dump(CHROME_MIN) as source:
        assert source.captured_runs() == ()
    with pytest.raises(msl_layer.MslLayerException, match="no captured or NotResident pages"):
        _stack(CHROME_MIN)
    assert "no captured or NotResident pages" in caplog.text


def test_not_resident_reads_zero_failed_and_unmapped_raise(plain_slice):
    path, data = plain_slice
    _ctx, top = _stack(path)
    page = [REGION_A + i * PAGE for i in range(len(STATES_A))]
    assert top.read(page[2], PAGE) == bytes(PAGE) and top.is_valid(page[2], PAGE)
    assert top.read(page[7], PAGE) == bytes(PAGE)
    for unreadable in (page[3], page[5], REGION_A - 1, REGION_C + 2 * PAGE):
        assert not top.is_valid(unreadable)
        with pytest.raises(exceptions.InvalidAddressException):
            top.read(unreadable, 1)
    # Run edges: captured -> NotResident joins; NotResident -> Failed stops.
    assert top.read(page[2] - 16, 32) == data["a"][2 * PAGE - 16:2 * PAGE] + bytes(16)
    with pytest.raises(exceptions.InvalidAddressException):
        top.read(page[4] - 8, 16)
    assert top.read(page[5] - 8, 16, pad=True) == data["a"][3 * PAGE - 8:3 * PAGE] + bytes(8)


def test_abutting_runs_read_and_scan_as_one_range(plain_slice):
    path, data = plain_slice
    ctx, top = _stack(path)
    assert top.read(REGION_C - 16, 32) == data["b"][-16:] + data["c"][:16]
    hits = list(top.scan(ctx, scanners.BytesScanner(NEEDLE)))
    assert hits == [STRADDLE_VA, NEEDLE_VA]


def test_metadata_describes_the_slice_without_an_os_key(plain_slice):
    path, _data = plain_slice
    ctx, top = _stack(path)
    meta = dict(top.metadata)
    assert "os" not in meta and "os" not in _vas_layer(ctx, top).metadata
    assert meta["msl"] is True
    assert (meta["msl_os"], meta["msl_arch"], meta["architecture"]) == ("linux", "x86_64",
                                                                        "Intel64")
    assert meta["pid"] == 4242 and meta["msl_path"] == str(path)


def test_region_map_prefers_the_vas_map(tmp_path):
    path = tmp_path / "vasmap.msl"
    writer = MslWriter(path, pid=1, os_type=OSType.LINUX, arch_type=ArchType.X86_64)
    writer.add_memory_region(0x7000, bytes(PAGE))
    writer.add_vas_map([MslVasEntry(0x7000, PAGE, 0x5, 0x02, "/usr/lib/libx.so"),
                        MslVasEntry(0x1000, PAGE, 0x1, 0x00, "")])
    writer.write()
    _ctx, top = _stack(path)
    assert [(r.start, r.end, r.path) for r in top.region_map()] == [
        (0x1000, 0x2000, ""), (0x7000, 0x8000, "/usr/lib/libx.so")]


def test_cloned_and_pickled_layers_reopen_the_capture(plain_slice):
    path, data = plain_slice
    ctx, top = _stack(path)
    clone = ctx.clone()  # vol's LayerStacker deep-copies whole contexts
    assert clone.layers[top.name].read(REGION_C, 64) == data["c"][:64]
    shipped = pickle.loads(pickle.dumps(top))  # what --parallelism processes sends a worker
    assert shipped.read(REGION_C, 64) == data["c"][:64]
    msl_layer.close_slices()  # a long-lived host dropping its cache must not break layers
    assert top.read(REGION_A, 32) == data["a"][:32]


def test_flatten_resolves_overlaps_later_span_wins():
    spans = [(0, 1000, 100), (40, 0, 20), (90, 500, 30)]
    assert msl_layer._flatten(spans) == [(0, 1000, 40), (40, 0, 20), (60, 1060, 30),
                                         (90, 500, 30)]
    assert msl_layer._flatten([(5, 0, 5), (0, 9, 5), (7, 1, 0)]) == [(0, 9, 5), (5, 0, 5)]


def test_coalesce_joins_only_va_and_stream_contiguous_neighbours():
    segments = [(0, 100, 10), (10, 110, 5), (15, 0, 5), (30, 20, 5)]
    assert msl_layer._coalesce(segments) == [(0, 100, 15), (15, 0, 5), (30, 20, 5)]


# ------------------------------------------------------------- (b) vas offsets


def test_vas_layer_is_memdiver_vas_view_byte_for_byte(plain_slice):
    path, _data = plain_slice
    ctx, top = _stack(path)
    vas = _vas_layer(ctx, top)
    with open_dump(path) as source:
        size = source.size_for("vas")
        assert vas.read(0, size) == source.read_all("vas")
        for _va, length, vas_offset in source.captured_runs():  # across every run joint
            start = max(0, vas_offset - 7)
            assert vas.read(start, 14) == source.read_range(start, 14, view="vas")
    assert vas.read(size, 32) == bytes(32)  # zero region backing the NotResident pages
    with pytest.raises(exceptions.InvalidAddressException):
        vas.read(vas.maximum_address, 2)


@needs_run_0001
def test_vas_layer_streams_identical_to_memdiver_and_finds_the_key():
    ctx, top = _stack(RUN_0001)
    vas = _vas_layer(ctx, top)
    key = bytes.fromhex(RUN_0001_MASTER_HEX)
    chunk = 16 * 1024 * 1024
    with open_dump(RUN_0001) as source:
        size = source.size_for("vas")
        for offset in range(0, size, chunk):
            length = min(chunk, size - offset)
            assert vas.read(offset, length) == source.read_range(offset, length, view="vas")
        assert source.find_all(key, view="vas")[0] == 0x57A220
    assert vas.read(0x57A220, 32) == key
    assert top.read(0xC0000BC220, 32) == key


@needs_run_0001
def test_failed_pages_of_the_real_capture_raise():
    from memdiver.msl.reader import MslReader

    with MslReader(RUN_0001) as reader:
        failed = list(msl_layer._page_spans(reader.collect_regions(), PageState.FAILED))
    assert failed
    _ctx, top = _stack(RUN_0001)
    for va, _length in failed:
        with pytest.raises(exceptions.InvalidAddressException):
            top.read(va, 1)


# ----------------------------------------------------- (c) stacker fast path


_STACKER_PROBE = textwrap.dedent("""
    import importlib, json, sys
    import volatility3.plugins
    from volatility3.framework import constants, contexts
    from volatility3.framework.configuration import requirements
    from volatility3.framework.layers import physical

    volatility3.plugins.__path__ = [sys.argv[1]] + constants.PLUGINS_PATH
    stackers = importlib.import_module("volatility3.plugins.memdiver_stackers")
    importlib.import_module("volatility3.plugins.msl_layer")
    imported_at_load = sorted(m for m in sys.modules if m.split(".")[0] == "memdiver")
    ctx = contexts.Context()
    ctx.config["FileLayer.location"] = requirements.URIRequirement.location_from_file(sys.argv[2])
    ctx.add_layer(physical.FileLayer(ctx, "FileLayer", "FileLayer"))
    layer = stackers.MslStacker.stack(ctx, "FileLayer")
    print(json.dumps({
        "layer": type(layer).__name__ if layer is not None else None,
        "at_load": imported_at_load,
        "after_stack": sorted(m for m in sys.modules if m.split(".")[0] == "memdiver"),
    }))
""")


def _probe_stacker(path: Path, cwd: Path) -> dict:
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    result = subprocess.run(
        [sys.executable, "-c", _STACKER_PROBE, str(PLUGIN_DIR), str(path)],
        capture_output=True, text=True, cwd=cwd, env=env, timeout=120, check=True)
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_stacker_ignores_non_msl_without_importing_memdiver(tmp_path):
    for name, head in (("random.bin", random.Random(5).randbytes(8192)),
                       ("elf.core", b"\x7fELF\x02\x01\x01" + bytes(8185)),
                       ("short.bin", b"MEMSLI")):
        path = tmp_path / name
        path.write_bytes(head)
        probe = _probe_stacker(path, tmp_path)
        assert probe == {"layer": None, "at_load": [], "after_stack": []}, name


def test_stacker_imports_memdiver_only_after_the_magic_matches(plain_slice, tmp_path):
    path, _data = plain_slice
    probe = _probe_stacker(path, tmp_path)
    assert probe["layer"] == "MslLayer" and probe["at_load"] == []
    assert "memdiver.msl.reader" in probe["after_stack"]


def test_match_across_captured_to_not_resident_edge_is_read_but_not_scanned(plain_slice):
    """Pins the documented limitation (module docstring, "Known limitation")."""
    path, _data = plain_slice
    ctx, top = _stack(path)
    pattern = EDGE_HEAD + bytes(4)
    edge = REGION_A + 2 * PAGE - len(EDGE_HEAD)
    assert top.read(edge, len(pattern)) == pattern
    assert list(top.scan(ctx, scanners.BytesScanner(pattern))) == []


_SHIM = """
from volatility3.framework import interfaces


class ShimStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 99

    @classmethod
    def stack(cls, context, layer_name, progress_callback=None):
        return None
"""

_LOAD_PROBE = textwrap.dedent("""
    import json, sys
    import volatility3.plugins
    from volatility3 import framework
    from volatility3.framework import constants, interfaces

    volatility3.plugins.__path__ = sys.argv[1].split(";") + constants.PLUGINS_PATH
    framework.import_files(volatility3.plugins, True)
    print(json.dumps(sorted(c.__name__ for c in framework.class_subclasses(
        interfaces.automagic.StackerLayerInterface))))
""")


@pytest.mark.parametrize("shim_first", [True, False])
def test_stacker_loads_beside_the_la57_shim_named_memdiver_layers(tmp_path, shim_first):
    shim_dir = tmp_path / "cfg_plugins"
    shim_dir.mkdir()
    (shim_dir / "memdiver_layers.py").write_text(_SHIM)  # app/tools_vol3_dev.py SHIM_FILE
    dirs = [str(shim_dir), str(PLUGIN_DIR)][::1 if shim_first else -1]
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    result = subprocess.run([sys.executable, "-c", _LOAD_PROBE, ";".join(dirs)],
                            capture_output=True, text=True, cwd=tmp_path, env=env,
                            timeout=120, check=True)
    stackers = json.loads(result.stdout.strip().splitlines()[-1])
    assert {"ShimStacker", "MslStacker"} <= set(stackers)


def test_stacker_returns_none_in_process_for_non_msl(tmp_path):
    path = tmp_path / "raw.bin"
    path.write_bytes(b"NOTSLICE" + bytes(100))
    assert memdiver_stackers.MslStacker.stack(_file_context(path), "FileLayer") is None


def test_file_path_of_rejects_non_file_locations():
    ctx = SimpleNamespace(layers={"L": SimpleNamespace(config={"location": "https://h/x.msl"})})
    with pytest.raises(msl_layer.MslLayerException, match="file:// locations"):
        msl_layer.file_path_of(ctx, "L")
    ctx.layers["L"].config["location"] = "file:///tmp/a%20b.msl"
    assert msl_layer.file_path_of(ctx, "L") == "/tmp/a b.msl"


# ------------------------------------------------------------ (d) encryption


@pytest.fixture
def raw_key_slice(tmp_path):
    path = tmp_path / "locked.msl"
    data = _write_slice(path, encryption=MslEncryptionConfig(raw_key=RAW_KEY))
    key_file = tmp_path / "slice.key"
    key_file.write_bytes(RAW_KEY)
    return path, data, key_file


def test_encrypted_without_key_fails_with_one_clear_line(raw_key_slice, caplog):
    path, _data, _key_file = raw_key_slice
    with pytest.raises(msl_layer.MslLayerException) as excinfo:
        _stack(path)
    message = str(excinfo.value)
    assert "\n" not in message
    assert "encrypted" in message and msl_layer.KEY_FILE_ENV in message
    assert message in caplog.text


def test_encrypted_with_key_file_option(raw_key_slice):
    path, data, key_file = raw_key_slice
    top = _construct(path, key_file=str(key_file))
    assert top.read(NEEDLE_VA - 16, 64) == data["c"][PAGE + 0x113:PAGE + 0x153]
    assert top.read(REGION_A, PAGE) == data["a"][:PAGE]


def test_encrypted_with_key_file_env_is_recorded_for_replay(raw_key_slice, monkeypatch):
    path, data, key_file = raw_key_slice
    monkeypatch.setenv(msl_layer.KEY_FILE_ENV, str(key_file))
    _ctx, top = _stack(path)
    assert top.read(REGION_B, 3 * PAGE) == data["b"]
    assert top.build_configuration()["base_layer.key_file"] == str(key_file)
    with open_dump(path, key=RAW_KEY) as source:
        assert _vas_layer(_ctx, top).read(0, source.size_for("vas")) == source.read_all("vas")


def test_key_env_is_ignored_and_not_saved_for_unencrypted_captures(plain_slice, tmp_path,
                                                                    monkeypatch):
    path, data = plain_slice
    monkeypatch.setenv(msl_layer.KEY_FILE_ENV, str(tmp_path / "absent.key"))
    _ctx, top = _stack(path)
    assert top.read(REGION_C, 64) == data["c"][:64]
    assert "base_layer.key_file" not in dict(top.build_configuration())


def test_encrypted_with_wrong_key_reports_failed_verification(raw_key_slice, tmp_path):
    path, _data, _key_file = raw_key_slice
    wrong = tmp_path / "wrong.key"
    wrong.write_bytes(bytes(32))
    with pytest.raises(msl_layer.MslLayerException, match="AEAD verification failed"):
        _construct(path, key_file=str(wrong))


def test_missing_key_file_is_a_clear_error(raw_key_slice, tmp_path):
    path, _data, _key_file = raw_key_slice
    with pytest.raises(msl_layer.MslLayerException, match="cannot read MSL key file"):
        _construct(path, key_file=str(tmp_path / "absent.key"))


@pytest.mark.skipif(not crypto.kdf_is_available(KdfType.ARGON2ID), reason="argon2 missing")
def test_encrypted_with_passphrase_env_never_saves_the_secret(tmp_path, monkeypatch):
    path = tmp_path / "pass.msl"
    data = _write_slice(path, encryption=MslEncryptionConfig(
        kdf_type=KdfType.ARGON2ID, passphrase=PASSPHRASE.encode()))
    monkeypatch.setenv(msl_layer.PASSPHRASE_ENV, PASSPHRASE)
    _ctx, top = _stack(path)
    assert top.read(REGION_C, 2 * PAGE) == data["c"]
    assert PASSPHRASE not in json.dumps(dict(top.build_configuration()))


# ----------------------------------------------- canonical class path / -c replay


def test_layer_classes_have_one_canonical_class_path(plain_slice):
    assert sys.modules[msl_layer.CANONICAL_MODULE] is msl_layer
    path, _data = plain_slice
    _ctx, top = _stack(path)
    config = top.build_configuration()
    assert config["class"] == "volatility3.plugins.msl_layer.MslLayer"
    assert config["base_layer.class"] == "volatility3.plugins.msl_layer.MslVasLayer"


_VOL_FIRST_PROBE = textwrap.dedent("""
    import importlib, json, sys
    import volatility3.plugins
    from volatility3.framework import constants

    volatility3.plugins.__path__ = [sys.argv[1]] + constants.PLUGINS_PATH
    vol_copy = importlib.import_module("volatility3.plugins.msl_layer")
    import memdiver.vol3plugins.msl_layer as memdiver_copy
    print(json.dumps({"same": memdiver_copy is vol_copy,
                      "module": memdiver_copy.MslLayer.__module__}))
""")


def test_vol_loaded_copy_wins_when_memdiver_imports_second(tmp_path):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    result = subprocess.run([sys.executable, "-c", _VOL_FIRST_PROBE, str(PLUGIN_DIR)],
                            capture_output=True, text=True, cwd=tmp_path, env=env,
                            timeout=120, check=True)
    probe = json.loads(result.stdout.strip().splitlines()[-1])
    assert probe == {"same": True, "module": msl_layer.CANONICAL_MODULE}


def test_config_written_in_process_replays_under_stock_vol(plain_slice, tmp_path):
    path, _data = plain_slice
    ctx, top = _stack(path)
    in_process = [hit for hit in top.scan(ctx, scanners.RegExScanner(NEEDLE))]
    config = {f"primary.{key}": value for key, value in top.build_configuration().items()}
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(config))
    # vol's CLI parses sys.argv[0] too, so it must run from a script file, not `-c`.
    vol = tmp_path / "vol_cli.py"
    vol.write_text(VOL_CLI)
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    result = subprocess.run(
        [sys.executable, str(vol), "-q", "-r", "json", "-p", str(PLUGIN_DIR),
         "-c", str(config_file), "regexscan.RegExScan", "--pattern", NEEDLE.decode()],
        capture_output=True, text=True, cwd=tmp_path, env=env, timeout=300)
    assert result.returncode == 0, result.stderr
    rows = json.loads(result.stdout[result.stdout.index("["):])
    assert [row["Offset"] for row in rows] == in_process == [STRADDLE_VA, NEEDLE_VA]


# ------------------------------------------------------- pickling / cache hygiene

_PICKLE_PROBE = textwrap.dedent("""
    import pickle, sys
    import volatility3.plugins
    from volatility3.framework import constants, contexts
    from volatility3.framework.configuration import requirements
    from volatility3.framework.layers import physical

    volatility3.plugins.__path__ = [sys.argv[1]] + constants.PLUGINS_PATH
    from volatility3.plugins import memdiver_stackers
    ctx = contexts.Context()
    ctx.config["FileLayer.location"] = requirements.URIRequirement.location_from_file(sys.argv[2])
    ctx.add_layer(physical.FileLayer(ctx, "FileLayer", "FileLayer"))
    top = memdiver_stackers.MslStacker.stack(ctx, "FileLayer")
    ctx.add_layer(top)
    sys.stdout.buffer.write(pickle.dumps(top))
""")

_UNPICKLE_PROBE = textwrap.dedent("""
    import pickle, sys
    layer = pickle.loads(sys.stdin.buffer.read())  # no plugin dir on any path here
    sys.stdout.write(layer.read(int(sys.argv[1]), int(sys.argv[2])).hex())
""")


def test_layer_pickled_under_vol_unpickles_in_a_fresh_interpreter(plain_slice, tmp_path):
    """What a spawned --parallelism processes worker does (macOS default: spawn)."""
    path, data = plain_slice
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    pickled = subprocess.run([sys.executable, "-c", _PICKLE_PROBE, str(PLUGIN_DIR), str(path)],
                             capture_output=True, cwd=tmp_path, env=env, timeout=120,
                             check=True).stdout
    shipped = subprocess.run([sys.executable, "-c", _UNPICKLE_PROBE, str(NEEDLE_VA), "16"],
                             input=pickled, capture_output=True, cwd=tmp_path, env=env,
                             timeout=120, check=True)
    assert bytes.fromhex(shipped.stdout.decode()) == NEEDLE


def test_vol_parallelism_processes_finishes_with_the_hits(plain_slice, tmp_path):
    path, _data = plain_slice
    vol = tmp_path / "vol_cli.py"
    vol.write_text(VOL_CLI)
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    result = subprocess.run(
        [sys.executable, str(vol), "-q", "-r", "json", "-p", str(PLUGIN_DIR), "-f", str(path),
         "--parallelism", "processes", "regexscan.RegExScan", "--pattern", NEEDLE.decode()],
        capture_output=True, text=True, cwd=tmp_path, env=env, timeout=180)
    assert result.returncode == 0, result.stderr
    rows = json.loads(result.stdout[result.stdout.index("["):])
    assert [row["Offset"] for row in rows] == [STRADDLE_VA, NEEDLE_VA]


def test_cache_key_is_salted_and_length_prefixed():
    tag = msl_layer._material_tag
    assert tag(b"ab", b"c", None) != tag(b"a", b"bc", None)
    assert tag(None, None, None) != tag(b"", None, None)
    unsalted = hashlib.sha256(PASSPHRASE.encode()).hexdigest()
    assert tag(None, PASSPHRASE.encode(), None) != unsalted


def test_open_capture_cache_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(msl_layer, "MAX_OPEN_SLICES", 1)
    first, second = tmp_path / "1.msl", tmp_path / "2.msl"
    _write_slice(first)
    _write_slice(second)
    opened = msl_layer.open_slice(str(first))
    msl_layer.open_slice(str(second))
    assert opened.closed and len(msl_layer._open_slices) == 1
    assert msl_layer.open_slice(str(first)) is not opened  # reopened, not the closed one


def test_failed_slice_construction_closes_the_source(plain_slice, monkeypatch):
    from memdiver.core.dump_source import MslDumpSource

    path, _data = plain_slice
    closed = []
    original_close = MslDumpSource.close
    monkeypatch.setattr(MslDumpSource, "close",
                        lambda self: (closed.append(True), original_close(self)))

    def broken(self, source):
        raise RuntimeError("boom")

    monkeypatch.setattr(msl_layer.MslSlice, "__init__", broken)
    with pytest.raises(RuntimeError, match="boom"):
        msl_layer.open_slice(str(path))
    assert closed


def test_both_layers_expose_the_shared_reader(plain_slice):
    path, _data = plain_slice
    ctx, top = _stack(path)
    vas = _vas_layer(ctx, top)
    assert top.reader is vas.reader is msl_layer.reader_for(str(path))
    assert top.reader.file_header.pid == 4242
