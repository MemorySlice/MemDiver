"""The LA57 (5-level paging) fallback in ``vol3plugins/memdiver_stackers.py``.

Synthetic page tables in a ``BufferDataLayer`` map a fake kernel (``linux_banner`` and
``init_task.comm``) with four or five levels; the stacker must restack only the 5-level
image, step aside when the running volatility3 has upstream LA57 support, and give its
layers a class path that ``-c`` replay and process layers can resolve.
"""
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("volatility3")

from volatility3.framework import contexts, interfaces  # noqa: E402
from volatility3.framework.layers import intel, physical  # noqa: E402

from memdiver.vol3plugins import memdiver_stackers as stackers  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
PLUGIN_DIR = REPO / "vol3plugins"
PAGE = 0x1000
PRESENT_RW = 0x3
ASLR_SHIFT = 0x2000000
BANNER_VA = 0xFFFFFFFF82000000
INIT_TASK_VA = 0xFFFFFFFF82400000
COMM_OFFSET = 0x10
BANNER = "Linux version 6.8.0-136-generic (fake) #1 SMP"


class _PhysicalImage:
    """A tiny physical memory with page tables built 4- or 5-level deep."""

    def __init__(self, levels: int, pages: int = 32):
        self.levels = levels
        self.memory = bytearray(pages * PAGE)
        self.next_free = 1
        self.dtb = self._alloc()

    def _alloc(self) -> int:
        address = self.next_free * PAGE
        self.next_free += 1
        return address

    def _entry(self, table: int, index: int, allocate: bool) -> int:
        slot = table + index * 8
        value = int.from_bytes(self.memory[slot:slot + 8], "little")
        if not value & 1 and allocate:
            value = self._alloc() | PRESENT_RW
            self.memory[slot:slot + 8] = value.to_bytes(8, "little")
        return value & ~0xFFF

    def map(self, va: int, data: bytes) -> None:
        """Map one fresh 4 KiB page at ``va`` and write ``data`` at its start."""
        shifts = [48, 39, 30, 21][-(self.levels - 1):] if self.levels == 5 else [39, 30, 21]
        table = self.dtb
        for shift in shifts:
            table = self._entry(table, (va >> shift) & 0x1FF, allocate=True)
        frame = self._entry(table, (va >> 12) & 0x1FF, allocate=True)
        self.memory[frame:frame + len(data)] = data


def _kernel_image(levels: int) -> _PhysicalImage:
    image = _PhysicalImage(levels)
    image.map(BANNER_VA + ASLR_SHIFT, BANNER.encode())
    image.map(INIT_TASK_VA + ASLR_SHIFT, bytes(COMM_OFFSET) + b"swapper/0\x00")
    return image


def _fake_table():
    addresses = {"linux_banner": BANNER_VA, "init_task": INIT_TASK_VA}
    task_struct = SimpleNamespace(relative_child_offset=lambda name: COMM_OFFSET)
    return SimpleNamespace(
        symbols=list(addresses), types=["task_struct"],
        get_symbol=lambda name: SimpleNamespace(address=addresses[name]),
        get_type=lambda name: task_struct)


def _stacked_context(image: _PhysicalImage, layer_class=intel.LinuxIntel32e,
                     config_root: str = "IntelHelper"):
    """A context holding what the stock Linux stacker leaves behind: physical + 4-level."""
    ctx = contexts.Context()
    ctx.add_layer(physical.BufferDataLayer(ctx, "Memory", "Memory", bytes(image.memory)))
    path = interfaces.configuration.path_join(config_root, "IntelLayer")
    ctx.config[f"{path}.memory_layer"] = "Memory"
    ctx.config[f"{path}.page_map_offset"] = image.dtb
    ctx.config[f"{path}.kernel_banner"] = BANNER
    layer = layer_class(ctx, config_path=path, name="IntelLayer", metadata={"os": "Linux"})
    layer.config["kernel_virtual_offset"] = ASLR_SHIFT
    ctx.add_layer(layer)
    return ctx


@pytest.fixture
def table(monkeypatch):
    fake = _fake_table()
    monkeypatch.setattr(stackers, "_kernel_table", lambda context, layer: fake)
    monkeypatch.delattr(intel, stackers.UPSTREAM_LA57_CLASS, raising=False)
    return fake


# ------------------------------------------------------------------- layer classes


def test_la57_classes_add_a_fifth_level_and_keep_their_family():
    for twin, four in ((stackers.LinuxIntel32eLA57, intel.LinuxIntel32e),
                       (stackers.Intel32eLA57, intel.Intel32e)):
        assert issubclass(twin, four)
        assert twin._maxvirtaddr == 57
        assert [entry[0] for entry in twin._structure] == ["page map layer 5"] + [
            entry[0] for entry in intel.Intel32e._structure]
    assert stackers.LinuxIntel32eLA57._maxphyaddr == 46  # PR #1991's 46-bit PFNs
    assert stackers.Intel32eLA57._maxphyaddr == intel.Intel32e._maxphyaddr


def test_la57_classes_have_the_vol_side_class_path():
    for twin in (stackers.Intel32eLA57, stackers.LinuxIntel32eLA57):
        assert twin.__module__ == stackers.CANONICAL_MODULE
        assert getattr(sys.modules[stackers.CANONICAL_MODULE], twin.__name__) is twin


# ------------------------------------------------------------------ read-back test


@pytest.mark.parametrize("levels", [4, 5])
def test_reads_kernel_back_passes_only_at_the_right_depth(levels):
    ctx = _stacked_context(_kernel_image(levels))
    four = ctx.layers["IntelLayer"]
    five = stackers._build_twin(ctx, four, stackers.LinuxIntel32eLA57)
    table = _fake_table()
    assert stackers.reads_kernel_back(four, table, ASLR_SHIFT) is (levels == 4)
    assert stackers.reads_kernel_back(five, table, ASLR_SHIFT) is (levels == 5)


def test_reads_kernel_back_fails_without_the_banner_symbol():
    ctx = _stacked_context(_kernel_image(4))
    table = _fake_table()
    table.symbols = ["init_task"]
    assert not stackers.reads_kernel_back(ctx.layers["IntelLayer"], table, ASLR_SHIFT)


# ------------------------------------------------------------------------ stacker


def test_stacker_restacks_a_five_level_kernel(table):
    ctx = _stacked_context(_kernel_image(5))
    twin = stackers.LinuxLA57IntelStacker.stack(ctx, "IntelLayer")
    assert type(twin) is stackers.LinuxIntel32eLA57
    assert twin.config["memory_layer"] == "Memory"
    assert twin.config["page_map_offset"] == ctx.layers["IntelLayer"].config["page_map_offset"]
    assert twin.config["kernel_virtual_offset"] == ASLR_SHIFT
    assert twin.config["kernel_banner"] == BANNER
    assert twin.config_path.startswith("IntelHelper.")
    assert twin.read(BANNER_VA + ASLR_SHIFT, 13) == b"Linux version"


def test_stacker_leaves_a_four_level_kernel_alone(table):
    ctx = _stacked_context(_kernel_image(4))
    assert stackers.LinuxLA57IntelStacker.stack(ctx, "IntelLayer") is None


def test_stacker_restacks_a_vmcoreinfo_intel32e_layer(table):
    ctx = _stacked_context(_kernel_image(5), intel.Intel32e, config_root="vmcoreinfo")
    twin = stackers.LinuxLA57IntelStacker.stack(ctx, "IntelLayer")
    assert type(twin) is stackers.Intel32eLA57
    assert twin.config_path.startswith("vmcoreinfo.")


def test_stacker_steps_aside_when_upstream_has_la57(table, monkeypatch):
    monkeypatch.setattr(intel, stackers.UPSTREAM_LA57_CLASS, object(), raising=False)
    ctx = _stacked_context(_kernel_image(5))
    assert stackers.LinuxLA57IntelStacker.stack(ctx, "IntelLayer") is None


def test_stacker_ignores_layers_it_did_not_expect(table):
    ctx = _stacked_context(_kernel_image(5), stackers.LinuxIntel32eLA57)
    assert stackers.LinuxLA57IntelStacker.stack(ctx, "IntelLayer") is None  # already 5-level
    assert stackers.LinuxLA57IntelStacker.stack(ctx, "Memory") is None      # not Intel


def test_stacker_returns_none_when_neither_depth_reads_the_kernel(table):
    image = _kernel_image(5)
    image.memory[image.dtb:image.dtb + PAGE] = bytes(PAGE)  # wipe the top-level table
    ctx = _stacked_context(image)
    assert stackers.LinuxLA57IntelStacker.stack(ctx, "IntelLayer") is None


def test_stacker_returns_none_without_a_kernel_table(monkeypatch):
    monkeypatch.setattr(stackers, "_kernel_table", lambda context, layer: None)
    monkeypatch.delattr(intel, stackers.UPSTREAM_LA57_CLASS, raising=False)
    ctx = _stacked_context(_kernel_image(5))
    assert stackers.LinuxLA57IntelStacker.stack(ctx, "IntelLayer") is None


def test_stacker_is_ordered_after_the_stock_linux_stackers():
    from volatility3.framework.automagic import linux
    assert stackers.LinuxLA57IntelStacker.stack_order > linux.LinuxIntelStacker.stack_order
    assert stackers.LinuxLA57IntelStacker.exclusion_list == ["mac", "windows"]
    assert stackers.LinuxLA57IntelStacker.__name__.endswith("IntelStacker")


# --------------------------------------------------------------- kernel table lookup


def test_kernel_table_matches_the_banner_isf(monkeypatch):
    from volatility3.framework.automagic import symbol_cache
    calls = []

    def find_location(identifier, operating_system):
        calls.append((identifier, operating_system))
        return "file:///isf/kernel.json"

    monkeypatch.setattr(symbol_cache, "load_cache_manager",
                        lambda: SimpleNamespace(find_location=find_location))
    wanted = SimpleNamespace(config={"isf_url": "file:///isf/kernel.json"})
    other = SimpleNamespace(config={"isf_url": "file:///isf/other.json"})
    ctx = SimpleNamespace(symbol_space={"LintelStacker1": other, "LintelStacker2": wanted})
    layer = SimpleNamespace(config={"kernel_banner": BANNER})
    assert stackers._kernel_table(ctx, layer) is wanted
    assert calls == [(BANNER.encode("latin-1"), "linux")]
    assert stackers._kernel_table(ctx, SimpleNamespace(config={})) is None


# ------------------------------------------------------ process layers and replay


def test_process_layers_inherit_five_level_paging(table):
    from volatility3.framework.symbols.generic import GenericIntelProcess
    ctx = _stacked_context(_kernel_image(5))
    twin = stackers.LinuxLA57IntelStacker.stack(ctx, "IntelLayer")
    ctx.add_layer(twin)
    task = SimpleNamespace(vol=SimpleNamespace(layer_name=twin.name))
    name = GenericIntelProcess._add_process_layer(task, ctx, twin.config["page_map_offset"])
    assert type(ctx.layers[name]) is stackers.LinuxIntel32eLA57
    assert ctx.layers[name].read(BANNER_VA + ASLR_SHIFT, 13) == b"Linux version"


def test_saved_configuration_replays_as_the_five_level_layer(table):
    from volatility3.framework.configuration import requirements
    ctx = _stacked_context(_kernel_image(5))
    twin = stackers.LinuxLA57IntelStacker.stack(ctx, "IntelLayer")
    ctx.add_layer(twin)
    config = twin.build_configuration()
    assert config["class"] == f"{stackers.CANONICAL_MODULE}.LinuxIntel32eLA57"

    replay = contexts.Context()  # what `vol -c` does: rebuild from the config alone
    replay.add_layer(physical.BufferDataLayer(replay, "Memory", "Memory",
                                              bytes(ctx.layers["Memory"].read(0, 32 * PAGE))))
    replay.config.splice("plugin.kernel_layer", config)
    replay.config["plugin.kernel_layer.memory_layer"] = "Memory"  # vol rebuilds it from -f
    requirement = requirements.TranslationLayerRequirement(name="kernel_layer")
    requirement.construct(replay, "plugin")
    assert not requirement.unsatisfied(replay, "plugin")
    rebuilt = replay.layers["kernel_layer"]
    assert type(rebuilt) is stackers.LinuxIntel32eLA57
    assert rebuilt.read(BANNER_VA + ASLR_SHIFT, 13) == b"Linux version"


_REPLAY_PROBE = textwrap.dedent("""
    import importlib, json, sys
    import volatility3.plugins
    from volatility3.framework import constants

    volatility3.plugins.__path__ = [sys.argv[1]] + constants.PLUGINS_PATH
    module = importlib.import_module("volatility3.plugins.memdiver_stackers")
    print(json.dumps({"module": module.LinuxIntel32eLA57.__module__,
                      "memdiver": sorted(m for m in sys.modules if m.startswith("memdiver"))}))
""")


def test_vol_side_import_resolves_the_class_path_without_memdiver(tmp_path):
    import json
    result = subprocess.run([sys.executable, "-c", _REPLAY_PROBE, str(PLUGIN_DIR)],
                            capture_output=True, text=True, cwd=tmp_path, timeout=120,
                            check=True, env={"PATH": "/usr/bin:/bin"})
    probe = json.loads(result.stdout.strip().splitlines()[-1])
    assert probe == {"module": stackers.CANONICAL_MODULE, "memdiver": []}


def test_stack_on_a_non_intel_layer_is_cheap(table):
    ctx = _stacked_context(_kernel_image(4))
    start = time.perf_counter()
    for _ in range(1000):
        stackers.LinuxLA57IntelStacker.stack(ctx, "Memory")
    assert time.perf_counter() - start < 0.5


_OLD_TREE_PROBE = textwrap.dedent("""
    import importlib, json, sys
    import volatility3.plugins
    from volatility3.framework import constants
    from volatility3.framework.layers import intel

    del intel.LinuxIntel32e  # like the 2.x arm64 fork: Intel32e only
    volatility3.plugins.__path__ = [sys.argv[1]] + constants.PLUGINS_PATH
    module = importlib.import_module("volatility3.plugins.memdiver_stackers")
    print(json.dumps(sorted(cls.__name__ for cls in module.LA57_TWIN)))
""")


def test_module_loads_on_a_volatility3_without_linux_intel32e(tmp_path):
    import json
    result = subprocess.run([sys.executable, "-c", _OLD_TREE_PROBE, str(PLUGIN_DIR)],
                            capture_output=True, text=True, cwd=tmp_path, timeout=120,
                            check=True, env={"PATH": "/usr/bin:/bin"})
    assert json.loads(result.stdout.strip().splitlines()[-1]) == ["Intel32e"]


# ------------------------------------------------------------ __pgtable_l5_enabled


L5_FLAG_VA = 0xFFFFFFFF82800000


@pytest.mark.parametrize("flag", [0, 1])
def test_l5_flag_set_reads_the_kernel_variable(flag):
    image = _kernel_image(4)
    image.map(L5_FLAG_VA + ASLR_SHIFT, flag.to_bytes(4, "little"))
    ctx = _stacked_context(image)
    table = _fake_table()
    addresses = {"linux_banner": BANNER_VA, "init_task": INIT_TASK_VA,
                 stackers.L5_FLAG_SYMBOL: L5_FLAG_VA}
    table.symbols = list(addresses)
    table.get_symbol = lambda name: SimpleNamespace(address=addresses[name])
    assert stackers.l5_flag_set(ctx.layers["IntelLayer"], table, ASLR_SHIFT) is bool(flag)
    assert not stackers.l5_flag_set(ctx.layers["IntelLayer"], _fake_table(), ASLR_SHIFT)


@pytest.mark.parametrize("flag", [False, True])
def test_flag_decides_when_both_depths_read_the_kernel(table, monkeypatch, flag):
    monkeypatch.setattr(stackers, "reads_kernel_back", lambda layer, table, shift: True)
    monkeypatch.setattr(stackers, "l5_flag_set", lambda layer, table, shift: flag)
    ctx = _stacked_context(_kernel_image(4))
    twin = stackers.LinuxLA57IntelStacker.stack(ctx, "IntelLayer")
    assert (type(twin) is stackers.LinuxIntel32eLA57) if flag else twin is None


# ----------------------------------------------- pickling (--parallelism processes)


_LA57_PICKLE_PROBE = textwrap.dedent("""
    import pickle, sys
    import volatility3.plugins
    from volatility3.framework import constants, contexts
    from volatility3.framework.layers import physical

    volatility3.plugins.__path__ = [sys.argv[1]] + constants.PLUGINS_PATH
    from volatility3.plugins import memdiver_stackers
    memory = bytes.fromhex(sys.stdin.read())
    ctx = contexts.Context()
    ctx.add_layer(physical.BufferDataLayer(ctx, "Memory", "Memory", memory))
    for name in ("Intel32eLA57", "LinuxIntel32eLA57"):
        ctx.config[name + ".memory_layer"] = "Memory"
        ctx.config[name + ".page_map_offset"] = int(sys.argv[2])
        layer = getattr(memdiver_stackers, name)(ctx, name, name)
        ctx.add_layer(layer)
    sys.stdout.buffer.write(pickle.dumps([ctx.layers["Intel32eLA57"],
                                          ctx.layers["LinuxIntel32eLA57"]]))
""")

_LA57_UNPICKLE_PROBE = textwrap.dedent("""
    import json, pickle, sys
    layers = pickle.loads(sys.stdin.buffer.read())  # no plugin dir on any path here
    print(json.dumps([[type(layer).__name__, type(layer).__module__,
                       layer.read(int(sys.argv[1]), 13).decode()] for layer in layers]))
""")


def test_la57_layers_pickled_under_vol_unpickle_in_a_fresh_interpreter(tmp_path):
    """What a spawned ``--parallelism processes`` worker does (macOS default: spawn)."""
    import json
    import os
    image = _kernel_image(5)
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    pickled = subprocess.run(
        [sys.executable, "-c", _LA57_PICKLE_PROBE, str(PLUGIN_DIR), str(image.dtb)],
        input=bytes(image.memory).hex().encode(), capture_output=True, cwd=tmp_path,
        env=env, timeout=120, check=True).stdout
    shipped = subprocess.run(
        [sys.executable, "-c", _LA57_UNPICKLE_PROBE, str(BANNER_VA + ASLR_SHIFT)],
        input=pickled, capture_output=True, cwd=tmp_path, env=env, timeout=120, check=True)
    rows = json.loads(shipped.stdout.decode().strip().splitlines()[-1])
    assert rows == [[name, stackers.CANONICAL_MODULE, "Linux version"]
                    for name in ("Intel32eLA57", "LinuxIntel32eLA57")]


# MEMDIVER_SECRETS_CORPUS = absolute path of the acquired-secrets capture dir (unset -> skipped).
LA57_CAPTURE = (Path(os.environ.get("MEMDIVER_SECRETS_CORPUS", "") or "/nonexistent")
                / "ubuntu-24.04-secrets-x86-la57_6.8.0-136-generic")


@pytest.mark.slow
def test_stock_vol_parallelism_processes_on_a_real_la57_capture(tmp_path):
    import json
    import os
    import shutil
    beside = Path(sys.executable).with_name("vol")  # the interpreter's own stock vol
    vol = str(beside) if beside.exists() else shutil.which("vol")
    stem = LA57_CAPTURE.name  # "...6.8.0-136-generic": with_suffix would cut ".0-136-generic"
    image, isf = (LA57_CAPTURE.with_name(stem + ext) for ext in (".lime", ".isf.json"))
    if vol is None or not image.exists() or not isf.exists():
        pytest.skip("stock vol or the LA57 secrets capture is not present")
    (tmp_path / "sym" / "linux").mkdir(parents=True)
    (tmp_path / "cache").mkdir()  # vol needs --cache-path to exist
    (tmp_path / "sym" / "linux" / "kernel.json").symlink_to(isf)
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    result = subprocess.run(
        [vol, "-q", "-r", "json", "--cache-path", str(tmp_path / "cache"),
         "-s", str(tmp_path / "sym"), "-p", str(PLUGIN_DIR), "--parallelism", "processes",
         "-f", str(image), "regexscan.RegExScan", "--pattern", "swapper/0"],
        capture_output=True, text=True, cwd=tmp_path, env=env, timeout=600)
    assert result.returncode == 0, result.stderr[-2000:]
    rows = json.loads(result.stdout[result.stdout.index("["):])
    # Same three hits PR #1991's own vol finds: init_task via the direct map twice + kernel text.
    assert len(rows) == 3
