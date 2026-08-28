"""End-to-end (synthetic) tests for the ``experiment`` path of
``memdiver.app.experiment_orchestration``.

The whole point of this file is to execute the *real* ``experiment_result``
producer and its ``_experiment_*`` helpers — nothing in the module under test
is mocked, patched, or stubbed. What we inject instead is a synthetic **dump
driver**: a fake :class:`DumpOrchestrator` whose ``run_experiment`` lays down
realistic multi-run memory dumps on disk via
``tests.fixtures.generate_realistic_fixtures.generate_dataset`` (the same
generator the ``benchmark_experiment`` fixture drives). The real consensus /
decryption-verify / plugin-emission stages then run against those dumps.

No private dataset is required and there is no e2e / requires_dataset marker.
"""

from __future__ import annotations

import ast
import shutil
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest
import yara

from memdiver.app import experiment_orchestration as tp
from memdiver.core.dump_driver import ExperimentResult
from memdiver.core.service_errors import (
    CapabilityError,
    ErrorCategory,
    FileNotFoundServiceError,
)
from memdiver.architect.pattern_generator import PatternGenerator

# The synthetic dump generator (importable because ``tests`` is a package;
# conftest already imports from ``tests.fixtures``).
from tests.fixtures.generate_realistic_fixtures import (
    KEY_LENGTH,
    KEY_OFFSET,
    generate_dataset,
)

NUM_RUNS = 24
SEED = 42


def _only_rule_meta(rule_source: str) -> dict:
    """Compile a single-rule YARA source and return its meta dict.

    Compiled for real (``yara`` is a declared base dependency), so a rule
    that libyara would reject fails here rather than in the field.
    """
    assert rule_source
    rules = list(yara.compile(source=rule_source))
    assert len(rules) == 1, f"expected exactly one rule, got {len(rules)}"
    return dict(rules[0].meta)


def _embedded_yara_meta(plugin_source: str) -> dict:
    """Compile the YARA_RULE embedded in a generated vol3 plugin."""
    tree = ast.parse(plugin_source)
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if "YARA_RULE" in targets and isinstance(node.value, ast.Constant):
            return _only_rule_meta(node.value.value)
    raise AssertionError("generated plugin has no YARA_RULE string assignment")


# ----------------------------------------------------------------------
# Synthetic dump driver: a fake DumpOrchestrator that materialises real
# on-disk dumps rather than spawning any process.
# ----------------------------------------------------------------------


class _FakeTool:
    def __init__(self, name: str) -> None:
        self.name = name


class _SyntheticOrchestrator:
    """Stand-in for ``core.dump_driver.DumpOrchestrator``.

    ``run_experiment`` writes a realistic fixture dataset (structural static
    base + per-run AES key + noise) into ``output_dir`` and returns the real
    :class:`ExperimentResult` container so every downstream ``_experiment_*``
    helper runs for real. ``fridump`` is deliberately pruned to a single dump
    so the consensus phase exercises its "not enough dumps -> skip" branch.
    """

    def __init__(self, tools=None) -> None:
        self.available_tools = [
            _FakeTool("memslicer"),
            _FakeTool("lldb"),
            _FakeTool("fridump"),
        ]

    def run_experiment(self, script_path, num_runs, output_dir) -> ExperimentResult:
        out = Path(output_dir)
        metadata = generate_dataset(out, num_runs=num_runs, seed=SEED)
        # Prune fridump down to one run dir so it is skipped in consensus.
        fridump_dir = out / "fridump"
        run_dirs = sorted(p for p in fridump_dir.iterdir() if p.is_dir())
        for extra in run_dirs[1:]:
            shutil.rmtree(extra)
        tool_dirs = {t.name: out / t.name for t in self.available_tools}
        return ExperimentResult(
            output_dir=out,
            tool_dirs=tool_dirs,
            num_runs=num_runs,
            tools_used=[t.name for t in self.available_tools],
            metadata=metadata,
        )


class _EmptyOrchestrator:
    """A DumpOrchestrator with no usable dump tools on this machine."""

    def __init__(self, tools=None) -> None:
        self.available_tools = []


@pytest.fixture
def target_file(tmp_path: Path) -> Path:
    t = tmp_path / "target.bin"
    t.write_bytes(b"fake target process image")
    return t


# ----------------------------------------------------------------------
# The full real experiment: spawn(fake) -> dump N x -> consensus ->
# decryption-verify -> emit plugin.
# ----------------------------------------------------------------------


def test_experiment_result_runs_end_to_end(monkeypatch, tmp_path, target_file):
    monkeypatch.setattr(
        "memdiver.core.dump_driver.DumpOrchestrator", _SyntheticOrchestrator
    )
    events: list = []
    out = tmp_path / "experiment_out"

    result = tp.experiment_result(
        target=str(target_file),
        output_dir=str(out),
        num_runs=NUM_RUNS,
        export_format="volatility3",
        convergence=True,
        max_fp=0,
        on_progress=lambda ev, **f: events.append((ev, f)),
    )

    # Top-level return contract.
    assert result["target"] == str(target_file)
    assert result["num_runs"] == NUM_RUNS
    # memslicer + lldb have >=2 dumps; fridump was pruned to 1 and skipped.
    assert set(result["tools_used"]) == {"memslicer", "lldb"}
    assert set(result["tool_results"]) == {"memslicer", "lldb"}

    ms = result["tool_results"]["memslicer"]
    assert ms["num_dumps"] == NUM_RUNS
    assert ms["format"] == "MSL (.msl)"
    assert ms["volatile_regions"] >= 1
    # metadata["runs"][0] is memslicer's run-1 key, and the sorted reference
    # dump IS memslicer run 1 -> the aligned scan finds the key.
    assert ms["decryption_verified"] is True
    # A plugin was emitted from the largest volatile region.
    plugin_path = Path(ms["plugin_saved"])
    assert plugin_path.is_file()
    assert plugin_path.suffix == ".py"
    assert plugin_path.parent == out / "plugins"
    # convergence sub-branch populated a serialized sweep.
    assert "convergence" in ms

    # lldb's reference carries a different per-run key than metadata runs[0],
    # so its scan does NOT verify -> exercises the False branch too.
    lldb = result["tool_results"]["lldb"]
    assert lldb["format"] == "Raw (.dump)"
    assert lldb["decryption_verified"] is False

    # Progress stream: capture -> consensus -> verify bracketing stages fired,
    # including the fridump skip notice.
    stages_started = {f.get("stage") for ev, f in events if ev == "stage_start"}
    assert {"capture", "consensus", "verify"} <= stages_started
    assert any(
        ev == "progress" and f.get("extra", {}).get("skipped")
        for ev, f in events
    )


def test_experiment_result_yara_export_writes_yar_plugin(monkeypatch, tmp_path,
                                                          target_file):
    """Driving with ``export_format='yara'`` routes the emit stage through the
    YARA renderer and writes a ``.yar`` plugin (covers that render branch)."""
    monkeypatch.setattr(
        "memdiver.core.dump_driver.DumpOrchestrator", _SyntheticOrchestrator
    )
    out = tmp_path / "yara_out"
    result = tp.experiment_result(
        target=str(target_file),
        output_dir=str(out),
        num_runs=NUM_RUNS,
        export_format="yara",
    )
    saved = result["tool_results"]["memslicer"]["plugin_saved"]
    assert saved is not None
    assert Path(saved).suffix == ".yar"
    assert Path(saved).is_file()


# ----------------------------------------------------------------------
# experiment_result guard branches.
# ----------------------------------------------------------------------


def test_experiment_result_missing_target_raises_not_found(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "memdiver.core.dump_driver.DumpOrchestrator", _SyntheticOrchestrator
    )
    events: list = []
    with pytest.raises(FileNotFoundServiceError, match="target not found"):
        tp.experiment_result(
            target=str(tmp_path / "does_not_exist.bin"),
            output_dir=str(tmp_path / "out"),
            on_progress=lambda ev, **f: events.append((ev, f)),
        )
    # The missing-target error is also streamed as an ``error`` event.
    assert any(ev == "error" for ev, _ in events)


def test_experiment_result_no_tools_raises_missing_backend(monkeypatch,
                                                           target_file, tmp_path):
    monkeypatch.setattr(
        "memdiver.core.dump_driver.DumpOrchestrator", _EmptyOrchestrator
    )
    with pytest.raises(CapabilityError) as exc:
        tp.experiment_result(
            target=str(target_file),
            output_dir=str(tmp_path / "out"),
        )
    assert exc.value.category == ErrorCategory.PRECONDITION
    assert exc.value.code == "missing_backend"


def test_experiment_result_cancelled_raises(monkeypatch, target_file, tmp_path):
    """``is_cancelled`` true at the first boundary aborts with a cancel error
    (covers ``_experiment_check_cancelled``)."""
    monkeypatch.setattr(
        "memdiver.core.dump_driver.DumpOrchestrator", _SyntheticOrchestrator
    )
    events: list = []
    with pytest.raises(CapabilityError) as exc:
        tp.experiment_result(
            target=str(target_file),
            output_dir=str(tmp_path / "out"),
            is_cancelled=lambda: True,
            on_progress=lambda ev, **f: events.append((ev, f)),
        )
    assert exc.value.code == "cancelled"
    assert any(ev == "error" and f.get("error") == "cancelled"
               for ev, f in events)


# ----------------------------------------------------------------------
# Focused real-helper coverage for branches the end-to-end run doesn't reach.
# These call the genuine helpers (no mocking of the module under test) with
# crafted inputs to drive their remaining branches.
# ----------------------------------------------------------------------


def test_render_plugin_yara_and_unknown_formats():
    reference = bytes(range(64))
    static_mask = [True] * 48 + [False] * 16  # 75% static -> pattern generates
    pattern = PatternGenerator.generate(reference, static_mask, "p")
    assert pattern is not None

    yara = tp._experiment_render_plugin(pattern, "yara")
    assert isinstance(yara, str) and yara
    # An unknown export format yields no rendered plugin.
    assert tp._experiment_render_plugin(pattern, "json") is None


def _static_pattern():
    """A 75%-static 64-byte pattern -- enough for PatternGenerator to accept."""
    pattern = PatternGenerator.generate(
        bytes(range(64)), [True] * 48 + [False] * 16, "p")
    assert pattern is not None
    return pattern


def test_render_plugin_emits_key_locator_metas():
    """GAP C: ``_experiment_render_plugin`` must forward the key locator.

    The experiment path knows the key's position inside the exported window
    exactly (the volatile region, padded by ``ctx_pad``), so its rule must
    carry the same ``key_offset``/``key_length`` metas every other emission
    path produces -- and must still compile.
    """
    pattern = dict(_static_pattern(), key_offset=48, key_length=16)
    meta = _only_rule_meta(tp._experiment_render_plugin(pattern, "yara"))
    assert meta["key_offset"] == 48
    assert meta["key_length"] == 16


def test_render_plugin_omits_key_locator_when_unknown():
    """A pattern carrying no locator must yield a rule without the metas."""
    meta = _only_rule_meta(
        tp._experiment_render_plugin(_static_pattern(), "yara"))
    assert "key_offset" not in meta
    assert "key_length" not in meta


def test_render_plugin_vol3_embeds_key_locator_metas():
    """The volatility3 branch builds its rule inline -- it must forward too."""
    pattern = dict(_static_pattern(), key_offset=48, key_length=16)
    source = tp._experiment_render_plugin(pattern, "volatility3")
    assert source is not None
    meta = _embedded_yara_meta(source)
    assert meta["key_offset"] == 48
    assert meta["key_length"] == 16
    # The rule meta and the plugin's own constants must agree -- one file may
    # not state two different key regions.
    assert "KEY_OFFSET = 48" in source
    assert "KEY_LENGTH = 16" in source


def test_emit_plugin_helper_derives_key_locator_from_volatile_region(tmp_path):
    """End of the chain: the emitted .yar carries the locator the helper derived.

    Region [32, 48) with ``ctx_pad=32`` clamps the window to slab offset 0,
    so the key sits 32 bytes into the exported pattern and is 16 long.
    """
    cm = SimpleNamespace(
        size=80, reference_bytes=bytes(80), variance=[0.0] * 80)
    region = SimpleNamespace(start=32, end=48)
    path = tp._experiment_emit_plugin(cm, [region], "keytool", tmp_path, "yara")
    assert path is not None
    meta = _only_rule_meta(path.read_text())
    assert meta["key_offset"] == 32
    assert meta["key_length"] == 16


def test_emit_plugin_helper_no_volatile_returns_none():
    assert tp._experiment_emit_plugin(
        cm=None, volatile=[], tool_name="t",
        output_dir=Path("."), export_format="volatility3") is None


def test_emit_plugin_helper_empty_reference_returns_none(tmp_path):
    cm = SimpleNamespace(
        size=0, reference_bytes=b"", variance=np.zeros(0, dtype=np.float32))
    region = SimpleNamespace(start=0, end=16)
    assert tp._experiment_emit_plugin(
        cm, [region], "t", tmp_path, "volatility3") is None


def test_emit_plugin_helper_list_variance_writes_yar(tmp_path):
    """A list-typed variance takes the non-ndarray static-mask branch and,
    with an all-static slab, writes a real .yar plugin."""
    cm = SimpleNamespace(
        size=80, reference_bytes=bytes(80), variance=[0.0] * 80)
    region = SimpleNamespace(start=32, end=48)
    path = tp._experiment_emit_plugin(cm, [region], "listtool", tmp_path, "yara")
    assert path is not None
    assert path.suffix == ".yar"
    assert path.read_text()


def test_emit_plugin_helper_no_static_returns_none(tmp_path):
    """An all-volatile slab fails the pattern's min-static-ratio -> None."""
    cm = SimpleNamespace(
        size=80, reference_bytes=bytes(range(80)),
        variance=np.full(80, 9999.0, dtype=np.float32))
    region = SimpleNamespace(start=16, end=64)
    assert tp._experiment_emit_plugin(
        cm, [region], "t", tmp_path, "volatility3") is None


def test_emit_plugin_helper_unknown_format_returns_none(tmp_path):
    """A valid pattern but an unrenderable export format -> None."""
    cm = SimpleNamespace(
        size=80, reference_bytes=bytes(80),
        variance=np.zeros(80, dtype=np.float32))
    region = SimpleNamespace(start=32, end=48)
    assert tp._experiment_emit_plugin(
        cm, [region], "t", tmp_path, "json") is None


def test_scan_for_key_returns_false_without_crypto(monkeypatch):
    """With crypto unavailable the scan short-circuits to False."""
    monkeypatch.setattr("memdiver.engine.verification.HAS_CRYPTO", False)
    region = SimpleNamespace(start=0, end=64)
    called = tp._experiment_scan_for_key(
        lambda *a, **k: True, [region], bytes(64), b"ct")
    assert called is False
