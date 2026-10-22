"""CLI ``--force-memory``: the memory-budget refusal and its override.

With ``MEMDIVER_MEMORY_BUDGET_MB=1`` a three-dump consensus over 512 KiB dumps
estimates ~3 MiB, so the guard refuses unless ``--force-memory`` is passed.
"""

import io
import json
import sys

import numpy as np
import pytest

from memdiver.cli import _build_parser, main
from memdiver.cli._shared import (
    FORCE_MEMORY_HINT,
    MEMORY_BUDGET_EXCEEDED_CODE,
    add_force_memory_argument,
    force_memory_requested,
    print_cli_error,
    to_cli_exit,
)
from memdiver.core.service_errors import CapabilityError, ErrorCategory

DUMP_SIZE = 512 * 1024

#: Every subcommand wired to a ``force``-taking producer, with the minimal
#: positional/required args the parser needs.
WIRED_COMMANDS = {
    "analyze": ["lib", "--phase", "p", "--protocol-version", "13"],
    "batch": ["--config", "c.json"],
    "consensus": ["a", "b"],
    "consensus-window": ["a", "b"],
    "consensus-regions": ["a", "b"],
    "analyze-candidates": ["a", "b"],
    "export": ["a", "b", "--auto"],
    "experiment": ["--target", "t.py"],
}


@pytest.fixture
def dumps(tmp_path):
    rng = np.random.default_rng(7)
    paths = []
    for i in range(3):
        path = tmp_path / f"d{i}.dump"
        path.write_bytes(rng.integers(0, 256, DUMP_SIZE, dtype=np.uint8).tobytes())
        paths.append(str(path))
    return paths


@pytest.fixture
def tiny_budget(monkeypatch, tmp_path):
    monkeypatch.setenv("MEMDIVER_MEMORY_BUDGET_MB", "1")
    # analyze-candidates files a stored comparison; keep it out of $HOME.
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


def _run_cli(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["memdiver", *argv])
    with pytest.raises(SystemExit) as exc_info:
        main()
    return exc_info.value.code


# --- parser ---------------------------------------------------------------

@pytest.mark.parametrize("command", sorted(WIRED_COMMANDS))
def test_force_memory_flag_registered(command):
    parser = _build_parser()
    base = [command, *WIRED_COMMANDS[command]]
    assert parser.parse_args(base).force_memory is False
    assert parser.parse_args([*base, "--force-memory"]).force_memory is True


def test_force_memory_requested_defaults_false_without_attribute():
    class _Bare:
        pass
    assert force_memory_requested(_Bare()) is False


def test_add_force_memory_argument_store_true():
    import argparse
    parser = argparse.ArgumentParser()
    add_force_memory_argument(parser)
    assert parser.parse_args(["--force-memory"]).force_memory is True
    assert "--force-memory" in parser.format_help()


# --- error mapping --------------------------------------------------------

def _budget_error():
    return CapabilityError("too big", category=ErrorCategory.PRECONDITION,
                           code=MEMORY_BUDGET_EXCEEDED_CODE)


def test_print_cli_error_adds_hint_for_budget_refusal():
    stream = io.StringIO()
    print_cli_error(_budget_error(), stream=stream)
    assert "too big" in stream.getvalue()
    assert FORCE_MEMORY_HINT in stream.getvalue()


def test_print_cli_error_no_hint_for_other_errors():
    stream = io.StringIO()
    print_cli_error(CapabilityError("bad", code="other"), stream=stream)
    assert FORCE_MEMORY_HINT not in stream.getvalue()


def test_to_cli_exit_budget_refusal_is_nonzero():
    stream = io.StringIO()
    assert to_cli_exit(_budget_error(), stream=stream) == 2
    assert "--force-memory" in stream.getvalue()


# --- end to end -----------------------------------------------------------

def test_consensus_refused_under_tiny_budget(monkeypatch, capsys, dumps,
                                             tiny_budget, tmp_path):
    out = tmp_path / "out.json"
    code = _run_cli(monkeypatch, ["consensus", *dumps, "-o", str(out)])
    assert code != 0
    assert "--force-memory" in capsys.readouterr().err
    assert not out.exists()


def test_consensus_runs_with_force_memory(monkeypatch, dumps, tiny_budget,
                                          tmp_path):
    out = tmp_path / "out.json"
    code = _run_cli(monkeypatch, ["consensus", *dumps, "-o", str(out),
                                  "--force-memory"])
    assert code == 0
    assert json.loads(out.read_text())["num_dumps"] == 3


def test_consensus_regions_refused_then_forced(monkeypatch, capsys, dumps,
                                               tiny_budget, tmp_path):
    out = tmp_path / "regions.json"
    assert _run_cli(monkeypatch, ["consensus-regions", *dumps,
                                  "-o", str(out)]) != 0
    assert "--force-memory" in capsys.readouterr().err
    assert _run_cli(monkeypatch, ["consensus-regions", *dumps, "-o", str(out),
                                  "--force-memory"]) == 0
    assert out.exists()


def test_consensus_window_refused_then_forced(monkeypatch, capsys, dumps,
                                              tiny_budget, tmp_path):
    out = tmp_path / "window.json"
    argv = ["consensus-window", *dumps, "--length", "64", "-o", str(out)]
    assert _run_cli(monkeypatch, argv) != 0
    assert "--force-memory" in capsys.readouterr().err
    assert _run_cli(monkeypatch, [*argv, "--force-memory"]) == 0
    assert out.exists()


def test_analyze_candidates_refused_then_forced(monkeypatch, capsys, dumps,
                                                tiny_budget, tmp_path):
    out = tmp_path / "cand.json"
    argv = ["analyze-candidates", *dumps, "-o", str(out)]
    assert _run_cli(monkeypatch, argv) != 0
    assert "--force-memory" in capsys.readouterr().err
    assert _run_cli(monkeypatch, [*argv, "--force-memory"]) == 0
    assert out.exists()


def test_consensus_convergence_refused_then_forced(monkeypatch, capsys, dumps,
                                                  tiny_budget, tmp_path):
    """``--force-memory`` reaches the convergence sweep's own budget check,
    not only the consensus build (the sweep re-checks for the largest N)."""
    out = tmp_path / "conv.json"
    argv = ["consensus", *dumps, "--convergence", "-o", str(out)]
    assert _run_cli(monkeypatch, argv) != 0
    assert "--force-memory" in capsys.readouterr().err
    assert not out.exists()
    assert _run_cli(monkeypatch, [*argv, "--force-memory"]) == 0
    payload = json.loads(out.read_text())
    assert payload["convergence"]["total_dumps"] == 3


def test_consensus_convergence_forwards_force(monkeypatch, dumps, tmp_path):
    from memdiver.engine import convergence
    from memdiver.engine.convergence import ConvergenceSweepResult

    seen = {}

    def spy(paths, **kwargs):
        seen["force"] = kwargs.get("force")
        return ConvergenceSweepResult(total_dumps=len(paths))

    monkeypatch.setattr(convergence, "run_convergence_sweep", spy)
    out = tmp_path / "conv.json"
    assert _run_cli(monkeypatch, ["consensus", *dumps, "--convergence",
                                  "-o", str(out), "--force-memory"]) == 0
    assert seen["force"] is True
