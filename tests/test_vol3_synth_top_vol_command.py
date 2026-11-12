"""The synthesize result's top-level ``vol_command`` points at the first PROVEN verdict.

With several targets the first ``.msl`` is not necessarily the one that proved the key; a
user re-running ``vol_command`` must be handed a command that proves. With no proven verdict
the historical behaviour (the first dump) is kept.
"""
from __future__ import annotations

from memdiver.app import tools_pipeline as tp
from memdiver.app import vol3_synth
from memdiver.app.tools_pipeline import synthesize_vol3_plugin

# Reuse the synthetic two-run fixtures of the main synthesis tests.
from tests.test_tools_synthesize_vol3_plugin import case_dir, two_runs  # noqa: F401

NAME = "memdiver_gocryptfs_topcmd"


def _fake_verify(statuses):
    """A ``_synth_verify_msl`` stand-in returning one verdict per dump with a given status."""

    def fake(source, *, paths, command, **_kwargs):
        out = []
        for path, status in zip(paths, statuses):
            hits = [{"key_offset": 1}] if status == "proven" else []
            out.append(tp._synth_verdict(
                "msl", path, proven_hits=hits, rows=len(hits), framework=None,
                display=command(path, ()), sample_override=False))
        return out

    return fake


def _run(runs, case_dir, monkeypatch, statuses):
    monkeypatch.setattr(vol3_synth, "_synth_verify_msl", _fake_verify(statuses))
    return synthesize_vol3_plugin(
        dump_paths=[r["msl"] for r in runs], name=NAME, key_hex=[r["key"] for r in runs],
        oracle_kind="gocryptfs-gcm", oracle_sample_path=[r["vault"] for r in runs],
        case_dir=case_dir, verify_on=("msl",))


def test_vol_command_is_the_first_proven_verdicts_command(two_runs, case_dir, monkeypatch):
    result = _run(two_runs, case_dir, monkeypatch, ("not_proven", "proven"))
    first, second = result["verdicts"]
    assert not first["proven"] and second["proven"]
    assert result["vol_command"] == second["vol_command"] != first["vol_command"]
    assert two_runs[1]["msl"] in result["vol_command"]


def test_vol_command_keeps_the_first_dump_when_the_first_verdict_proves(two_runs, case_dir, monkeypatch):
    result = _run(two_runs, case_dir, monkeypatch, ("proven", "proven"))
    assert result["vol_command"] == result["verdicts"][0]["vol_command"]


def test_vol_command_falls_back_to_the_first_dump_when_nothing_proves(two_runs, case_dir, monkeypatch):
    result = _run(two_runs, case_dir, monkeypatch, ("not_proven", "not_proven"))
    assert not result["proven"]
    assert result["vol_command"] == result["verdicts"][0]["vol_command"]
    assert two_runs[0]["msl"] in result["vol_command"]
