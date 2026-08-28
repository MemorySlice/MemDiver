"""Surface-wiring proof for the pcap brute-force oracle.

The engine + producer (``engine.brute_force.run_brute_force`` /
``app.tools_pipeline.brute_force``) are exercised end-to-end in
``test_pcap_oracle_e2e.py``. This module proves only that the *surfaces*
(MCP tool, CLI subcommand, async web pipeline runner) forward the two new
``pcap_path`` / ``tls_client_random`` params to the producer — the parity a
user relies on to reach the feature at all. The producer itself is patched, so
these tests need no crypto/pcap fixtures.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

# --------------------------------------------------------------------------- #
# MCP surface
# --------------------------------------------------------------------------- #


def test_mcp_brute_force_tool_forwards_pcap_params():
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server

    server = create_server()
    tool = {t.name: t for t in server._tool_manager.list_tools()}["brute_force"]

    captured: dict = {}

    def _fake_brute_force(**kwargs):
        captured.update(kwargs)
        return {
            "hits_path": "/tmp/hits.json",
            "verified_count": 0,
            "total_candidates": 0,
            "exit_code": 1,
            "hits": [],
        }

    with patch("memdiver.mcp_server.tools_pipeline.brute_force", _fake_brute_force):
        tool.fn(
            candidates_path="/c/candidates.json",
            reference_path="/c/ref.bin",
            output_dir="/c/out",
            pcap_path="/c/session.pcap",
            tls_client_random="00" * 32,
        )

    assert captured["pcap_path"] == "/c/session.pcap"
    assert captured["tls_client_random"] == "00" * 32
    # oracle is now optional on the MCP surface.
    assert captured["oracle_path"] is None


# --------------------------------------------------------------------------- #
# CLI surface
# --------------------------------------------------------------------------- #


def test_cli_brute_force_accepts_pcap_flags():
    """The ``brute-force`` subcommand parses ``--pcap`` / ``--tls-client-random``
    and forwards them; ``--oracle`` is now optional."""
    from memdiver.cli.main import build_parser
    from memdiver.cli import pipeline as cli_pipeline

    parser = build_parser()
    args = parser.parse_args([
        "brute-force",
        "--candidates", "/c/candidates.json",
        "--dump", "/c/ref.bin",
        "--pcap", "/c/session.pcap",
        "--tls-client-random", "ab" * 32,
        "--output", "/c/hits.json",
    ])
    assert args.pcap == "/c/session.pcap"
    assert args.tls_client_random == "ab" * 32
    assert args.oracle is None  # oracle no longer required

    captured: dict = {}

    def _fake_brute_force(**kwargs):
        captured.update(kwargs)
        return {
            "hits_path": "/c/scratch/hits.json",
            "verified_count": 1,
            "total_candidates": 1,
            "exit_code": 0,
            # A single hit takes the summary branch that avoids reading the
            # output file back, so no real filesystem is touched.
            "hits": [{"offset": 0, "length": 32}],
        }

    # ``brute_force`` / ``shutil`` are imported inside the handler; patch them at
    # their source so the local ``from ... import`` / ``import`` pick up the fake.
    with patch("memdiver.app.tools_pipeline.brute_force", _fake_brute_force), \
            patch("shutil.copyfile"), \
            patch("pathlib.Path.mkdir"):
        cli_pipeline._cmd_brute_force(args)

    assert captured["pcap_path"] == "/c/session.pcap"
    assert captured["tls_client_random"] == "ab" * 32
    assert captured["oracle_path"] is None


def test_cli_brute_force_keeps_oracle_path_working():
    """The existing ``--oracle`` script path is unchanged: oracle forwarded,
    pcap params defaulting to ``None``."""
    from memdiver.cli.main import build_parser

    parser = build_parser()
    args = parser.parse_args([
        "brute-force",
        "--candidates", "/c/candidates.json",
        "--dump", "/c/ref.bin",
        "--oracle", "/c/oracle.py",
        "--output", "/c/hits.json",
    ])
    assert args.oracle == "/c/oracle.py"
    assert args.pcap is None
    assert args.tls_client_random is None


# --------------------------------------------------------------------------- #
# Async web pipeline runner
# --------------------------------------------------------------------------- #


def test_pipeline_runner_brute_force_stage_forwards_pcap():
    """``_run_brute_force`` (the async pipeline wrapper) forwards ``pcap_path`` /
    ``tls_client_random`` and omits the oracle path when a pcap is supplied."""
    from pathlib import Path

    from memdiver.app.pipeline import pipeline_runner

    captured: dict = {}

    def _fake_run_producer(_producer, **kwargs):
        captured.update(kwargs)

    class _Ctx:
        def is_cancelled(self):
            return False

    with patch.object(pipeline_runner, "_run_producer", _fake_run_producer), \
            patch.object(pipeline_runner, "register_artifact"), \
            patch.object(pipeline_runner, "_producer_sink", return_value=None):
        pipeline_runner._run_brute_force(
            Path("/c/candidates.json"),
            Path("/c/ref.bin"),
            None,  # oracle_path
            {},
            pcap_path="/c/session.pcap",
            tls_client_random="cd" * 32,
            ctx=_Ctx(),
            artifact_dir=Path("/c/artifacts"),
            artifacts=[],
        )

    assert captured["pcap_path"] == "/c/session.pcap"
    assert captured["tls_client_random"] == "cd" * 32
    assert captured["oracle_path"] is None


# --------------------------------------------------------------------------- #
# Library surface
# --------------------------------------------------------------------------- #


def test_library_surface_exports_inspect_pcap():
    """``memdiver.services`` is the documented library surface for the pcap
    "arm" step (docs/oracle/pcap_oracle.md), so ``inspect_pcap`` must be
    re-exported there — and be the very same producer object, not a copy."""
    import memdiver.services as services
    from memdiver.app import tools_pipeline

    assert services.inspect_pcap is tools_pipeline.inspect_pcap
    assert "inspect_pcap" in services.__all__


# --------------------------------------------------------------------------- #
# Pcap-oracle work caps (Wave 0 D0c) — previously unreachable from any surface
# --------------------------------------------------------------------------- #


def test_mcp_brute_force_tool_forwards_pcap_caps():
    """``pcap_max_records`` / ``pcap_max_challenges`` reach the producer via MCP.

    Both caps silently truncate verification coverage; before this they lived
    only as defaults inside the resource/oracle with no surface to set them.
    """
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server

    server = create_server()
    tool = {t.name: t for t in server._tool_manager.list_tools()}["brute_force"]

    captured: dict = {}

    def _fake_brute_force(**kwargs):
        captured.update(kwargs)
        return {
            "hits_path": "/tmp/hits.json",
            "verified_count": 0,
            "total_candidates": 0,
            "exit_code": 1,
            "hits": [],
        }

    with patch("memdiver.mcp_server.tools_pipeline.brute_force", _fake_brute_force):
        tool.fn(
            candidates_path="/c/candidates.json",
            reference_path="/c/ref.bin",
            output_dir="/c/out",
            pcap_path="/c/session.pcap",
            pcap_max_records=4,
            pcap_max_challenges=32,
        )

    assert captured["pcap_max_records"] == 4
    assert captured["pcap_max_challenges"] == 32


def test_cli_brute_force_accepts_pcap_cap_flags():
    """The ``brute-force`` subcommand parses and forwards both cap flags."""
    from memdiver.cli.main import build_parser
    from memdiver.cli import pipeline as cli_pipeline

    parser = build_parser()
    args = parser.parse_args([
        "brute-force",
        "--candidates", "/c/candidates.json",
        "--dump", "/c/ref.bin",
        "--pcap", "/c/session.pcap",
        "--pcap-max-records", "4",
        "--pcap-max-challenges", "32",
        "--output", "/c/hits.json",
    ])
    assert args.pcap_max_records == 4
    assert args.pcap_max_challenges == 32

    captured: dict = {}

    def _fake_brute_force(**kwargs):
        captured.update(kwargs)
        return {
            "hits_path": "/c/scratch/hits.json",
            "verified_count": 1,
            "total_candidates": 1,
            "exit_code": 0,
            "hits": [{"offset": 0, "length": 32}],
        }

    with patch("memdiver.app.tools_pipeline.brute_force", _fake_brute_force), \
            patch("shutil.copyfile"), \
            patch("pathlib.Path.mkdir"):
        cli_pipeline._cmd_brute_force(args)

    assert captured["pcap_max_records"] == 4
    assert captured["pcap_max_challenges"] == 32


def test_cli_brute_force_pcap_caps_default_to_none():
    """Unset flags forward ``None`` — "keep today's default", so behaviour is
    unchanged unless the caps are asked for explicitly."""
    from memdiver.cli.main import build_parser

    parser = build_parser()
    args = parser.parse_args([
        "brute-force",
        "--candidates", "/c/candidates.json",
        "--dump", "/c/ref.bin",
        "--pcap", "/c/session.pcap",
        "--output", "/c/hits.json",
    ])
    assert args.pcap_max_records is None
    assert args.pcap_max_challenges is None


def test_producer_omits_absent_caps_from_the_pcap_oracle_config():
    """``None`` caps leave the oracle config exactly as it was.

    The producer builds the pcap oracle's config dict; an unset cap must not
    appear at all, so ``builtin_oracle`` keeps the resource/oracle defaults.
    """
    from memdiver.app import tools_pipeline

    def _capture_config(*_args, **kwargs):
        _capture_config.oracle_config = kwargs.get("oracle_config")
        raise RuntimeError("stop after the config is built")

    for caps, expected in (
        ({}, {"resource_type", "pcap"}),
        (
            {"pcap_max_records": 4, "pcap_max_challenges": 32},
            {"resource_type", "pcap", "max_records_per_direction", "max_challenges"},
        ),
    ):
        with patch("memdiver.engine.brute_force.run_brute_force", _capture_config), \
                patch.object(tools_pipeline, "_read_reference_bytes", return_value=b""):
            with pytest.raises(RuntimeError):
                tools_pipeline.brute_force(
                    candidates_path="/c/candidates.json",
                    reference_path="/c/ref.bin",
                    output_dir="/c/out",
                    pcap_path="/c/session.pcap",
                    **caps,
                )
        config = _capture_config.oracle_config
        assert set(config) == expected
        if caps:
            assert config["max_records_per_direction"] == 4
            assert config["max_challenges"] == 32


def test_pipeline_runner_brute_force_stage_forwards_pcap_caps():
    """The async web pipeline wrapper forwards both caps to the producer."""
    from pathlib import Path

    from memdiver.app.pipeline import pipeline_runner

    captured: dict = {}

    def _fake_run_producer(_producer, **kwargs):
        captured.update(kwargs)

    class _Ctx:
        def is_cancelled(self):
            return False

    with patch.object(pipeline_runner, "_run_producer", _fake_run_producer), \
            patch.object(pipeline_runner, "register_artifact"), \
            patch.object(pipeline_runner, "_producer_sink", return_value=None):
        pipeline_runner._run_brute_force(
            Path("/c/candidates.json"),
            Path("/c/ref.bin"),
            None,  # oracle_path
            {},
            pcap_path="/c/session.pcap",
            pcap_max_records=4,
            pcap_max_challenges=32,
            ctx=_Ctx(),
            artifact_dir=Path("/c/artifacts"),
            artifacts=[],
        )

    assert captured["pcap_max_records"] == 4
    assert captured["pcap_max_challenges"] == 32


def test_web_request_model_carries_pcap_caps_to_worker_params():
    """``POST /api/pipeline/run`` accepts the caps and relays them to the worker."""
    from pathlib import Path

    from memdiver.api.routers.pipeline import (
        PipelineRunRequest,
        _build_worker_params,
    )

    request = PipelineRunRequest(
        source_paths=["/c/dump1.msl"],
        pcap_path="/c/session.pcap",
        pcap_max_records=4,
        pcap_max_challenges=32,
    )
    worker = _build_worker_params(request, None, Path("/c/tasks"))

    assert worker["pcap_max_records"] == 4
    assert worker["pcap_max_challenges"] == 32

    # Unset stays None: the worker then keeps the producer defaults.
    default = _build_worker_params(
        PipelineRunRequest(source_paths=["/c/dump1.msl"], pcap_path="/c/session.pcap"),
        None,
        Path("/c/tasks"),
    )
    assert default["pcap_max_records"] is None
    assert default["pcap_max_challenges"] is None


# --------------------------------------------------------------------------- #
# Producer -> ground-truth ledger: the corpus axes must survive the hop
# --------------------------------------------------------------------------- #
#
# `--persist-ground-truth` is the W5 proof ledger's only production writer. It
# used to file hits with no axes at all, so every `library` / `protocol_version`
# / `scenario` / `run_number` / `phase` / `dump_path` column landed empty on
# every real run and the ledger could not be sliced by anything. These tests
# pin the producer end of that hop; `tests/test_project_db.py` pins the DB end.

#: A real corpus dump path (see core.corpus_axes for the layout). Axis
#: resolution is pure path decomposition, so this is a STRING and the tests
#: below need no corpus tree on disk.
CORPUS_DUMP = (
    "/Users/danielbaier/Desktop/tls_dumps/TLS13/"
    "100_iterations_Abort_KeyUpdate/openssl/openssl_run_13_1/"
    "20251020_171845_606711_pre_server_key_update.dump"
)


class _FakeBruteForceResult:
    """Minimal stand-in for ``engine.brute_force``'s result object."""

    stride = 4
    candidates_tested = 1
    candidates_possible = 1
    coverage_fraction = 1.0
    verified_count = 1
    total_candidates = 1
    exit_code = 0

    def to_dict(self):
        return {"hits": [{"offset": 585148, "length": 32, "key_hex": "ab" * 32}]}


def _run_producer_capturing_ledger_call(tmp_path, reference_path):
    """Run ``brute_force`` with the engine stubbed; return the ledger kwargs."""
    from memdiver.app import tools_pipeline

    captured: dict = {}

    def _fake_persist(hits, **kwargs):
        captured["hits"] = hits
        captured.update(kwargs)
        return "run-id"

    with patch("memdiver.engine.brute_force.run_brute_force",
               return_value=_FakeBruteForceResult()), \
            patch.object(tools_pipeline, "_read_reference_bytes", return_value=b""), \
            patch.object(tools_pipeline, "_persist_ground_truth_hits", _fake_persist):
        result = tools_pipeline.brute_force(
            candidates_path=str(tmp_path / "candidates.json"),
            reference_path=reference_path,
            output_dir=str(tmp_path / "out"),
            pcap_path=str(tmp_path / "session.pcap"),
            persist_ground_truth=True,
        )
    return captured, result


def test_producer_sends_corpus_axes_to_the_ground_truth_ledger(tmp_path):
    """A corpus dump's axes are resolved from ``reference_path`` and forwarded."""
    captured, result = _run_producer_capturing_ledger_call(tmp_path, CORPUS_DUMP)

    assert captured["confirmed_by"] == "pcap"
    assert captured["library"] == "openssl"
    assert captured["protocol_version"] == "13"
    assert captured["library_version"] == "unknown"
    assert captured["scenario"] == "100_iterations_Abort_KeyUpdate"
    assert captured["run_number"] == 1
    assert captured["phase"] == "pre_server_key_update"
    assert captured["dump_path"] == CORPUS_DUMP
    # Never guessed from a single path: it is positional across a run's SIBLING
    # dumps, so inventing one would make the ledger key mutate (core.corpus_axes).
    assert captured["canonical_phase"] == ""
    assert result["ground_truth_run_id"] == "run-id"


def test_producer_ledger_call_degrades_for_a_non_corpus_dump(tmp_path):
    """An ad-hoc reference dump still files hits, with the path as the only axis.

    A path outside the corpus layout resolves to no axes, so the producer
    forwards ONLY ``dump_path`` and lets every other axis fall through to the
    ledger's own documented default — the defaults live in one place
    (``_persist_ground_truth_hits``'s signature), never restated here.
    """
    adhoc = str(tmp_path / "reference.bin")
    captured, result = _run_producer_capturing_ledger_call(tmp_path, adhoc)

    assert captured["dump_path"] == adhoc
    assert set(captured) == {"hits", "confirmed_by", "project_name", "dump_path"}
    assert result["ground_truth_run_id"] == "run-id"


def test_producer_skips_the_ledger_when_the_opt_in_is_off(tmp_path):
    """``persist_ground_truth`` stays opt-in: no flag, no ledger call at all."""
    from memdiver.app import tools_pipeline

    calls: list = []

    with patch("memdiver.engine.brute_force.run_brute_force",
               return_value=_FakeBruteForceResult()), \
            patch.object(tools_pipeline, "_read_reference_bytes", return_value=b""), \
            patch.object(tools_pipeline, "_persist_ground_truth_hits",
                         lambda *a, **k: calls.append(k)):
        result = tools_pipeline.brute_force(
            candidates_path=str(tmp_path / "candidates.json"),
            reference_path=CORPUS_DUMP,
            output_dir=str(tmp_path / "out"),
            pcap_path=str(tmp_path / "session.pcap"),
        )

    assert calls == []
    assert result["ground_truth_run_id"] is None


# --------------------------------------------------------------------------- #
# producer cap validation (regression guard for the brute_force call site)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("cap", ["pcap_max_records", "pcap_max_challenges"])
@pytest.mark.parametrize("value", [0, -1])
def test_brute_force_rejects_a_cap_below_one(tmp_path, cap, value):
    """The run itself refuses a cap below 1, matching ``inspect_pcap``'s arm step.

    ``_validate_pcap_caps`` is shared, but only ``inspect_pcap``'s call site was
    covered; this pins ``brute_force``'s. A cap of 0 yields zero decryption
    challenges and a negative one reaches ``challenges[:-1]``, so either would
    report a genuine key as "0 confirmed" from a run that looks successful.
    Validation happens before any oracle or reference I/O, so nothing is stubbed.
    """
    from memdiver.app import tools_pipeline
    from memdiver.core.service_errors import CapabilityError, ErrorCategory

    with pytest.raises(CapabilityError) as excinfo:
        tools_pipeline.brute_force(
            candidates_path=str(tmp_path / "candidates.json"),
            reference_path=str(tmp_path / "ref.bin"),
            output_dir=str(tmp_path / "out"),
            pcap_path=str(tmp_path / "session.pcap"),
            **{cap: value},
        )

    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    # 400, not 500: a bad cap is the caller's input, and the web surface derives
    # its status from the category alone.
    assert excinfo.value.status == 400
    assert cap in str(excinfo.value)
    assert "must be >= 1" in str(excinfo.value)
