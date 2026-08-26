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
