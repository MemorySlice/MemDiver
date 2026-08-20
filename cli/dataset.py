"""Dataset/analysis/UI/web/MCP/batch/import CLI commands, extracted from cli.main (P3.1)."""

import argparse
import json
import logging
import subprocess
import sys
from pathlib import Path

from ._shared import _print_missing_package, _write_output, to_cli_exit

logger = logging.getLogger("memdiver.cli")


def _cmd_ui(args: argparse.Namespace) -> int:
    """Launch the Marimo interactive UI."""
    import importlib.util
    if importlib.util.find_spec("marimo") is None:
        _print_missing_package("Marimo", extra="marimo")
        return 1
    extra = getattr(args, "extra_args", [])
    # run.py lives at the memdiver package root; this module is one level deeper
    # (memdiver/cli/dataset.py) since the P3.1 cli-package split, so go up twice.
    app = str(Path(__file__).parent.parent / "run.py")
    return subprocess.call([sys.executable, "-m", "marimo", "run", app] + extra)


def _cmd_web(args: argparse.Namespace) -> int:
    """Launch the FastAPI + React web application."""
    try:
        import uvicorn
        from memdiver.api.config import get_settings
        from memdiver.api.main import create_app
        from memdiver.api.security import InsecureBindError, enforce_bind_guardrail
    except ImportError:
        _print_missing_package("The FastAPI web backend (fastapi + uvicorn)", extra="api")
        return 1
    port = getattr(args, "port", 8080)
    settings = get_settings()
    # Refuse a non-loopback bind with no auth and no explicit override
    # *before* touching the socket — see api/security.py for the rationale.
    try:
        enforce_bind_guardrail(settings.host, settings)
    except InsecureBindError as exc:
        # Funnel through the shared CLI error mapper (prefixed message +
        # category exit code) rather than a bespoke print — see api/security.py.
        # This path is dispatched at main.py:main() *outside* the CapabilityError
        # backstop, so the catch is kept here (not delegated upward).
        return to_cli_exit(exc)
    print(f"MemDiver starting on http://{settings.host}:{port}", file=sys.stderr, flush=True)
    try:
        app = create_app()
        uvicorn.run(app, host=settings.host, port=port, log_level="info")
    except KeyboardInterrupt:
        pass
    return 0


def _cmd_analyze(args: argparse.Namespace) -> int:
    """Run analysis on library directories."""
    from memdiver.core.input_schemas import AnalyzeRequest
    from memdiver.engine.batch import run_analysis_request
    from memdiver.engine.serializer import serialize_result

    lib_dirs = [Path(d) for d in args.library_dirs]
    try:
        request = AnalyzeRequest(
            library_dirs=lib_dirs,
            phase=args.phase,
            protocol_version=args.protocol_version,
            keylog_filename=args.keylog_filename,
            template_name=args.template,
            max_runs=args.max_runs,
            normalize=args.normalize,
            expand_keys=not args.no_expand,
        )
    except ValueError as exc:
        logger.error("Invalid request: %s", exc)
        return 1

    result = run_analysis_request(request)
    _write_output(serialize_result(result), args.output)
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    """Scan a dataset root for available data."""
    from memdiver.app.composition import build_dataset_scanner
    from memdiver.core.input_schemas import ScanRequest
    from memdiver.engine.serializer import serialize_dataset_info

    try:
        request = ScanRequest(
            dataset_root=Path(args.root),
            keylog_filename=args.keylog_filename,
            protocols=args.protocols,
        )
    except ValueError as exc:
        logger.error("Invalid request: %s", exc)
        return 1

    scanner = build_dataset_scanner(request.dataset_root, request.keylog_filename)
    info = scanner.fast_scan(protocols=request.protocols)
    _write_output(serialize_dataset_info(info), args.output)
    return 0


def _cmd_mcp(args: argparse.Namespace) -> int:
    """Start the MCP server for AI integration."""
    import importlib.util
    # `mcp_server.server` imports the `mcp` SDK lazily inside create_server(), so
    # a plain `import main` would succeed without the extra and only crash later.
    # Probe the SDK up front so a missing extra yields the clean install hint.
    if importlib.util.find_spec("mcp") is None:
        _print_missing_package("The 'mcp' package", extra="mcp")
        return 1
    from memdiver.mcp_server.server import main as mcp_main
    transport = "sse" if args.sse else "stdio"
    mcp_main(transport=transport, port=getattr(args, "port", 8080))
    return 0


def _cmd_batch(args: argparse.Namespace) -> int:
    """Run a batch of analysis jobs from a config file."""
    from memdiver.core.input_schemas import AnalyzeRequest, BatchRequest
    from memdiver.engine.batch import BatchRunner

    config_path = Path(args.config)
    try:
        with open(config_path) as f:
            batch_cfg = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("Failed to read batch config: %s", exc)
        return 1

    jobs = []
    for job_cfg in batch_cfg.get("jobs", []):
        try:
            jobs.append(AnalyzeRequest(
                library_dirs=[Path(d) for d in job_cfg["library_dirs"]],
                phase=job_cfg["phase"],
                protocol_version=job_cfg["protocol_version"],
                keylog_filename=job_cfg.get("keylog_filename", "keylog.csv"),
                template_name=job_cfg.get("template_name", "Auto-detect"),
                max_runs=job_cfg.get("max_runs", 10),
                normalize=job_cfg.get("normalize", False),
                expand_keys=job_cfg.get("expand_keys", True),
            ))
        except (ValueError, KeyError) as exc:
            logger.error("Invalid job config: %s", exc)
            return 1

    effective_format = (
        getattr(args, "output_format", None)
        or batch_cfg.get("output_format", "json")
    )
    try:
        batch = BatchRequest(
            jobs=jobs,
            output_format=effective_format,
        )
    except ValueError as exc:
        logger.error("Invalid batch config: %s", exc)
        return 1

    def _progress(current: int, total: int, status: str | None) -> None:
        if args.verbose:
            print(f"[{current}/{total}] {status or ''}", file=sys.stderr)

    runner = BatchRunner(workers=args.workers)
    result = runner.run(batch, progress_callback=_progress)
    _write_output(result.to_dict(), args.output, fmt=batch.output_format)
    return 0


def _cmd_import(args: argparse.Namespace) -> int:
    """Import a dump file (raw .dump, ELF core, or minidump) to .msl format."""
    from memdiver.msl.importer import import_dump

    raw = Path(args.dump_file)
    out = Path(args.output) if args.output else raw.with_suffix(".msl")
    secrets = None
    if args.keylog:
        from memdiver.core.keylog import KeylogParser
        secrets = KeylogParser().parse(Path(args.keylog))

    result = import_dump(raw, out, pid=args.pid, secrets=secrets)
    print(json.dumps({
        "source": str(result.source_path),
        "output": str(result.output_path),
        "regions": result.regions_written,
        "key_hints": result.key_hints_written,
        "bytes": result.total_bytes,
    }, indent=2))
    return 0
