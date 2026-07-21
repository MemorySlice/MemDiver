"""CLI entry point for MemDiver — headless analysis and interactive UI."""

import argparse
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

from memdiver.core.service_errors import CapabilityError, ErrorCategory

logger = logging.getLogger("memdiver.cli")


# Per-category process exit codes for the CLI backstop: NOT_FOUND is its own
# code (3) so scripts can distinguish "missing input" from a bad argument (2);
# caller-correctable input/precondition/unsupported errors share 2; anything
# INTERNAL is 1 (and additionally logs a traceback for the operator).
_CLI_EXIT = {
    ErrorCategory.NOT_FOUND: 3,
    ErrorCategory.INVALID_INPUT: 2,
    ErrorCategory.PRECONDITION: 2,
    ErrorCategory.UNSUPPORTED: 2,
    ErrorCategory.INTERNAL: 1,
}


def to_cli_exit(err: CapabilityError, *, stream=sys.stderr) -> int:
    """Translate a propagating ``CapabilityError`` into a CLI message + exit code.

    Prints a single ``memdiver: ERROR — <message>`` line to ``stream`` and maps
    the error's category to a process exit code via ``_CLI_EXIT``. Internal
    errors additionally log a full traceback under ``memdiver.cli`` so an
    operator can diagnose an unexpected failure.
    """
    print(f"memdiver: ERROR — {err.message}", file=stream)
    if err.category is ErrorCategory.INTERNAL:
        logging.getLogger("memdiver.cli").exception("internal error")
    return _CLI_EXIT[err.category]


def _decrypt_parent_parser() -> argparse.ArgumentParser:
    """Shared parent parser for encrypted-MSL decryption flags (spec §10).

    Attach via ``parents=[_decrypt_parent_parser()]`` to any subcommand that
    opens a dump, so it accepts a key for AES/XChaCha-encrypted .msl files.
    """
    p = argparse.ArgumentParser(add_help=False)
    g = p.add_argument_group("encrypted MSL (spec §10)")
    g.add_argument("--key-file", help="32-byte raw content-encryption key file "
                                      "(KeyEncap=None, KDF=None)")
    g.add_argument("--passphrase", help="Passphrase for Argon2id-derived key "
                                        "(KeyEncap=None, KDF=Argon2id)")
    g.add_argument("--kem-key-file", help="Recipient private key file for "
                                          "X25519/ML-KEM/hybrid key encapsulation")
    return p


def _key_material_from_args(args: argparse.Namespace) -> dict:
    """Build the open_dump() key-material kwargs from decryption CLI flags.

    Returns a dict with key/passphrase/kem_private_key (all None when no
    decryption flags were supplied), suitable for ``open_dump(path, **kw)``.
    """
    key = None
    if getattr(args, "key_file", None):
        key = Path(args.key_file).read_bytes()
    kem_private = None
    if getattr(args, "kem_key_file", None):
        kem_private = Path(args.kem_key_file).read_bytes()
    passphrase = None
    if getattr(args, "passphrase", None):
        passphrase = args.passphrase.encode("utf-8")
    return {"key": key, "passphrase": passphrase, "kem_private_key": kem_private}


def _warn_tag_status(source) -> None:
    """Print a user-facing line about an encrypted dump's AEAD verification.

    Green = verified, red = failed/missing key. Plaintext dumps say nothing.
    """
    from memdiver.msl.enums import TagStatus
    status = getattr(source, "tag_status", TagStatus.NOT_ENCRYPTED)
    if status == TagStatus.VALID:
        print("memdiver: AEAD verified — encrypted dump decrypted successfully",
              file=sys.stderr)
    elif status == TagStatus.CORRUPTED:
        print("memdiver: ERROR — AEAD verification FAILED (wrong key or tampered file)",
              file=sys.stderr)
    elif status == TagStatus.MISSING_KEY:
        print("memdiver: ERROR — dump is encrypted; supply --key-file / "
              "--passphrase / --kem-key-file", file=sys.stderr)


def _resolve_dump_paths(raw_paths: list) -> list:
    """Expand directories to all supported dump flavours; pass through files.

    Recognised extensions inside a run directory:
      * ``.dump`` and ``.msl`` (legacy + Memory Slice)
      * ``.gcore.core`` and bare ``.core`` (Linux gcore/ELF core)
      * ``gdb_raw.bin`` / ``lldb_raw.bin`` (regioned raw dumps)
    """
    paths: list[Path] = []
    for p in raw_paths:
        path = Path(p)
        if path.is_dir():
            collected: list[Path] = []
            collected.extend(path.glob("*.dump"))
            collected.extend(path.glob("*.msl"))
            collected.extend(path.glob("*.gcore.core"))
            collected.extend(path.glob("*.core"))
            collected.extend(path.glob("*gdb_raw.bin"))
            collected.extend(path.glob("*lldb_raw.bin"))
            # De-duplicate (``*.gcore.core`` overlaps ``*.core``) and sort.
            paths.extend(sorted({c.resolve(): c for c in collected}.values()))
        elif path.is_file():
            paths.append(path)
        else:
            logger.warning("Skipping non-existent path: %s", p)
    return paths


def _setup_logging(verbose: bool) -> None:
    """Configure logging for CLI mode."""
    from memdiver.core.log import setup_logging
    setup_logging(level="DEBUG" if verbose else "WARNING")


def _write_output(
    data: dict,
    output_path: str | None,
    fmt: str = "json",
) -> None:
    """Write data to file or stdout as json or jsonl."""
    if fmt == "jsonl":
        text = _format_jsonl(data)
    else:
        text = json.dumps(data, indent=2)
    if output_path:
        try:
            Path(output_path).write_text(text)
        except OSError as exc:
            print(f"memdiver: cannot write output to {output_path}: {exc}",
                  file=sys.stderr)
            raise SystemExit(1)
        logger.info("Output written to %s", output_path)
    else:
        print(text)


def _format_jsonl(data: dict) -> str:
    """Serialize a BatchResult-shaped dict as newline-delimited JSON.

    One record per completed job + a trailing summary line tagged
    ``"_type": "summary"``. Non-batch shapes (no ``jobs`` list) fall
    back to a single-line JSON dump.
    """
    jobs = data.get("jobs")
    if not isinstance(jobs, list):
        return json.dumps(data)
    lines = [json.dumps(j) for j in jobs]
    summary = {k: v for k, v in data.items() if k != "jobs"}
    summary["_type"] = "summary"
    lines.append(json.dumps(summary))
    return "\n".join(lines) + "\n"


def _print_missing_package(package: str, extra: str | None = None) -> None:
    """Print a uniform 'package missing' install hint to stderr.

    ``extra`` names an optional-dependencies group (e.g. ``"experiment"``).
    When omitted, the hint points at a base-install reinstall.
    """
    if extra:
        message = (
            f"{package} is not available. Install the '{extra}' extras with:\n"
            f"    pip install memdiver[{extra}]"
        )
    else:
        message = (
            f"{package} is missing from your environment. It is part of the "
            f"base install; try: pip install --force-reinstall memdiver"
        )
    print(message, file=sys.stderr)


def _cmd_ui(args: argparse.Namespace) -> int:
    """Launch the Marimo interactive UI."""
    import importlib.util
    if importlib.util.find_spec("marimo") is None:
        _print_missing_package("Marimo", extra="marimo")
        return 1
    extra = getattr(args, "extra_args", [])
    app = str(Path(__file__).parent / "run.py")
    return subprocess.call([sys.executable, "-m", "marimo", "run", app] + extra)


def _cmd_web(args: argparse.Namespace) -> int:
    """Launch the FastAPI + React web application."""
    try:
        import uvicorn
        from memdiver.api.main import create_app
    except ImportError:
        _print_missing_package("The FastAPI web backend (fastapi + uvicorn)", extra="api")
        return 1
    port = getattr(args, "port", 8080)
    print(f"MemDiver starting on http://127.0.0.1:{port}", file=sys.stderr, flush=True)
    try:
        app = create_app()
        uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")
    except KeyboardInterrupt:
        pass
    return 0


def _cmd_app(args: argparse.Namespace) -> int:
    """Launch the legacy NiceGUI web application (if installed)."""
    try:
        import nicegui  # noqa: F401
    except ImportError:
        _print_missing_package("NiceGUI", extra="nicegui")
        return 1
    app_path = str(Path(__file__).parent / "legacy_app.py")
    return subprocess.call([sys.executable, app_path])


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
    from memdiver.core.discovery import DatasetScanner
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

    scanner = DatasetScanner(request.dataset_root, request.keylog_filename)
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


def _cmd_consensus(args: argparse.Namespace) -> int:
    """Build consensus matrix from dump files and output region analysis."""
    from memdiver.engine.consensus_service import build_consensus

    dump_paths = _resolve_dump_paths(args.dumps)

    if len(dump_paths) < 2:
        print(f"Need at least 2 dumps, got {len(dump_paths)}", file=sys.stderr)
        return 1

    logger.info("Building consensus from %d dumps", len(dump_paths))
    key_material = _key_material_from_args(args)
    # build_consensus opens each dump as a context-managed source, warns on
    # tag status per source (the on_source hook, in order) while they are all
    # live, builds the vector, then closes the sources — cm retains its own
    # copies of variance/reference_bytes for the region shaping below.
    cm = build_consensus(
        dump_paths,
        normalize=args.normalize,
        key_material=key_material,
        on_source=_warn_tag_status,
    )

    min_len = args.min_length
    volatile = cm.get_volatile_regions(min_length=min_len)
    static = cm.get_static_regions(min_length=min_len)

    result = {
        "num_dumps": cm.num_dumps,
        "size": cm.size,
        "classification_counts": cm.classification_counts(),
        "volatile_regions": [
            {"start": r.start, "end": r.end, "length": r.end - r.start,
             "mean_variance": round(float(r.mean_variance), 2), "classification": r.classification}
            for r in volatile
        ],
        "static_regions": [
            {"start": r.start, "end": r.end, "length": r.end - r.start,
             "mean_variance": 0.0, "classification": r.classification}
            for r in static
        ],
    }

    # Alignment filtering
    if args.align:
        aligned = cm.get_aligned_candidates(
            block_size=args.block_size,
            alignment=args.alignment_bytes,
            density_threshold=args.density,
        )
        result["aligned_candidates"] = [
            {"start": r.start, "end": r.end, "length": r.end - r.start,
             "mean_variance": round(float(r.mean_variance), 2)}
            for r in aligned
        ]

    # Convergence sweep
    if args.convergence:
        from memdiver.engine.convergence import run_convergence_sweep
        from memdiver.engine.serializer import serialize_convergence_result
        sweep = run_convergence_sweep(
            dump_paths,
            max_fp=args.max_fp,
        )
        result["convergence"] = serialize_convergence_result(sweep)

    _write_output(result, args.output)
    return 0


def _consensus_state_paths(state_path: Path) -> "tuple[Path, Path]":
    stem = state_path.with_suffix("")
    return stem.with_suffix(".mean.npy"), stem.with_suffix(".m2.npy")


def _load_welford_session(state_path: Path):
    """Load persisted incremental-consensus state from disk."""
    import numpy as np

    from memdiver.core.variance import WelfordVariance

    state = json.loads(state_path.read_text())
    mean = np.load(state["mean_path"])
    m2 = np.load(state["m2_path"])
    welford = WelfordVariance.from_state(mean, m2, int(state["num_dumps"]))
    return state, welford


def _cmd_consensus_begin(args: argparse.Namespace) -> int:
    """Create a new incremental consensus session persisted on disk."""
    import numpy as np

    state_path = Path(args.state)
    mean_path, m2_path = _consensus_state_paths(state_path)
    state_path.parent.mkdir(parents=True, exist_ok=True)

    mean = np.zeros(args.size, dtype=np.float32)
    m2 = np.zeros(args.size, dtype=np.float32)
    np.save(mean_path, mean)
    np.save(m2_path, m2)
    state_path.write_text(json.dumps({
        "size": args.size,
        "num_dumps": 0,
        "mean_path": str(mean_path),
        "m2_path": str(m2_path),
    }, indent=2))
    print(f"Begun consensus session: size={args.size} state={state_path}")
    return 0


def _cmd_consensus_add(args: argparse.Namespace) -> int:
    """Fold one dump into an existing incremental consensus session."""
    import numpy as np

    from memdiver.core.dump_source import open_dump

    state_path = Path(args.state)
    state, welford = _load_welford_session(state_path)
    size = int(state["size"])

    with open_dump(Path(args.dump), **_key_material_from_args(args)) as source:
        _warn_tag_status(source)
        data = source.read_all()[:size]
    if len(data) < size:
        print(
            f"Dump shorter than consensus size ({len(data)} < {size})",
            file=sys.stderr,
        )
        return 1
    if not data.strip(b"\x00"):
        logger.warning(
            "Folded dump %s is entirely zero bytes — consensus may be meaningless",
            args.dump,
        )
    welford.add_dump(data)

    new_mean, new_m2, new_n = welford.state_arrays()
    np.save(state["mean_path"], new_mean)
    np.save(state["m2_path"], new_m2)
    state["num_dumps"] = new_n
    state_path.write_text(json.dumps(state, indent=2))

    current = welford.variance()
    print(
        f"[{new_n}] mean_var={float(current.mean()):.2f} "
        f"max_var={float(current.max()):.2f}"
    )
    return 0


def _cmd_consensus_finalize(args: argparse.Namespace) -> int:
    """Materialize variance + classifications from a persisted session."""
    from memdiver.core.variance import classify_variance, count_classifications

    state_path = Path(args.state)
    state, welford = _load_welford_session(state_path)
    size = int(state["size"])

    variance = welford.variance()
    classifications = classify_variance(variance)
    counts = count_classifications(classifications)

    result = {
        "num_dumps": welford.num_dumps,
        "size": size,
        "classification_counts": counts,
        "variance_summary": {
            "mean": float(variance.mean()),
            "max": float(variance.max()),
            "min": float(variance.min()),
        },
    }
    _write_output(result, args.output)
    return 0


def _cmd_search_reduce(args: argparse.Namespace) -> int:
    """Run variance → alignment → entropy reduction on a finalized session."""
    from memdiver.core.dump_source import open_dump
    from memdiver.engine.candidate_pipeline import reduce_search_space

    state_path = Path(args.state)
    _state, welford = _load_welford_session(state_path)
    variance = welford.variance()

    with open_dump(Path(args.reference_dump), **_key_material_from_args(args)) as source:
        _warn_tag_status(source)
        reference_data = source.read_all()[: len(variance)]

    result = reduce_search_space(
        variance, reference_data, num_dumps=welford.num_dumps,
        alignment=args.alignment,
        block_size=args.block_size,
        density_threshold=args.density_threshold,
        min_variance=args.min_variance,
        entropy_window=args.entropy_window,
        entropy_threshold=args.entropy_threshold,
        min_region=args.min_region,
    )
    _write_output(result.to_dict(), args.output)
    return 0


def _cmd_brute_force(args: argparse.Namespace) -> int:
    """Iterate candidates through a user oracle and emit hits.json."""
    from memdiver.core.dump_source import open_dump
    from memdiver.engine.brute_force import run_brute_force, write_result

    with open_dump(Path(args.dump), **_key_material_from_args(args)) as source:
        _warn_tag_status(source)
        reference_data = source.read_all()

    key_sizes = tuple(int(k.strip()) for k in args.key_sizes.split(",") if k.strip())
    result = run_brute_force(
        candidates_path=Path(args.candidates),
        reference_data=reference_data,
        oracle_path=Path(args.oracle),
        oracle_config_path=Path(args.oracle_config) if args.oracle_config else None,
        key_sizes=key_sizes,
        stride=args.stride,
        jobs=args.jobs,
        exhaustive=not args.first_hit,
        state_path=Path(args.state) if args.state else None,
        top_k=args.top_k,
    )
    write_result(result, Path(args.output))
    if result.hits:
        print(
            f"memdiver: verified {len(result.hits)} hit(s); first at offset "
            f"0x{result.hits[0].offset:x} ({result.hits[0].length} bytes)",
            file=sys.stderr,
        )
    else:
        print(
            f"memdiver: exhausted {result.total_candidates} candidates, "
            f"0 verified; top-{len(result.top_k)} written to {args.output}",
            file=sys.stderr,
        )
    return result.exit_code


def _cmd_n_sweep(args: argparse.Namespace) -> int:
    """Sweep N ∈ n_values, run consensus → reduce → oracle, emit reports."""
    from memdiver.core.dump_source import open_dump
    from memdiver.engine.nsweep import run_nsweep, write_nsweep_artifacts
    from memdiver.engine.oracle import load_oracle, load_oracle_config

    runs_dir = Path(args.runs_dir)
    dump_paths = sorted(runs_dir.glob(f"*/{args.dump_glob}"))
    if not dump_paths:
        dump_paths = sorted(runs_dir.rglob(args.dump_glob))
    if not dump_paths:
        print(f"no dumps matched {runs_dir}/*/{args.dump_glob}", file=sys.stderr)
        return 1

    n_values = [int(n.strip()) for n in args.n_values.split(",") if n.strip()]
    key_sizes = tuple(int(k.strip()) for k in args.key_sizes.split(",") if k.strip())
    oracle_config = load_oracle_config(
        Path(args.oracle_config) if args.oracle_config else None
    )
    oracle = load_oracle(Path(args.oracle), oracle_config)

    km = _key_material_from_args(args)
    sources = [open_dump(p, **km).__enter__() for p in dump_paths]
    if sources:
        _warn_tag_status(sources[0])
    try:
        result = run_nsweep(
            sources,
            n_values=n_values,
            reduce_kwargs=dict(
                alignment=args.alignment,
                block_size=args.block_size,
                density_threshold=args.density_threshold,
                min_variance=args.min_variance,
                entropy_window=args.entropy_window,
                entropy_threshold=args.entropy_threshold,
                min_region=args.min_region,
            ),
            oracle=oracle,
            key_sizes=key_sizes,
            stride=args.stride,
            exhaustive=not args.first_hit,
        )
    finally:
        for src in sources:
            try:
                src.__exit__(None, None, None)
            except Exception:
                pass

    paths = write_nsweep_artifacts(result, Path(args.output_dir))
    print(result.headline(), file=sys.stderr)
    print(f"wrote {paths['json']}, {paths['md']}, {paths['html']}", file=sys.stderr)
    return 0 if result.first_hit_n is not None else 2


def _cmd_auto_floor(args: argparse.Namespace) -> int:
    """Automated ground-truth-free variance-floor selection → single verdict."""
    from memdiver.core.dump_source import open_dump
    from memdiver.engine.auto_floor import run_auto_floor, write_auto_floor_artifacts
    from memdiver.engine.oracle import load_oracle, load_oracle_config

    _state, welford = _load_welford_session(Path(args.state))
    variance = welford.variance()
    with open_dump(Path(args.reference_dump), **_key_material_from_args(args)) as source:
        _warn_tag_status(source)
        reference_data = source.read_all()[: len(variance)]

    oracle = load_oracle(
        Path(args.oracle),
        load_oracle_config(Path(args.oracle_config) if args.oracle_config else None),
    )
    key_sizes = tuple(int(k.strip()) for k in args.key_sizes.split(",") if k.strip())
    positive_control = (
        bytes.fromhex(args.positive_control) if args.positive_control else None
    )
    reduce_kwargs = dict(
        alignment=args.alignment, block_size=args.block_size,
        density_threshold=args.density_threshold, entropy_window=args.entropy_window,
        entropy_threshold=args.entropy_threshold, min_region=args.min_region,
    )
    result = run_auto_floor(
        variance, reference_data, welford.num_dumps, oracle,
        reduce_kwargs=reduce_kwargs, key_sizes=key_sizes, stride=args.stride,
        coverage=args.coverage, correspondence=args.correspondence,
        filter_recall=args.filter_recall, min_coverage=args.min_coverage,
        positive_control=positive_control, phi0_method=args.phi0_method,
        p_min=args.p_min, self_test_trials=args.self_test_trials,
        oracle_budget=args.oracle_budget, alignment_quality=args.alignment_quality,
        min_alignment=args.min_alignment, managed_region=args.managed_region,
    )
    write_auto_floor_artifacts(result, Path(args.output_dir))
    tail = (f" key=0x{result.offset:x} phi*={result.phi_star:.1f} phi0={result.phi0:.1f}"
            if result.offset is not None else
            (f" ({result.inconclusive_reason})" if result.inconclusive_reason else ""))
    print(f"memdiver auto-floor: {result.verdict}{tail}", file=sys.stderr)
    return result.exit_code


def _cmd_emit_plugin(args: argparse.Namespace) -> int:
    """Emit a Volatility3 plugin from a hits.json neighborhood variance."""
    from memdiver.core.dump_source import open_dump
    from memdiver.engine.vol3_emit import emit_plugin_from_hits_file

    with open_dump(Path(args.reference), **_key_material_from_args(args)) as source:
        _warn_tag_status(source)
        reference_data = source.read_all()

    out = emit_plugin_from_hits_file(
        hits_path=Path(args.hit),
        reference_data=reference_data,
        name=args.name,
        output_path=Path(args.output),
        hit_index=args.hit_index,
        description=args.description,
        variance_threshold=args.variance_threshold,
    )
    print(f"wrote vol3 plugin {out}", file=sys.stderr)
    return 0


def _cmd_export(args: argparse.Namespace) -> int:
    """Export a byte pattern from dump files as YARA/JSON/Volatility3.

    Thin CLI adapter over ``api.services.analysis_service.auto_export_pattern``.
    The service function owns the consensus → pattern pipeline, so the
    CLI and the HTTP API cannot drift. Prior to PR 4 this command had
    its own copy of the pipeline that:

    1. Opened DumpSource objects via ``open_dump(p)`` without calling
       ``.open()`` on them, so ``MslDumpSource.get_reader()`` raised
       ``RuntimeError("MslDumpSource not opened; use context manager")``
       on any MSL input — effectively crashing ``memdiver export --auto``
       outright for the ``.msl`` file type.
    2. Fed the aligned memory-relative offsets from ``build_from_sources``
       into ``StaticChecker.check(dump_paths, offset, length)`` which
       reads **raw file bytes** at those offsets. The bytes that came
       back were not the bytes at the memory offset — they were
       arbitrary file content that happened to sit at the same numeric
       position. Latent bug; never triggered because (1) killed the
       command first.

    Both bugs are closed here by delegation to the service.
    """
    from memdiver.api.services.analysis_service import (
        AnalysisServiceError,
        auto_export_pattern,
        manual_export_pattern,
    )

    dump_paths = _resolve_dump_paths(args.dumps)

    if len(dump_paths) < 2:
        print(f"Need at least 2 dumps, got {len(dump_paths)}", file=sys.stderr)
        return 1

    key_material = _key_material_from_args(args)

    try:
        if args.auto:
            result = auto_export_pattern(
                dump_paths,
                fmt=args.format,
                name=args.name,
                align=getattr(args, "align", False),
                context=getattr(args, "context", 32),
                min_static_ratio=args.min_static_ratio,
                key_material=key_material,
            )
        else:
            if args.offset is None or args.length is None:
                print(
                    "Specify --offset and --length, or use --auto",
                    file=sys.stderr,
                )
                return 1
            result = manual_export_pattern(
                dump_paths,
                offset=args.offset,
                length=args.length,
                fmt=args.format,
                name=args.name,
                min_static_ratio=args.min_static_ratio,
                key_material=key_material,
            )
    except AnalysisServiceError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    region = result["region"]
    logger.info(
        "Auto-selected region: offset=0x%x length=%d (key 0x%x-0x%x)",
        region["offset"], region["length"],
        region["key_start"], region["key_end"],
    )
    print(
        f"Auto-detected region: offset=0x{region['offset']:x}, "
        f"{region['length']} bytes (key at 0x{region['key_start']:x}-"
        f"0x{region['key_end']:x}, context={args.context}B)",
        file=sys.stderr,
    )

    content = result["content"]
    if args.output:
        Path(args.output).write_text(content)
        print(f"Exported {result['format']} to {args.output}", file=sys.stderr)
    else:
        print(content)
    return 0


def _cmd_gen_kem_key(args: argparse.Namespace) -> int:
    """Generate a KEM keypair for encrypted-MSL recipients (spec §10.4).

    Writes the public key (shared with producers) and the private key (used
    later via ``--kem-key-file`` to decrypt). Hybrid keys are the
    concatenation of the X25519 and ML-KEM-768 halves.
    """
    from memdiver.msl.crypto import (MslCryptoError, kem_generate_keypair,
                            kem_is_available)
    from memdiver.msl.enums import KeyEncap

    mechanisms = {
        "X25519": KeyEncap.X25519,
        "ML-KEM-768": KeyEncap.ML_KEM_768,
        "ML-KEM-1024": KeyEncap.ML_KEM_1024,
        "X25519+ML-KEM-768": KeyEncap.X25519_ML_KEM_768,
    }
    mech = mechanisms[args.mechanism]
    if not kem_is_available(mech):
        print(f"memdiver: {args.mechanism} unavailable; install the post-quantum "
              f"extra: pip install memdiver[crypto]", file=sys.stderr)
        return 1
    try:
        public_key, private_key = kem_generate_keypair(mech)
    except MslCryptoError as exc:
        print(f"memdiver: {exc}", file=sys.stderr)
        return 1
    public_path = Path(args.public_out)
    private_path = Path(args.private_out)
    try:
        # Write the private key first, with owner-only (0o600) permissions so
        # it never inherits a world/group-readable umask. Use os.open with the
        # mode up-front to avoid a brief window where the secret is readable.
        fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(private_key)
        finally:
            # chmod again in case the file pre-existed (O_CREAT mode is ignored
            # for an existing file).
            os.chmod(private_path, 0o600)
        public_path.write_bytes(public_key)
    except OSError as exc:
        # Avoid leaving a half-written keypair behind on failure.
        for partial in (private_path, public_path):
            try:
                partial.unlink()
            except OSError:
                pass
        print(f"memdiver: cannot write KEM keypair: {exc}", file=sys.stderr)
        return 1
    print(f"memdiver: wrote {args.public_out} ({len(public_key)}B public) and "
          f"{args.private_out} ({len(private_key)}B private) for {args.mechanism}",
          file=sys.stderr)
    return 0


def _cmd_import_dir(args: argparse.Namespace) -> int:
    """Import all dumps (.dump/.dmp/.core) in a run directory to .msl format."""
    from memdiver.msl.importer import import_run_directory

    results = import_run_directory(
        Path(args.run_dir), Path(args.output_dir),
        keylog_filename=args.keylog_filename,
    )
    print(json.dumps([{
        "source": str(r.source_path),
        "output": str(r.output_path),
        "key_hints": r.key_hints_written,
    } for r in results], indent=2))
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    """Verify a candidate key at a given offset against known ciphertext."""
    from memdiver.core.dump_source import open_dump
    from memdiver.engine.verification import VERIFIER_REGISTRY, VERIFICATION_IV

    dump_path = Path(args.dump)
    if not dump_path.is_file():
        print(f"Dump file not found: {dump_path}", file=sys.stderr)
        return 1

    cipher = args.cipher
    if cipher not in VERIFIER_REGISTRY:
        print(f"Unknown cipher: {cipher}. Available: {list(VERIFIER_REGISTRY)}",
              file=sys.stderr)
        return 1

    verifier = VERIFIER_REGISTRY[cipher]
    offset = args.offset
    length = args.length

    # Read the candidate through the DumpSource memory projection instead of
    # raw container bytes. For .msl inputs the offset is MEMORY-relative (it
    # comes from consensus/analysis on the flattened VAS view), so slicing raw
    # file bytes would return the wrong region — the same class of bug closed
    # for `memdiver export`. open_dump() serves the VAS projection for .msl and
    # raw bytes for .dump, so the offset is interpreted in the space it was
    # derived in. Key material lets encrypted .msl containers be decrypted.
    key_material = _key_material_from_args(args)
    with open_dump(dump_path, **key_material) as source:
        _warn_tag_status(source)
        dump_size = source.size
        if offset + length > dump_size:
            print(f"Offset 0x{offset:x} + length {length} exceeds dump size {dump_size}",
                  file=sys.stderr)
            return 1
        candidate = source.read_range(offset, length)

    ciphertext = bytes.fromhex(args.ciphertext_hex)
    iv = bytes.fromhex(args.iv_hex) if args.iv_hex else VERIFICATION_IV

    from memdiver.engine.verification import VERIFICATION_PLAINTEXT
    result_val = verifier.verify(candidate, ciphertext, iv, VERIFICATION_PLAINTEXT)

    result = {
        "offset": f"0x{offset:x}",
        "length": length,
        "cipher": cipher,
        "verified": result_val,
        "key_hex": candidate.hex() if result_val else None,
    }
    _write_output(result, getattr(args, 'output', None))
    return 0


def _cmd_experiment(args: argparse.Namespace) -> int:
    """Orchestrate: spawn target, dump, build consensus, verify, export."""
    try:
        from memdiver.core.dump_driver import DumpOrchestrator
        from memdiver.engine.consensus_service import build_consensus
        from memdiver.engine.verification import (
            AesCbcVerifier, VERIFICATION_PLAINTEXT, VERIFICATION_IV,
        )
        from memdiver.architect.pattern_generator import PatternGenerator
    except ImportError:
        _print_missing_package("The experiment flow", extra="experiment")
        return 1

    target_path = Path(args.target)
    if not target_path.is_file():
        print(f"Target script not found: {target_path}", file=sys.stderr)
        return 1

    tools = args.tools.split(",") if args.tools else None
    orch = DumpOrchestrator(tools=tools)

    if not orch.available_tools:
        _print_missing_package("No dump tools available", extra="experiment")
        print(
            "This installs frida-tools and memslicer. The lldb backend is "
            "optional and must be installed via your OS (Xcode on macOS, "
            "'apt install lldb' on Debian/Ubuntu, etc.).",
            file=sys.stderr,
        )
        return 1

    print(f"Available tools: {[t.name for t in orch.available_tools]}", file=sys.stderr)
    print(f"Running {args.num_runs} iterations per tool...", file=sys.stderr)

    # Step 1: Run experiment
    exp = orch.run_experiment(
        target_path, args.num_runs, args.output_dir,
    )

    # Step 2: Per-tool analysis
    verifier = AesCbcVerifier()
    all_tool_results = {}

    for tool_name, tool_dir in exp.tool_dirs.items():
        dump_paths = sorted(
            list(tool_dir.glob("*/*.dump")) + list(tool_dir.glob("*/*.msl"))
        )
        if len(dump_paths) < 2:
            print(f"  [{tool_name}] Not enough dumps ({len(dump_paths)}), skipping",
                  file=sys.stderr)
            continue

        print(f"  [{tool_name}] Analyzing {len(dump_paths)} dumps...", file=sys.stderr)

        # Build consensus from opened DumpSources so consensus offsets are
        # memory-relative (ASLR-invariant for native .msl). Reading raw file
        # bytes here — as the old cm.build(dump_paths) did — makes every
        # downstream offset point into the .msl container layout instead of
        # memory (the A5 bug, already closed for `memdiver export`).
        key_material = _key_material_from_args(args)
        cm = build_consensus(
            dump_paths,
            key_material=key_material,
            on_source=_warn_tag_status,
        )
        # Sources are closed once consensus is built; cm.reference_bytes and
        # cm.variance are retained copies in the consensus coordinate space.
        aligned = cm.get_aligned_candidates()
        volatile = cm.get_volatile_regions()

        # Decryption verification — scan the FIRST dump's bytes in the same
        # (memory-relative) coordinate space the aligned offsets live in.
        # cm.reference_bytes IS dump[0]'s aligned slab, so region.start indexes
        # it correctly; re-reading raw container bytes would slice the wrong
        # region for .msl inputs.
        first_data = cm.reference_bytes
        first_key = exp.metadata["runs"][0]["key_hex"]
        key_bytes = bytes.fromhex(first_key)
        ct = verifier.create_ciphertext(key_bytes, VERIFICATION_PLAINTEXT, VERIFICATION_IV)

        dec_verified = False
        for region in aligned:
            for off in range(region.start, region.end - 31):
                candidate = first_data[off:off + 32]
                if verifier.verify(candidate, ct, VERIFICATION_IV, VERIFICATION_PLAINTEXT):
                    dec_verified = True
                    break
            if dec_verified:
                break

        # Auto-export pattern
        plugin_content = None
        if volatile:
            best = max(volatile, key=lambda r: r.end - r.start)
            ctx = 32
            exp_offset = max(0, best.start - ctx)
            exp_end = min(cm.size, best.end + ctx)

            # Derive the reference bytes and static mask from the consensus
            # vector (memory-relative), mirroring auto_export_pattern. The old
            # StaticChecker.check(dump_paths, exp_offset, exp_length) re-read
            # RAW file bytes at these memory-relative offsets, returning
            # arbitrary container content for .msl inputs (the A5 bug). A byte
            # is static across all inputs iff its consensus variance is zero.
            import numpy as np

            reference = cm.reference_bytes[exp_offset:exp_end]
            var_slice = cm.variance[exp_offset:exp_end]
            if isinstance(var_slice, np.ndarray):
                static_mask = (var_slice == 0.0).tolist()
            else:
                static_mask = [v == 0.0 for v in var_slice]
            if reference:
                pattern = PatternGenerator.generate(reference, static_mask, f"{tool_name}_aes256_key")
                if pattern:
                    fmt = args.export_format
                    if fmt in ("volatility3", "vol3"):
                        from memdiver.architect.volatility3_exporter import Volatility3Exporter
                        from memdiver.architect.yara_exporter import YaraExporter
                        yara_rule = YaraExporter.export(pattern)
                        plugin_content = Volatility3Exporter.export(pattern, yara_rule=yara_rule)
                    elif fmt == "yara":
                        from memdiver.architect.yara_exporter import YaraExporter
                        plugin_content = YaraExporter.export(pattern)

        # Save plugin
        plugin_path = None
        if plugin_content:
            plugins_dir = args.output_dir / "plugins"
            plugins_dir.mkdir(parents=True, exist_ok=True)
            ext = ".py" if args.export_format in ("volatility3", "vol3") else ".yar"
            plugin_path = plugins_dir / f"{tool_name}_aes256_key{ext}"
            plugin_path.write_text(plugin_content)

        tool_result = {
            "tool": tool_name,
            "format": "MSL (.msl)" if tool_name == "memslicer" else "Raw (.dump)",
            "num_dumps": len(dump_paths),
            "volatile_regions": len(volatile),
            "aligned_regions": len(aligned),
            "decryption_verified": dec_verified,
            "plugin_saved": str(plugin_path) if plugin_path else None,
        }

        # Convergence sweep
        if args.convergence:
            from memdiver.engine.convergence import run_convergence_sweep
            from memdiver.engine.serializer import serialize_convergence_result

            # Build ground truth from first run's key position
            # (we don't know the exact offset in real dumps, so skip precision/recall)
            sweep = run_convergence_sweep(
                dump_paths, max_fp=args.max_fp,
            )
            tool_result["convergence"] = serialize_convergence_result(sweep)

        all_tool_results[tool_name] = tool_result

    # Print comparison table
    _print_experiment_table(all_tool_results)

    # Write JSON output
    if args.output:
        _write_output(all_tool_results, args.output)

    return 0


def _print_experiment_table(results: dict) -> None:
    """Print side-by-side tool comparison table."""
    tools = list(results.keys())
    if not tools:
        print("No results to display.")
        return

    w = 17
    tw = 15

    print(f"\n{'=' * (w + len(tools) * (tw + 3) + 3)}")
    print("  EXPERIMENT RESULTS — Per-Tool Comparison")
    print(f"{'=' * (w + len(tools) * (tw + 3) + 3)}")

    # Header
    header = f"{'Metric':<{w}}"
    for t in tools:
        header += f" | {t:^{tw}}"
    print(f"\n{header}")
    print(f"{'-' * w}" + "".join(f"-+-{'-' * tw}" for _ in tools))

    # Format row
    fmt_row = f"{'Format':<{w}}"
    for t in tools:
        fmt_row += f" | {results[t]['format']:^{tw}}"
    print(fmt_row)

    # Dumps row
    row = f"{'Dumps':<{w}}"
    for t in tools:
        row += f" | {results[t]['num_dumps']:^{tw}}"
    print(row)

    # Volatile regions
    row = f"{'Volatile regions':<{w}}"
    for t in tools:
        row += f" | {results[t]['volatile_regions']:^{tw}}"
    print(row)

    # Aligned regions
    row = f"{'Aligned regions':<{w}}"
    for t in tools:
        row += f" | {results[t]['aligned_regions']:^{tw}}"
    print(row)

    # Decryption
    row = f"{'Decryption':<{w}}"
    for t in tools:
        val = "YES" if results[t]['decryption_verified'] else "NO"
        row += f" | {val:^{tw}}"
    print(row)

    # Plugin
    row = f"{'Plugin saved':<{w}}"
    for t in tools:
        val = "yes" if results[t]['plugin_saved'] else "no"
        row += f" | {val:^{tw}}"
    print(row)

    print()

    # Print plugin paths
    for t in tools:
        if results[t]['plugin_saved']:
            print(f"  {t} plugin: {results[t]['plugin_saved']}")
    print()


# ---------------------------------------------------------------------------
# inspect — low-level dump / structured-MSL inspection views
#
# Thin CLI adapters over the exact pure tool functions that the HTTP
# `/api/inspect` endpoints and the MCP server already expose
# (``mcp_server.tools_inspect`` / ``mcp_server.tools_xref``), so the three
# surfaces cannot drift. The stateless read functions take a ``ToolSession``
# only to share the MCP signature; a throwaway instance carries no state.
#
# These reuse the same pure tools_inspect / tools_xref functions behind the
# `/api/inspect` endpoints and the MCP server. The decryption flags
# (--key-file / --passphrase / --kem-key-file) are forwarded to the key-aware
# tools (hex, entropy, strings, byte-search, page-states, session-info), which
# open an uncached keyed reader, so an encrypted `.msl` is read transparently.
# ---------------------------------------------------------------------------


def _new_tool_session():
    """Construct a stateless ToolSession for reuse of the shared tool funcs."""
    from memdiver.mcp_server.session import ToolSession
    return ToolSession()


def _emit_inspect(result: dict, output: str | None) -> int:
    """Write an inspect result as JSON; exit non-zero when it carries an error.

    When the error stems from an undecryptable encrypted container the tool
    layer tags it with ``tag_status`` (missing/wrong key). Surface that on
    stderr so an operator is not left staring at an empty-looking result and
    mistaking a key failure for a genuinely empty capture (O-3).
    """
    if isinstance(result, dict) and result.get("tag_status") in ("missing_key", "corrupted"):
        print(f"memdiver: ERROR — {result.get('error')}", file=sys.stderr)
    _write_output(result, output)
    return 1 if isinstance(result, dict) and "error" in result else 0


def _inspect_key_kwargs(args: argparse.Namespace) -> dict:
    """Decrypt flags → tools_inspect key kwargs, so `inspect` can read an
    encrypted .msl. Passed as keyword args (the underlying tools accept
    key_file / passphrase / kem_key_file)."""
    return {
        "key_file": getattr(args, "key_file", None),
        "passphrase": getattr(args, "passphrase", None),
        "kem_key_file": getattr(args, "kem_key_file", None),
    }


def present_inspect_cli(result) -> tuple[dict, int, str | None]:
    """Present an inspect ``ServiceResult`` as the CLI's observable triple.

    Returns ``(machine_payload, exit_code, stderr_msg)``:

    * **Locked** (``not result.status.key.decrypted``) — an encrypted container
      opened with a missing / wrong key. The machine payload reproduces exactly
      the legacy error dict the tool layer used to return under the
      ``report_key_status`` default (``{"error": <hint>, "tag_status": …}``),
      the exit code is ``1`` and the stderr message is the key hint.
    * **OK** — the producer's payload passes through untouched, exit code ``0``,
      no stderr message.

    This is the explicit CLI presenter that lets the handlers drop the
    ``report_key_status`` default: the producer always carries the key state in
    ``result.status`` and this function turns it into the same bytes the old
    error-dict path emitted.
    """
    key = result.status.key
    if not key.decrypted:
        return key.locked_error_dict(), 1, key.hint
    return result.payload, 0, None


def _present_inspect_cli_call(produce) -> tuple[dict, int, str | None]:
    """Run a ServiceResult producer and present it for the CLI.

    Hard errors are RAISED by the producers as ``CapabilityError`` subclasses
    (missing file, wrong format, out-of-range offset, invalid pattern). Convert
    them back into the SAME error tuple the legacy ``{"error": …}`` dict path
    produced — the message plus any structured ``details`` — so the machine
    payload and exit code stay byte-for-byte unchanged.
    """
    from memdiver.core.service_errors import CapabilityError
    try:
        return present_inspect_cli(produce())
    except CapabilityError as e:
        return e.to_error_body(), 1, e.message


def _cmd_inspect_hex(args: argparse.Namespace) -> int:
    """Hex + ASCII dump of a byte range."""
    from memdiver.mcp_server.tools_inspect import read_hex_result
    machine_payload, _exit_code, _stderr_msg = _present_inspect_cli_call(
        lambda: read_hex_result(_new_tool_session(), args.dump_path,
                                args.offset, args.length, view=args.view,
                                **_inspect_key_kwargs(args)))
    return _emit_inspect(machine_payload, args.output)


def _cmd_inspect_entropy(args: argparse.Namespace) -> int:
    """Shannon entropy profile of a region."""
    from memdiver.mcp_server.tools_inspect import get_entropy
    result = get_entropy(_new_tool_session(), args.dump_path, args.offset,
                         args.length, args.window, args.step, args.threshold,
                         **_inspect_key_kwargs(args))
    return _emit_inspect(result, args.output)


def _cmd_inspect_strings(args: argparse.Namespace) -> int:
    """Extract printable strings from a dump region."""
    from memdiver.mcp_server.tools_inspect import _extract_strings
    result = _extract_strings(_new_tool_session(), args.dump_path, args.offset,
                              args.length, args.min_length, args.encoding,
                              args.max_results, **_inspect_key_kwargs(args))
    return _emit_inspect(result, args.output)


def _cmd_inspect_byte_search(args: argparse.Namespace) -> int:
    """Find every occurrence of a hex byte pattern."""
    from memdiver.mcp_server.tools_inspect import search_bytes_result
    machine_payload, _exit_code, _stderr_msg = _present_inspect_cli_call(
        lambda: search_bytes_result(_new_tool_session(), args.dump_path,
                                    args.pattern, view=args.view,
                                    max_results=args.max_results,
                                    **_inspect_key_kwargs(args)))
    return _emit_inspect(machine_payload, args.output)


def _cmd_inspect_page_states(args: argparse.Namespace) -> int:
    """Surface the MSL three-state page model (MSL only)."""
    from memdiver.mcp_server.tools_inspect import page_states_result
    machine_payload, _exit_code, _stderr_msg = _present_inspect_cli_call(
        lambda: page_states_result(_new_tool_session(), args.msl_path,
                                   **_inspect_key_kwargs(args)))
    return _emit_inspect(machine_payload, args.output)


def _cmd_inspect_session_info(args: argparse.Namespace) -> int:
    """Extract MSL session metadata (MSL only)."""
    from memdiver.mcp_server.tools_inspect import session_info_result
    machine_payload, _exit_code, _stderr_msg = _present_inspect_cli_call(
        lambda: session_info_result(_new_tool_session(), args.msl_path,
                                    **_inspect_key_kwargs(args)))
    return _emit_inspect(machine_payload, args.output)


def _cmd_inspect_processes(args: argparse.Namespace) -> int:
    """List PROCESS_TABLE entries (MSL only)."""
    from memdiver.mcp_server.tools_inspect import processes_result
    machine_payload, _exit_code, _stderr_msg = _present_inspect_cli_call(
        lambda: processes_result(_new_tool_session(), args.msl_path,
                                 **_inspect_key_kwargs(args)))
    return _emit_inspect(machine_payload, args.output)


def _cmd_inspect_modules(args: argparse.Namespace) -> int:
    """List loaded modules from MSL metadata (MSL only)."""
    from memdiver.mcp_server.tools_inspect import modules_result
    machine_payload, _exit_code, _stderr_msg = _present_inspect_cli_call(
        lambda: modules_result(_new_tool_session(), args.msl_path,
                               **_inspect_key_kwargs(args)))
    return _emit_inspect(machine_payload, args.output)


def _cmd_inspect_handles(args: argparse.Namespace) -> int:
    """List HANDLE_TABLE entries (MSL only)."""
    from memdiver.mcp_server.tools_inspect import handles_result
    machine_payload, _exit_code, _stderr_msg = _present_inspect_cli_call(
        lambda: handles_result(_new_tool_session(), args.msl_path,
                               **_inspect_key_kwargs(args)))
    return _emit_inspect(machine_payload, args.output)


def _cmd_inspect_xref(args: argparse.Namespace) -> int:
    """Resolve cross-references for an MSL file (MSL only)."""
    from memdiver.mcp_server.tools_xref import get_cross_references
    result = get_cross_references(_new_tool_session(), args.msl_path)
    return _emit_inspect(result, args.output)


def _cmd_inspect_structure(args: argparse.Namespace) -> int:
    """Identify a data structure at the given offset."""
    from memdiver.mcp_server.tools_xref import identify_structure
    result = identify_structure(_new_tool_session(), args.dump_path,
                                args.offset, args.protocol)
    return _emit_inspect(result, args.output)


_INSPECT_HANDLERS = {
    "hex": _cmd_inspect_hex,
    "entropy": _cmd_inspect_entropy,
    "strings": _cmd_inspect_strings,
    "byte-search": _cmd_inspect_byte_search,
    "page-states": _cmd_inspect_page_states,
    "session-info": _cmd_inspect_session_info,
    "processes": _cmd_inspect_processes,
    "modules": _cmd_inspect_modules,
    "handles": _cmd_inspect_handles,
    "xref": _cmd_inspect_xref,
    "structure": _cmd_inspect_structure,
}


def _cmd_inspect(args: argparse.Namespace) -> int:
    """Dispatch an ``inspect <action>`` subcommand to its handler."""
    handler = _INSPECT_HANDLERS.get(getattr(args, "inspect_action", None))
    if handler is None:
        print("memdiver inspect: pick an action: "
              + ", ".join(_INSPECT_HANDLERS), file=sys.stderr)
        return 1
    return handler(args)


def _build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(prog="memdiver", description="MemDiver — Memory dump analysis platform")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("ui", help="Launch interactive Marimo UI (needs memdiver[marimo])").add_argument("extra_args", nargs="*", default=[])
    az = sub.add_parser("analyze", help="Analyze library directories")
    az.add_argument("library_dirs", nargs="+", help="Library directory paths")
    az.add_argument("--phase", required=True, help="Lifecycle phase")
    az.add_argument("--protocol-version", required=True, help="Protocol version")
    az.add_argument("--keylog-filename", default="keylog.csv")
    az.add_argument("--template", default="Auto-detect")
    az.add_argument("--max-runs", type=int, default=10)
    az.add_argument("--normalize", action="store_true")
    az.add_argument("--no-expand", action="store_true", help="Skip key expansion")
    az.add_argument("-o", "--output", help="Output JSON file")
    az.add_argument("-v", "--verbose", action="store_true")
    # scan
    sc = sub.add_parser("scan", help="Scan dataset root")
    sc.add_argument("--root", required=True, help="Dataset root path")
    sc.add_argument("--keylog-filename", default="keylog.csv")
    sc.add_argument("--protocols", nargs="*", help="Protocol names to scan")
    sc.add_argument("-o", "--output", help="Output JSON file")
    sc.add_argument("-v", "--verbose", action="store_true")
    # mcp
    mc = sub.add_parser("mcp", help="Start MCP server for AI integration (needs memdiver[mcp])")
    mc.add_argument("--sse", action="store_true", help="Use SSE transport instead of stdio")
    mc.add_argument("--port", type=int, default=8080, help="SSE port (default: 8080)")
    mc.add_argument("-v", "--verbose", action="store_true")
    # batch
    bt = sub.add_parser("batch", help="Run batch analysis from config")
    bt.add_argument("--config", required=True, help="Batch config JSON file")
    bt.add_argument("-w", "--workers", type=int, default=1,
                    help="Number of parallel workers (default: 1)")
    bt.add_argument("-o", "--output", help="Output file")
    bt.add_argument("--output-format", choices=["json", "jsonl"], default=None,
                    help="Output format (overrides config); default: from config or 'json'")
    bt.add_argument("-v", "--verbose", action="store_true")
    # web (FastAPI + React — also the default when no command given)
    wp = sub.add_parser("web", help="Launch FastAPI + React web application (needs memdiver[api])")
    wp.add_argument("--port", type=int, default=8080, help="Server port (default: 8080)")
    # app (legacy NiceGUI — install with `pip install memdiver[nicegui]`)
    sub.add_parser("app", help="Launch legacy NiceGUI application (needs memdiver[nicegui])")
    # consensus
    cs = sub.add_parser("consensus", help="Build consensus matrix from dumps",
                        parents=[_decrypt_parent_parser()])
    cs.add_argument("dumps", nargs="+", help="Dump file paths or directories")
    cs.add_argument("--normalize", action="store_true", help="ASLR-aware normalization")
    cs.add_argument("--min-length", type=int, default=16,
                    help="Minimum region length (default: 16)")
    cs.add_argument("--align", action="store_true",
                    help="Apply alignment filtering to KEY_CANDIDATE regions")
    cs.add_argument("--block-size", type=int, default=32,
                    help="Alignment block size (default: 32)")
    cs.add_argument("--alignment-bytes", type=int, default=16,
                    help="Memory alignment (default: 16)")
    cs.add_argument("--density", type=float, default=0.75,
                    help="Alignment density threshold (default: 0.75)")
    cs.add_argument("--convergence", action="store_true",
                    help="Run convergence sweep")
    cs.add_argument("--max-fp", type=int, default=0,
                    help="FP target for convergence (default: 0)")
    cs.add_argument("-o", "--output", help="Output JSON file")
    cs.add_argument("-v", "--verbose", action="store_true")
    # incremental consensus (Welford-backed, persisted state)
    cb = sub.add_parser(
        "consensus-begin",
        help="Create a new incremental consensus session on disk",
    )
    cb.add_argument("--state", required=True, help="Path to session state JSON")
    cb.add_argument("--size", type=int, required=True,
                    help="Consensus width in bytes")
    cb.add_argument("-v", "--verbose", action="store_true")
    ca = sub.add_parser(
        "consensus-add",
        help="Fold one dump into an existing incremental consensus session",
        parents=[_decrypt_parent_parser()],
    )
    ca.add_argument("--state", required=True, help="Path to session state JSON")
    ca.add_argument("dump", help="Path to a .dump or .msl file")
    ca.add_argument("-v", "--verbose", action="store_true")
    cf = sub.add_parser(
        "consensus-finalize",
        help="Materialize variance + classifications from a session",
    )
    cf.add_argument("--state", required=True, help="Path to session state JSON")
    cf.add_argument("-o", "--output", help="Output JSON file")
    cf.add_argument("-v", "--verbose", action="store_true")
    # search-reduce
    sr = sub.add_parser(
        "search-reduce",
        help="Reduce candidate set: variance → alignment → entropy",
        parents=[_decrypt_parent_parser()],
    )
    sr.add_argument("--state", required=True, help="Path to consensus state JSON")
    sr.add_argument("--reference-dump", required=True,
                    help="One dump file used for per-region entropy sampling")
    sr.add_argument("--alignment", type=int, default=8)
    sr.add_argument("--block-size", type=int, default=32)
    sr.add_argument("--density-threshold", type=float, default=0.5)
    sr.add_argument("--min-variance", type=float, default=3000.0)
    sr.add_argument("--entropy-window", type=int, default=32)
    sr.add_argument("--entropy-threshold", type=float, default=4.5)
    sr.add_argument("--min-region", type=int, default=16)
    sr.add_argument("-o", "--output", required=True, help="Output candidates.json")
    sr.add_argument("-v", "--verbose", action="store_true")
    # brute-force
    bf = sub.add_parser(
        "brute-force",
        help="Iterate candidates through a user oracle script",
        parents=[_decrypt_parent_parser()],
    )
    bf.add_argument("--candidates", required=True, help="candidates.json from search-reduce")
    bf.add_argument("--dump", required=True, help="Reference dump file")
    bf.add_argument("--oracle", required=True, help="Path to user Python oracle script")
    bf.add_argument("--oracle-config", help="Optional TOML config passed to build_oracle")
    bf.add_argument("--key-sizes", default="32", help="Comma-separated key sizes in bytes")
    bf.add_argument("--stride", type=int, default=8)
    bf.add_argument("--jobs", type=int, default=1)
    bf.add_argument("--first-hit", action="store_true",
                    help="Stop at the first verified candidate (default: exhaustive)")
    bf.add_argument("--state", help="Consensus state path (attaches neighborhood variance)")
    bf.add_argument("--top-k", type=int, default=10)
    bf.add_argument("-o", "--output", required=True, help="Output hits.json")
    bf.add_argument("-v", "--verbose", action="store_true")
    # n-sweep
    ns = sub.add_parser(
        "n-sweep",
        help="Sweep N=1..N_max; emit survivor-count curve + oracle hits",
        parents=[_decrypt_parent_parser()],
    )
    ns.add_argument("--runs-dir", required=True, help="Directory containing run_* subdirs")
    ns.add_argument("--dump-glob", default="*.msl", help="Glob under each run")
    ns.add_argument("--n-values", default="1,3,5,10,20,30,50,75,100")
    ns.add_argument("--alignment", type=int, default=8)
    ns.add_argument("--block-size", type=int, default=32)
    ns.add_argument("--density-threshold", type=float, default=0.5)
    ns.add_argument("--min-variance", type=float, default=3000.0)
    ns.add_argument("--entropy-window", type=int, default=32)
    ns.add_argument("--entropy-threshold", type=float, default=4.5)
    ns.add_argument("--min-region", type=int, default=16)
    ns.add_argument("--oracle", required=True, help="Path to user oracle script")
    ns.add_argument("--oracle-config", help="Optional TOML config")
    ns.add_argument("--key-sizes", default="32")
    ns.add_argument("--stride", type=int, default=8)
    ns.add_argument("--first-hit", action="store_true")
    ns.add_argument("--output-dir", required=True, help="Directory for report.{json,md,html}")
    ns.add_argument("-v", "--verbose", action="store_true")
    # auto-floor
    af = sub.add_parser(
        "auto-floor",
        help="Automated ground-truth-free variance-floor selection (single verdict)",
        parents=[_decrypt_parent_parser()],
    )
    af.add_argument("--state", required=True, help="Path to consensus state JSON")
    af.add_argument("--reference-dump", required=True,
                    help="One dump the oracle verifies candidates against")
    af.add_argument("--oracle", required=True, help="Path to user Python oracle script")
    af.add_argument("--oracle-config", help="Optional TOML config passed to build_oracle")
    af.add_argument("--key-sizes", default="32", help="Comma-separated key sizes in bytes")
    af.add_argument("--stride", type=int, default=8)
    af.add_argument("--alignment", type=int, default=8)
    af.add_argument("--block-size", type=int, default=32)
    af.add_argument("--density-threshold", type=float, default=0.5)
    af.add_argument("--entropy-window", type=int, default=32)
    af.add_argument("--entropy-threshold", type=float, default=4.5)
    af.add_argument("--min-region", type=int, default=16)
    af.add_argument("--phi0-method", default="pmin", choices=["pmin", "otsu"],
                    help="Recommended-floor method: 'pmin' (phi=p_min*sigma_k^2, "
                         "default) or 'otsu' (legacy data-driven valley fit)")
    af.add_argument("--p-min", type=float, default=0.35,
                    help="Retention policy for --phi0-method pmin: retain keys "
                         "whose per-run correspondence >= p_min (default 0.35)")
    af.add_argument("--coverage", type=float, default=None,
                    help="Precomputed cross-run coverage-intersection C∩ in [0,1] "
                         "(gates/qualifies the ABSENT verdict)")
    af.add_argument("--correspondence", type=float, default=None,
                    help="Precomputed correspondence score in [0,1] (reported)")
    af.add_argument("--filter-recall", type=float, default=None,
                    help="Precomputed entropy/alignment filter recall in [0,1]")
    af.add_argument("--min-coverage", type=float, default=0.80)
    af.add_argument("--self-test-trials", type=int, default=8,
                    help="Oracle self-test random-negative probes (lower for "
                         "one-shot/rate-limited oracles; each costs one call)")
    af.add_argument("--oracle-budget", type=int, default=None,
                    help="Max total oracle calls; if the maximal set is not "
                         "exhausted within budget, the verdict is INCONCLUSIVE(cost), "
                         "never a false ABSENT")
    af.add_argument("--alignment-quality", type=float, default=None,
                    help="Precomputed per-region alignment quality in [0,1]; below "
                         "--min-alignment a no-hit is INCONCLUSIVE(alignment)")
    af.add_argument("--min-alignment", type=float, default=0.5)
    af.add_argument("--managed-region", action="store_true",
                    help="Target is a managed runtime / moving-GC heap: a no-hit is "
                         "INCONCLUSIVE(regime) (off-grid object headers may hide the key)")
    af.add_argument("--positive-control",
                    help="Hex of a known-good key for the oracle self-test (optional)")
    af.add_argument("--output-dir", required=True, help="Directory for verdict.json/report.md")
    af.add_argument("-v", "--verbose", action="store_true")
    # emit-plugin
    ep_emit = sub.add_parser(
        "emit-plugin",
        help="Emit a Volatility3 plugin from a brute-force hit neighborhood",
        parents=[_decrypt_parent_parser()],
    )
    ep_emit.add_argument("--hit", required=True, help="hits.json from brute-force")
    ep_emit.add_argument("--reference", required=True, help="Reference dump file")
    ep_emit.add_argument("--name", required=True, help="Plugin class / rule name")
    ep_emit.add_argument("--hit-index", type=int, default=0)
    ep_emit.add_argument("--description")
    ep_emit.add_argument(
        "--variance-threshold", type=float, default=None,
        help="Max variance for static bytes (default: 3000). Lower values "
        "produce more wildcards → more cross-session robust patterns.",
    )
    ep_emit.add_argument("-o", "--output", required=True, help="Output .py file path")
    ep_emit.add_argument("-v", "--verbose", action="store_true")
    # export
    ex = sub.add_parser("export", help="Export pattern as YARA/JSON/Volatility3",
                        parents=[_decrypt_parent_parser()])
    ex.add_argument("dumps", nargs="+", help="Dump file paths or directories")
    ex.add_argument("--offset", type=lambda x: int(x, 0), default=None,
                    help="Region offset (hex or decimal)")
    ex.add_argument("--length", type=int, default=None, help="Region length in bytes")
    ex.add_argument("--auto", action="store_true",
                    help="Auto-detect largest KEY_CANDIDATE region")
    ex.add_argument("--context", type=int, default=32,
                    help="Bytes of context around auto-detected region (default: 32)")
    ex.add_argument("--name", default="memdiver_pattern", help="Pattern name")
    ex.add_argument("--format", default="volatility3",
                    choices=["yara", "json", "volatility3", "vol3"])
    ex.add_argument("--min-static-ratio", type=float, default=0.3,
                    help="Minimum static byte ratio (default: 0.3)")
    ex.add_argument("--align", action="store_true",
                    help="Use alignment-filtered candidates for auto-detection")
    ex.add_argument("-o", "--output", help="Output file path")
    ex.add_argument("-v", "--verbose", action="store_true")
    # gen-kem-key
    gk = sub.add_parser(
        "gen-kem-key",
        help="Generate a KEM keypair for encrypted-MSL recipients (spec §10.4)",
    )
    gk.add_argument("--mechanism", required=True,
                    choices=["X25519", "ML-KEM-768", "ML-KEM-1024",
                             "X25519+ML-KEM-768"],
                    help="Key encapsulation mechanism")
    gk.add_argument("--public-out", required=True,
                    help="Output path for the recipient public key")
    gk.add_argument("--private-out", required=True,
                    help="Output path for the recipient private key "
                         "(use later via --kem-key-file)")
    gk.add_argument("-v", "--verbose", action="store_true")
    # import
    im = sub.add_parser(
        "import", help="Import a dump (raw .dump, ELF core, or minidump) to .msl")
    im.add_argument("dump_file", help="Dump file path (.dump/.core/.dmp)")
    im.add_argument("-o", "--output", help="Output .msl file path")
    im.add_argument("--pid", type=int, default=0, help="Process ID")
    im.add_argument("--keylog", help="Keylog file for key hints")
    im.add_argument("-v", "--verbose", action="store_true")
    # import-dir
    imd = sub.add_parser(
        "import-dir",
        help="Import all dumps (.dump/.dmp/.core) in a directory to .msl")
    imd.add_argument("run_dir", help="Run directory path")
    imd.add_argument("-o", "--output-dir", required=True, help="Output directory")
    imd.add_argument("--keylog-filename", default="keylog.csv")
    imd.add_argument("-v", "--verbose", action="store_true")
    # verify
    vr = sub.add_parser("verify", help="Verify candidate key via decryption",
                        parents=[_decrypt_parent_parser()])
    vr.add_argument("dump", help="Dump file path")
    vr.add_argument("--offset", type=lambda x: int(x, 0), required=True,
                    help="Candidate key offset (hex or decimal)")
    vr.add_argument("--length", type=int, default=32, help="Key length (default: 32)")
    vr.add_argument("--ciphertext-hex", required=True, help="Known ciphertext (hex)")
    vr.add_argument("--iv-hex", help="IV (hex, default: 0x00010203...0f)")
    vr.add_argument("--cipher", default="AES-256-CBC", help="Cipher name")
    vr.add_argument("-o", "--output", help="Output JSON file")
    vr.add_argument("-v", "--verbose", action="store_true")
    # experiment
    ep_exp = sub.add_parser("experiment",
                            help="Run full dump-and-analyze experiment",
                            parents=[_decrypt_parent_parser()])
    ep_exp.add_argument("--target", required=True,
                        help="Target script path (e.g., aes_sample_process.py)")
    ep_exp.add_argument("--num-runs", type=int, default=30,
                        help="Number of dump iterations per tool (default: 30)")
    ep_exp.add_argument("--tools", help="Comma-separated dump tools (default: auto-detect)")
    ep_exp.add_argument("--output-dir", type=Path, default=Path("./experiment_output"),
                        help="Output directory (default: ./experiment_output)")
    ep_exp.add_argument("--convergence", action="store_true",
                        help="Run convergence sweep after dumping")
    ep_exp.add_argument("--max-fp", type=int, default=0,
                        help="FP target for convergence (default: 0)")
    ep_exp.add_argument("--export-format", default="volatility3",
                        choices=["yara", "json", "volatility3"],
                        help="Auto-export format (default: volatility3)")
    ep_exp.add_argument("-o", "--output", help="Output JSON results file")
    ep_exp.add_argument("-v", "--verbose", action="store_true")
    # inspect — low-level dump / structured-MSL inspection views. Nested
    # `inspect <action>` group reusing the pure tools_inspect / tools_xref
    # functions behind the HTTP `/api/inspect` endpoints and the MCP server.
    dp = _decrypt_parent_parser()
    insp = sub.add_parser(
        "inspect",
        help="Low-level dump / structured-MSL inspection views (hex, entropy, "
             "strings, byte-search, page-states, session-info, processes, "
             "modules, handles, xref, structure)",
    )
    insp_sub = insp.add_subparsers(dest="inspect_action")
    # inspect hex
    ih = insp_sub.add_parser("hex", parents=[dp],
                             help="Hex + ASCII dump of a byte range")
    ih.add_argument("dump_path", help="Dump (.dump/.core) or .msl file path")
    ih.add_argument("--offset", type=lambda x: int(x, 0), default=0,
                    help="Start offset (hex or decimal, default: 0)")
    ih.add_argument("--length", type=int, default=256,
                    help="Bytes to read (default: 256)")
    ih.add_argument("--view", choices=["raw", "vas"], default="raw",
                    help="MSL byte source: raw container or flattened VAS")
    ih.add_argument("-o", "--output", help="Output JSON file")
    ih.add_argument("-v", "--verbose", action="store_true")
    # inspect entropy
    ie = insp_sub.add_parser("entropy", parents=[dp],
                             help="Shannon entropy profile of a region")
    ie.add_argument("dump_path", help="Dump or .msl file path")
    ie.add_argument("--offset", type=lambda x: int(x, 0), default=0,
                    help="Start offset (hex or decimal, default: 0)")
    ie.add_argument("--length", type=int, default=0,
                    help="Region length (0 = whole file)")
    ie.add_argument("--window", type=int, default=32,
                    help="Sliding window size (default: 32)")
    ie.add_argument("--step", type=int, default=16,
                    help="Window step (default: 16)")
    ie.add_argument("--threshold", type=float, default=7.5,
                    help="High-entropy region threshold (default: 7.5)")
    ie.add_argument("-o", "--output", help="Output JSON file")
    ie.add_argument("-v", "--verbose", action="store_true")
    # inspect strings
    istr = insp_sub.add_parser("strings", parents=[dp],
                               help="Extract printable strings")
    istr.add_argument("dump_path", help="Dump or .msl file path")
    istr.add_argument("--offset", type=lambda x: int(x, 0), default=0,
                      help="Start offset (hex or decimal, default: 0)")
    istr.add_argument("--length", type=int, default=0,
                      help="Scan window length (0 = to end of file)")
    istr.add_argument("--min-length", type=int, default=4,
                      help="Minimum string length (default: 4)")
    istr.add_argument("--encoding", default="ascii",
                      help="String encoding (default: ascii)")
    istr.add_argument("--max-results", type=int, default=500,
                      help="Maximum strings to return (default: 500)")
    istr.add_argument("-o", "--output", help="Output JSON file")
    istr.add_argument("-v", "--verbose", action="store_true")
    # inspect byte-search
    ibs = insp_sub.add_parser("byte-search", parents=[dp],
                              help="Find all occurrences of a hex byte pattern")
    ibs.add_argument("dump_path", help="Dump or .msl file path")
    ibs.add_argument("--pattern", required=True,
                     help="Hex byte pattern (optional leading 0x)")
    ibs.add_argument("--view", choices=["raw", "vas"], default="raw",
                     help="MSL byte source: raw container or flattened VAS")
    ibs.add_argument("--max-results", type=int, default=500,
                     help="Maximum matches to return (default: 500)")
    ibs.add_argument("-o", "--output", help="Output JSON file")
    ibs.add_argument("-v", "--verbose", action="store_true")
    # inspect page-states
    ips = insp_sub.add_parser("page-states", parents=[dp],
                              help="MSL three-state page model (MSL only)")
    ips.add_argument("msl_path", help=".msl file path")
    ips.add_argument("-o", "--output", help="Output JSON file")
    ips.add_argument("-v", "--verbose", action="store_true")
    # inspect session-info
    isi = insp_sub.add_parser("session-info", parents=[dp],
                              help="MSL session metadata (MSL only)")
    isi.add_argument("msl_path", help=".msl file path")
    isi.add_argument("-o", "--output", help="Output JSON file")
    isi.add_argument("-v", "--verbose", action="store_true")
    # inspect processes
    ipr = insp_sub.add_parser("processes", parents=[dp],
                              help="List PROCESS_TABLE entries (MSL only)")
    ipr.add_argument("msl_path", help=".msl file path")
    ipr.add_argument("-o", "--output", help="Output JSON file")
    ipr.add_argument("-v", "--verbose", action="store_true")
    # inspect modules
    imo = insp_sub.add_parser("modules", parents=[dp],
                              help="List loaded modules from MSL metadata (MSL only)")
    imo.add_argument("msl_path", help=".msl file path")
    imo.add_argument("-o", "--output", help="Output JSON file")
    imo.add_argument("-v", "--verbose", action="store_true")
    # inspect handles
    ihn = insp_sub.add_parser("handles", parents=[dp],
                              help="List HANDLE_TABLE entries (MSL only)")
    ihn.add_argument("msl_path", help=".msl file path")
    ihn.add_argument("-o", "--output", help="Output JSON file")
    ihn.add_argument("-v", "--verbose", action="store_true")
    # inspect xref
    ixr = insp_sub.add_parser("xref", parents=[dp],
                              help="Resolve cross-references (MSL only)")
    ixr.add_argument("msl_path", help=".msl file path")
    ixr.add_argument("-o", "--output", help="Output JSON file")
    ixr.add_argument("-v", "--verbose", action="store_true")
    # inspect structure
    ist = insp_sub.add_parser("structure", parents=[dp],
                              help="Identify a data structure at an offset")
    ist.add_argument("dump_path", help="Dump or .msl file path")
    ist.add_argument("--offset", type=lambda x: int(x, 0), default=0,
                     help="Offset to overlay structures at (hex or decimal)")
    ist.add_argument("--protocol", default="",
                     help="Restrict candidates to a protocol (default: all)")
    ist.add_argument("-o", "--output", help="Output JSON file")
    ist.add_argument("-v", "--verbose", action="store_true")
    return parser


def build_parser() -> argparse.ArgumentParser:
    """Public alias for sphinx-argparse and external tooling."""
    return _build_parser()


def main():
    """MemDiver CLI entry point."""
    parser = _build_parser()
    args = parser.parse_args()
    if args.command is None or args.command == "web":
        sys.exit(_cmd_web(args))
    if args.command == "app":
        sys.exit(_cmd_app(args))
    if args.command == "ui":
        sys.exit(_cmd_ui(args))
    _setup_logging(getattr(args, "verbose", False))
    handlers = {
        "analyze": _cmd_analyze, "scan": _cmd_scan, "batch": _cmd_batch,
        "mcp": _cmd_mcp, "import": _cmd_import, "import-dir": _cmd_import_dir,
        "consensus": _cmd_consensus, "export": _cmd_export, "web": _cmd_web,
        "verify": _cmd_verify, "experiment": _cmd_experiment,
        "consensus-begin": _cmd_consensus_begin,
        "consensus-add": _cmd_consensus_add,
        "consensus-finalize": _cmd_consensus_finalize,
        "search-reduce": _cmd_search_reduce,
        "brute-force": _cmd_brute_force,
        "n-sweep": _cmd_n_sweep,
        "auto-floor": _cmd_auto_floor,
        "emit-plugin": _cmd_emit_plugin,
        "gen-kem-key": _cmd_gen_kem_key,
        "inspect": _cmd_inspect,
    }
    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)
    # BACKSTOP: a CapabilityError propagating out of ANY handler is translated
    # here into a single stderr line + category exit code, so it never escapes
    # as a traceback. Handlers that already present their own errors and return
    # an exit code (e.g. the inspect handlers, which catch CapabilityError in
    # _present_inspect_cli_call) never reach this except clause.
    try:
        sys.exit(handler(args))
    except CapabilityError as e:
        sys.exit(to_cli_exit(e))


if __name__ == "__main__":
    main()
