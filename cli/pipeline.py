"""Search-reduce/brute-force/n-sweep/auto-floor/emit-plugin/export/KEM/import-dir/verify CLI commands, extracted from cli.main (P3.1)."""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from memdiver.core.service_errors import CapabilityError

from ._shared import (
    _key_material_from_args,
    _resolve_dump_paths,
    _warn_tag_status,
    _write_output,
)
from .consensus import _load_welford_session

logger = logging.getLogger("memdiver.cli")


def _cmd_search_reduce(args: argparse.Namespace) -> int:
    """Run variance → alignment → entropy reduction on a finalized session.

    Routes the compute through ``app.tools_pipeline.search_reduce`` — the same
    producer the MCP ``search_reduce`` tool uses — so the reduction chain has a
    single implementation. The CLI's input model differs (a Welford ``--state``
    session vs. the producer's precomputed ``variance.npy``); the handler
    materialises that variance into a scratch ``variance.npy`` and hands it to
    the producer, then relays the persisted ``candidates.json`` payload to the
    CLI's ``--output`` (the payload the CLI has always emitted, verbatim).
    """
    import tempfile

    import numpy as np

    from memdiver.app.tools_pipeline import search_reduce

    _state, welford = _load_welford_session(Path(args.state))
    variance = welford.variance()

    with tempfile.TemporaryDirectory() as scratch:
        variance_path = Path(scratch) / "variance.npy"
        np.save(variance_path, variance)
        search_reduce(
            variance_path=str(variance_path),
            reference_path=args.reference_dump,
            num_dumps=welford.num_dumps,
            output_dir=scratch,
            alignment=args.alignment,
            block_size=args.block_size,
            density_threshold=args.density_threshold,
            min_variance=args.min_variance,
            entropy_window=args.entropy_window,
            entropy_threshold=args.entropy_threshold,
            min_region=args.min_region,
            key_file=args.key_file,
            passphrase=args.passphrase,
            kem_key_file=args.kem_key_file,
            on_source=_warn_tag_status,
        )
        payload = json.loads((Path(scratch) / "candidates.json").read_text())
    _write_output(payload, args.output)
    return 0


def _cmd_brute_force(args: argparse.Namespace) -> int:
    """Iterate candidates through a user oracle and emit hits.json.

    Routes the compute through ``app.tools_pipeline.brute_force`` (the shared
    producer the MCP ``brute_force`` tool uses). The producer writes the
    ``hits.json`` the CLI has always written (identical bytes — both serialise
    ``BruteForceResult.to_dict()``); the handler relays it to ``--output`` and
    keeps its own stderr hit/miss summary + exit-code contract.
    """
    import shutil
    import tempfile

    from memdiver.app.tools_pipeline import brute_force

    key_sizes = tuple(int(k.strip()) for k in args.key_sizes.split(",") if k.strip())
    with tempfile.TemporaryDirectory() as scratch:
        result = brute_force(
            candidates_path=args.candidates,
            reference_path=args.dump,
            oracle_path=args.oracle,
            output_dir=scratch,
            oracle_config_path=args.oracle_config,
            pcap_path=args.pcap,
            tls_client_random=args.tls_client_random,
            persist_ground_truth=getattr(args, "persist_ground_truth", False),
            key_sizes=key_sizes,
            stride=args.stride,
            jobs=args.jobs,
            exhaustive=not args.first_hit,
            state_path=args.state,
            top_k=args.top_k,
            key_file=args.key_file,
            passphrase=args.passphrase,
            kem_key_file=args.kem_key_file,
            on_source=_warn_tag_status,
        )
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(result["hits_path"], output_path)

    hits = result["hits"]
    if hits:
        print(
            f"memdiver: verified {len(hits)} hit(s); first at offset "
            f"0x{hits[0]['offset']:x} ({hits[0]['length']} bytes)",
            file=sys.stderr,
        )
    else:
        payload = json.loads(output_path.read_text())
        print(
            f"memdiver: exhausted {result['total_candidates']} candidates, "
            f"0 verified; top-{len(payload.get('top_k', []))} written to {args.output}",
            file=sys.stderr,
        )
    return result["exit_code"]


def _cmd_n_sweep(args: argparse.Namespace) -> int:
    """Sweep N ∈ n_values, run consensus → reduce → oracle, emit reports.

    Routes the compute through ``app.tools_pipeline.n_sweep`` (the shared
    producer the MCP ``n_sweep`` tool uses). The CLI keeps its own input model
    — discovering dumps under ``--runs-dir`` — then hands the resolved paths to
    the producer, which opens them key-aware, runs the sweep and writes the
    ``report.{json,md,html}`` artifacts. The AEAD warning is relayed per source
    through the producer's ``on_source`` hook; stderr headline + exit code are
    preserved.
    """
    from memdiver.app.tools_pipeline import n_sweep

    runs_dir = Path(args.runs_dir)
    dump_paths = sorted(runs_dir.glob(f"*/{args.dump_glob}"))
    if not dump_paths:
        dump_paths = sorted(runs_dir.rglob(args.dump_glob))
    if not dump_paths:
        print(f"no dumps matched {runs_dir}/*/{args.dump_glob}", file=sys.stderr)
        return 1

    n_values = [int(n.strip()) for n in args.n_values.split(",") if n.strip()]
    key_sizes = tuple(int(k.strip()) for k in args.key_sizes.split(",") if k.strip())
    result = n_sweep(
        source_paths=[str(p) for p in dump_paths],
        oracle_path=args.oracle,
        output_dir=args.output_dir,
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
        key_sizes=key_sizes,
        stride=args.stride,
        exhaustive=not args.first_hit,
        oracle_config_path=args.oracle_config,
        escalate=args.escalate,
        escalate_oracle_budget=args.escalate_oracle_budget,
        key_file=args.key_file,
        passphrase=args.passphrase,
        kem_key_file=args.kem_key_file,
        on_source=_warn_tag_status,
    )
    print(result["headline"], file=sys.stderr)
    print(
        f"wrote {result['report_json']}, {result['report_md']}, "
        f"{result['report_html']}",
        file=sys.stderr,
    )
    return 0 if result["first_hit_n"] is not None else 2


def _cmd_auto_floor(args: argparse.Namespace) -> int:
    """Automated ground-truth-free variance-floor selection → single verdict.

    Routes the compute through ``app.tools_pipeline.auto_floor`` (the shared
    producer the MCP ``auto_floor`` tool uses). The CLI's Welford ``--state``
    variance is materialised into a scratch ``variance.npy`` for the producer,
    which opens the reference key-aware, runs the verdict and writes
    ``verdict.json`` + ``report.md`` into ``--output-dir``. The stderr verdict
    line and category exit code are rebuilt from the returned verdict dict.
    """
    import tempfile

    import numpy as np

    from memdiver.app.tools_pipeline import auto_floor

    _state, welford = _load_welford_session(Path(args.state))
    variance = welford.variance()
    key_sizes = tuple(int(k.strip()) for k in args.key_sizes.split(",") if k.strip())
    reduce_kwargs = dict(
        alignment=args.alignment, block_size=args.block_size,
        density_threshold=args.density_threshold, entropy_window=args.entropy_window,
        entropy_threshold=args.entropy_threshold, min_region=args.min_region,
    )
    with tempfile.TemporaryDirectory() as scratch:
        variance_path = Path(scratch) / "variance.npy"
        np.save(variance_path, variance)
        verdict = auto_floor(
            variance_path=str(variance_path),
            reference_path=args.reference_dump,
            oracle_path=args.oracle,
            output_dir=args.output_dir,
            num_dumps=welford.num_dumps,
            oracle_config_path=args.oracle_config,
            key_sizes=key_sizes,
            stride=args.stride,
            reduce_kwargs=reduce_kwargs,
            coverage=args.coverage,
            correspondence=args.correspondence,
            filter_recall=args.filter_recall,
            min_coverage=args.min_coverage,
            positive_control_hex=args.positive_control,
            phi0_method=args.phi0_method,
            p_min=args.p_min,
            self_test_trials=args.self_test_trials,
            oracle_budget=args.oracle_budget,
            alignment_quality=args.alignment_quality,
            min_alignment=args.min_alignment,
            managed_region=args.managed_region,
            key_file=args.key_file,
            passphrase=args.passphrase,
            kem_key_file=args.kem_key_file,
            on_source=_warn_tag_status,
        )
    offset = verdict["offset"]
    tail = (f" key=0x{offset:x} phi*={verdict['phi_star']:.1f} phi0={verdict['phi0']:.1f}"
            if offset is not None else
            (f" ({verdict['inconclusive_reason']})" if verdict["inconclusive_reason"] else ""))
    print(f"memdiver auto-floor: {verdict['verdict']}{tail}", file=sys.stderr)
    return verdict["exit_code"]


def _cmd_emit_plugin(args: argparse.Namespace) -> int:
    """Emit a Volatility3 plugin from a hits.json neighborhood variance.

    Routes the compute through ``app.tools_pipeline.emit_plugin`` (the shared
    producer the MCP ``emit_plugin`` tool uses). The producer names its output
    ``<name>.py`` inside a directory; the CLI keeps its arbitrary ``--output``
    filepath by having the producer emit into a scratch dir and copying the
    plugin to ``--output``.
    """
    import shutil
    import tempfile

    from memdiver.app.tools_pipeline import emit_plugin

    with tempfile.TemporaryDirectory() as scratch:
        result = emit_plugin(
            hits_path=args.hit,
            reference_path=args.reference,
            name=args.name,
            output_dir=scratch,
            description=args.description,
            hit_index=args.hit_index,
            variance_threshold=args.variance_threshold,
            key_file=args.key_file,
            passphrase=args.passphrase,
            kem_key_file=args.kem_key_file,
            on_source=_warn_tag_status,
        )
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(result["plugin_path"], out)
    print(f"wrote vol3 plugin {out}", file=sys.stderr)
    return 0


def _cmd_export(args: argparse.Namespace) -> int:
    """Export a byte pattern from dump files as YARA/JSON/Volatility3.

    Thin CLI adapter over the ``app`` producers
    :func:`memdiver.app.tools_pipeline.export_pattern` (auto) and
    :func:`memdiver.app.tools_pipeline.manual_export_pattern` (manual).
    The producers own the consensus → pattern pipeline, so the
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
    from memdiver.app.export_service import AnalysisServiceError
    from memdiver.app.tools_pipeline import export_pattern, manual_export_pattern

    dump_paths = _resolve_dump_paths(args.dumps)

    if len(dump_paths) < 2:
        print(f"Need at least 2 dumps, got {len(dump_paths)}", file=sys.stderr)
        return 1

    key_material = _key_material_from_args(args)

    try:
        if args.auto:
            result = export_pattern(
                dump_paths=dump_paths,
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
                dump_paths=dump_paths,
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


def _cmd_export_keylog(args: argparse.Namespace) -> int:
    """Emit a Wireshark NSS key log from a recovered-secrets JSON file.

    Routes the compute through ``app.tools_pipeline.keylog_result`` — the same
    producer the HTTP ``/api/analysis/export-keylog`` route and the MCP
    ``export_keylog`` tool use, so the headline artifact has ONE implementation.
    Reads a JSON list of ``{secret_type, client_random, secret}`` dicts from
    ``--secrets`` and writes the key log to ``--output`` (or stdout). A malformed
    hex / missing key raises a ``CapabilityError`` the main-loop backstop renders
    to stderr + a category exit code.
    """
    from memdiver.app.tools_pipeline import keylog_result

    try:
        secrets = json.loads(Path(args.secrets).read_text())
    except (OSError, ValueError) as exc:
        print(f"memdiver: cannot read secrets file {args.secrets}: {exc}",
              file=sys.stderr)
        return 1

    result = keylog_result(secrets=secrets, output_path=args.output)
    if args.output:
        print(f"memdiver: wrote {result['count']} key(s) to {args.output}",
              file=sys.stderr)
    else:
        sys.stdout.write(result["keylog"])
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
    """Verify a candidate key at a given offset against known ciphertext.

    Routes the compute through ``app.tools_pipeline.verify_key_result`` — the
    same producer the HTTP ``/api/analysis/verify-key`` route and the MCP
    ``verify`` tool use — so the candidate-read + decryption check has ONE
    implementation. The producer reads through the DumpSource memory projection
    (VAS for ``.msl``, so a memory-relative offset lands in the space it was
    derived in) and decrypts encrypted containers with the supplied key
    material. Any hard error surfaces as a ``CapabilityError`` which the CLI
    renders to stderr + exit 1, preserving this command's exit contract.
    """
    from memdiver.app.tools_pipeline import verify_key_result

    try:
        result = verify_key_result(
            dump_path=args.dump,
            offset=args.offset,
            length=args.length,
            ciphertext_hex=args.ciphertext_hex,
            cipher=args.cipher,
            iv_hex=args.iv_hex,
            nonce_hex=getattr(args, "nonce_hex", None),
            aad_hex=getattr(args, "aad_hex", None),
            tag_hex=getattr(args, "tag_hex", None),
            key_material=_key_material_from_args(args),
            on_source=_warn_tag_status,
        )
    except CapabilityError as exc:
        print(f"memdiver: ERROR — {exc.message}", file=sys.stderr)
        return 1

    payload = {
        "offset": f"0x{args.offset:x}",
        "length": args.length,
        "cipher": args.cipher,
        "verified": result["verified"],
        "key_hex": result["key_hex"],
    }
    _write_output(payload, getattr(args, "output", None))
    return 0
