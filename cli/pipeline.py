"""Search-reduce/brute-force/n-sweep/auto-floor/emit-plugin/export/KEM/import-dir/verify CLI commands, extracted from cli.main (P3.1)."""

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Optional

from memdiver.core.service_errors import CapabilityError, ErrorCategory

from ._shared import (
    _key_material_from_args,
    _resolve_dump_paths,
    _warn_tag_status,
    _write_output,
)
from .consensus import _load_welford_session

logger = logging.getLogger("memdiver.cli")

#: Static-anchor padding ``export --auto`` applies per side of the detected
#: region when ``--context`` is omitted. Mirrors the producer default in
#: ``app.export_service.auto_export_pattern``; the parser advertises None so
#: "omitted" and "explicitly 32" stay distinguishable on the manual path.
DEFAULT_AUTO_EXPORT_CONTEXT = 32

#: Why ``export --offset/--length --context N`` is refused instead of silently
#: dropping N: ``manual_export_pattern`` has no ``context`` parameter, and its
#: contract is "the offset you gave me IS the key start" -- the emitted pattern
#: therefore has ``key_offset=0`` and contains none of the requested anchor
#: bytes. ``export-key-pattern`` is the command that does build a padded
#: window around an already-known secret.
_MANUAL_CONTEXT_REJECTION = (
    "--context applies only to `export --auto`, where it pads the "
    "auto-detected region. A manual --offset/--length region IS the key "
    "(the pattern starts at the key, with no static-anchor context), so "
    "--context cannot be honoured here and is refused rather than ignored.\n"
    "To build a padded signature around a key you already know, use "
    "`memdiver export-key-pattern <dumps...> --key-hex <hex> --context N` "
    "(or --keylog-line '<LABEL> <client_random_hex> <secret_hex>'): it "
    "locates the secret across the dumps itself and keeps N static-anchor "
    "bytes per side."
)


def _split_classes(spec):
    """Split a ``--classes key_candidate,pointer`` flag into class names.

    ``None`` / empty stays ``None`` so the producer leaves the class gate a
    pass-through. Unknown names are rejected downstream by
    ``candidate_pipeline.resolve_byte_classes``, which owns the one spelling of
    that error for every surface.
    """
    if not spec:
        return None
    return [name.strip() for name in spec.split(",") if name.strip()]


def _cmd_search_reduce(args: argparse.Namespace) -> int:
    """Run variance → alignment → entropy reduction on a finalized session.

    Routes the compute through ``app.tools_pipeline.search_reduce`` — the same
    producer the MCP ``search_reduce`` tool uses — so the reduction chain has a
    single implementation. The CLI's input model differs (a Welford ``--state``
    session vs. the producer's precomputed ``variance.npy``); the handler
    materialises that variance into a scratch ``variance.npy`` and hands it to
    the producer, then relays the persisted ``candidates.json`` payload to the
    CLI's ``--output`` (the payload the CLI has always emitted, verbatim).

    ``--classes`` / ``--max-region`` / ``--order`` reach the same producer
    parameters. They are read with ``getattr`` defaults because this handler is
    also driven by hand-built ``argparse.Namespace`` objects that predate the
    flags; an omitted flag reproduces the pre-flag reduction exactly.
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
            max_region=getattr(args, "max_region", 0),
            classes=_split_classes(getattr(args, "classes", None)),
            order=getattr(args, "order", "offset"),
            key_file=args.key_file,
            passphrase=args.passphrase,
            kem_key_file=args.kem_key_file,
            on_source=_warn_tag_status,
        )
        payload = json.loads((Path(scratch) / "candidates.json").read_text())
    _write_output(payload, args.output)
    return 0


def _cmd_analyze_candidates(args: argparse.Namespace) -> int:
    """Rank candidate regions across N dumps with no oracle and no capture.

    The headless twin of the web's ``POST /api/analysis/candidates``: it routes
    straight through ``app.tools_pipeline.analyze_candidates``, so the
    exploratory path (consensus → class/length/entropy filters → ranking) has
    one implementation across every surface. Unlike ``search-reduce`` it needs
    no ``--state`` session and no precomputed variance — dump paths in, ranked
    regions out — and unlike ``brute-force`` it confirms nothing, which is what
    makes it reachable for an analyst who has no oracle yet.

    The full payload (regions, class histogram, alignment provenance, resolved
    thresholds, diagnostics) is written through ``_write_output``; the
    alignment warnings and diagnostics additionally go to stderr, where an
    operator piping the JSON onward still sees them.
    """
    from memdiver.app.tools_pipeline import analyze_candidates

    payload = analyze_candidates(
        dump_paths=[str(p) for p in _resolve_dump_paths(args.dumps)],
        classes=_split_classes(getattr(args, "classes", None)),
        min_variance=args.min_variance,
        min_region=args.min_region,
        max_region=args.max_region,
        alignment=args.alignment,
        block_size=args.block_size,
        density_threshold=args.density_threshold,
        entropy_window=args.entropy_window,
        entropy_threshold=args.entropy_threshold,
        order=args.order,
        max_returned=args.max_returned,
        normalize=args.normalize,
        project_id=args.project_id,
        key_file=args.key_file,
        passphrase=args.passphrase,
        kem_key_file=args.kem_key_file,
        on_source=_warn_tag_status,
    )
    for warning in payload["warnings"]:
        print(f"memdiver: WARNING — {warning}", file=sys.stderr)
    for diagnostic in payload["diagnostics"]:
        print(f"memdiver: {diagnostic['message']}", file=sys.stderr)
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

    from memdiver.app.tools_pipeline import DEFAULT_RESOURCE_TYPE, brute_force
    from memdiver.engine.brute_force import DEFAULT_NEIGHBORHOOD_PAD

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
            pcap_max_records=args.pcap_max_records,
            pcap_max_challenges=args.pcap_max_challenges,
            # getattr for the same reason ``persist_ground_truth`` below uses
            # it: these handlers are also driven with a hand-built
            # argparse.Namespace that need not carry every flag.
            resource_type=getattr(args, "resource_type", DEFAULT_RESOURCE_TYPE),
            persist_ground_truth=getattr(args, "persist_ground_truth", False),
            key_sizes=key_sizes,
            stride=args.stride,
            jobs=args.jobs,
            exhaustive=not args.first_hit,
            state_path=args.state,
            top_k=args.top_k,
            # getattr with the shared default, matching `persist_ground_truth`
            # above: these handlers are also driven directly with a hand-built
            # argparse.Namespace (the test convention in tests/test_cli.py and
            # tests/test_pipeline_key_aware.py), which need not carry every flag.
            neighborhood_pad=getattr(
                args, "neighborhood_pad", DEFAULT_NEIGHBORHOOD_PAD
            ),
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
    # A partial-coverage warning turns "0 verified" from an ambiguous silence
    # into an actionable finding; the producer decides when one applies, the CLI
    # only relays it. hits.json already carries the same numbers.
    for warning in result.get("warnings", []):
        print(f"memdiver: warning: {warning['message']}", file=sys.stderr)
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

    Takes the same two mutually-exclusive oracle sources ``brute-force`` takes:
    ``--oracle`` (a BYO script) or ``--pcap`` (a capture of the same session,
    re-verified through the first-party pcap oracle at every N).
    """
    from memdiver.app.tools_pipeline import DEFAULT_RESOURCE_TYPE, n_sweep

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
        # Exactly one oracle source; the producer raises on both/neither, so the
        # CLI does not restate the guard (same shape as ``brute-force``).
        oracle_path=args.oracle,
        pcap_path=args.pcap,
        tls_client_random=args.tls_client_random,
        pcap_max_records=args.pcap_max_records,
        pcap_max_challenges=args.pcap_max_challenges,
        resource_type=getattr(args, "resource_type", DEFAULT_RESOURCE_TYPE),
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
    from memdiver.engine.brute_force import DEFAULT_NEIGHBORHOOD_PAD

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
            # getattr with the shared default, matching `persist_ground_truth`
            # above: these handlers are also driven directly with a hand-built
            # argparse.Namespace (the test convention in tests/test_cli.py and
            # tests/test_pipeline_key_aware.py), which need not carry every flag.
            neighborhood_pad=getattr(
                args, "neighborhood_pad", DEFAULT_NEIGHBORHOOD_PAD
            ),
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

    # ``--context`` defaults to None at the parser so "not supplied" stays
    # distinguishable from an explicit ``--context 32``; the 32 is resolved
    # here, on the only path that can honour it.
    supplied_context = getattr(args, "context", None)
    # Meaningful on the --auto path only; the manual path refuses the flag.
    auto_context = (DEFAULT_AUTO_EXPORT_CONTEXT
                    if supplied_context is None else supplied_context)

    try:
        if args.auto:
            result = export_pattern(
                dump_paths=dump_paths,
                fmt=args.format,
                name=args.name,
                align=getattr(args, "align", False),
                context=auto_context,
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
            if supplied_context is not None:
                print(_MANUAL_CONTEXT_REJECTION, file=sys.stderr)
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
    if args.auto:
        logger.info(
            "Auto-selected region: offset=0x%x length=%d (key 0x%x-0x%x)",
            region["offset"], region["length"],
            region["key_start"], region["key_end"],
        )
        print(
            f"Auto-detected region: offset=0x{region['offset']:x}, "
            f"{region['length']} bytes (key at 0x{region['key_start']:x}-"
            f"0x{region['key_end']:x}, context={auto_context}B)",
            file=sys.stderr,
        )
    else:
        # Nothing was detected on this path and nothing was padded: the region
        # the operator gave IS the key, so ``manual_export_pattern`` renders it
        # with ``key_offset=0`` (see ``export_service._render_content``). Saying
        # "auto-detected" or quoting a context width here would both be false.
        logger.info(
            "Specified region: offset=0x%x length=%d (key at pattern offset 0)",
            region["offset"], region["length"],
        )
        print(
            f"Specified region: offset=0x{region['offset']:x}, "
            f"{region['length']} bytes (the region IS the key: it begins at "
            f"pattern offset 0, with no static-anchor context)",
            file=sys.stderr,
        )

    content = result["content"]
    if args.output:
        Path(args.output).write_text(content)
        print(f"Exported {result['format']} to {args.output}", file=sys.stderr)
    else:
        print(content)
    return 0


def _cmd_locate_key(args: argparse.Namespace) -> int:
    """Locate ONE known secret across N dumps and report the honest verdict.

    Routes through ``app.tools_pipeline.locate_key`` — the same producer the
    HTTP ``POST /api/analysis/locate-key`` route and the MCP ``locate_key`` tool
    use. The full payload (verdict, six per-status counts, the per-dump census in
    the supplied order, diagnostics) goes to ``--output``; the verdict line and
    the diagnostics go to STDERR, so an operator piping the JSON onward still
    sees the qualifications.

    Exit codes make the command SCRIPTABLE, which is the point of a CLI here:

    * ``0`` — ``found``.
    * ``3`` — ``absent``. Already ``_CLI_EXIT[NOT_FOUND]``, so this reuses the
      established "the thing you asked about is not there" code rather than
      inventing a locate-key-specific vocabulary.
    * ``2`` — ``not_searched``. Grouped with the caller-correctable codes because
      that is what it is: nothing was read, and the inputs need fixing.

    The full payload is written in ALL THREE cases. A non-zero exit is a verdict,
    not a failure, and the census that produced it is exactly what the operator
    needs to see.

    Three spellings of the secret reach the producer from here: ``--key-hex``,
    ``--keylog-line`` and — C2's symbolic form — ``--pcap-field FIELD_ID``
    together with ``--pcap`` (and ``--pcap-session`` when the capture holds more
    than one session). All three are one mutually-exclusive group, so a mixture
    is refused by the parser rather than by the producer.
    """
    from memdiver.app.tools_pipeline import locate_key

    payload = locate_key(
        dump_paths=[str(p) for p in _resolve_dump_paths(args.dumps)],
        key_hex=args.key_hex or "",
        keylog_line=args.keylog_line or "",
        pcap_field=_pcap_field_from_args(args),
        view=args.view,
        max_offsets=args.max_offsets,
        key_file=args.key_file,
        passphrase=args.passphrase,
        kem_key_file=args.kem_key_file,
        on_source=_warn_tag_status,
    )
    print(
        f"memdiver: verdict={payload['verdict']} "
        f"present={payload['dumps_present']}/{payload['dumps_searched']} "
        f"searched (of {payload['dumps_total']} supplied)",
        file=sys.stderr,
    )
    for diagnostic in payload["diagnostics"]:
        print(f"memdiver: {diagnostic['message']}", file=sys.stderr)
    _write_output(payload, args.output)
    return _LOCATE_KEY_EXIT.get(payload["verdict"], 2)


def _pcap_field_from_args(args: argparse.Namespace) -> Optional[dict]:
    """Assemble ``locate-key``'s ``--pcap-field`` trio into the producer's dict.

    Three flags rather than one packed value (``PATH:FIELD``) because a capture
    path can itself contain a colon, and splitting one wrong is how a "capture
    not found" error ends up blaming the field name.

    ``None`` when ``--pcap-field`` was not given, so the other three input forms
    reach the producer exactly as before. When it WAS given, the dict is built
    even if ``--pcap`` is absent: the producer owns the "missing pcap_path"
    message, so the CLI and the other three surfaces report that mistake in the
    same words instead of each inventing their own.
    """
    field_id = getattr(args, "pcap_field", None)
    if not field_id:
        return None
    pcap_field = {
        "pcap_path": getattr(args, "pcap", None) or "",
        "field_id": field_id,
    }
    session = getattr(args, "pcap_session", None)
    if session:
        pcap_field["client_random"] = session
    return pcap_field


#: Verdict -> process exit code. ``3`` is ``_CLI_EXIT[NOT_FOUND]``; ``2`` is the
#: shared caller-correctable code. Kept as a dict so a new verdict in
#: ``engine.key_location.KEY_LOCATION_VERDICTS`` fails loudly at the ``.get``
#: default (2) rather than silently exiting 0.
_LOCATE_KEY_EXIT = {"found": 0, "absent": 3, "not_searched": 2}


def _cmd_locate_field_pairs(args: argparse.Namespace) -> int:
    """Locate a handshake FIELD across N dumps, each from its OWN capture.

    Routes through ``app.tools_pipeline.locate_field_across_pairs`` -- the same
    producer the HTTP ``POST /api/pcaps/locate-field`` route and the MCP
    ``locate_field_across_pairs`` tool use. The full payload (verdict, the pair
    census, per-pair ``location`` blocks, diagnostics) goes to ``--output``; the
    verdict line and the diagnostics go to STDERR, so an operator piping the
    JSON onward still sees the qualifications.

    Where ``locate-key`` takes ONE needle for N dumps, this takes N pairs and a
    field NAME. No key log is read -- the needle comes off the wire -- which is
    what makes it usable on a corpus that ships captures but no ground truth.

    Exit codes are ``locate-key``'s, deliberately: ``0`` found, ``3`` absent
    (``_CLI_EXIT[NOT_FOUND]``), ``2`` nothing searched. The full payload is
    written in all three cases -- a non-zero exit is a verdict, not a failure.
    """
    from memdiver.app.tools_pipeline import locate_field_across_pairs

    pairs = _pcap_pairs_from_args(args)
    # The positional dumps are dropped to ``None`` when --pairs was given, so
    # the producer sees exactly one input form and owns the "both / neither"
    # message. Passing an empty list instead would read as "supplied, empty" and
    # trip the both-forms guard with a confusing pair of names.
    dumps = (None if pairs is not None
             else [str(p) for p in _resolve_dump_paths(args.dumps)])

    payload = locate_field_across_pairs(
        pairs=pairs,
        dump_paths=dumps,
        field_id=args.field_id,
        view=args.view,
        max_offsets=args.max_offsets,
        pcap_max_records=args.pcap_max_records,
        pcap_max_challenges=args.pcap_max_challenges,
        key_file=args.key_file,
        passphrase=args.passphrase,
        kem_key_file=args.kem_key_file,
        on_source=_warn_tag_status,
    )
    counts = payload["counts"]
    print(
        f"memdiver: verdict={payload['verdict']} field={payload['field_id']} "
        f"present={counts['pairs_present']}/{counts['pairs_searched']} "
        f"searched (of {counts['pairs_total']} pairs; "
        f"{counts['pairs_unpaired']} unpaired, "
        f"{counts['pairs_field_unresolved']} field-unresolved) "
        f"across {counts['captures_distinct']} capture(s)",
        file=sys.stderr,
    )
    for diagnostic in payload["diagnostics"]:
        print(f"memdiver: {diagnostic['message']}", file=sys.stderr)
    _write_output(payload, args.output)
    # Reuses ``locate-key``'s verdict -> exit map rather than a second copy:
    # both producers speak ``engine.key_location.KEY_LOCATION_VERDICTS``, so a
    # divergence here could only be a bug.
    return _LOCATE_KEY_EXIT.get(payload["verdict"], 2)


def _pcap_pairs_from_args(args: argparse.Namespace) -> Optional[list]:
    """Read ``--pairs`` as a JSON file path, or as inline JSON.

    ``None`` when the flag was not given, which is what selects the producer's
    discovery form. A path is tried first (the ordinary case -- an explicit
    pairing for a real corpus is far too long to type), and the value is parsed
    as inline JSON only when no such file exists, so a filename that happens to
    look like JSON is never silently reinterpreted.

    The per-entry key validation is deliberately NOT done here: the producer
    owns it, so the CLI and the other three surfaces report a misspelt
    ``pcap`` in the same words.
    """
    raw = getattr(args, "pairs", None)
    if not raw:
        return None
    path = Path(raw).expanduser()
    text = path.read_text() if path.is_file() else raw
    try:
        parsed = json.loads(text)
    except ValueError as exc:
        raise CapabilityError(
            f"--pairs is neither a readable JSON file nor valid inline JSON: "
            f"{exc}",
            category=ErrorCategory.INVALID_INPUT,
        ) from exc
    if not isinstance(parsed, list):
        raise CapabilityError(
            f"--pairs must hold a JSON list of "
            f"{{'dump_path', 'pcap_path'}} objects, got "
            f"{type(parsed).__name__}",
            category=ErrorCategory.INVALID_INPUT,
        )
    return parsed


def _cmd_export_key_pattern(args: argparse.Namespace) -> int:
    """Export a scanning signature anchored on an already-known secret.

    Routes through ``app.tools_pipeline.export_key_pattern`` — the same producer
    the HTTP ``POST /api/analysis/key-pattern`` route and the MCP
    ``export_key_pattern`` tool use. The full payload goes to ``--output``; the
    verdict line and every diagnostic go to stderr, because the two WARNING
    diagnostics (``key_fully_static`` / ``degenerate_anchors``) are the whole
    reason an operator should not paste the rule straight into production.

    ``--format`` defaults to ``yara`` here, not to the producer's
    ``volatility3``: this is a documented per-surface default divergence of the
    same kind as ``--order`` (``rank`` on the surfaces, ``offset`` in the
    producer) — an operator asking for a signature on the terminal wants the
    portable one.
    """
    from memdiver.app.tools_pipeline import export_key_pattern

    payload = export_key_pattern(
        dump_paths=[str(p) for p in _resolve_dump_paths(args.dumps)],
        key_hex=args.key_hex or "",
        keylog_line=args.keylog_line or "",
        context=args.context,
        fmt=args.format,
        name=args.name,
        min_static_ratio=args.min_static_ratio,
        view=args.view,
        output_dir=args.output_dir,
        include_window_hex=args.include_window_hex,
        max_offsets=args.max_offsets,
        key_file=args.key_file,
        passphrase=args.passphrase,
        kem_key_file=args.kem_key_file,
        on_source=_warn_tag_status,
    )
    location = payload["location"]
    print(
        f"memdiver: verdict={location['verdict']} "
        f"mask over {payload['mask_regions']} dump(s) "
        f"({payload['mask_dumps_present']} present, "
        f"{payload['mask_dumps_absent']} absent); "
        f"{payload['key_wildcard_count']}/{location['needle_length']} key bytes "
        f"wildcarded",
        file=sys.stderr,
    )
    for diagnostic in payload["diagnostics"]:
        print(f"memdiver: {diagnostic['message']}", file=sys.stderr)
    _write_output(payload, args.output)
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


def _cmd_inspect_pcap(args: argparse.Namespace) -> int:
    """Summarise the TLS sessions in a capture (the pcap arm/validate step).

    Routes the compute through ``app.tools_pipeline.inspect_pcap`` — the same
    producer the HTTP ``POST /api/pcaps/validate`` route and the MCP
    ``inspect_pcap`` tool use, so the summary has ONE implementation. Prints the
    JSON summary to ``--output`` (or stdout). A missing ``pcap`` extra or an
    unreadable capture raises a ``CapabilityError`` the main-loop backstop
    renders to stderr + a category exit code.

    ``--fields`` additionally reports each session's byte-addressable protocol
    fields with their wire provenance, plus the top-level ``field_index`` — the
    catalogue an operator reads to pick a ``locate-key --pcap-field`` id. Off by
    default, so the plain summary costs one read of the capture as before.

    ``--protocols`` adds the top-level ``protocols`` inventory — what the
    capture holds and which ``--resource-type`` (if any) can decrypt each. It is
    the flag to reach for when ``session_count`` is 0: that zero says the
    capture has no TLS, not that it is empty. Also off by default, and it never
    fails the command — an unrecognisable capture simply reports no candidates.
    """
    from memdiver.app.tools_pipeline import inspect_pcap

    result = inspect_pcap(
        pcap_path=args.pcap,
        pcap_max_records=args.pcap_max_records,
        pcap_max_challenges=args.pcap_max_challenges,
        include_fields=bool(getattr(args, "fields", False)),
        detect_protocols=bool(getattr(args, "protocols", False)),
    )
    _write_output(result, getattr(args, "output", None))
    return 0


def _cmd_gen_kem_key(args: argparse.Namespace) -> int:
    """Generate a KEM keypair for encrypted-MSL recipients (spec §10.4).

    Writes the public key (shared with producers) and the private key (used
    later via ``--kem-key-file`` to decrypt). Hybrid keys are the
    concatenation of the X25519 and ML-KEM-768 halves.
    """
    from memdiver.msl.crypto import (MslCryptoError, kem_generate_keypair,
                            kem_is_available, kem_unavailable_hint)
    from memdiver.msl.enums import KeyEncap

    mechanisms = {
        "X25519": KeyEncap.X25519,
        "ML-KEM-768": KeyEncap.ML_KEM_768,
        "ML-KEM-1024": KeyEncap.ML_KEM_1024,
        "X25519+ML-KEM-768": KeyEncap.X25519_ML_KEM_768,
    }
    mech = mechanisms[args.mechanism]
    if not kem_is_available(mech):
        # The remedy is mechanism-specific (base package vs native liboqs), so
        # let msl.crypto — which owns the probe — also own the wording.
        print(f"memdiver: {args.mechanism} unavailable; "
              f"{kem_unavailable_hint(mech)}", file=sys.stderr)
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
