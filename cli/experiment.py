"""Experiment orchestration CLI command + its progress relay and results table, extracted from cli.main (P3.1)."""

import argparse
import sys

from memdiver.core.service_errors import CapabilityError

from ._shared import _key_material_from_args, _warn_tag_status, _write_output


def _experiment_cli_progress(event: str, **fields) -> None:
    """Relay a producer progress event to stderr for the CLI experiment run."""
    msg = fields.get("msg")
    if event in ("stage_start", "progress", "stage_end") and msg:
        print(f"memdiver experiment: {msg}", file=sys.stderr)
    elif event == "error" and fields.get("error"):
        print(f"memdiver experiment: {fields['error']}", file=sys.stderr)


def _cmd_experiment(args: argparse.Namespace) -> int:
    """Orchestrate: spawn target, dump, build consensus, verify, export.

    Routes the whole flow through ``app.experiment_orchestration.experiment_result`` —
    the single implementation now shared with the API experiment task runner
    and the MCP ``experiment`` tool (previously the CLI and the API each
    re-implemented the spawn→dump→consensus→verify→emit orchestration, with the
    API copy still carrying the A5 raw-offset bug the CLI had fixed). The
    handler keeps its own presentation: streamed stderr progress, the
    side-by-side comparison table, and the JSON ``--output`` file.
    """
    from memdiver.app.experiment_orchestration import experiment_result

    tools = args.tools.split(",") if args.tools else None
    try:
        result = experiment_result(
            target=args.target,
            output_dir=str(args.output_dir),
            num_runs=args.num_runs,
            tools=tools,
            export_format=args.export_format,
            convergence=args.convergence,
            max_fp=args.max_fp,
            key_material=_key_material_from_args(args),
            on_source=_warn_tag_status,
            on_progress=_experiment_cli_progress,
        )
    except CapabilityError as exc:
        print(f"memdiver: ERROR — {exc.message}", file=sys.stderr)
        return 1

    all_tool_results = result["tool_results"]
    _print_experiment_table(all_tool_results)
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
