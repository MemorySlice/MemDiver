#!/usr/bin/env python3
"""AES-256 memory dump experiment driver.

Thin CLI wrapper around core.dump_driver.DumpOrchestrator.
Spawns aes_sample_process.py, dumps memory via available tools,
and generates keylog.csv files for analysis.

Usage: python aes_dump_driver.py [--output-dir DIR] [--num-runs N] [--tools TOOLS]
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.dump_driver import DumpOrchestrator
from tests.fixtures._aes_sample_builder import ensure_built


def main():
    parser = argparse.ArgumentParser(
        description="Run AES-256 memory dump experiment")
    parser.add_argument("--output-dir", type=Path,
                        default=Path("/tmp/aes_experiment"),
                        help="Output directory (default: /tmp/aes_experiment)")
    parser.add_argument("--num-runs", type=int, default=30,
                        help="Number of dump iterations per tool (default: 30)")
    parser.add_argument("--tools", help="Comma-separated tools (default: auto-detect)")
    parser.add_argument("--target", type=Path, default=None,
                        help="Override target process. Defaults to aes_sample_process.py; "
                             "the compiled aes_sample binary is built on first use when needed.")
    args = parser.parse_args()

    # Build the native aes_sample binary on first use so downstream tools
    # that prefer it over the Python variant are ready to go.
    built = ensure_built()
    if built is None:
        print("WARNING: could not build aes_sample binary (cc missing or "
              "build failed); falling back to aes_sample_process.py",
              file=sys.stderr)

    if args.target is not None:
        target = args.target
    elif built is not None:
        target = built
    else:
        target = Path(__file__).parent / "aes_sample_process.py"

    if not target.is_file():
        print(f"Target not found: {target}", file=sys.stderr)
        return 1

    tools = args.tools.split(",") if args.tools else None
    orch = DumpOrchestrator(tools=tools)

    if not orch.available_tools:
        print("No dump tools available", file=sys.stderr)
        return 1

    print(f"Available tools: {[t.name for t in orch.available_tools]}")
    print(f"Running {args.num_runs} iterations...")

    result = orch.run_experiment(target, args.num_runs, args.output_dir)

    print(f"\nExperiment complete:")
    print(f"  Tools used: {result.tools_used}")
    print(f"  Runs per tool: {result.num_runs}")
    print(f"  Output: {result.output_dir}")
    for tool, path in result.tool_dirs.items():
        dumps = list(path.glob("*/*.dump")) + list(path.glob("*/*.msl"))
        print(f"  {tool}: {len(dumps)} dumps in {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
