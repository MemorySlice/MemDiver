"""Consensus (region-report + incremental Welford session) CLI commands, extracted from cli.main (P3.1)."""

import argparse
import json
import logging
import sys
from pathlib import Path

from ._shared import (
    _key_material_from_args,
    _resolve_dump_paths,
    _warn_tag_status,
    _write_output,
)

logger = logging.getLogger("memdiver.cli")


def _cmd_consensus(args: argparse.Namespace) -> int:
    """Build consensus matrix from dump files and output region analysis.

    NOTE(single-source): the CLI ``consensus`` command is a REGION-REPORT
    surface (volatile/static/aligned regions + optional convergence), distinct
    from the pipeline-origination ``app.tools_pipeline.consensus`` producer the
    MCP ``consensus`` tool uses (which writes ``variance.npy`` / ``reference.bin``
    to feed ``search_reduce``). Both already share the ONE compute leaf,
    ``engine.consensus_service.build_consensus`` (called below with the same
    key-material + ``on_source`` contract), so there is no forked orchestration
    to collapse here — only the per-surface region/artifact shaping differs.
    """
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

    from memdiver.app.composition import open_dump

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
