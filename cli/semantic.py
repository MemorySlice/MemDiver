"""Semantic producer CLI commands: ``propose-layout``, ``model-build``,
``model-export`` and ``model-validate``.

The CLI face of :mod:`memdiver.app.tools_semantic`; JSON inputs arrive as
files (``--needles-file``, ``--related-file``, ``--spec-file``).
"""

import argparse
import json
import sys
from pathlib import Path

from ._shared import _resolve_dump_paths, _write_output, keylog_spec_from_args
from .consensus import _anchor_specs_from_args


def _json_file(path):
    return None if not path else json.loads(Path(path).read_text())


def _learn_kwargs(args: argparse.Namespace) -> dict:
    dump_paths = [str(p) for p in _resolve_dump_paths(args.dumps)]
    needle_file = getattr(args, "needles_file", None)
    # consensus-anchor names the per-dump file --needle-file; reuse its resolver.
    shim = argparse.Namespace(anchor=args.anchor, needle_file=needle_file,
                              needle=args.needle)
    anchors, needles = _anchor_specs_from_args(shim, dump_paths)
    return dict(
        dump_paths=dump_paths, anchors=anchors, needles=needles,
        occurrence=args.occurrence, delta_start=args.delta_start,
        length=args.length, anchor_length=args.anchor_length,
        related=_json_file(args.related_file), pointer_quorum=args.pointer_quorum,
        heap=not args.no_heap, mixed_ok=getattr(args, "mixed_ok", False),
        case_dir=args.case_dir, keylog=keylog_spec_from_args(args),
        anchor_label=args.anchor_label, related_labels=args.related_labels,
        detail=getattr(args, "detail", "summary"))


def _run(producer, args: argparse.Namespace, **extra) -> int:
    from memdiver.app.composition import build_tool_session
    from memdiver.core.service_errors import CapabilityError

    try:
        result = producer(build_tool_session(), **_learn_kwargs(args), **extra)
    except (CapabilityError, OSError, ValueError) as exc:
        print(f"memdiver: {exc}", file=sys.stderr)
        return 1
    _write_output(result.payload, args.output)
    return 0


def _cmd_propose_layout(args: argparse.Namespace) -> int:
    """Field-boundary proposal; the sibling of ``POST /api/semantic/propose-layout``."""
    from memdiver.app.tools_semantic import propose_layout_result

    return _run(propose_layout_result, args)


def _cmd_model_build(args: argparse.Namespace) -> int:
    """Build + write the artifact model; sibling of ``POST /api/semantic/model-build``."""
    from memdiver.app.tools_semantic import artifact_model_build_result

    try:
        spec = _json_file(args.spec_file) or {}
    except (OSError, ValueError) as exc:
        print(f"memdiver: cannot read --spec-file: {exc}", file=sys.stderr)
        return 1
    return _run(
        artifact_model_build_result, args, name=args.name,
        meanings=spec.get("meanings", []), relationships=spec.get("relationships", []),
        applicability=spec.get("applicability"),
        prefilter_length=args.prefilter_length, out_path=args.out_path)


def _run_plain(producer, args: argparse.Namespace, **kwargs) -> int:
    from memdiver.app.composition import build_tool_session
    from memdiver.core.service_errors import CapabilityError

    try:
        result = producer(build_tool_session(), **kwargs)
    except (CapabilityError, OSError, ValueError) as exc:
        print(f"memdiver: {exc}", file=sys.stderr)
        return 1
    _write_output(result.payload, args.output)
    return 0


def _cmd_model_export(args: argparse.Namespace) -> int:
    """Export the model as a plugin; sibling of ``POST /api/semantic/model-export``."""
    from memdiver.app.tools_semantic import artifact_model_export_result

    return _run_plain(artifact_model_export_result, args, model_path=args.model,
                      out_path=args.out_path, plugin_name=args.plugin_name)


def _run_dir_capture(run_dir: str) -> dict:
    """One held-out capture from a run dir: its .msl paired with its keylog.csv."""
    root = Path(run_dir).expanduser()
    dumps = sorted((root / "dumps" / "msl").glob("*.msl"))
    if not dumps or not (root / "keylog.csv").is_file():
        raise ValueError(f"{run_dir}: needs dumps/msl/*.msl and keylog.csv")
    return {"dump_path": str(dumps[0]), "keylog_path": str(root / "keylog.csv")}


def _held_out_from_args(args: argparse.Namespace) -> list:
    held = list(_json_file(args.held_out_file) or [])
    held += [_run_dir_capture(d) for d in args.keylog_run_dir or []]
    held += [{"dump_path": str(p)} for p in getattr(args, "held_out_dumps", None) or []]
    return held


def _cmd_model_validate(args: argparse.Namespace) -> int:
    """Held-out scoring; sibling of ``POST /api/semantic/model-validate``."""
    from memdiver.app.tools_semantic import artifact_model_validate_result

    try:
        held_out = _held_out_from_args(args)
        keylog = keylog_spec_from_args(args)
    except (OSError, ValueError) as exc:
        print(f"memdiver: cannot read held-out inputs: {exc}", file=sys.stderr)
        return 1
    return _run_plain(artifact_model_validate_result, args, model_path=args.model,
                      held_out=held_out, labels=args.labels, plugin_path=args.plugin,
                      out_path=args.out_path, min_run=args.min_run, keylog=keylog)
