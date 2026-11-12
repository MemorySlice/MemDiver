"""Format-oracle CLI: ``memdiver oracle {formats,suggest,spec}``.

Thin adapters over :mod:`memdiver.app.tools_format_oracle` (the same producers
behind ``/api/oracles/formats*`` and the MCP ``format_oracles`` /
``suggest_format_oracle`` / ``format_oracle_spec`` tools). Output is the
producer payload as JSON (stdout, or ``-o FILE``). ``spec`` prints the
``oracle_path`` + ``oracle_config`` pair a BYO-oracle run takes; ``--candidate``
grades key hex (a dry run) and exits 1 when none is proven, so a script can
gate on it. A :class:`CapabilityError` propagates to the CLI backstop.
"""

import argparse
import sys
from pathlib import Path
from typing import List

from ._shared import emit, output_parent_parser
from .vol3 import _json_object


def add_oracle_parser(sub) -> None:
    """Register the ``oracle <action>`` group on the top-level subparsers."""
    group = sub.add_parser(
        "oracle", help="Format oracles (gocryptfs, LUKS, ...) as a BYO-oracle source: "
                       "list, suggest for a dump, build a spec")
    actions = group.add_subparsers(dest="oracle_action")
    actions.add_parser("formats", parents=[output_parent_parser()],
                       help="List the shipped format oracles")
    sug = actions.add_parser("suggest", parents=[output_parent_parser()],
                             help="Which format oracle fits a dump, and why")
    sug.add_argument("dump_path")
    spec = actions.add_parser(
        "spec", parents=[output_parent_parser()],
        help="Build one format oracle and print its oracle_path + oracle_config")
    spec.add_argument("kind", help="Format kind (see `memdiver oracle formats`)")
    evidence = spec.add_mutually_exclusive_group()
    evidence.add_argument("--sample", dest="oracle_sample_path",
                          help="Sample blob, or the artefact it is packed from "
                               "(gocryptfs vault file/dir, raw LUKS header)")
    evidence.add_argument("--sample-base64", dest="sample_b64", help="The sample blob, base64")
    spec.add_argument("--params", type=_json_object, help="JSON oracle params")
    spec.add_argument("--candidate", action="append", default=[], dest="candidates_hex",
                      help="Key hex to grade (repeatable); exit 1 unless one is proven")
    spec.add_argument("--candidate-file", dest="candidate_file",
                      help="File with one key hex per line, also graded")


def _candidates(args: argparse.Namespace) -> List[str]:
    found = list(args.candidates_hex)
    if args.candidate_file:
        text = Path(args.candidate_file).expanduser().read_text(encoding="utf-8")
        found += [line.strip() for line in text.splitlines() if line.strip()]
    return found


def _cmd_oracle(args: argparse.Namespace) -> int:
    from memdiver.app import tools_format_oracle as fmt

    action = getattr(args, "oracle_action", None)
    if action == "formats":
        return emit(args, fmt.list_format_oracles_result().payload)
    if action == "suggest":
        return emit(args, fmt.suggest_format_oracle_result(args.dump_path).payload)
    if action == "spec":
        candidates = _candidates(args)
        payload = fmt.format_oracle_spec_result(
            args.kind, oracle_sample_path=args.oracle_sample_path,
            sample_b64=args.sample_b64, params=args.params,
            candidates_hex=candidates).payload
        emit(args, payload)
        return 0 if not candidates or payload["proven"] else 1
    print("memdiver oracle: pick an action: formats, suggest, spec", file=sys.stderr)
    return 1
