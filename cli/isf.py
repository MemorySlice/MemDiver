"""ISF workbench CLI: ``memdiver isf {probe,draft ...,try}``.

Thin adapters over the ``isf.*`` producers in :mod:`memdiver.app.tools_isf` (the same
functions behind ``/api/isf`` and the MCP ``isf_*`` tools). Structured arguments are JSON
text: ``--params`` (probe), ``--args`` (a draft op), ``--only`` (``{section: [names]}``),
``--base-metadata``. Output is the producer payload as JSON (stdout, or ``-o FILE``); a
:class:`CapabilityError` propagates to the CLI backstop.
"""

import argparse
import json
import sys
from typing import Any, Callable, Dict, Optional

from ._shared import emit, output_parent_parser

DRAFT_ACTIONS = ("create", "list", "get", "set", "import", "retract", "versions", "diff",
                 "validate", "export")


def _json_arg(text: Optional[str], flag: str) -> Any:
    """Parse a JSON flag value; a malformed one is a usage error (exit 2)."""
    if text is None:
        return None
    try:
        return json.loads(text)
    except ValueError as exc:
        print(f"memdiver isf: {flag} is not valid JSON: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


def _draft_parser(name_arg: bool = True) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False, parents=[output_parent_parser()])
    p.add_argument("case_dir", metavar="CASE", help="Case directory")
    p.add_argument("capture_id", metavar="CAPTURE", help="Capture id (image sha256)")
    if name_arg:
        p.add_argument("name", metavar="DRAFT", help="Draft name")
    return p


def _add_probe_and_try(actions) -> None:
    probe = actions.add_parser("probe", parents=[output_parent_parser()],
                               help="Run one pakunoda probe on a full image")
    probe.add_argument("image", metavar="IMAGE")
    probe.add_argument("probe_name", metavar="PROBE", help="viability, banner, kallsyms, ...")
    probe.add_argument("--arch", default="auto")
    probe.add_argument("--params", help='JSON, e.g. \'{"limit": 50, "va_bits": 48}\'')
    probe.add_argument("--case", dest="case_dir", help="Case holding --draft (feed its hits)")
    probe.add_argument("--draft", help="Draft that receives the probe's findings")
    probe.add_argument("--author")
    run = actions.add_parser("try", parents=[output_parent_parser()],
                             help="Try a draft or an ISF file on the image with a vol3 plugin")
    run.add_argument("image", metavar="IMAGE")
    run.add_argument("--case", dest="case_dir")
    run.add_argument("--draft")
    run.add_argument("--version", help="Draft version (default: current)")
    run.add_argument("--isf", dest="isf_path", help="ISF file instead of a draft")
    run.add_argument("--plugin", default="linux.pslist")
    run.add_argument("--ground-truth", dest="ground_truth")
    run.add_argument("--timeout", type=float, default=120.0, dest="timeout_s")
    run.add_argument("--min-recall", type=float, default=0.95)
    run.add_argument("--min-precision", type=float, default=0.95)
    run.add_argument("--author", default="agent")


def _add_code_evidence(actions) -> None:
    ce = actions.add_parser("code-evidence", parents=[output_parent_parser()],
                            help="Struct fields a kernel function touches (code evidence)")
    ce.add_argument("image", metavar="IMAGE")
    ce.add_argument("function", metavar="FUNCTION", help="kallsyms name or 0x VA")
    ce.add_argument("--arch")
    ce.add_argument("--max-bytes", type=int, default=4096)
    ce.add_argument("--isf", help="ISF JSON to join `current` accesses against")
    ce.add_argument("--base", help="Keep one symbolic base, e.g. current")


def _add_provenance(p: argparse.ArgumentParser, source: str, tier: str) -> None:
    p.add_argument("--source", default=source)
    p.add_argument("--tier", default=tier)
    p.add_argument("--evidence", action="append", default=[], help="Repeatable")
    p.add_argument("--author", default="human")


def _add_draft_group(actions, limit_default: int) -> None:
    draft = actions.add_parser("draft", help="ISF drafts: " + ", ".join(DRAFT_ACTIONS))
    verbs = draft.add_subparsers(dest="draft_action")
    create = verbs.add_parser("create", parents=[_draft_parser()], help="Create a draft")
    create.add_argument("arch", metavar="ARCH")
    create.add_argument("--author", default="human")
    create.add_argument("--banner")
    create.add_argument("--base-metadata", help="JSON object")
    verbs.add_parser("list", parents=[_draft_parser(False)], help="List a capture's drafts")
    get = verbs.add_parser("get", parents=[_draft_parser()], help="Materialized summary")
    get.add_argument("--only", help='JSON {"symbols": ["init_task"], "user_types": []}')
    get.add_argument("--version")
    get.add_argument("--origins", action="store_true", dest="include_origins")
    get.add_argument("--limit", type=int, default=limit_default)
    get.add_argument("--search", help="Case-insensitive name substring filter")
    get.add_argument("--offset", type=int, default=0, help="Skip this many matches per section")
    st = verbs.add_parser("set", parents=[_draft_parser()], help="One draft operation")
    st.add_argument("op", metavar="OP", help="symbol|struct|field|base_type|enum|remove")
    st.add_argument("--args", dest="op_args", default="{}", help="JSON op arguments")
    _add_provenance(st, "manual", "manual")
    st.add_argument("--witnesses", type=int, default=1)
    imp = verbs.add_parser("import", parents=[_draft_parser()], help="Import an ISF file")
    imp.add_argument("isf_path", metavar="ISF")
    imp.add_argument("--only", help="JSON {section: [names]}")
    _add_provenance(imp, "isf_import", "imported")
    ret = verbs.add_parser("retract", parents=[_draft_parser()], help="Retract one entry")
    ret.add_argument("entry_id", metavar="ENTRY")
    ret.add_argument("--author", default="human")
    ret.add_argument("--reason", default="")
    ver = verbs.add_parser("versions", parents=[_draft_parser()], help="Version history")
    ver.add_argument("--limit", type=int, default=limit_default)
    diff = verbs.add_parser("diff", parents=[_draft_parser()], help="Draft vs a version/ISF")
    diff.add_argument("--against-version")
    diff.add_argument("--against-isf")
    diff.add_argument("--only", help="JSON {section: [names]}")
    diff.add_argument("--limit", type=int, default=limit_default)
    val = verbs.add_parser("validate", parents=[_draft_parser()], help="Validate + readiness")
    val.add_argument("--check-schema", action="store_true")
    val.add_argument("--limit", type=int, default=limit_default)
    exp = verbs.add_parser("export", parents=[_draft_parser()], help="Write the draft as ISF")
    exp.add_argument("--version")
    exp.add_argument("--out", dest="out_path")


def add_isf_parser(sub) -> None:
    """Register the ``isf <action>`` group on the top-level subparsers."""
    from memdiver.app.tools_isf import DEFAULT_LIMIT
    group = sub.add_parser("isf", help="ISF workbench: probe an image, edit drafts, try them")
    actions = group.add_subparsers(dest="isf_action")
    _add_probe_and_try(actions)
    _add_code_evidence(actions)
    _add_draft_group(actions, DEFAULT_LIMIT)


def _cmd_probe(args: argparse.Namespace) -> int:
    from memdiver.app.tools_isf import DEFAULT_AUTHOR, isf_probe_result
    return emit(args, isf_probe_result(
        args.image, args.probe_name, arch=args.arch, params=_json_arg(args.params, "--params"),
        case_dir=args.case_dir, draft=args.draft, author=args.author or DEFAULT_AUTHOR).payload)


def _cmd_try(args: argparse.Namespace) -> int:
    from memdiver.app.tools_isf import isf_try_result
    return emit(args, isf_try_result(
        args.image, case_dir=args.case_dir, draft=args.draft, version=args.version,
        isf_path=args.isf_path, plugin=args.plugin, ground_truth=args.ground_truth,
        timeout_s=args.timeout_s, min_recall=args.min_recall,
        min_precision=args.min_precision, author=args.author).payload)


def _cmd_code_evidence(args: argparse.Namespace) -> int:
    from memdiver.app.tools_code_evidence import code_evidence_result
    return emit(args, code_evidence_result(
        image_path=args.image, function=args.function, arch=args.arch,
        max_bytes=args.max_bytes, base=args.base,
        params={"isf": args.isf} if args.isf else None).payload)


def _draft_handlers() -> Dict[str, Callable[[argparse.Namespace], Any]]:
    from memdiver.app import tools_isf as t
    return {
        "create": lambda a: t.isf_draft_create_result(
            a.case_dir, a.capture_id, a.name, a.arch, author=a.author, banner=a.banner,
            base_metadata=_json_arg(a.base_metadata, "--base-metadata")),
        "list": lambda a: t.isf_draft_list_result(a.case_dir, a.capture_id),
        "get": lambda a: t.isf_draft_get_result(
            a.case_dir, a.capture_id, a.name, only=_json_arg(a.only, "--only"),
            version=a.version, include_origins=a.include_origins, limit=a.limit,
            search=a.search, offset=a.offset),
        "set": lambda a: t.isf_draft_set_result(
            a.case_dir, a.capture_id, a.name, a.op, _json_arg(a.op_args, "--args"),
            source=a.source, tier=a.tier, evidence=a.evidence, author=a.author,
            witnesses=a.witnesses),
        "import": lambda a: t.isf_draft_import_result(
            a.case_dir, a.capture_id, a.name, a.isf_path, only=_json_arg(a.only, "--only"),
            source=a.source, tier=a.tier, evidence=a.evidence, author=a.author),
        "retract": lambda a: t.isf_draft_retract_result(
            a.case_dir, a.capture_id, a.name, a.entry_id, author=a.author, reason=a.reason),
        "versions": lambda a: t.isf_draft_versions_result(
            a.case_dir, a.capture_id, a.name, limit=a.limit),
        "diff": lambda a: t.isf_draft_diff_result(
            a.case_dir, a.capture_id, a.name, against_version=a.against_version,
            against_isf=a.against_isf, only=_json_arg(a.only, "--only"), limit=a.limit),
        "validate": lambda a: t.isf_draft_validate_result(
            a.case_dir, a.capture_id, a.name, check_schema=a.check_schema, limit=a.limit),
        "export": lambda a: t.isf_draft_export_result(
            a.case_dir, a.capture_id, a.name, version=a.version, out_path=a.out_path),
    }


def _cmd_draft(args: argparse.Namespace) -> int:
    handler = _draft_handlers().get(getattr(args, "draft_action", None) or "")
    if handler is None:
        print("memdiver isf draft: pick an action: " + ", ".join(DRAFT_ACTIONS),
              file=sys.stderr)
        return 1
    return emit(args, handler(args).payload)


_ISF_HANDLERS: Dict[str, Callable[[argparse.Namespace], int]] = {
    "probe": _cmd_probe, "try": _cmd_try, "draft": _cmd_draft,
    "code-evidence": _cmd_code_evidence,
}


def _cmd_isf(args: argparse.Namespace) -> int:
    """Dispatch an ``isf <action>`` subcommand to its handler."""
    handler: Optional[Callable] = _ISF_HANDLERS.get(getattr(args, "isf_action", None) or "")
    if handler is None:
        print("memdiver isf: pick an action: " + ", ".join(_ISF_HANDLERS), file=sys.stderr)
        return 1
    return handler(args)
