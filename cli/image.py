"""Memory-image CLI: ``memdiver image {probe,profile,open,processes,extract}``.

Thin adapters over the ``image.*`` producers in :mod:`memdiver.app.tools_image`
(the same functions behind the REST routes and the MCP tools). Unlike REST, the
CLI runs the slow steps inline. Output is the producer payload as JSON (stdout,
or ``-o FILE``); a :class:`CapabilityError` propagates to the CLI backstop.
"""

import argparse
import sys
from typing import Callable, Dict, Optional

from ._shared import _write_output


def _common_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("-o", "--output", help="Write the JSON payload to this file")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def add_image_parser(sub) -> None:
    """Register the ``image <action>`` group on the top-level subparsers."""
    group = sub.add_parser(
        "image", help="Memory images: probe, profile, .mdview views, processes, extract")
    actions = group.add_subparsers(dest="image_action")
    probe = actions.add_parser("probe", parents=[_common_parser()],
                               help="Size, layer chain and profile status of an image")
    probe.add_argument("image", metavar="IMAGE", help="Memory image file")
    probe.add_argument("--banners", action="store_true",
                       help="Also scan the image for Linux banners (may read it all)")
    probe.add_argument("--isf", help="ISF file to report as the explicit profile")
    prof = actions.add_parser("profile", parents=[_common_parser()],
                              help="Resolve the kernel profile (may run pakunoda, ~15 s)")
    prof.add_argument("image", metavar="IMAGE")
    prof.add_argument("--isf", help="Use this ISF file")
    prof.add_argument("--no-pakunoda", action="store_true",
                      help="Do not extract an ISF with pakunoda")
    op = actions.add_parser("open", parents=[_common_parser()],
                            help="Write a .mdview descriptor for one view of an image")
    op.add_argument("image", metavar="IMAGE")
    op.add_argument("--view", required=True, choices=("physical", "kernel", "process"))
    op.add_argument("--pid", type=int, help="Process id (process view only)")
    op.add_argument("--isf", help="Use this ISF file instead of the cached profile")
    op.add_argument("--case", dest="case_dir",
                    help="Case directory or bare name; the view goes to <case>/views/")
    op.add_argument("--out", dest="out_path", help="Write the descriptor here")
    procs = actions.add_parser("processes", parents=[_common_parser()],
                               help="List the tasks of a kernel or process .mdview")
    procs.add_argument("view", metavar="VIEW", help=".mdview descriptor")
    procs.add_argument("--limit", type=int, default=100_000, help="Row cap")
    ext = actions.add_parser("extract", parents=[_common_parser()],
                             help="Extract a process .mdview into an .msl file")
    ext.add_argument("view", metavar="VIEW", help="process .mdview descriptor")
    ext.add_argument("--out", required=True, dest="out_path", help="Output .msl path")


def _emit(args: argparse.Namespace, payload: dict) -> int:
    _write_output(payload, args.output)
    return 0


def _cmd_image_probe(args: argparse.Namespace) -> int:
    from memdiver.app.tools_image import image_probe_result
    return _emit(args, image_probe_result(args.image, args.banners, args.isf).payload)


def _print_stage(stage: str, elapsed: float) -> None:
    """pakunoda stage line on stderr so stdout stays the JSON payload."""
    print(f"[{elapsed:7.1f}s] {stage}", file=sys.stderr, flush=True)


def _cmd_image_profile(args: argparse.Namespace) -> int:
    from memdiver.app.tools_image import image_profile_result
    return _emit(args, image_profile_result(
        args.image, args.isf, not args.no_pakunoda, progress=_print_stage).payload)


def _cmd_image_open(args: argparse.Namespace) -> int:
    from memdiver.app.tools_image import image_open_view_result
    return _emit(args, image_open_view_result(
        args.image, args.view, args.pid, args.isf, args.case_dir, args.out_path).payload)


def _cmd_image_processes(args: argparse.Namespace) -> int:
    from memdiver.app.tools_image import image_processes_result
    return _emit(args, image_processes_result(args.view, args.limit).payload)


def _cmd_image_extract(args: argparse.Namespace) -> int:
    from memdiver.app.tools_image import image_extract_process_result
    return _emit(args, image_extract_process_result(args.view, args.out_path).payload)


_IMAGE_HANDLERS: Dict[str, Callable[[argparse.Namespace], int]] = {
    "probe": _cmd_image_probe, "profile": _cmd_image_profile, "open": _cmd_image_open,
    "processes": _cmd_image_processes, "extract": _cmd_image_extract,
}


def _cmd_image(args: argparse.Namespace) -> int:
    """Dispatch an ``image <action>`` subcommand to its handler."""
    handler: Optional[Callable] = _IMAGE_HANDLERS.get(
        getattr(args, "image_action", None) or "")
    if handler is None:
        print("memdiver image: pick an action: " + ", ".join(_IMAGE_HANDLERS),
              file=sys.stderr)
        return 1
    return handler(args)
