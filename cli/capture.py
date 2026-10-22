"""``memdiver capture`` -- one dump of an existing process (pid or name).

Thin presenter over :func:`memdiver.app.experiment_orchestration.capture_result`
(the producer shared with REST ``POST /api/experiment/capture`` and the MCP
``capture_dump`` tool). Every region the backend could not capture is printed
to stderr; the full report (with the ``skipped`` list) goes to ``--output``.
"""

import argparse
import sys

from memdiver.core.service_errors import CapabilityError

from ._shared import _write_output, print_cli_error


def add_capture_parser(sub) -> None:
    """Register the ``capture`` subcommand on the top-level subparsers."""
    cp = sub.add_parser(
        "capture",
        help="Capture one dump of a running process (local, USB/Android or "
             "remote) with memslicer, lldb or fridump")
    cp.add_argument("target", help="Process ID, or process / Android package name")
    cp.add_argument("dump_path", help="Output dump path (.msl for memslicer, "
                                      ".bin/.dump for lldb and fridump)")
    cp.add_argument("--tool", default="memslicer",
                    choices=["memslicer", "lldb", "fridump"],
                    help="Dump backend (default: memslicer)")
    cp.add_argument("--device", default="local",
                    help="Where the target runs: local (default), usb, "
                         "usb:<frida-device-id> (e.g. usb:emulator-5554) or "
                         "remote:<host>[:<port>]")
    cp.add_argument("--max-region-size", type=int, default=None, metavar="BYTES",
                    help="Skip (and report) regions of at least this many bytes "
                         "(default: no cap)")
    cp.add_argument("--include-large-readonly", action="store_true",
                    help="lldb: also capture non-writable regions of 100 MiB or "
                         "more (the multi-GB macOS shared cache; default: "
                         "skipped and reported)")
    cp.add_argument("--timeout", type=float, default=None, metavar="SECONDS",
                    help="Backend timeout (default: memslicer/fridump 300 s, "
                         "lldb 600 s)")
    cp.add_argument("-o", "--output", help="Write the JSON capture report here "
                                           "(default: stdout)")
    cp.add_argument("-v", "--verbose", action="store_true")


def _cmd_capture(args: argparse.Namespace) -> int:
    """Run one capture; exit 0 captured / 1 failed or invalid input."""
    from memdiver.app.experiment_orchestration import capture_result

    try:
        report = capture_result(
            target=args.target, output=args.dump_path, tool=args.tool,
            device=args.device, max_region_size=args.max_region_size,
            include_large_readonly=args.include_large_readonly,
            timeout=args.timeout)
    except CapabilityError as exc:
        print_cli_error(exc)
        return 1
    for line in report.get("summary_warnings") or []:
        print(f"memdiver capture: WARNING — {line}", file=sys.stderr)
    if not report["ok"]:
        print(f"memdiver: ERROR — capture failed: {report.get('error')}",
              file=sys.stderr)
    _write_output(report, args.output)
    return 0 if report["ok"] else 1
