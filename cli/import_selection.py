"""Region-selection glue shared by ``memdiver import`` and ``import-dir``.

Turns the parsed region flags into a :class:`RegionChoice` (prompting when
allowed), implements the ``--list-regions`` dry run, and reports selection
outcomes on stderr. The JSON summary on stdout is built by the commands.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Callable, List, Optional, Sequence, TextIO

from memdiver.msl.import_preview import (LAYOUT_NONE, ImportPreview,
                                         preview_import)
from memdiver.msl.region_select import RegionSelection, parse_selection

from .region_prompt import (
    InputFn, PromptAborted, RegionChoice, is_interactive,
    resolve_region_choice,
)
from .region_report import preview_report, write_import_summary

logger = logging.getLogger("memdiver.cli")

#: Exit codes: a bad region spec is a usage error (argparse uses 2 too).
EXIT_BAD_SPEC = 2
EXIT_CANCELLED = 1


class SelectionError(Exception):
    """A region choice could not be made; carries the CLI exit code."""

    def __init__(self, message: str, exit_code: int) -> None:
        super().__init__(message)
        self.exit_code = exit_code


#: One-line note printed instead of the region prompt for a layout-less raw dump.
NO_LAYOUT_PROMPT_NOTE = ("memdiver: note — raw dump without a memory map, "
                         "so regions cannot be selected; importing it whole (pass --maps or add "
                         "a .maps sidecar to split it into regions)")


def safe_preview(path: Path, out: Optional[TextIO] = None,
                 key_material: Optional[dict] = None,
                 maps_path: Optional[Path] = None
                 ) -> Optional[ImportPreview]:
    """Preview *path*, or ``None`` (with a note) when it cannot be read.

    *key_material* opens an encrypted ``.msl`` so its regions are listed;
    *maps_path* splits a raw dump into regions (else a sidecar is detected).
    """
    out = out or sys.stderr
    try:
        return preview_import(path, key_material=key_material,
                              maps_path=maps_path)
    except (OSError, ValueError) as exc:
        print(f"memdiver: note — cannot preview regions of {path}: {exc}; "
              f"importing all regions", file=out)
        return None


def choice_from_args(args: argparse.Namespace,
                     load_preview: Callable[[], Optional[ImportPreview]],
                     applies_to: Optional[str] = None,
                     input_fn: Optional[InputFn] = None,
                     interactive: Optional[bool] = None,
                     out: Optional[TextIO] = None) -> RegionChoice:
    """Resolve the region choice for a command; raises :class:`SelectionError`.

    *input_fn* / *interactive* / *out* default to ``input`` / a TTY check /
    stderr, looked up at call time so tests can patch them.
    """
    if interactive is None:
        interactive = is_interactive()
    input_fn = input_fn or input
    out = out or sys.stderr
    try:
        return resolve_region_choice(
            args.regions, args.exclude_regions, args.materialize, args.yes,
            _skip_layoutless(load_preview, out), interactive, input_fn, out,
            applies_to)
    except ValueError as exc:
        raise SelectionError(f"memdiver: ERROR — {exc}", EXIT_BAD_SPEC) from None
    except PromptAborted as exc:
        raise SelectionError(f"memdiver: {exc}", EXIT_CANCELLED) from None


def _skip_layoutless(load_preview: Callable[[], Optional[ImportPreview]],
                     out: TextIO) -> Callable[[], Optional[ImportPreview]]:
    """*load_preview*, but a layout-less raw preview means "no prompt".

    Its only region is UNCLASSIFIED, so a category prompt could only offer a
    choice that silently falls back to importing everything.
    """
    def _load() -> Optional[ImportPreview]:
        preview = load_preview()
        if preview is not None and preview.layout == LAYOUT_NONE:
            print(NO_LAYOUT_PROMPT_NOTE, file=out)
            return None
        return preview
    return _load


def explicit_selection(args: argparse.Namespace) -> Optional[RegionSelection]:
    """The selection named by flags alone (no prompt); raises SelectionError."""
    try:
        return parse_selection(args.regions, args.exclude_regions)
    except ValueError as exc:
        raise SelectionError(f"memdiver: ERROR — {exc}", EXIT_BAD_SPEC) from None


def list_regions(args: argparse.Namespace, paths: Sequence[Path],
                 as_list: bool = False, out: Optional[TextIO] = None,
                 key_material: Optional[dict] = None,
                 maps_path: Optional[Path] = None) -> int:
    """``--list-regions``: print a preview per path and import nothing.

    ``--json`` prints one object (or, with *as_list*, an array of them).
    """
    out = out or sys.stdout
    try:
        selection = explicit_selection(args)
    except SelectionError as exc:
        print(str(exc), file=sys.stderr)
        return exc.exit_code
    previews = [(path, preview_import(path, key_material=key_material,
                                      maps_path=maps_path))
                for path in paths]
    if args.json:
        payload: List[dict] = [{"source": str(path), **p.to_dict(selection)}
                               for path, p in previews]
        print(json.dumps(payload if as_list else payload[0], indent=2),
              file=out)
        return 0
    for path, preview in previews:
        for line in preview_report(preview, str(path), selection,
                                   verbose=args.verbose):
            print(line, file=out)
    return 0


def report_results(results, out: Optional[TextIO] = None) -> None:
    """Human selection summary of each import on stderr."""
    out = out or sys.stderr
    for result in results:
        write_import_summary(result, out)
