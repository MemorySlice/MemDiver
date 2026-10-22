"""Interactive region-selection prompt for ``memdiver import`` / ``import-dir``.

Only used when both stdin and stdout are TTYs and no region flag was given.
Everything the prompt prints goes to *out* (stderr by default) so stdout
keeps carrying only the JSON summary. *input_fn* is injectable for tests.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Callable, FrozenSet, Optional, TextIO

from memdiver.msl.import_preview import ImportPreview
from memdiver.msl.region_select import (
    ALL_CATEGORIES, RegionCategory, RegionSelection, parse_selection,
)

from .region_report import (
    CATEGORY_ORDER, category_table, platform_line, selection_totals_line,
)

InputFn = Callable[[], str]

MAX_ATTEMPTS = 3

_SELECTION_HELP = ("Enter numbers (e.g. 1,2,7), category names "
                   "(e.g. heap,stack), 'all', or press Enter for the "
                   "[x] defaults.")

_MATERIALIZE_EXPLANATION = (
    "This input is already a .msl container. By default it is copied\n"
    "verbatim and the region selection is only applied at analysis time\n"
    "(nothing is removed from the file). Opt-in: write a FILTERED copy\n"
    "instead, which drops the excluded regions and any key hints inside\n"
    "them (same as --materialize).")


class PromptAborted(Exception):
    """The user cancelled (EOF / Ctrl-C) or gave too many invalid answers."""


@dataclass(frozen=True)
class RegionChoice:
    """Resolved region selection for an import (``None`` = everything)."""

    selection: Optional[RegionSelection]
    materialize: bool = False


def is_interactive(stdin: Optional[TextIO] = None,
                   stdout: Optional[TextIO] = None) -> bool:
    """True when both streams are terminals (prompting is allowed)."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    try:
        return bool(stdin.isatty() and stdout.isatty())
    except (AttributeError, ValueError):  # closed / replaced stream
        return False


def _category_by_number(token: str) -> FrozenSet[RegionCategory]:
    index = int(token)
    if not 1 <= index <= len(CATEGORY_ORDER):
        raise ValueError(f"no category number {index} "
                         f"(valid: 1-{len(CATEGORY_ORDER)})")
    return frozenset({CATEGORY_ORDER[index - 1]})


def parse_choice(answer: str, default: RegionSelection) -> RegionSelection:
    """Turn a prompt answer into a selection; raises ``ValueError``.

    Accepts an empty answer (= *default*), ``all``, numbers from the table,
    category names / aliases, or any comma-separated mix of them.
    """
    answer = answer.strip()
    if not answer:
        return default
    categories: FrozenSet[RegionCategory] = frozenset()
    for token in (t.strip() for t in answer.split(",") if t.strip()):
        if token.isdigit():
            categories |= _category_by_number(token)
        else:
            categories |= parse_selection(token).categories
    if not categories:
        raise ValueError("no category selected")
    if categories == ALL_CATEGORIES:
        return RegionSelection.all()
    return RegionSelection(categories)


def _ask(question: str, input_fn: InputFn, out: TextIO) -> str:
    out.write(question)
    out.flush()
    try:
        return input_fn()
    except (EOFError, KeyboardInterrupt):
        out.write("\n")
        raise PromptAborted("import cancelled") from None


def prompt_selection(preview: ImportPreview, input_fn: InputFn,
                     out: TextIO,
                     default: Optional[RegionSelection] = None
                     ) -> RegionSelection:
    """Show the category table and read a selection (re-asks on errors)."""
    default = default or RegionSelection.default_interactive()
    platform = platform_line(preview)
    if platform:
        print(platform, file=out)
    print("Region categories in this dump ([x] = preselected):", file=out)
    for line in category_table(preview, default):
        print(line, file=out)
    print(_SELECTION_HELP, file=out)
    for _ in range(MAX_ATTEMPTS):
        answer = _ask("Regions to import [Enter = defaults]: ", input_fn, out)
        try:
            return parse_choice(answer, default)
        except ValueError as exc:
            print(f"  invalid choice: {exc}", file=out)
    raise PromptAborted(f"no valid region choice after {MAX_ATTEMPTS} attempts")


def prompt_materialize(input_fn: InputFn, out: TextIO) -> bool:
    """Ask the y/N materialize question for ``.msl`` input."""
    print(_MATERIALIZE_EXPLANATION, file=out)
    for _ in range(MAX_ATTEMPTS):
        answer = _ask("Write a filtered copy? [y/N]: ",
                      input_fn, out).strip().lower()
        if answer in ("", "n", "no"):
            return False
        if answer in ("y", "yes"):
            return True
        print("  please answer y or n", file=out)
    raise PromptAborted(f"no valid y/N answer after {MAX_ATTEMPTS} attempts")


def run_prompt(preview: ImportPreview, input_fn: InputFn = input,
               out: Optional[TextIO] = None, materialize: bool = False,
               applies_to: Optional[str] = None) -> RegionChoice:
    """The full interactive flow: category choice, then (``.msl``) materialize.

    *materialize* already True (``--materialize``) skips the y/N question.
    *applies_to* (e.g. ``"all 4 dumps in run1/"``) is announced up front.
    """
    out = out or sys.stderr
    if applies_to:
        print(f"The selection below will be applied to {applies_to}.",
              file=out)
    selection = prompt_selection(preview, input_fn, out)
    print("  " + selection_totals_line(preview, selection), file=out)
    if preview.is_msl and not selection.is_all and not materialize:
        materialize = prompt_materialize(input_fn, out)
    return RegionChoice(selection, materialize)


def resolve_region_choice(regions: Optional[str],
                          exclude_regions: Optional[str],
                          materialize: bool, assume_yes: bool,
                          load_preview: Callable[[], Optional[ImportPreview]],
                          interactive: bool, input_fn: InputFn = input,
                          out: Optional[TextIO] = None,
                          applies_to: Optional[str] = None) -> RegionChoice:
    """Decide the selection from flags, falling back to the prompt.

    Order: explicit ``--regions`` / ``--exclude-regions`` win; otherwise
    ``--yes`` or a non-interactive session imports everything (the
    backward-compatible default); otherwise the user is prompted.
    *load_preview* returning ``None`` (nothing to preview) also means
    "everything". Raises ``ValueError`` on a bad spec, ``PromptAborted``
    when the user cancels.
    """
    explicit = parse_selection(regions, exclude_regions)
    if explicit is not None:
        return RegionChoice(explicit, materialize)
    if assume_yes or not interactive:
        return RegionChoice(None, materialize)
    preview = load_preview()
    if preview is None:
        return RegionChoice(None, materialize)
    return run_prompt(preview, input_fn, out, materialize, applies_to)
