"""Unit tests for the interactive region prompt (cli/region_prompt.py)."""

import io
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.cli.region_prompt import (  # noqa: E402
    MAX_ATTEMPTS, PromptAborted, RegionChoice, is_interactive, parse_choice,
    prompt_materialize, prompt_selection, resolve_region_choice, run_prompt,
)
from memdiver.cli.region_report import (  # noqa: E402
    CATEGORY_ORDER, category_table, preview_report, region_list,
    write_import_summary,
)
from memdiver.msl.import_preview import ImportPreview  # noqa: E402
from memdiver.msl.importer import ImportResult  # noqa: E402
from memdiver.msl.region_select import (  # noqa: E402
    RegionCategory as C, RegionInfo, RegionSelection, parse_selection,
)

DEFAULT = RegionSelection.default_interactive()


def _info(base, category, size=0x1000, module=None):
    return RegionInfo(base, size, 3, 0, category, module, size)


def _preview(is_msl=False):
    regions = [_info(0x1000, C.HEAP), _info(0x2000, C.HEAP),
               _info(0x3000, C.STACK),
               _info(0x4000, C.IMAGE_CODE, module="/usr/lib/libssl.so")]
    return ImportPreview(format="msl" if is_msl else "elf_core",
                         is_msl=is_msl, regions=regions)


def _answers(*values):
    """An injectable input function returning *values* in order."""
    it = iter(values)
    return lambda: next(it)


def _raising(exc):
    def _fn():
        raise exc
    return _fn


def _number(category):
    return str(CATEGORY_ORDER.index(category) + 1)


# -- parse_choice ------------------------------------------------------------


def test_parse_choice_empty_is_default():
    assert parse_choice("", DEFAULT) == DEFAULT
    assert parse_choice("   ", DEFAULT) == DEFAULT


def test_parse_choice_numbers():
    answer = f"{_number(C.HEAP)},{_number(C.SHARED)}"
    assert parse_choice(answer, DEFAULT).categories == {C.HEAP, C.SHARED}


def test_parse_choice_names_and_mix():
    sel = parse_choice(f"stack, {_number(C.HEAP)} ,image", DEFAULT)
    assert sel.categories == {C.STACK, C.HEAP, C.IMAGE_CODE, C.IMAGE_DATA}


def test_parse_choice_all_and_every_number_is_all():
    assert parse_choice("all", DEFAULT).is_all
    every = ",".join(str(i) for i in range(1, len(CATEGORY_ORDER) + 1))
    assert parse_choice(every, DEFAULT).is_all


@pytest.mark.parametrize("bad", ["0", str(len(CATEGORY_ORDER) + 1), "heapz",
                                 ",,"])
def test_parse_choice_invalid(bad):
    with pytest.raises(ValueError):
        parse_choice(bad, DEFAULT)


# -- tables ------------------------------------------------------------------


def test_category_table_marks_defaults_and_sizes():
    lines = category_table(_preview(), DEFAULT)
    assert len(lines) == len(CATEGORY_ORDER)
    heap = next(l for l in lines if " heap " in l)
    assert heap.lstrip().startswith("[x] 1)")
    assert "2 regions" in heap and "8.0 KB" in heap
    code = next(l for l in lines if "image_code" in l)
    assert code.lstrip().startswith("[ ]")


def test_region_list_keep_drop():
    lines = region_list(_preview(), parse_selection("heap"))
    assert sum(l.lstrip().startswith("keep") for l in lines) == 2
    assert any("drop" in l and "libssl" in l for l in lines)


def test_preview_report_msl_mentions_materialize():
    text = "\n".join(preview_report(_preview(is_msl=True), "x.msl"))
    assert "--materialize" in text
    assert "excludes 0 region(s)" in text


# -- prompts -----------------------------------------------------------------


def test_prompt_selection_enter_accepts_defaults():
    out = io.StringIO()
    assert prompt_selection(_preview(), _answers(""), out) == DEFAULT
    text = out.getvalue()
    assert "[x]" in text and "Enter" in text


def test_prompt_selection_retries_then_accepts():
    out = io.StringIO()
    sel = prompt_selection(_preview(), _answers("99", "heap"), out)
    assert sel.categories == {C.HEAP}
    assert "invalid choice" in out.getvalue()


def test_prompt_selection_gives_up():
    with pytest.raises(PromptAborted):
        prompt_selection(_preview(), _answers(*["bad"] * MAX_ATTEMPTS),
                         io.StringIO())


@pytest.mark.parametrize("exc", [EOFError, KeyboardInterrupt])
def test_prompt_cancel(exc):
    with pytest.raises(PromptAborted):
        prompt_selection(_preview(), _raising(exc()), io.StringIO())


@pytest.mark.parametrize("answer,expected", [("", False), ("n", False),
                                             ("YES", True), ("y", True)])
def test_prompt_materialize(answer, expected):
    out = io.StringIO()
    assert prompt_materialize(_answers(answer), out) is expected
    assert "verbatim" in out.getvalue()


def test_run_prompt_non_msl_never_asks_materialize():
    choice = run_prompt(_preview(), _answers(""), io.StringIO())
    assert choice == RegionChoice(DEFAULT, False)


def test_run_prompt_msl_asks_materialize():
    out = io.StringIO()
    choice = run_prompt(_preview(is_msl=True), _answers("", "y"), out)
    assert choice == RegionChoice(DEFAULT, True)
    assert "filtered copy" in out.getvalue().lower()


def test_run_prompt_msl_all_skips_materialize_question():
    choice = run_prompt(_preview(is_msl=True), _answers("all"), io.StringIO())
    assert choice.selection.is_all and choice.materialize is False


def test_run_prompt_msl_flag_skips_question():
    choice = run_prompt(_preview(is_msl=True), _answers(""), io.StringIO(),
                        materialize=True)
    assert choice.materialize is True


def test_run_prompt_announces_scope():
    out = io.StringIO()
    run_prompt(_preview(), _answers(""), out, applies_to="all 3 dump(s) in d")
    assert "applied to all 3 dump(s) in d" in out.getvalue()


# -- resolution order --------------------------------------------------------


def _never():
    raise AssertionError("must not prompt / preview")


def test_resolve_explicit_wins_over_prompt():
    choice = resolve_region_choice("heap,stack", None, False, False, _never,
                                   interactive=True, input_fn=_never)
    assert choice.selection == parse_selection("heap,stack")


def test_resolve_exclude_only():
    choice = resolve_region_choice(None, "image", True, False, _never,
                                   interactive=True, input_fn=_never)
    assert C.IMAGE_CODE not in choice.selection.categories
    assert C.HEAP in choice.selection.categories
    assert choice.materialize is True


@pytest.mark.parametrize("interactive,yes", [(False, False), (True, True)])
def test_resolve_non_interactive_or_yes_is_all(interactive, yes):
    choice = resolve_region_choice(None, None, False, yes, _never,
                                   interactive=interactive, input_fn=_never)
    assert choice == RegionChoice(None, False)


def test_resolve_interactive_prompts():
    choice = resolve_region_choice(None, None, False, False, _preview,
                                   interactive=True, input_fn=_answers("2"),
                                   out=io.StringIO())
    assert choice.selection.categories == {CATEGORY_ORDER[1]}


def test_resolve_interactive_without_preview_is_all():
    choice = resolve_region_choice(None, None, False, False, lambda: None,
                                   interactive=True, input_fn=_never)
    assert choice.selection is None


def test_resolve_bad_spec_raises():
    with pytest.raises(ValueError):
        resolve_region_choice("bogus", None, False, False, _never, False)


# -- misc --------------------------------------------------------------------


class _Tty(io.StringIO):
    def __init__(self, tty):
        super().__init__()
        self._tty = tty

    def isatty(self):
        return self._tty


@pytest.mark.parametrize("i,o,expected", [(True, True, True),
                                          (True, False, False),
                                          (False, True, False)])
def test_is_interactive(i, o, expected):
    assert is_interactive(_Tty(i), _Tty(o)) is expected


def test_write_import_summary_warns():
    result = ImportResult(Path("a"), Path("b.msl"), 3, 0, 10,
                          selection="regions=heap", excluded_region_count=2,
                          excluded_bytes=8192, secrets_only_in_excluded=1,
                          warnings=["1 keylog secret(s) found only in "
                                    "excluded regions"])
    out = io.StringIO()
    write_import_summary(result, out)
    text = out.getvalue()
    assert "excluded 2 region(s) (8.0 KB)" in text
    assert "WARNING" in text and "only in excluded regions" in text


def test_write_import_summary_silent_without_selection():
    out = io.StringIO()
    write_import_summary(ImportResult(Path("a"), Path("b"), 1, 0, 1), out)
    assert out.getvalue() == ""


# -- runtime category / platform line (W1b) ----------------------------------


def _android_preview():
    regions = [_info(0x1000, C.HEAP), _info(0x2000, C.RUNTIME)]
    return ImportPreview(format="msl", is_msl=True, regions=regions,
                         platform="android", platform_source="header")


def test_runtime_is_category_number_eight_and_not_preselected():
    assert _number(C.RUNTIME) == "8"
    assert parse_choice("8", DEFAULT).categories == {C.RUNTIME}
    runtime = next(l for l in category_table(_preview(), DEFAULT)
                   if " runtime " in l)
    assert runtime.lstrip().startswith("[ ] 8)")
    assert "zygote" in runtime and "[vdso]" in runtime


def test_preview_report_prints_platform_line():
    lines = preview_report(_android_preview(), "a.msl")
    assert "  platform: android (header)" in lines


def test_preview_report_omits_platform_line_when_unknown():
    assert not any("platform:" in l
                   for l in preview_report(_preview(), "x.core"))


def test_prompt_header_shows_platform():
    out = io.StringIO()
    prompt_selection(_android_preview(), _answers(""), out)
    assert out.getvalue().splitlines()[0] == "platform: android (header)"


def test_import_help_mentions_runtime_category():
    from memdiver.cli._shared import _region_selection_parent_parser
    help_text = " ".join(_region_selection_parent_parser().format_help().split())
    assert "runtime" in help_text
    assert "never preselected" in help_text
    assert "[vdso]/[vvar]" in help_text
