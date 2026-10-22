"""Tests for the marimo MSL import panel helpers (ui/controls/import_panel)."""

import json
from pathlib import Path

import pytest

from memdiver.msl.region_select import RegionCategory
from memdiver.ui.controls import import_panel as panel

_LOCALE = Path(__file__).resolve().parents[1] / "ui" / "locales" / "en.json"


def test_category_options_cover_every_category():
    assert sorted(panel.category_options().values()) == sorted(
        c.value for c in RegionCategory)


def test_default_labels_are_heap_stack_unclassified():
    opts = panel.category_options()
    assert sorted(opts[label] for label in panel.default_category_labels()) == [
        "heap", "stack", "unclassified"]


def test_selection_spec_subset_in_enum_order():
    assert panel.selection_spec(["unclassified", "heap"]) == "heap,unclassified"


def test_selection_spec_all_is_none():
    assert panel.selection_spec([c.value for c in RegionCategory]) is None


def test_selection_spec_empty_raises():
    with pytest.raises(ValueError):
        panel.selection_spec([])


def test_output_path_never_overwrites_msl_source():
    assert panel.output_path_for(Path("/x/a.dump")) == Path("/x/a.msl")
    assert panel.output_path_for(Path("/x/a.msl")) == Path("/x/a.filtered.msl")


def test_preview_rows_mark_included_categories():
    preview = {"totals": {"heap": {"count": 2, "bytes": 8192},
                          "image_code": {"count": 1, "bytes": 100}}}
    rows = panel.preview_rows(preview, ["heap"])
    assert [r["Category"] for r in rows] == ["Heap", "Image code"]
    assert [r["Included"] for r in rows] == ["Yes", "No"]
    assert rows[0]["Regions"] == 2 and rows[0]["Captured"] == "8.0 KiB"


def test_result_markdown_reports_exclusions_and_warnings():
    res = {"regions_written": 3, "key_hints_written": 1,
           "excluded_region_count": 4, "excluded_bytes": 10,
           "secrets_only_in_excluded": 0, "warnings": ["careful"]}
    text = panel.result_markdown(res, Path("a.dump"), Path("a.msl"))
    assert "Excluded regions: 4 (10 B)" in text
    assert "Warning: careful" in text
    assert "Secrets only" not in text


def test_result_markdown_plain_import_has_no_selection_lines():
    res = {"regions_written": 3, "key_hints_written": 0}
    text = panel.result_markdown(res, Path("a.dump"), Path("a.msl"))
    assert "Excluded" not in text and "Warning" not in text


def test_panel_strings_exist_in_english_locale():
    table = json.loads(_LOCALE.read_text(encoding="utf-8"))
    for key in panel._CATEGORY_LABEL_KEYS.values():
        assert key in table


# -- runtime category / Android notice (W1b) ----------------------------------

_ANDROID_PREVIEW = {"platform": "android", "platform_source": "header",
                    "runtime_count": 3, "runtime_bytes": 12288,
                    "notes": ["3 region(s) (12288 bytes) classified 'runtime' "
                              "by mapping name (...)", "other note"],
                    "totals": {"runtime": {"count": 3, "bytes": 12288}}}


def test_runtime_label_says_not_default():
    label = panel.category_label(RegionCategory.RUNTIME)
    assert "not default" in label
    assert label not in panel.default_category_labels()


def test_platform_markdown():
    assert panel.platform_markdown(_ANDROID_PREVIEW) == (
        "Platform: **android** (header)")
    assert panel.platform_markdown({"platform": None}) is None


def test_runtime_notice_android_not_selected():
    text = panel.runtime_notice(_ANDROID_PREVIEW, ["heap", "stack"])
    assert text.startswith("Android dump: 3 runtime region(s) (12.0 KiB)")
    assert "not selected by default" in text


def test_runtime_notice_selected_and_non_android():
    preview = dict(_ANDROID_PREVIEW, platform="linux")
    text = panel.runtime_notice(preview, ["heap", "runtime"])
    assert "[vdso]" in text and "included in this import" in text
    assert not text.startswith("Android")


def test_runtime_notice_absent_without_runtime_regions():
    assert panel.runtime_notice({"runtime_count": 0}, []) is None


class _FakeMo:
    """Records what render_preview builds (no marimo runtime needed)."""

    def __init__(self):
        self.md_calls, self.callouts = [], []
        self.ui = type("UI", (), {"table": staticmethod(
            lambda rows, **kw: ("table", rows))})()

    def md(self, text):
        self.md_calls.append(text)
        return ("md", text)

    def callout(self, body, kind):
        self.callouts.append((body, kind))
        return ("callout", body)

    def vstack(self, items):
        return items


def test_render_preview_shows_notice_once_and_platform():
    mo = _FakeMo()
    panel.render_preview(mo, dict(_ANDROID_PREVIEW, format="msl"), ["heap"],
                         materialize_cb=None)
    assert "Platform: **android** (header)" in mo.md_calls
    assert len(mo.callouts) == 1
    assert not any("classified 'runtime'" in t for t in mo.md_calls)
    assert "- other note" in mo.md_calls


def test_runtime_strings_exist_in_english_locale():
    table = json.loads(_LOCALE.read_text(encoding="utf-8"))
    for key in ("Platform: **{platform}** ({source})",
                "They are included in this import.",
                "They are not selected by default; add the Runtime category "
                "to import them."):
        assert key in table
    assert any(k.startswith("Android dump: {count} runtime") for k in table)
