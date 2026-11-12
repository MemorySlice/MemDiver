"""docs/dev (maintainer notes, drafts, progress logs) must never ship in a wheel or sdist.

``docs/**/*.md`` is package data (the in-app documentation panel reads it) and
``MANIFEST.in`` includes ``docs *.md``, so without an explicit exclusion every build also
carries ``docs/dev``. A real build was checked once (114 -> 98 docs files in the wheel, 22 ->
0 ``docs/dev`` entries in the sdist); this is the fast guard that the rule stays in place.
"""

import tomllib
from fnmatch import fnmatch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _pyproject():
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["setuptools"]


def test_manifest_prunes_docs_dev():
    lines = [ln.strip() for ln in (ROOT / "MANIFEST.in").read_text().splitlines()]
    assert "prune docs/dev" in lines
    assert lines.index("prune docs/dev") > lines.index("recursive-include docs *.md"), (
        "the prune must come after the include, or the include re-adds the files")


def test_package_data_excludes_docs_dev():
    setuptools_table = _pyproject()
    patterns = setuptools_table["exclude-package-data"]["memdiver"]
    shipped = [p for p in setuptools_table["package-data"]["memdiver"] if p.startswith("docs/")]
    assert shipped, "docs are package data; this guard has nothing to exclude otherwise"
    for sample in ("docs/dev/contest_progress.md", "docs/dev/contest/icla_email_draft.md",
                   "docs/dev/semantic_workbench_p4_gate/notes.md"):
        assert any(fnmatch(sample, pattern) for pattern in patterns), sample


def test_exclusion_does_not_touch_the_user_docs():
    patterns = _pyproject()["exclude-package-data"]["memdiver"]
    for sample in ("docs/index.md", "docs/user_guide/vol3.md", "docs/oracle/examples/gocryptfs.toml"):
        assert not any(fnmatch(sample, pattern) for pattern in patterns), sample
