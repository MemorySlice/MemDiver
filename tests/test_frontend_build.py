"""Tests for the "your web UI is older than your source" startup warning.

``memdiver web`` serves a PREBUILT bundle. A stale one has no symptom: the same
URL answers, nothing errors, and the change is simply absent — which reads as a
broken feature rather than a missing build. These tests pin the warning that
replaces that silence, and just as importantly pin the cases where it must stay
quiet, because a warning that cries wolf on every packaged install would be
turned off and then miss the real thing.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from memdiver.api import frontend_build


@pytest.fixture
def tree(tmp_path: Path, monkeypatch) -> Path:
    """Relocate the package root so ``frontend/`` is a tree we control."""
    monkeypatch.delenv(frontend_build.DIST_ENV_VAR, raising=False)
    monkeypatch.setattr(frontend_build, "_package_root", lambda: tmp_path)
    return tmp_path


def write(path: Path, mtime: float, content: str = "x") -> Path:
    """Create *path* with an exact mtime, so "newer" is never a race."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    os.utime(path, (mtime, mtime))
    return path


# Far enough apart that no filesystem timestamp granularity can blur them.
OLD = 1_700_000_000.0
NEW = 1_700_086_400.0


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------


def test_dist_defaults_beside_the_package(tree):
    assert frontend_build.frontend_dist_path() == tree / "frontend" / "dist"
    assert frontend_build.frontend_src_path() == tree / "frontend" / "src"


def test_dist_honours_the_env_override(tree, monkeypatch):
    monkeypatch.setenv(frontend_build.DIST_ENV_VAR, "/opt/memdiver-ui")

    assert frontend_build.frontend_dist_path() == Path("/opt/memdiver-ui")


# ---------------------------------------------------------------------------
# newest_file
# ---------------------------------------------------------------------------


def test_newest_file_returns_none_for_a_missing_directory(tree):
    assert frontend_build.newest_file(tree / "nope") is None


def test_newest_file_returns_none_for_an_empty_directory(tree):
    (tree / "empty").mkdir()

    assert frontend_build.newest_file(tree / "empty") is None


def test_newest_file_finds_the_latest_nested_file(tree):
    write(tree / "src" / "a.ts", OLD)
    newest = write(tree / "src" / "deep" / "b.ts", NEW)
    write(tree / "src" / "c.ts", OLD)

    found = frontend_build.newest_file(tree / "src")

    assert found is not None
    assert found[0] == newest
    assert found[1] == pytest.approx(NEW)


def test_newest_file_skips_an_entry_it_cannot_stat(tree):
    """A dangling symlink says nothing about whether the build is current."""
    src = tree / "src"
    src.mkdir()
    (src / "dangling").symlink_to(tree / "does-not-exist")
    real = write(src / "real.ts", OLD)

    found = frontend_build.newest_file(src)

    assert found is not None
    assert found[0] == real


# ---------------------------------------------------------------------------
# The warning itself
# ---------------------------------------------------------------------------


def test_silent_when_the_build_is_current(tree):
    write(tree / "frontend" / "src" / "App.tsx", OLD)
    write(tree / "frontend" / "dist" / "index.html", NEW)

    assert frontend_build.frontend_build_warning() is None


def test_silent_when_the_timestamps_match(tree):
    """Equal is not stale — a build triggered by the very edit it contains."""
    write(tree / "frontend" / "src" / "App.tsx", OLD)
    write(tree / "frontend" / "dist" / "index.html", OLD)

    assert frontend_build.frontend_build_warning() is None


def test_silent_in_a_packaged_install_with_no_source_tree(tree):
    """Nothing to rebuild from, so nothing actionable to say."""
    write(tree / "frontend" / "dist" / "index.html", OLD)

    assert frontend_build.frontend_build_warning() is None


def test_silent_when_the_bundle_was_relocated(tree, monkeypatch):
    """An operator who set the override knows where their build comes from.

    This repo's ``frontend/src`` is then not what produced the served bundle,
    so comparing the two would be noise.
    """
    write(tree / "frontend" / "src" / "App.tsx", NEW)
    write(tree / "frontend" / "dist" / "index.html", OLD)
    monkeypatch.setenv(frontend_build.DIST_ENV_VAR, str(tree / "elsewhere"))

    assert frontend_build.frontend_build_warning() is None


def test_warns_when_the_source_is_newer(tree):
    changed = write(tree / "frontend" / "src" / "components" / "Wizard.tsx", NEW)
    write(tree / "frontend" / "dist" / "index.html", OLD)

    warning = frontend_build.frontend_build_warning()

    assert warning is not None
    assert "OLDER" in warning
    # Names the file that triggered it, relative to the package root, so the
    # reader can tell a real edit from a `git checkout` touching everything.
    assert "frontend/src/components/Wizard.tsx" in warning
    # Both sides of the comparison are shown, not just the verdict.
    assert "2023-11-15" in warning or "2023-11-14" in warning


def test_the_warning_says_exactly_what_to_do(tree):
    write(tree / "frontend" / "src" / "App.tsx", NEW)
    write(tree / "frontend" / "dist" / "index.html", OLD)

    warning = frontend_build.frontend_build_warning() or ""

    assert frontend_build.BUILD_COMMAND in warning
    # The second half of the fix: a rebuild alone can still look like nothing
    # happened, because the browser holds index.html and with it the old
    # bundle's content-hashed name.
    assert "hard refresh" in warning
    assert "index.html" in warning


def test_warns_when_there_is_no_build_at_all(tree):
    write(tree / "frontend" / "src" / "App.tsx", NEW)

    warning = frontend_build.frontend_build_warning()

    assert warning is not None
    assert "no built web UI" in warning
    assert frontend_build.BUILD_COMMAND in warning
    # A missing build is not a stale build; do not tell the user to hard-refresh
    # a page that was never served.
    assert "hard refresh" not in warning


def test_silent_when_the_build_directory_is_empty(tree):
    """An empty dist is not something to compare mtimes against."""
    write(tree / "frontend" / "src" / "App.tsx", NEW)
    (tree / "frontend" / "dist").mkdir(parents=True)

    assert frontend_build.frontend_build_warning() is None


# ---------------------------------------------------------------------------
# The command that prints it
# ---------------------------------------------------------------------------


def test_web_command_prints_the_warning_before_serving(tree, monkeypatch, capsys):
    """The guidance has to reach the operator, not a log level set up later."""
    write(tree / "frontend" / "src" / "App.tsx", NEW)
    write(tree / "frontend" / "dist" / "index.html", OLD)

    import argparse

    from memdiver.cli import dataset as cli_dataset

    started: dict = {}

    def fake_run(app, **kwargs):
        started["ran"] = True

    monkeypatch.setattr("uvicorn.run", fake_run)
    monkeypatch.setattr("memdiver.api.main.create_app", lambda: object())

    rc = cli_dataset._cmd_web(argparse.Namespace(port=8080))

    assert rc == 0
    assert started.get("ran") is True
    err = capsys.readouterr().err
    assert "OLDER" in err
    assert frontend_build.BUILD_COMMAND in err
