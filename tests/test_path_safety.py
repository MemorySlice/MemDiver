"""Unit tests for api.path_safety containment helpers.

Covers ``safe_filename`` (bare-name-only) and ``ensure_within`` (nested-ok,
escape-rejected). These guard request handlers against ``..`` traversal,
absolute paths, and subdirectory addressing.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.api.path_safety import ensure_within, safe_filename


# ---------------------------------------------------------------------------
# safe_filename
# ---------------------------------------------------------------------------


def test_safe_filename_accepts_bare_name(tmp_path):
    """A bare name resolves to a direct child file of base."""
    result = safe_filename(tmp_path, "session", ".memdiver")
    assert result == (tmp_path.resolve() / "session.memdiver")
    assert result.parent == tmp_path.resolve()


@pytest.mark.parametrize(
    "bad_name",
    [
        "../evil",
        "sub/evil",
        "/etc/passwd",
    ],
)
def test_safe_filename_rejects_traversal_and_separators(tmp_path, bad_name):
    """Traversal, separators, and absolute paths raise ValueError."""
    with pytest.raises(ValueError):
        safe_filename(tmp_path, bad_name, ".memdiver")


def test_safe_filename_rejects_dotdot_bare(tmp_path):
    """A bare ``..`` name (no suffix) is traversal and is rejected.

    Note: with a suffix, ``".." + ".memdiver"`` resolves to the benign bare
    filename ``"...memdiver"`` — containment is by design about the *resolved*
    path, so the dotdot case is exercised here without a suffix.
    """
    with pytest.raises(ValueError):
        safe_filename(tmp_path, "..")


# ---------------------------------------------------------------------------
# ensure_within
# ---------------------------------------------------------------------------


def test_ensure_within_accepts_nested_path(tmp_path):
    """A path nested beneath base is accepted and returned resolved."""
    nested = tmp_path / "a" / "b" / "c.bin"
    result = ensure_within(tmp_path, nested)
    assert result == nested.resolve()


def test_ensure_within_accepts_base_itself(tmp_path):
    """Base itself is considered within base."""
    assert ensure_within(tmp_path, tmp_path) == tmp_path.resolve()


def test_ensure_within_rejects_parent_escape(tmp_path):
    """A parent of base escapes containment."""
    with pytest.raises(ValueError):
        ensure_within(tmp_path, tmp_path.parent)


def test_ensure_within_rejects_sibling_escape(tmp_path):
    """A sibling directory of base escapes containment."""
    sibling = tmp_path.parent / "sibling_dir" / "x.bin"
    with pytest.raises(ValueError):
        ensure_within(tmp_path, sibling)
