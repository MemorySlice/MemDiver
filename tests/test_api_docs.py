"""HTTP-layer tests for api.routers.docs (prefix ``/api/docs``).

The router serves the repo's bundled ``docs/*.md`` to the SPA's in-app
documentation panel. Two things are worth pinning here:

1. It really serves a REAL doc — the four SPA empty states that used to link
   at the dead ``/docs/...`` path now resolve through this endpoint, so the
   files they name must actually come back.
2. It cannot be walked out of the docs tree. Every rejection test below is
   written NON-VACUOUSLY: it asserts both the status code AND that the target
   file's real content is absent from the response, so a future refactor that
   started leaking bytes with a 400 attached would still fail.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from memdiver.api.config import get_settings
from memdiver.api.main import create_app
from memdiver.api.routers.docs import DOCS_ROOT, PUBLISHED_DOCS_URL, resolve_doc

# The three pages the SPA's repaired empty states link to.
LINKED_DOCS = [
    "visualizations/consensus.md",
    "visualizations/architect.md",
    "quickstart/experiment.md",
]


@pytest.fixture
def isolated_env(tmp_path: Path, monkeypatch):
    """Redirect every settings-controlled directory into tmp_path."""
    for sub, env in [
        ("oracles", "MEMDIVER_ORACLE_DIR"),
        ("tasks", "MEMDIVER_TASK_ROOT"),
        ("uploads", "MEMDIVER_UPLOAD_DIR"),
        ("sessions", "MEMDIVER_SESSION_DIR"),
    ]:
        d = tmp_path / sub
        d.mkdir()
        monkeypatch.setenv(env, str(d))
    monkeypatch.setenv("MEMDIVER_PIPELINE_MAX_WORKERS", "1")
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


@pytest.fixture
def client(isolated_env):
    app = create_app()
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# The docs root resolves to a real directory
# ---------------------------------------------------------------------------


def test_docs_root_points_at_the_repo_docs_tree():
    """Three ``.parent`` hops from ``api/routers/docs.py`` land on ``docs/``.

    Off-by-one here is invisible at import time and fatal at request time, so
    it gets its own assertion rather than being implied by the serving tests.
    """
    assert DOCS_ROOT.is_dir(), f"docs root does not exist: {DOCS_ROOT}"
    assert DOCS_ROOT.name == "docs"
    assert (DOCS_ROOT / "index.md").is_file()


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("doc_path", LINKED_DOCS)
def test_serves_a_real_doc(client, doc_path):
    """Each page the SPA links to comes back verbatim."""
    res = client.get(f"/api/docs/{doc_path}")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["path"] == doc_path
    assert body["content"] == (DOCS_ROOT / doc_path).read_text(encoding="utf-8")
    assert body["content"].startswith("#")


def test_serves_a_top_level_doc(client):
    """A page with no directory component works too (path param edge case)."""
    res = client.get("/api/docs/index.md")
    assert res.status_code == 200, res.text
    assert res.json()["content"] == (DOCS_ROOT / "index.md").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# 404 — and it must name the published fallback
# ---------------------------------------------------------------------------


def test_missing_doc_is_404_with_the_published_fallback_url(client):
    """``docs/`` can be absent from an install, so the 404 carries a real link."""
    res = client.get("/api/docs/visualizations/no_such_page.md")
    assert res.status_code == 404
    detail = res.json()["detail"]
    assert detail["path"] == "visualizations/no_such_page.md"
    assert detail["docs_url"].startswith(PUBLISHED_DOCS_URL)
    # The .md -> .html mapping the published site uses.
    assert detail["docs_url"].endswith("visualizations/no_such_page.html")


def test_missing_directory_is_404_not_500(client):
    res = client.get("/api/docs/no_such_dir/page.md")
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# Traversal — every one of these asserts the target's CONTENT never appears
# ---------------------------------------------------------------------------


def _repo_root() -> Path:
    return DOCS_ROOT.parent


def test_dotdot_traversal_is_rejected_and_leaks_nothing(client):
    """``../../pyproject.toml`` — the canonical walk-out attempt.

    Note the HTTP client collapses ``..`` segments before the request is even
    sent (``/api/docs/../../pyproject.toml`` leaves as ``/pyproject.toml``), so
    the status may be the router's 400 or the app's own 404 depending on where
    the normalisation lands. Either is a refusal; what this test actually pins
    is the non-vacuous half — pyproject's real content is nowhere in the
    response. :func:`test_resolve_doc_rejects_dotdot_before_the_filesystem`
    covers the guard itself, un-normalised.
    """
    res = client.get("/api/docs/../../pyproject.toml")
    assert res.status_code in (400, 404), res.text
    assert "[tool.setuptools]" not in res.text
    assert "[project]" not in res.text


def test_dotdot_traversal_to_a_md_file_is_rejected_and_leaks_nothing(client):
    """``../README.md`` passes the extension rule, so something else must hold.

    The extension check cannot save us here and README.md genuinely exists one
    level up, so a leak would be real. It must not come back.
    """
    readme = _repo_root() / "README.md"
    assert readme.is_file(), "fixture assumption: repo has a README.md"
    marker = readme.read_text(encoding="utf-8")[:200]

    res = client.get("/api/docs/../README.md")
    assert res.status_code in (400, 404), res.text
    assert marker not in res.text


@pytest.mark.parametrize(
    "doc_path",
    [
        "../README.md",
        "../../README.md",
        "visualizations/../../README.md",
        "./../README.md",
    ],
)
def test_resolve_doc_rejects_dotdot_before_the_filesystem(doc_path):
    """The guard itself, called with a path no HTTP client has normalised.

    This is the real traversal test: ``client.get()`` can never deliver a raw
    ``..`` to the route, so the only way to prove the rule holds is to call
    :func:`resolve_doc` directly. Non-vacuous because each path resolves to a
    file that genuinely exists outside ``docs/``.
    """
    with pytest.raises(HTTPException) as excinfo:
        resolve_doc(doc_path)
    assert excinfo.value.status_code == 400


def test_resolve_doc_accepts_a_real_doc():
    """Counterpart to the rejections: the guard is not refusing everything."""
    assert resolve_doc("visualizations/consensus.md") == (
        DOCS_ROOT / "visualizations" / "consensus.md"
    ).resolve()


def test_encoded_dotdot_traversal_is_rejected(client):
    """A percent-encoded ``..`` must not slip past the syntactic check."""
    readme = _repo_root() / "README.md"
    marker = readme.read_text(encoding="utf-8")[:200]

    res = client.get("/api/docs/%2E%2E/README.md")
    assert res.status_code in (400, 404), res.text
    assert marker not in res.text


def test_absolute_path_is_rejected_and_leaks_nothing(client):
    """An absolute path must never be honoured."""
    pyproject = _repo_root() / "pyproject.toml"
    assert pyproject.is_file()

    # The leading "/" of the absolute path collapses into the route's own
    # separator, so request the encoded form too -- both must be refused.
    for suffix in (str(pyproject), str(pyproject).lstrip("/")):
        res = client.get(f"/api/docs/{suffix}")
        assert res.status_code in (400, 404), (suffix, res.text)
        assert "[tool.setuptools]" not in res.text


def test_absolute_md_path_is_rejected(client):
    """Absolute + ``.md``: only the is_absolute() rule stands between us and it."""
    readme = _repo_root() / "README.md"
    marker = readme.read_text(encoding="utf-8")[:200]

    res = client.get(f"/api/docs/{readme}")
    assert res.status_code in (400, 404), res.text
    assert marker not in res.text


def test_non_md_extension_is_rejected_and_leaks_nothing(client):
    """A ``.py`` inside the docs tree is still refused — prose only."""
    conf = DOCS_ROOT / "conf.py"
    assert conf.is_file(), "fixture assumption: docs/conf.py exists"
    marker = conf.read_text(encoding="utf-8")[:120]

    res = client.get("/api/docs/conf.py")
    assert res.status_code == 400, res.text
    assert marker not in res.text
    assert "project =" not in res.text


def test_empty_path_is_rejected(client):
    res = client.get("/api/docs/")
    assert res.status_code == 400, res.text


# ---------------------------------------------------------------------------
# Symlink containment — the resolve() check, not the syntactic ones
# ---------------------------------------------------------------------------


def test_symlink_out_of_the_docs_tree_is_rejected(tmp_path, client, monkeypatch):
    """A ``.md`` symlink pointing outside the root is caught by resolve().

    Built against a throwaway root so the real ``docs/`` is never mutated.
    """
    from memdiver.api.routers import docs as docs_router

    secret = tmp_path / "secret.md"
    secret.write_text("TOP-SECRET-DOC-BODY", encoding="utf-8")
    fake_root = tmp_path / "docs"
    fake_root.mkdir()
    link = fake_root / "escape.md"
    try:
        link.symlink_to(secret)
    except (OSError, NotImplementedError):  # pragma: no cover - platform guard
        pytest.skip("symlinks unavailable on this platform")

    monkeypatch.setattr(docs_router, "DOCS_ROOT", fake_root)
    res = client.get("/api/docs/escape.md")
    assert res.status_code == 400, res.text
    assert "TOP-SECRET-DOC-BODY" not in res.text


# ---------------------------------------------------------------------------
# It must NOT have taken over FastAPI's /docs
# ---------------------------------------------------------------------------


def test_swagger_ui_still_owns_slash_docs(client):
    """Registering under /api must leave the OpenAPI UI untouched."""
    res = client.get("/docs")
    assert res.status_code == 200
    assert "swagger" in res.text.lower()
