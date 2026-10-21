"""Regression tests for the two bare-path routes the SPA catch-all used to eat.

Both routes exist because ``api/main.py`` mounts the React bundle at ``"/"``.
That mount matches *every* path, so anything not claimed by an earlier route
resolves to "a file in ``frontend/dist``" and 404s when no such file exists.

The notebook case is the subtle one. Starlette compiles a ``Mount`` path as
``path + "/{path:path}"`` (``starlette/routing.py``), so ``Mount("/notebook")``
matches ``/notebook/...`` but *never* the bare ``/notebook``. Router-level
``redirect_slashes`` does not rescue it either: that fallback only runs when no
route matched at all, and the ``"/"`` catch-all always matches. The result was a
404 on the one URL the "Open Notebook" button actually linked to.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from memdiver.api.frontend_build import frontend_dist_path
from memdiver.api.main import create_app


marimo = pytest.importorskip("marimo", reason="Marimo is an optional extra")


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


def test_bare_notebook_path_redirects_to_the_mount(client: TestClient) -> None:
    """``/notebook`` must reach the notebook, not the bundle's 404."""
    response = client.get("/notebook", follow_redirects=False)

    assert response.status_code in (307, 308)
    assert response.headers["location"] == "/notebook/"


def test_notebook_mount_serves_the_notebook(client: TestClient) -> None:
    """The redirect target is real -- guards against redirecting into a 404."""
    assert client.get("/notebook/", follow_redirects=False).status_code == 200


def test_notebook_redirect_is_only_registered_when_the_mount_exists(
    client: TestClient,
) -> None:
    """The redirect and the mount are advertised together, never separately.

    ``/api/notebook/status`` is what the toolbar button renders itself on, so a
    ``True`` here with a broken ``/notebook`` is exactly the reported bug.
    """
    assert client.get("/api/notebook/status").json()["available"] is True


@pytest.mark.skipif(
    not (frontend_dist_path() / "favicon.svg").is_file(),
    reason="frontend bundle not built (run `npm run build` in frontend/)",
)
def test_favicon_is_served_rather_than_404ing(client: TestClient) -> None:
    """Browsers request /favicon.ico for any page that declares no icon."""
    response = client.get("/favicon.ico")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/svg+xml")


def test_broken_marimo_install_is_not_reported_as_missing(monkeypatch) -> None:
    """An ImportError raised *inside* marimo is a broken install, not an absent one.

    CI once resolved an old marimo whose server imported a ``websockets`` name
    the installed websockets lacked; the blanket ``except ImportError`` turned
    that into "Marimo not installed" and hid the real error.
    """

    def _broken_create_asgi_app(**_kwargs):
        raise ImportError(
            "cannot import name 'ClientConnection' from 'websockets'",
            name="websockets",
        )

    monkeypatch.setattr(marimo, "create_asgi_app", _broken_create_asgi_app)
    status = TestClient(create_app()).get("/api/notebook/status").json()

    assert status["available"] is False
    assert "ClientConnection" in status["error"]
