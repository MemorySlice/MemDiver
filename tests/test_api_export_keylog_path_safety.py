"""Path-containment tests for ``POST /api/analysis/export-keylog``.

``output_path`` is the one *write* primitive on this API's path parameters.
Reads of operator-chosen paths (inspect / analysis / browse / verify-key, and
the pcap arm+run flow) are an accepted, documented risk on a localhost-bound
service — see ``api/main.py`` and handoff item O-15. A write is a different
class: ``app.tools_pipeline.keylog_result`` does ``Path(output_path).write_text``,
so an uncontained value could land on a shell rc file, ``~/.ssh/authorized_keys``,
or a ``.pth`` in site-packages — arbitrary code execution at next login.

These tests pin that the router resolves ``output_path`` inside ``upload_dir``
and rejects everything else, WITHOUT pushing the restriction down into the
producer, which the CLI and MCP surfaces share and which may legitimately write
wherever the operator's own shell can.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from memdiver.api.config import get_settings
from memdiver.api.main import create_app

# One well-formed TLS 1.3 client_random/secret pair; the values are irrelevant
# to containment but must parse so a rejection can only come from the path gate.
SECRETS = [
    {
        "secret_type": "CLIENT_TRAFFIC_SECRET_0",
        "client_random": "ab" * 32,
        "secret": "cd" * 32,
    }
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
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


@pytest.fixture
def client(isolated_env):
    app = create_app()
    with TestClient(app) as c:
        yield c


def _post(client, **body):
    return client.post("/api/analysis/export-keylog", json={"secrets": SECRETS, **body})


def test_output_path_inside_upload_dir_is_written(client, isolated_env):
    """The documented capability still works for a contained path."""
    dest = isolated_env / "uploads" / "session.keylog"

    r = _post(client, output_path=str(dest))
    assert r.status_code == 200, r.text
    assert dest.is_file()
    # What landed on disk is exactly what the caller was handed back.
    assert dest.read_text() == r.json()["keylog"]


def test_traversal_escape_is_rejected_and_writes_nothing(client, isolated_env):
    """``..`` traversal out of upload_dir must 400 and leave no file behind."""
    escape = isolated_env / "escape.log"

    r = _post(client, output_path="../escape.log")
    assert r.status_code == 400, r.text
    assert "escapes" in r.json()["detail"].lower()
    assert not escape.exists()


def test_absolute_path_outside_upload_dir_is_rejected(client, tmp_path):
    """An absolute path is the direct form of the attack; it must 400."""
    target = tmp_path / "pwned.log"

    r = _post(client, output_path=str(target))
    assert r.status_code == 400, r.text
    assert not target.exists()


def test_symlink_escape_is_rejected(client, isolated_env, tmp_path):
    """A symlink out of the tree must not be a bypass.

    ``ensure_within`` compares fully ``resolve()``-d paths precisely so a link
    planted inside upload_dir cannot redirect the write outside it.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    link = isolated_env / "uploads" / "link"
    link.symlink_to(outside, target_is_directory=True)

    r = _post(client, output_path=str(link / "x.log"))
    assert r.status_code == 400, r.text
    assert not (outside / "x.log").exists()


def test_omitted_output_path_still_returns_the_keylog(client):
    """The default (and only) path the UI uses must not regress.

    ``KeyVerificationPanel`` never sends ``output_path`` — it consumes the
    ``keylog`` string from the response body — so containment must be inert
    when the field is absent.
    """
    r = _post(client)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["keylog"]
    assert body["count"] == 1


def test_producer_itself_is_not_contained(tmp_path):
    """Containment must live at the HTTP boundary, not in the shared producer.

    The CLI ``export-keylog`` command and the MCP ``export_keylog`` tool route
    through the same ``keylog_result`` producer and legitimately write wherever
    the operator's shell can. Pushing ``ensure_within`` down into it would break
    both surfaces, so this pins the split.
    """
    from memdiver.app.tools_pipeline import keylog_result

    dest = tmp_path / "anywhere" / "out.keylog"
    dest.parent.mkdir()
    result = keylog_result(secrets=SECRETS, output_path=str(dest))
    assert dest.is_file()
    assert dest.read_text() == result["keylog"]
