"""HTTP-layer tests for api.routers.dumps (prefix ``/api/dumps``).

The dumps router exposes ``POST /api/dumps/upload`` which streams a
multipart file to a temp path, enforces a 4 GiB size cap
(``DUMP_UPLOAD_MAX_BYTES``), then converts it via ``tools.import_dump``.

We redirect every settings-controlled directory into ``tmp_path`` (same
fixtures as tests/test_api_sessions.py) and monkeypatch
``import_dump`` for the happy path so the test doesn't depend on the
real MSL importer accepting garbage bytes.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from memdiver.api.config import get_settings
from memdiver.api.main import create_app
from memdiver.api.routers import dumps as dumps_router
from memdiver.mcp_server import tools


# ---------------------------------------------------------------------------
# Fixtures (copied verbatim from tests/test_api_sessions.py)
# ---------------------------------------------------------------------------


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
# POST /api/dumps/upload — happy path
# ---------------------------------------------------------------------------


def test_upload_dump_happy_path(client, monkeypatch):
    """A valid upload streams through to ``import_dump`` and returns
    its dict result. We patch ``import_dump`` where the router calls
    it (``mcp_server.tools.import_dump``) so the test does not depend
    on the real MSL importer parsing garbage bytes.
    """
    sentinel = {"source": "x", "output": "y", "regions_written": 3}

    def _fake_import(session, raw_path, output_path, pid=0):
        # The router should have written the uploaded bytes to a real temp
        # file before calling us.
        assert Path(raw_path).is_file()
        return sentinel

    monkeypatch.setattr(tools, "import_dump", _fake_import)

    r = client.post(
        "/api/dumps/upload",
        files={"file": ("t.dump", b"\x00\x01\x02\x03small", "application/octet-stream")},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body, dict)
    assert body == sentinel


# ---------------------------------------------------------------------------
# POST /api/dumps/upload — the blocking importer must be offloaded
# ---------------------------------------------------------------------------


def test_upload_dump_offloads_import_to_thread(client, monkeypatch):
    """Regression: ``tools.import_dump`` (up to 4 GiB parse/convert) is
    CPU/IO-heavy and synchronous, so the async handler must run it via
    ``asyncio.to_thread`` instead of blocking the event loop. We assert the
    router dispatches the importer through ``asyncio.to_thread`` while
    preserving the temp-file + result contract."""
    sentinel = {"source": "x", "output": "y", "regions_written": 1}

    def _fake_import(session, raw_path, output_path, pid=0):
        assert Path(raw_path).is_file()
        return sentinel

    monkeypatch.setattr(tools, "import_dump", _fake_import)

    calls: list[str] = []
    real_to_thread = dumps_router.asyncio.to_thread

    async def spy_to_thread(func, *args, **kwargs):
        calls.append(getattr(func, "__name__", repr(func)))
        return await real_to_thread(func, *args, **kwargs)

    monkeypatch.setattr(dumps_router.asyncio, "to_thread", spy_to_thread)

    r = client.post(
        "/api/dumps/upload",
        files={"file": ("t.dump", b"\x00\x01\x02\x03small", "application/octet-stream")},
    )
    assert r.status_code == 200, r.text
    assert r.json() == sentinel
    assert "_fake_import" in calls, "import_dump must be offloaded via asyncio.to_thread"


# ---------------------------------------------------------------------------
# POST /api/dumps/upload — missing file → 422
# ---------------------------------------------------------------------------


def test_upload_dump_missing_file_is_422(client):
    """``file`` is a required multipart field → 422 when absent."""
    r = client.post("/api/dumps/upload")
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# POST /api/dumps/upload — size cap → 413
# ---------------------------------------------------------------------------


def test_upload_dump_over_cap_is_413(client, monkeypatch):
    """An upload larger than the size cap is rejected with 413.

    We shrink the module-level ``DUMP_UPLOAD_MAX_BYTES`` constant so we
    don't have to stream 4 GiB.
    """
    monkeypatch.setattr(dumps_router, "DUMP_UPLOAD_MAX_BYTES", 1024)

    payload = b"a" * 2048  # > 1024-byte cap
    r = client.post(
        "/api/dumps/upload",
        files={"file": ("big.dump", payload, "application/octet-stream")},
    )
    assert r.status_code == 413
    assert "cap" in r.json()["detail"].lower()


# ---------------------------------------------------------------------------
# POST /api/dumps/upload — output_dir escaping settings.upload_dir → 400
# ---------------------------------------------------------------------------


def test_upload_dump_output_dir_outside_upload_dir_is_400(client):
    """An ``output_dir`` resolving outside ``settings.upload_dir`` is rejected
    with 400 (path containment), before any conversion runs."""
    r = client.post(
        "/api/dumps/upload",
        params={"output_dir": "/etc"},
        files={"file": ("t.dump", b"\x00\x01\x02\x03", "application/octet-stream")},
    )
    assert r.status_code == 400, r.text


def test_upload_dump_output_dir_traversal_is_400(client):
    """A traversal ``output_dir`` (``../`` escape) is rejected with 400."""
    r = client.post(
        "/api/dumps/upload",
        params={"output_dir": "../../../../tmp/evil_out"},
        files={"file": ("t.dump", b"\x00\x01\x02\x03", "application/octet-stream")},
    )
    assert r.status_code == 400, r.text


# ---------------------------------------------------------------------------
# Real (un-monkeypatched) imports.
#
# Every test above patches ``tools.import_dump``, which is exactly why the
# import path could delete its own output unnoticed: with the converter stubbed
# out, no real file is ever produced and the input/output collision is
# invisible. These tests run the REAL converter and assert on the file on disk.
# ---------------------------------------------------------------------------


def _write_msl(path: Path, *, regions: int = 3) -> bytes:
    """Write a real multi-region .msl container and return its bytes."""
    from memdiver.msl.writer import MslWriter

    w = MslWriter(path, pid=7)
    for i in range(regions):
        w.add_memory_region(0x1000 * (i + 1), bytes([0xA0 + i]) * 4096)
    w.add_end_of_capture()
    w.write()
    return path.read_bytes()


def test_upload_msl_output_survives_and_is_byte_identical(client, tmp_path):
    """Regression: uploading a file that is ALREADY .msl used to resolve its
    output to the very temp path it was uploaded to, so the ``finally`` that
    cleans up the upload deleted the converted result. The endpoint answered
    200 with a path that no longer existed, and every downstream analysis call
    then 500'd with FileNotFoundError.
    """
    src = tmp_path / "memslicer.msl"
    original = _write_msl(src, regions=3)

    resp = client.post(
        "/api/dumps/upload",
        files={"file": ("memslicer.msl", original, "application/octet-stream")},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    out = Path(body["output"])
    assert out.is_file(), f"import returned a path that does not exist: {out}"
    assert body["output"] != body["source"], "output must never be the temp upload"
    assert out.read_bytes() == original, "an already-MSL upload must be staged verbatim"
    # The re-wrap bug reported exactly 1 region (the whole container as one
    # opaque blob at VA 0); a passthrough reports the container's real count.
    assert body["regions_written"] == 3


def test_upload_raw_dump_output_survives(client):
    """The raw path stays a real conversion and its output also survives."""
    resp = client.post(
        "/api/dumps/upload",
        files={"file": ("t.dump", b"\xAA" * 8192, "application/octet-stream")},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    out = Path(body["output"])
    assert out.is_file()
    assert out.read_bytes()[:8] == b"MEMSLICE"
    assert body["regions_written"] == 1


def test_upload_lands_under_configured_upload_dir(client, isolated_env):
    """With an upload dir configured, imports land in <upload_dir>/imports."""
    resp = client.post(
        "/api/dumps/upload",
        files={"file": ("t.dump", b"\xAA" * 4096, "application/octet-stream")},
    )
    assert resp.status_code == 200, resp.text
    out = Path(resp.json()["output"]).resolve()
    expected = (isolated_env / "uploads" / "imports").resolve()
    assert out.parent == expected
    # Never the OS temp dir, which the OS purges out from under a live session.
    assert "pytest-of-" not in str(out) or str(out).startswith(str(isolated_env))


def test_upload_without_configured_upload_dir_is_not_409(tmp_path, monkeypatch):
    """An unconfigured server must still import — falling back to
    ``memdiver_home()/imports`` rather than answering 409 or, as before,
    writing into the OS temp directory."""
    monkeypatch.delenv("MEMDIVER_UPLOAD_DIR", raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    for sub, env in [("oracles", "MEMDIVER_ORACLE_DIR"),
                     ("tasks", "MEMDIVER_TASK_ROOT"),
                     ("sessions", "MEMDIVER_SESSION_DIR")]:
        d = tmp_path / sub
        d.mkdir()
        monkeypatch.setenv(env, str(d))
    get_settings.cache_clear()
    try:
        app = create_app()
        with TestClient(app) as c:
            resp = c.post(
                "/api/dumps/upload",
                files={"file": ("t.dump", b"\xAA" * 4096, "application/octet-stream")},
            )
        assert resp.status_code == 200, resp.text
        out = Path(resp.json()["output"]).resolve()
        assert out.is_file()
        assert out.parent == (tmp_path / "xdg" / "memdiver" / "imports").resolve()
    finally:
        get_settings.cache_clear()


def test_upload_names_output_after_the_uploaded_file(client):
    """The output stem comes from the dropped file, not the temp name, so the
    UI can label the pane ``memslicer-<hex>.msl`` instead of ``tmpvqb05sie.msl``."""
    resp = client.post(
        "/api/dumps/upload",
        files={"file": ("memslicer.dump", b"\xAA" * 4096, "application/octet-stream")},
    )
    assert resp.status_code == 200, resp.text
    name = Path(resp.json()["output"]).name
    assert name.startswith("memslicer-")
    assert name.endswith(".msl")


def test_upload_same_name_twice_does_not_clobber(client):
    """Two uploads of the same filename used to resolve to one output path."""
    outs = []
    for _ in range(2):
        resp = client.post(
            "/api/dumps/upload",
            files={"file": ("a.dump", b"\xAA" * 4096, "application/octet-stream")},
        )
        assert resp.status_code == 200, resp.text
        outs.append(Path(resp.json()["output"]))
    assert outs[0] != outs[1]
    assert all(o.is_file() for o in outs)


def test_upload_filename_traversal_cannot_escape_the_output_dir(client, isolated_env):
    """``file.filename`` is client-controlled and now helps build a path."""
    resp = client.post(
        "/api/dumps/upload",
        files={"file": ("../../evil.msl", b"\xAA" * 4096, "application/octet-stream")},
    )
    assert resp.status_code in (200, 400), resp.text
    if resp.status_code == 200:
        out = Path(resp.json()["output"]).resolve()
        assert out.parent == (isolated_env / "uploads" / "imports").resolve()
        assert ".." not in out.name


def test_upload_prunes_oldest_import_over_quota(client, isolated_env, monkeypatch):
    """The imports dir is bounded, like the pcaps dir."""
    from memdiver.api.config import get_settings as _get

    _get().dump_quota_bytes = 20 * 1024  # room for ~1 container
    outs = []
    for i in range(3):
        resp = client.post(
            "/api/dumps/upload",
            files={"file": (f"d{i}.dump", bytes([i]) * 8192, "application/octet-stream")},
        )
        assert resp.status_code == 200, resp.text
        outs.append(Path(resp.json()["output"]))
    imports_dir = (isolated_env / "uploads" / "imports")
    total = sum(p.stat().st_size for p in imports_dir.iterdir() if p.is_file())
    assert total <= 20 * 1024
    assert outs[-1].is_file(), "the just-imported container is never evicted"
