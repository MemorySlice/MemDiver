"""Tests for the configure-on-first-use upload directory (B0).

``upload_dir`` used to default to a hardcoded, world-writable
``/tmp/memdiver_uploads`` — the repo's only MEDIUM bandit finding (B108). It is
now unconfigured by default, which must fail **closed**: it is not merely where
uploads land, it is the containment root ``api.path_safety.ensure_within``
measures every write path against, so a permissive fallback would silently widen
those checks instead of failing.

These tests pin, in order:

* the ``GET``/``POST`` settings endpoints;
* that the three consumer routers fail closed (409) exactly where they need the
  directory and keep working where they do not;
* the validation matrix, one test per rule;
* the 0o700 posture and the legacy ``/tmp`` migration's anti-symlink rules;
* and ``test_config_has_no_hardcoded_tmp_path``, the durable B108 guard.

Two seams are monkeypatched throughout, both load-bearing:

``upload_dir_mod.legacy_dir``
    so tests never read, move, or delete the developer's real
    ``/tmp/memdiver_uploads``.
``upload_dir_mod._temp_roots``
    because pytest's ``tmp_path`` lives *inside* ``tempfile.gettempdir()``, and
    validation rule 3 rejects temp directories. Without this seam a happy-path
    test could not name a directory validation accepts. One test
    (:func:`test_reject_real_gettempdir`) deliberately does NOT patch it,
    so the real rule stays covered.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from memdiver.api import upload_dir as upload_dir_mod
from memdiver.api.config import get_settings
from memdiver.api.dependencies import UPLOAD_DIR_UNCONFIGURED
from memdiver.api.main import create_app
from memdiver.mcp_server import tools

ROOT = Path(__file__).resolve().parent.parent

SECRETS = [
    {
        "secret_type": "CLIENT_TRAFFIC_SECRET_0",
        "client_random": "ab" * 32,
        "secret": "cd" * 32,
    }
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def unconfigured_env(tmp_path: Path, monkeypatch):
    """A server with NO upload dir configured, fully isolated from the developer.

    ``XDG_DATA_HOME`` is redirected so ``core.constants.memdiver_home()`` — and
    therefore the prefs file this feature writes — lands in ``tmp_path`` and the
    real ``~/.memdiver/config.json`` is never touched.
    """
    monkeypatch.delenv("MEMDIVER_UPLOAD_DIR", raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    for sub, env in [
        ("oracles", "MEMDIVER_ORACLE_DIR"),
        ("tasks", "MEMDIVER_TASK_ROOT"),
        ("sessions", "MEMDIVER_SESSION_DIR"),
    ]:
        d = tmp_path / sub
        d.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv(env, str(d))
    monkeypatch.setenv("MEMDIVER_PIPELINE_MAX_WORKERS", "1")
    # Never touch the real legacy dir.
    monkeypatch.setattr(
        upload_dir_mod, "legacy_dir", lambda: tmp_path / "legacy_uploads"
    )
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


@pytest.fixture
def allow_tmp_path(monkeypatch):
    """Narrow the temp-root deny list so ``tmp_path`` is an acceptable choice."""
    monkeypatch.setattr(
        upload_dir_mod,
        "_temp_roots",
        lambda: (Path("/nonexistent-temp-root-for-tests"),),
    )


@pytest.fixture
def client(unconfigured_env):
    app = create_app()
    with TestClient(app) as c:
        yield c


def _post_dir(client, path, migrate=False):
    return client.post(
        "/api/settings/upload-dir",
        json={"path": str(path), "migrate_legacy": migrate},
    )


def _upload_pcap(client):
    return client.post(
        "/api/pcaps/upload",
        files={"file": ("c.pcap", b"\xd4\xc3\xb2\xa1body", "application/octet-stream")},
    )


# ---------------------------------------------------------------------------
# GET /api/settings/upload-dir
# ---------------------------------------------------------------------------


def test_get_upload_dir_unconfigured(client):
    """The unconfigured state is a 200 the UI renders, not an error."""
    r = client.get("/api/settings/upload-dir")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["configured"] is False
    assert body["path"] is None
    assert body["source"] is None
    assert body["env_pinned"] is False
    assert "quota_bytes" in body


def test_startup_does_not_create_any_upload_dir(client, unconfigured_env):
    """create_app()/lifespan must not materialise a directory any more.

    The deleted ``settings.upload_dir.mkdir()`` in api/main.py's lifespan is
    what used to create world-writable ``/tmp/memdiver_uploads`` on every app
    build, including every test collection.
    """
    assert get_settings().upload_dir is None
    assert not (unconfigured_env / "legacy_uploads").exists()


# ---------------------------------------------------------------------------
# Consumers fail closed — and only where they must
# ---------------------------------------------------------------------------


def test_pcap_upload_unconfigured_is_409(client, unconfigured_env):
    """The pcaps router ALWAYS needs the dir: 409 with the machine token."""
    r = _upload_pcap(client)
    assert r.status_code == 409, r.text
    detail = r.json()["detail"]
    assert isinstance(detail, str), "detail must be a plain string, not a dict"
    assert detail.startswith(UPLOAD_DIR_UNCONFIGURED + ":")
    # Nothing was written anywhere under the isolated tree.
    assert not list(unconfigured_env.rglob("*.pcap"))


def test_dump_upload_without_output_dir_still_works(client, monkeypatch):
    """The real frontend flow (no output_dir) must keep working unconfigured."""
    monkeypatch.setattr(
        tools, "import_dump", lambda session, raw, out, pid=0: {"ok": True}
    )
    r = client.post(
        "/api/dumps/upload",
        files={"file": ("t.dump", b"\x00\x01\x02\x03", "application/octet-stream")},
    )
    assert r.status_code == 200, r.text
    assert r.json() == {"ok": True}


def test_dump_upload_with_output_dir_is_409(client):
    """A caller-supplied ``output_dir`` needs the containment root -> 409."""
    r = client.post(
        "/api/dumps/upload",
        params={"output_dir": "sub"},
        files={"file": ("t.dump", b"\x00\x01\x02\x03", "application/octet-stream")},
    )
    assert r.status_code == 409, r.text
    assert r.json()["detail"].startswith(UPLOAD_DIR_UNCONFIGURED + ":")


def test_export_keylog_without_output_path_still_works(client):
    """No write -> no containment root needed -> 200."""
    r = client.post("/api/analysis/export-keylog", json={"secrets": SECRETS})
    assert r.status_code == 200, r.text
    assert r.json()["count"] == 1


def test_export_keylog_with_output_path_is_409(client, unconfigured_env):
    """The one write primitive needs the containment root -> 409, no file."""
    target = unconfigured_env / "out.keylog"
    r = client.post(
        "/api/analysis/export-keylog",
        json={"secrets": SECRETS, "output_path": str(target)},
    )
    assert r.status_code == 409, r.text
    assert r.json()["detail"].startswith(UPLOAD_DIR_UNCONFIGURED + ":")
    assert not target.exists()


# ---------------------------------------------------------------------------
# POST /api/settings/upload-dir — the happy path
# ---------------------------------------------------------------------------


def test_post_then_get_reports_user_config(client, unconfigured_env, allow_tmp_path):
    """A valid choice is accepted, persisted, and reported as user_config."""
    chosen = unconfigured_env / "MyUploads"

    r = _post_dir(client, chosen)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["configured"] is True
    assert body["path"] == str(chosen.resolve())
    assert body["source"] == "user_config"
    assert body["migrated"] == 0 and body["skipped"] == 0

    g = client.get("/api/settings/upload-dir").json()
    assert g["source"] == "user_config"
    assert g["path"] == str(chosen.resolve())


def test_upload_lands_under_chosen_dir(client, unconfigured_env, allow_tmp_path):
    """After configuring, the previously-409 upload succeeds in the new home."""
    chosen = unconfigured_env / "MyUploads"
    assert _post_dir(client, chosen).status_code == 200

    r = _upload_pcap(client)
    assert r.status_code == 200, r.text
    dest = Path(r.json()["pcap_path"])
    assert dest.parent == (chosen.resolve() / "pcaps")
    assert dest.is_file()


def test_chosen_dir_is_owner_only_0700(client, unconfigured_env, allow_tmp_path):
    """The dir holds captures and dumps; other local users must not read it."""
    chosen = unconfigured_env / "MyUploads"
    assert _post_dir(client, chosen).status_code == 200
    assert stat.S_IMODE(os.stat(chosen).st_mode) == 0o700


def test_settings_instance_is_mutated_not_rebuilt(
    client, unconfigured_env, allow_tmp_path
):
    """The cached Settings object must be updated IN PLACE.

    ``get_settings`` is ``lru_cache(maxsize=1)`` and the auth middleware plus
    the startup ArtifactStore hold this exact instance; a ``cache_clear()``
    would strand them on a stale object.
    """
    before = get_settings()
    chosen = unconfigured_env / "MyUploads"
    assert _post_dir(client, chosen).status_code == 200
    assert get_settings() is before
    assert before.upload_dir == chosen.resolve()


# ---------------------------------------------------------------------------
# Prefs-file persistence
# ---------------------------------------------------------------------------


def test_prefs_merge_preserves_existing_keys(
    client, unconfigured_env, allow_tmp_path
):
    """The prefs file is shared with the setup wizard; its keys must survive."""
    prefs_path = upload_dir_mod.user_config_path()
    prefs_path.write_text(json.dumps({"skip_duckdb_setup": True}))

    chosen = unconfigured_env / "MyUploads"
    assert _post_dir(client, chosen).status_code == 200

    prefs = json.loads(prefs_path.read_text())
    assert prefs["skip_duckdb_setup"] is True
    assert prefs["upload_dir"] == str(chosen.resolve())


def test_prefs_file_is_owner_only(client, unconfigured_env, allow_tmp_path):
    """The atomic temp file is chmod'd 0o600 before the rename."""
    chosen = unconfigured_env / "MyUploads"
    assert _post_dir(client, chosen).status_code == 200
    prefs_path = upload_dir_mod.user_config_path()
    assert stat.S_IMODE(os.stat(prefs_path).st_mode) == 0o600
    # No stray temp file left behind.
    assert not prefs_path.with_suffix(".json.tmp").exists()


def test_persisted_choice_is_picked_up_by_a_fresh_settings(
    client, unconfigured_env, allow_tmp_path
):
    """The whole point of persisting: the next process starts configured."""
    chosen = unconfigured_env / "MyUploads"
    assert _post_dir(client, chosen).status_code == 200
    get_settings.cache_clear()
    assert get_settings().upload_dir == chosen.resolve()


def test_corrupt_prefs_file_degrades_to_unconfigured(unconfigured_env):
    """A tolerant read: garbage prefs must not break every request."""
    upload_dir_mod.user_config_path().write_text("{not json")
    assert upload_dir_mod.read_user_upload_dir() is None
    get_settings.cache_clear()
    assert get_settings().upload_dir is None


# ---------------------------------------------------------------------------
# Environment pinning
# ---------------------------------------------------------------------------


def test_env_pinned_is_reported_and_post_is_409(unconfigured_env, monkeypatch):
    """MEMDIVER_UPLOAD_DIR always wins; writing a shadowed file is worse than 409."""
    pinned = unconfigured_env / "pinned"
    pinned.mkdir()
    monkeypatch.setenv("MEMDIVER_UPLOAD_DIR", str(pinned))
    get_settings.cache_clear()

    with TestClient(create_app()) as c:
        body = c.get("/api/settings/upload-dir").json()
        assert body["configured"] is True
        assert body["env_pinned"] is True
        assert body["source"] == "env"
        assert body["path"] == str(pinned)

        r = _post_dir(c, unconfigured_env / "other")
        assert r.status_code == 409, r.text
        assert "MEMDIVER_UPLOAD_DIR" in r.json()["detail"]
    # Nothing was persisted.
    assert upload_dir_mod.read_user_upload_dir() is None


def test_empty_env_var_is_treated_as_unconfigured(unconfigured_env, monkeypatch):
    """MEMDIVER_UPLOAD_DIR="" parses to Path(".") — the server CWD — not a dir."""
    monkeypatch.setenv("MEMDIVER_UPLOAD_DIR", "")
    get_settings.cache_clear()
    with TestClient(create_app()) as c:
        body = c.get("/api/settings/upload-dir").json()
    assert body["configured"] is False
    assert body["path"] is None
    assert get_settings().upload_dir is None


# ---------------------------------------------------------------------------
# Validation matrix — one test per rule, all 400
# ---------------------------------------------------------------------------


def _expect_400(client, path, needle):
    r = _post_dir(client, path)
    assert r.status_code == 400, r.text
    assert needle in r.json()["detail"].lower(), r.json()["detail"]


def test_reject_relative_path(client, allow_tmp_path):
    _expect_400(client, "relative/path", "absolute")


def test_reject_filesystem_root(client, allow_tmp_path):
    _expect_400(client, "/", "root")


def test_reject_system_dir_itself(client, allow_tmp_path):
    _expect_400(client, "/etc", "system directory")


def test_reject_inside_system_dir(client, allow_tmp_path):
    _expect_400(client, "/usr/lib/memdiver-uploads", "system directory")


def test_reject_real_gettempdir(client):
    """Rule 3 is the whole point of B0 — asserted WITHOUT the temp-root seam."""
    _expect_400(client, Path(tempfile.gettempdir()) / "x", "temporary directory")


def test_reject_slash_tmp(client):
    """A user-chosen /tmp path would be the same world-writable exposure."""
    _expect_400(client, "/tmp/x", "temporary directory")


def test_reject_inside_sys_prefix(client, allow_tmp_path):
    """A write into site-packages is a ``.pth`` import-hijack primitive."""
    _expect_400(client, Path(sys.prefix) / "memdiver-uploads", "python installation")


def test_reject_bare_home(client, allow_tmp_path):
    _expect_400(client, Path.home(), "subdirectory")


def test_reject_existing_non_directory(client, unconfigured_env, allow_tmp_path):
    f = unconfigured_env / "afile"
    f.write_text("x")
    _expect_400(client, f, "not a directory")


def test_reject_path_whose_parent_is_a_file(client, unconfigured_env, allow_tmp_path):
    parent = unconfigured_env / "parentfile"
    parent.write_text("x")
    _expect_400(client, parent / "sub", "cannot write")


def test_reject_unwritable_parent(client, unconfigured_env, allow_tmp_path):
    """Writability is PROVEN with a real temp file, never inferred from os.access."""
    locked = unconfigured_env / "locked"
    locked.mkdir(mode=0o500)
    try:
        _expect_400(client, locked / "uploads", "cannot write")
    finally:
        locked.chmod(0o700)


def test_reject_symlink_to_system_dir(client, unconfigured_env, allow_tmp_path):
    """resolve() (not absolute()) is why a link aimed at /etc is caught."""
    link = unconfigured_env / "sneaky"
    link.symlink_to("/etc", target_is_directory=True)
    _expect_400(client, link, "system directory")


# ---------------------------------------------------------------------------
# Legacy /tmp migration
# ---------------------------------------------------------------------------


def test_get_offers_legacy_migration_when_present(
    client, unconfigured_env, allow_tmp_path
):
    """``legacy`` appears only when there is something to move."""
    assert "legacy" not in client.get("/api/settings/upload-dir").json()

    legacy = unconfigured_env / "legacy_uploads"
    legacy.mkdir()
    (legacy / "a.pcap").write_bytes(b"abc")

    body = client.get("/api/settings/upload-dir").json()
    assert body["legacy"]["path"] == str(legacy)
    assert body["legacy"]["file_count"] == 1
    assert body["legacy"]["total_bytes"] == 3
    assert body["legacy"]["owned_by_us"] is True


def test_migration_moves_files_and_skips_symlinks(
    client, unconfigured_env, allow_tmp_path
):
    """/tmp is drwxrwxrwt: a planted symlink must never be relocated inward."""
    legacy = unconfigured_env / "legacy_uploads"
    legacy.mkdir()
    (legacy / "a.pcap").write_bytes(b"aaa")
    (legacy / "b.pcap").write_bytes(b"bbb")
    outside = unconfigured_env / "attacker-target"
    outside.write_text("secret")
    (legacy / "evil").symlink_to(outside)

    chosen = unconfigured_env / "MyUploads"
    r = _post_dir(client, chosen, migrate=True)
    assert r.status_code == 200, r.text
    assert r.json()["migrated"] == 2
    assert r.json()["skipped"] == 1

    resolved = chosen.resolve()
    assert (resolved / "a.pcap").read_bytes() == b"aaa"
    assert (resolved / "b.pcap").read_bytes() == b"bbb"
    assert not (resolved / "evil").exists()
    # The symlink and its target are untouched where they were.
    assert (legacy / "evil").is_symlink()
    assert outside.read_text() == "secret"
    # Not empty (the skipped symlink remains), so the dir is kept.
    assert legacy.is_dir()


def test_migration_removes_emptied_legacy_dir(client, unconfigured_env, allow_tmp_path):
    """With nothing skipped, the legacy directory itself goes away."""
    legacy = unconfigured_env / "legacy_uploads"
    legacy.mkdir()
    (legacy / "a.pcap").write_bytes(b"aaa")

    chosen = unconfigured_env / "MyUploads"
    assert _post_dir(client, chosen, migrate=True).json()["migrated"] == 1
    assert not legacy.exists()


def test_migration_skips_name_collisions(client, unconfigured_env, allow_tmp_path):
    """The user's own file is never clobbered by a legacy entry."""
    legacy = unconfigured_env / "legacy_uploads"
    legacy.mkdir()
    (legacy / "a.pcap").write_bytes(b"legacy")
    chosen = unconfigured_env / "MyUploads"
    chosen.mkdir()
    (chosen / "a.pcap").write_bytes(b"mine")

    r = _post_dir(client, chosen, migrate=True)
    assert r.json() == {**r.json(), "migrated": 0, "skipped": 1}
    assert (chosen / "a.pcap").read_bytes() == b"mine"


def test_migration_refuses_a_symlinked_legacy_dir(
    client, unconfigured_env, allow_tmp_path, monkeypatch
):
    """If the legacy dir is itself a link, migration is refused outright."""
    real = unconfigured_env / "planted"
    real.mkdir()
    (real / "a.pcap").write_bytes(b"aaa")
    link = unconfigured_env / "legacy_link"
    link.symlink_to(real, target_is_directory=True)
    monkeypatch.setattr(upload_dir_mod, "legacy_dir", lambda: link)

    assert upload_dir_mod.legacy_dir_report() is None
    chosen = unconfigured_env / "MyUploads"
    r = _post_dir(client, chosen, migrate=True)
    assert r.status_code == 200, r.text
    assert r.json()["migrated"] == 0
    assert (real / "a.pcap").is_file()


def test_migration_refuses_a_foreign_owned_legacy_dir(
    unconfigured_env, allow_tmp_path, monkeypatch
):
    """Not owned by us -> someone else controls the contents -> refuse."""
    legacy = unconfigured_env / "legacy_uploads"
    legacy.mkdir()
    (legacy / "a.pcap").write_bytes(b"aaa")

    # Pretend WE are a different user than the dir's owner — the same
    # asymmetry as an attacker having created /tmp/memdiver_uploads first.
    monkeypatch.setattr(os, "getuid", lambda: os.stat(legacy).st_uid + 1)
    assert upload_dir_mod.migrate_legacy(unconfigured_env / "dest") == (0, 0)
    assert (legacy / "a.pcap").is_file()


# ---------------------------------------------------------------------------
# The durable B108 guard
# ---------------------------------------------------------------------------


def test_config_has_no_hardcoded_tmp_path():
    """api/config.py must never regain a hardcoded temp-directory default.

    This is the durable form of the bandit B108 MEDIUM finding this change
    removed: a stale baseline entry never fails ``bandit -b``, so the guard
    lives here instead.
    """
    assert "/tmp" not in (ROOT / "api" / "config.py").read_text()
