"""Tests for the file browser's favourite directories and last-used directory.

The browse dialog opens on ``Path.home()`` every time, so getting back to a
working directory means walking the tree again on every visit. Favourites fix
that, and they are kept SERVER side precisely so they survive what the browser
cannot promise: a different ``--port`` (``localStorage`` is keyed by origin), a
cleared cache, or a second browser.

Pinned here, in order: the validation matrix, the upsert-by-path identity, the
"you can always delete a broken entry" rule, the last-dir resource, and the
HTTP surface for all of it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from memdiver.api import favourites as fav
from memdiver.api import user_prefs
from memdiver.api.config import get_settings
from memdiver.api.main import create_app


@pytest.fixture
def prefs_home(tmp_path: Path, monkeypatch) -> Path:
    """A server fully isolated from the developer's real MemDiver home.

    ``XDG_DATA_HOME`` is what moves ``memdiver_home()`` — and therefore the
    prefs file this feature writes. The other three redirects are not
    decoration: without them ``create_app()`` builds its oracle, task and
    session stores against the real home, which makes the HTTP tests below
    depend on (and write into) whatever the developer already has. Same shape
    as ``unconfigured_env`` in ``tests/test_api_upload_dir.py``.
    """
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    monkeypatch.delenv("MEMDIVER_UPLOAD_DIR", raising=False)
    for sub, env in [
        ("oracles", "MEMDIVER_ORACLE_DIR"),
        ("tasks", "MEMDIVER_TASK_ROOT"),
        ("sessions", "MEMDIVER_SESSION_DIR"),
    ]:
        d = tmp_path / sub
        d.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv(env, str(d))
    monkeypatch.setenv("MEMDIVER_PIPELINE_MAX_WORKERS", "1")
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


@pytest.fixture
def client(prefs_home):
    with TestClient(create_app()) as c:
        yield c


@pytest.fixture
def a_dir(tmp_path: Path) -> Path:
    d = tmp_path / "captures"
    d.mkdir()
    return d


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_accepts_an_existing_directory(prefs_home, a_dir):
    assert fav.validate_favourite(str(a_dir)) == a_dir.resolve()


def test_accepts_a_temp_directory(prefs_home, a_dir):
    """Weaker than the upload dir's rules ON PURPOSE.

    ``validate_candidate`` rejects every temp root because uploads WRITE there.
    A favourite is only ever read from and navigated to, so a directory under
    ``tmp_path`` — which is inside ``tempfile.gettempdir()`` — is a perfectly
    legitimate thing to save, and refusing it would be a bug.
    """
    assert fav.validate_favourite(str(a_dir)) == a_dir.resolve()


@pytest.mark.parametrize(
    "raw, reason",
    [
        ("", "no path given"),
        ("   ", "no path given"),
        ("relative/dir", "not an absolute path"),
    ],
)
def test_rejects_unusable_input(prefs_home, raw, reason):
    with pytest.raises(ValueError, match=reason):
        fav.validate_favourite(raw)


def test_rejects_a_missing_directory(prefs_home, tmp_path):
    with pytest.raises(ValueError, match="does not exist"):
        fav.validate_favourite(str(tmp_path / "gone"))


def test_rejects_a_file(prefs_home, tmp_path):
    f = tmp_path / "dump.msl"
    f.write_bytes(b"x")
    with pytest.raises(ValueError, match="is not a directory"):
        fav.validate_favourite(str(f))


def test_default_label_is_the_directory_name(prefs_home, a_dir):
    assert fav.default_label(a_dir) == "captures"
    assert fav.default_label(Path("/")) == "/"


# ---------------------------------------------------------------------------
# The stored list
# ---------------------------------------------------------------------------


def test_add_then_read(prefs_home, a_dir):
    fav.add_favourite(str(a_dir))

    stored = fav.read_favourites()
    assert [e["path"] for e in stored] == [str(a_dir.resolve())]
    assert stored[0]["label"] == "captures"
    assert stored[0]["added_at"] > 0


def test_add_uses_the_given_label(prefs_home, a_dir):
    fav.add_favourite(str(a_dir), "TLS corpus")

    assert fav.read_favourites()[0]["label"] == "TLS corpus"


def test_adding_the_same_path_twice_relabels_instead_of_duplicating(prefs_home, a_dir):
    """The path IS the identity — saving a directory twice means one entry."""
    fav.add_favourite(str(a_dir), "first")
    added_at = fav.read_favourites()[0]["added_at"]

    fav.add_favourite(str(a_dir), "second")

    stored = fav.read_favourites()
    assert len(stored) == 1
    assert stored[0]["label"] == "second"
    # Relabelling is not re-adding.
    assert stored[0]["added_at"] == added_at


def test_a_trailing_slash_is_the_same_directory(prefs_home, a_dir):
    fav.add_favourite(str(a_dir))
    fav.add_favourite(str(a_dir) + "/")

    assert len(fav.read_favourites()) == 1


def test_remove(prefs_home, a_dir):
    fav.add_favourite(str(a_dir))

    assert fav.remove_favourite(str(a_dir)) == []
    assert fav.read_favourites() == []


def test_a_deleted_directory_can_still_be_removed(prefs_home, tmp_path):
    """The worst version of this feature is an entry you cannot delete.

    ``validate_favourite`` refuses a path that no longer exists, which is
    exactly the entry a user most wants gone — so removal must not validate.
    """
    doomed = tmp_path / "ejected"
    doomed.mkdir()
    fav.add_favourite(str(doomed))
    doomed.rmdir()

    assert fav.remove_favourite(str(doomed)) == []


def test_removing_something_absent_is_a_no_op(prefs_home, a_dir):
    fav.add_favourite(str(a_dir))

    assert len(fav.remove_favourite("/not/saved")) == 1


def test_malformed_entries_are_dropped_not_raised(prefs_home, a_dir):
    """A hand-edited list must cost the user the bad line, not the whole list."""
    user_prefs.write_pref(
        fav.FAVOURITES_KEY,
        ["just a string", {"no": "path"}, {"path": str(a_dir), "label": "good"}, 42],
    )

    stored = fav.read_favourites()
    assert [e["label"] for e in stored] == ["good"]


def test_entry_missing_a_label_gets_the_directory_name(prefs_home, a_dir):
    user_prefs.write_pref(fav.FAVOURITES_KEY, [{"path": str(a_dir)}])

    assert fav.read_favourites()[0]["label"] == a_dir.name


def test_non_list_value_degrades_to_empty(prefs_home):
    user_prefs.write_pref(fav.FAVOURITES_KEY, {"not": "a list"})

    assert fav.read_favourites() == []


def test_the_list_is_capped(prefs_home, tmp_path, monkeypatch):
    """The prefs file is shared; a looping client may not grow it without end."""
    monkeypatch.setattr(fav, "MAX_FAVOURITES", 2)
    for name in ("a", "b"):
        d = tmp_path / name
        d.mkdir()
        fav.add_favourite(str(d))

    overflow = tmp_path / "c"
    overflow.mkdir()
    with pytest.raises(ValueError, match="cannot save more than 2"):
        fav.add_favourite(str(overflow))

    # ...but relabelling one already saved still works at the cap.
    fav.add_favourite(str(tmp_path / "a"), "renamed")
    assert len(fav.read_favourites()) == 2


def test_favourites_coexist_with_the_other_settings_in_the_file(prefs_home, a_dir):
    """The one that matters: three features, one file, no losses."""
    from memdiver.api import upload_dir as upload_dir_mod

    user_prefs.write_pref("skip_duckdb_setup", True)
    upload_dir_mod.write_user_upload_dir(a_dir)

    fav.add_favourite(str(a_dir), "corpus")
    fav.write_last_dir(str(a_dir))

    stored = json.loads(user_prefs.user_config_path().read_text())
    assert stored["skip_duckdb_setup"] is True
    assert stored["upload_dir"] == str(a_dir)
    assert stored["favourite_dirs"][0]["label"] == "corpus"
    assert stored["last_browsed_dir"] == str(a_dir.resolve())


# ---------------------------------------------------------------------------
# Last browsed directory
# ---------------------------------------------------------------------------


def test_last_dir_round_trips(prefs_home, a_dir):
    fav.write_last_dir(str(a_dir))

    assert fav.read_last_dir() == str(a_dir.resolve())


def test_last_dir_is_unset_by_default(prefs_home):
    assert fav.read_last_dir() is None


def test_last_dir_rejects_a_non_directory(prefs_home, tmp_path):
    with pytest.raises(ValueError):
        fav.write_last_dir(str(tmp_path / "nope"))


# ---------------------------------------------------------------------------
# HTTP surface
# ---------------------------------------------------------------------------


def test_get_favourites_is_empty_not_an_error(client):
    r = client.get("/api/settings/favourites")

    assert r.status_code == 200, r.text
    assert r.json() == {"favourites": []}


def test_post_returns_the_whole_list(client, a_dir):
    r = client.post("/api/settings/favourites", json={"path": str(a_dir)})

    assert r.status_code == 200, r.text
    favs = r.json()["favourites"]
    assert len(favs) == 1
    assert favs[0]["path"] == str(a_dir.resolve())
    assert favs[0]["label"] == "captures"


def test_post_accepts_a_label(client, a_dir):
    r = client.post(
        "/api/settings/favourites", json={"path": str(a_dir), "label": "TLS corpus"}
    )

    assert r.json()["favourites"][0]["label"] == "TLS corpus"


def test_post_rejects_a_bad_path_with_a_reason(client, tmp_path):
    r = client.post("/api/settings/favourites", json={"path": str(tmp_path / "gone")})

    assert r.status_code == 400, r.text
    assert "does not exist" in r.json()["detail"]


def test_delete_returns_the_whole_list(client, a_dir):
    client.post("/api/settings/favourites", json={"path": str(a_dir)})

    r = client.request(
        "DELETE", "/api/settings/favourites", params={"path": str(a_dir)}
    )

    assert r.status_code == 200, r.text
    assert r.json() == {"favourites": []}


def test_last_dir_endpoints(client, a_dir):
    assert client.get("/api/settings/last-dir").json() == {"path": None}

    r = client.put("/api/settings/last-dir", json={"path": str(a_dir)})
    assert r.status_code == 200, r.text
    assert r.json() == {"path": str(a_dir.resolve())}

    assert client.get("/api/settings/last-dir").json() == {"path": str(a_dir.resolve())}


def test_last_dir_put_rejects_a_bad_path(client, tmp_path):
    r = client.put("/api/settings/last-dir", json={"path": str(tmp_path / "gone")})

    assert r.status_code == 400, r.text


def test_favourites_survive_a_server_restart(prefs_home, a_dir):
    """The reason this is server-side at all: a new app, same list.

    Deliberately does NOT take the ``client`` fixture. Two ``TestClient``
    lifespans open at once deadlock on anyio's blocking portal thread at
    teardown, so the two servers are opened one after the other — which is also
    the more faithful model of a restart.
    """
    with TestClient(create_app()) as first:
        first.post("/api/settings/favourites", json={"path": str(a_dir)})

    with TestClient(create_app()) as second:
        favs = second.get("/api/settings/favourites").json()["favourites"]

    assert [e["path"] for e in favs] == [str(a_dir.resolve())]
