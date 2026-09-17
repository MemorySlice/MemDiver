"""Tests for api.services.oracle_registry + api.routers.oracles.

Covers Phase 25 B5: upload, arm-by-sha256, dry-run, delete, 503 when
MEMDIVER_ORACLE_DIR is unset, and the pycache-poisoning mitigation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
from contextlib import contextmanager
from pathlib import Path

import pytest

from memdiver.api.services.oracle_registry import (
    OracleConfigInvalid,
    OracleDisabled,
    OracleNotFound,
    OracleRegistry,
    OracleRegistryError,
    OracleShaMismatch,
    _describe_config_keys,
    _find_unexpanded_placeholder,
    reset_oracle_registry,
)


# A Shape-1 oracle that only passes on a specific sentinel.
ORACLE_SHAPE1 = """\
SENTINEL = bytes(range(16))

def verify(candidate):
    return candidate == SENTINEL
"""


# A Shape-2 oracle that exposes a class + build_oracle factory.
ORACLE_SHAPE2 = """\
class MyOracle:
    def __init__(self, cfg):
        self.tag = cfg.get("tag", b"magic!") if isinstance(cfg, dict) else b"magic!"
        if isinstance(self.tag, str):
            self.tag = self.tag.encode()
    def verify(self, candidate):
        return candidate == self.tag

def build_oracle(cfg):
    return MyOracle(cfg)
"""


@pytest.fixture
def examples_dir():
    return Path(__file__).parent.parent / "docs" / "oracle" / "examples"


@pytest.fixture
def registry(tmp_path, examples_dir):
    reg = OracleRegistry(oracle_dir=tmp_path / "oracles", examples_dir=examples_dir)
    yield reg
    reset_oracle_registry()


@pytest.fixture
def disabled_registry(tmp_path, examples_dir):
    reg = OracleRegistry(oracle_dir=None, examples_dir=examples_dir)
    yield reg
    reset_oracle_registry()


# ---------- examples enumeration ----------


def test_list_examples_returns_bundled_oracles(registry, examples_dir):
    examples = registry.list_examples()
    names = {e["filename"] for e in examples}
    # All three example oracles from the Phase 25 deliverables.
    assert {"gocryptfs.py", "generic_aes_gcm.py", "tls13_stub.py"} <= names
    for ex in examples:
        assert ex["shape"] in (1, 2)
        assert len(ex["sha256"]) == 64


def test_list_examples_works_when_disabled(disabled_registry):
    # examples don't require an oracle_dir to be configured
    examples = disabled_registry.list_examples()
    assert len(examples) >= 3


# ---------- upload / shape detection ----------


def test_upload_shape1(registry):
    entry = registry.upload(filename="my.py", content=ORACLE_SHAPE1.encode())
    assert entry.shape == 1
    assert entry.sha256 == hashlib.sha256(ORACLE_SHAPE1.encode()).hexdigest()
    assert entry.armed is False
    # On-disk file is locked down to 0o600.
    mode = entry.path.stat().st_mode & 0o777
    assert mode == 0o600
    # head_lines preserved
    assert any("verify" in ln for ln in entry.head_lines)


def test_upload_shape2(registry):
    entry = registry.upload(filename="stateful.py", content=ORACLE_SHAPE2.encode())
    assert entry.shape == 2


def test_upload_disabled_raises(disabled_registry):
    with pytest.raises(OracleDisabled):
        disabled_registry.upload(filename="x.py", content=ORACLE_SHAPE1.encode())


def test_upload_broken_oracle_rejected(registry):
    with pytest.raises(OracleRegistryError):
        registry.upload(filename="broken.py", content=b"this is not python(((")


def test_upload_rejects_sandbox_failure(registry, monkeypatch):
    """A hanging/OOMing oracle rejected by the load-time sandbox surfaces as an
    OracleRegistryError (→ 4xx), not a 500. We patch the sandbox validator (the
    real subprocess behaviour is covered in test_oracle) to raise before
    _detect_shape imports the untrusted module in-process."""
    import memdiver.api.services.oracle_registry as reg_mod
    from memdiver.engine.oracle import OracleLoadError

    def _reject(path, config=None, **kw):
        raise OracleLoadError("oracle load exceeded 10.0s wall-clock (possible hang)")

    monkeypatch.setattr(reg_mod, "validate_oracle_sandboxed", _reject)
    with pytest.raises(OracleRegistryError, match="failed to load"):
        registry.upload(filename="hang.py", content=ORACLE_SHAPE1.encode())


def test_upload_sandbox_runs_before_shape_detection(registry, monkeypatch):
    """The sandbox validation must run BEFORE _detect_shape imports the module
    in-process, so a hang is caught before any untrusted in-process import."""
    import memdiver.api.services.oracle_registry as reg_mod

    order = []

    real_detect = reg_mod._detect_shape

    def _spy_validate(path, config=None, **kw):
        order.append("validate")

    def _spy_detect(path):
        order.append("detect")
        return real_detect(path)

    monkeypatch.setattr(reg_mod, "validate_oracle_sandboxed", _spy_validate)
    monkeypatch.setattr(reg_mod, "_detect_shape", _spy_detect)
    registry.upload(filename="s.py", content=ORACLE_SHAPE1.encode())
    assert order == ["validate", "detect"]


def test_upload_purges_pycache(registry, tmp_path):
    # Upload, create a rogue __pycache__ next to it, then re-detect
    # shape via list_entries; the pycache should not cause a load.
    entry = registry.upload(filename="s1.py", content=ORACLE_SHAPE1.encode())
    cache_dir = entry.path.parent / "__pycache__"
    cache_dir.mkdir(exist_ok=True)
    (cache_dir / "poisoned.cpython-314.pyc").write_bytes(b"\x00" * 32)
    # arm re-hashes and purges the cache; this should still succeed.
    armed = registry.arm(entry.oracle_id, entry.sha256)
    assert armed.armed is True
    assert not cache_dir.exists()


# ---------- arm sha256 echo ----------


def test_arm_rejects_mismatched_sha(registry):
    entry = registry.upload(filename="s.py", content=ORACLE_SHAPE1.encode())
    bogus = "0" * 64
    with pytest.raises(OracleShaMismatch):
        registry.arm(entry.oracle_id, bogus)
    assert registry.get(entry.oracle_id).armed is False


def test_arm_accepts_matching_sha(registry):
    entry = registry.upload(filename="s.py", content=ORACLE_SHAPE1.encode())
    armed = registry.arm(entry.oracle_id, entry.sha256)
    assert armed.armed is True
    # Subsequent require_armed() returns without raising.
    registry.require_armed(entry.oracle_id)


def test_arm_detects_on_disk_tamper(registry):
    entry = registry.upload(filename="s.py", content=ORACLE_SHAPE1.encode())
    # Swap the file contents after upload.
    entry.path.write_bytes(b"verify = lambda c: True\n")
    with pytest.raises(OracleShaMismatch):
        registry.arm(entry.oracle_id, entry.sha256)


# ---------- dry run ----------


def test_dry_run_shape1(registry):
    entry = registry.upload(filename="s1.py", content=ORACLE_SHAPE1.encode())
    sentinel = bytes(range(16))
    samples = [sentinel, b"nope-nope-nope!!", sentinel, b"\x00" * 16]
    report = registry.dry_run(entry.oracle_id, samples=samples)
    assert report["samples"] == 4
    assert report["passes"] == 2
    assert report["fails"] == 2
    assert report["errors"] == 0
    assert all("duration_us" in r for r in report["results"])


def test_dry_run_shape2(registry):
    entry = registry.upload(filename="s2.py", content=ORACLE_SHAPE2.encode())
    samples = [b"magic!", b"bogus!"]
    report = registry.dry_run(entry.oracle_id, samples=samples)
    assert report["passes"] == 1
    assert report["fails"] == 1


def test_dry_run_does_not_require_armed(registry):
    entry = registry.upload(filename="s1.py", content=ORACLE_SHAPE1.encode())
    assert entry.armed is False
    # Should not raise.
    registry.dry_run(entry.oracle_id, samples=[b"x" * 16])


# ---------- delete / not found ----------


def test_delete_removes_file_and_entry(registry):
    entry = registry.upload(filename="s.py", content=ORACLE_SHAPE1.encode())
    path = entry.path
    assert path.is_file()
    registry.delete(entry.oracle_id)
    assert not path.is_file()
    with pytest.raises(OracleNotFound):
        registry.get(entry.oracle_id)


def test_delete_unknown_raises(registry):
    with pytest.raises(OracleNotFound):
        registry.delete("deadbeef")


# ---------- HTTP router integration ----------


def test_router_returns_503_when_disabled(tmp_path, monkeypatch):
    """The upload endpoint must 503 when MEMDIVER_ORACLE_DIR is unset."""
    from fastapi.testclient import TestClient

    from memdiver.api.services.oracle_registry import init_oracle_registry

    examples_dir = Path(__file__).parent.parent / "docs" / "oracle" / "examples"
    init_oracle_registry(oracle_dir=None, examples_dir=examples_dir)
    try:
        from fastapi import FastAPI
        from memdiver.api.routers.oracles import router

        app = FastAPI()
        app.include_router(router, prefix="/api/oracles")
        client = TestClient(app)
        # examples still work
        r = client.get("/api/oracles/examples")
        assert r.status_code == 200
        # upload is gated on MEMDIVER_ORACLE_DIR
        r = client.post(
            "/api/oracles/upload",
            files={"file": ("x.py", ORACLE_SHAPE1.encode(), "text/x-python")},
        )
        assert r.status_code == 503
    finally:
        reset_oracle_registry()


def test_router_full_round_trip(tmp_path):
    """Upload → arm → dry-run → delete via the real router."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from memdiver.api.routers.oracles import router
    from memdiver.api.services.oracle_registry import init_oracle_registry

    examples_dir = Path(__file__).parent.parent / "docs" / "oracle" / "examples"
    init_oracle_registry(
        oracle_dir=tmp_path / "oracles",
        examples_dir=examples_dir,
    )
    try:
        app = FastAPI()
        app.include_router(router, prefix="/api/oracles")
        client = TestClient(app)

        upload = client.post(
            "/api/oracles/upload",
            files={"file": ("my.py", ORACLE_SHAPE1.encode(), "text/x-python")},
            data={"description": "sentinel"},
        )
        assert upload.status_code == 200, upload.text
        body = upload.json()
        oracle_id = body["id"]
        sha = body["sha256"]
        assert body["armed"] is False
        assert body["shape"] == 1

        # list returns it
        listed = client.get("/api/oracles")
        assert any(o["id"] == oracle_id for o in listed.json()["oracles"])

        # mismatched arm rejected
        r = client.post(f"/api/oracles/{oracle_id}/arm", json={"sha256": "0" * 64})
        assert r.status_code == 409

        # correct arm accepted
        r = client.post(f"/api/oracles/{oracle_id}/arm", json={"sha256": sha})
        assert r.status_code == 200
        assert r.json()["armed"] is True

        # dry-run returns structured report
        sentinel_b64 = base64.b64encode(bytes(range(16))).decode()
        other_b64 = base64.b64encode(b"\x00" * 16).decode()
        r = client.post(
            f"/api/oracles/{oracle_id}/dry-run",
            json={"samples_b64": [sentinel_b64, other_b64]},
        )
        assert r.status_code == 200
        report = r.json()
        assert report["passes"] == 1
        assert report["fails"] == 1

        # delete
        r = client.delete(f"/api/oracles/{oracle_id}")
        assert r.status_code == 200

        r = client.get("/api/oracles")
        assert not any(o["id"] == oracle_id for o in r.json()["oracles"])
    finally:
        reset_oracle_registry()


# ---------- oracle-dir status / enable (Work item 1) ----------
#
# Before these endpoints existed, the only way to turn oracle storage on was
# MEMDIVER_ORACLE_DIR, read once at startup — so the Upload dropzone the UI
# renders could only ever answer 503. These tests pin the runtime opt-in, and
# in particular the three things that are easy to get subtly wrong: the 409
# when the env var pins the value, the in-place Settings mutation (the cached
# instance is held by middleware, so rebuilding it would strand them), and the
# route ordering against the existing ``/{oracle_id}`` paths.


@pytest.fixture
def oracle_api(tmp_path, monkeypatch):
    """A TestClient over the oracle router with the registry DISABLED.

    ``XDG_DATA_HOME`` is redirected so the prefs file this feature writes lands
    in ``tmp_path`` and the developer's real ``~/.memdiver/config.json`` is
    never touched; ``upload_dir._temp_roots`` is emptied because pytest's
    ``tmp_path`` is itself inside ``tempfile.gettempdir()``, which validation
    rejects.
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from memdiver.api import upload_dir as upload_dir_mod
    from memdiver.api.config import get_settings
    from memdiver.api.routers.oracles import router
    from memdiver.api.services.oracle_registry import init_oracle_registry

    monkeypatch.delenv("MEMDIVER_ORACLE_DIR", raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(upload_dir_mod, "_temp_roots", lambda: ())
    get_settings.cache_clear()

    examples = Path(__file__).parent.parent / "docs" / "oracle" / "examples"
    registry = init_oracle_registry(oracle_dir=None, examples_dir=examples)
    app = FastAPI()
    app.include_router(router, prefix="/api/oracles")
    try:
        yield TestClient(app), registry, tmp_path
    finally:
        reset_oracle_registry()
        get_settings.cache_clear()


def test_status_is_200_and_disabled_before_opt_in(oracle_api):
    """Disabled is a state the UI renders, not an error — so never a 503 here."""
    client, _registry, _tmp = oracle_api
    r = client.get("/api/oracles/status")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["enabled"] is False
    assert body["path"] is None
    assert body["source"] is None
    assert body["env_pinned"] is False
    assert body["default_path"].endswith("/oracles")


def test_status_and_enable_are_not_captured_by_the_oracle_id_route(oracle_api):
    """Route ordering: ``/{oracle_id}`` must not swallow these literal paths.

    Verified by hitting them for real rather than by inspecting the route
    table — a 422 (``ArmRequest`` body validation) or a 404 (unknown oracle id)
    would be the symptom of the ordering bug.
    """
    client, _registry, _tmp = oracle_api
    status_keys = {
        "enabled", "path", "source", "env_pinned", "default_path", "orphans",
    }
    assert set(client.get("/api/oracles/status").json()) == status_keys
    body = client.post("/api/oracles/enable").json()
    assert set(body) == status_keys


def test_enable_without_a_body_uses_the_default_dir(oracle_api):
    from memdiver.api.oracle_dir import default_oracle_dir

    client, registry, _tmp = oracle_api
    r = client.post("/api/oracles/enable")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["enabled"] is True
    assert body["path"] == str(default_oracle_dir())
    assert body["source"] == "user_config"
    assert registry.enabled is True


def test_enable_with_an_explicit_path_makes_upload_work(oracle_api):
    """The whole point: the 503 goes away with no restart."""
    client, _registry, tmp_path = oracle_api
    chosen = tmp_path / "chosen_oracles"

    blocked = client.post(
        "/api/oracles/upload",
        files={"file": ("x.py", ORACLE_SHAPE1.encode(), "text/x-python")},
    )
    assert blocked.status_code == 503

    r = client.post("/api/oracles/enable", json={"path": str(chosen)})
    assert r.status_code == 200, r.text
    assert r.json()["path"] == str(chosen.resolve())

    allowed = client.post(
        "/api/oracles/upload",
        files={"file": ("x.py", ORACLE_SHAPE1.encode(), "text/x-python")},
    )
    assert allowed.status_code == 200, allowed.text
    # Stored under a uuid, not the client-supplied basename (see upload()).
    assert (chosen / f"{allowed.json()['id']}.py").is_file()


def test_enable_pins_the_directory_to_0700(oracle_api):
    """engine.oracle._assert_safe_path refuses a group/world-writable parent."""
    import os
    import stat as stat_mod

    client, _registry, tmp_path = oracle_api
    chosen = tmp_path / "loose"
    chosen.mkdir(mode=0o777)
    os.chmod(chosen, 0o777)

    r = client.post("/api/oracles/enable", json={"path": str(chosen)})
    assert r.status_code == 200, r.text
    assert stat_mod.S_IMODE(chosen.stat().st_mode) == 0o700


def test_enable_persists_to_the_prefs_file(oracle_api):
    import json

    from memdiver.api.user_prefs import user_config_path

    client, _registry, tmp_path = oracle_api
    chosen = tmp_path / "persisted"
    client.post("/api/oracles/enable", json={"path": str(chosen)})
    stored = json.loads(user_config_path().read_text())
    assert stored["oracle_dir"] == str(chosen.resolve())


def test_enable_mutates_the_cached_settings_in_place(oracle_api):
    """Never cache_clear(): middleware holds a reference to this exact object."""
    from memdiver.api.config import get_settings

    client, _registry, tmp_path = oracle_api
    before = get_settings()
    assert before.oracle_dir is None

    chosen = tmp_path / "inplace"
    client.post("/api/oracles/enable", json={"path": str(chosen)})

    assert get_settings() is before
    assert before.oracle_dir == chosen.resolve()


def test_enable_is_409_when_the_env_var_pins_the_value(oracle_api, monkeypatch):
    """Persisting a value pydantic-settings would shadow forever is worse."""
    client, _registry, tmp_path = oracle_api
    monkeypatch.setenv("MEMDIVER_ORACLE_DIR", str(tmp_path / "pinned"))

    status = client.get("/api/oracles/status").json()
    assert status["env_pinned"] is True

    r = client.post("/api/oracles/enable", json={"path": str(tmp_path / "other")})
    assert r.status_code == 409
    assert "MEMDIVER_ORACLE_DIR" in r.json()["detail"]


def test_enable_rejects_an_unsafe_path_without_persisting(oracle_api):
    """Validate BEFORE persisting: a refusal must leave disk and memory alone."""
    from memdiver.api.config import get_settings
    from memdiver.api.user_prefs import user_config_path

    client, registry, _tmp = oracle_api
    r = client.post("/api/oracles/enable", json={"path": "/usr/lib/oracles"})
    assert r.status_code == 400
    assert "system directory" in r.json()["detail"]
    assert get_settings().oracle_dir is None
    assert registry.enabled is False
    assert not user_config_path().is_file()


def test_enable_rejects_a_relative_path(oracle_api):
    client, _registry, _tmp = oracle_api
    r = client.post("/api/oracles/enable", json={"path": "oracles"})
    assert r.status_code == 400


def test_registry_enable_keeps_already_registered_entries(registry, tmp_path):
    """Why enable() is a method and not a call to init_oracle_registry().

    Rebuilding the singleton would construct a fresh OracleRegistry and drop
    ``_entries`` — uploaded oracles would vanish from the catalog while their
    files stayed on disk.
    """
    entry = registry.upload(filename="keepme.py", content=ORACLE_SHAPE1.encode())
    moved = tmp_path / "elsewhere"

    returned = registry.enable(moved)

    assert returned == moved
    assert registry.enabled is True
    assert registry.require_enabled() == moved
    assert registry.get(entry.oracle_id).oracle_id == entry.oracle_id
    assert len(registry.list_entries()) == 1


def test_registry_enable_creates_the_dir_at_0700(registry, tmp_path):
    import stat as stat_mod

    target = tmp_path / "deep" / "nested" / "oracles"
    registry.enable(target)
    assert target.is_dir()
    assert stat_mod.S_IMODE(target.stat().st_mode) == 0o700


# ---------- three-layer validation: lenient upload, strict arm (Work item 2) --
#
# Uploading used to replay build_oracle({}) under the STRICT validator, so the
# bundled gocryptfs example — a Shape-2 oracle with a *required* config key —
# could not be uploaded through the endpoint the UI steers users to at all:
# KeyError('sample_ciphertext') -> 400, file already unlinked. The fix moves the
# config-aware check to arm(), which is where user intent is confirmed anyway.
#
# Note why the pre-existing ORACLE_SHAPE2 fixture never caught this: every key
# it reads has a ``cfg.get(..., default)`` fallback, so build_oracle({})
# succeeds. The fixture below deliberately does a bare ``cfg[...]`` lookup.


# A Shape-2 oracle with a REQUIRED config key — the gocryptfs shape.
ORACLE_SHAPE2_REQUIRED_KEY = """\
class NeedyOracle:
    def __init__(self, cfg):
        self.tag = cfg["required_tag"].encode()
    def verify(self, candidate):
        return candidate == self.tag

def build_oracle(cfg):
    return NeedyOracle(cfg)
"""


# Minimum a gocryptfs ciphertext sample must be for GocryptfsOracle to build:
# version(2) + file_id(16) + nonce(16) + gcm_tag(16). Verification correctness
# is not what these tests exercise — only that the oracle constructs.
def _fake_gocryptfs_sample(path: Path) -> Path:
    path.write_bytes(bytes(range(64)))
    return path


@pytest.fixture
def gocryptfs_source(examples_dir):
    return (examples_dir / "gocryptfs.py").read_bytes()


def test_upload_shape2_with_required_key_no_longer_rejected(registry):
    """The regression in miniature: a required key must not block the upload."""
    entry = registry.upload(
        filename="needy.py", content=ORACLE_SHAPE2_REQUIRED_KEY.encode()
    )
    assert entry.shape == 2
    assert entry.armed is False
    assert entry.config == {}
    assert entry.path.is_file()


def test_upload_bundled_gocryptfs_example_succeeds_with_no_config(
    registry, gocryptfs_source
):
    """THE headline case: the bundled example must upload with no config.

    Previously: OracleRegistryError("oracle failed to load: ...
    KeyError('sample_ciphertext')") and the stored file unlinked.
    """
    entry = registry.upload(filename="gocryptfs.py", content=gocryptfs_source)
    assert entry.shape == 2
    assert entry.path.is_file()
    assert entry.config == {}


def test_arm_gocryptfs_without_a_sample_ciphertext_fails_readably(
    registry, gocryptfs_source
):
    """The strict gate moved to arm — and must speak to a human when it fires."""
    entry = registry.upload(filename="gocryptfs.py", content=gocryptfs_source)
    with pytest.raises(OracleConfigInvalid) as excinfo:
        registry.arm(entry.oracle_id, entry.sha256)
    message = str(excinfo.value)
    assert "gocryptfs.py" in message
    assert "sample_ciphertext" in message
    assert "configuration" in message
    # Not a raw traceback, and not a bare KeyError repr as the whole message.
    assert "Traceback" not in message
    assert message != "'sample_ciphertext'"
    # A failed arm leaves the oracle unarmed.
    assert registry.get(entry.oracle_id).armed is False


def test_arm_gocryptfs_with_a_missing_file_fails_readably(
    registry, gocryptfs_source, tmp_path
):
    entry = registry.upload(filename="gocryptfs.py", content=gocryptfs_source)
    with pytest.raises(OracleConfigInvalid, match="could not be loaded"):
        registry.arm(
            entry.oracle_id,
            entry.sha256,
            config={"sample_ciphertext": str(tmp_path / "nope")},
        )
    assert registry.get(entry.oracle_id).armed is False


# ---------- unexpanded ${VAR} placeholders ----------------------------------
#
# Nothing in this repo expands ${VAR} in an oracle config (by design), so a
# template that ships one reaches the filesystem verbatim and used to surface
# as FileNotFoundError(2, 'No such file or directory') — true, but it never
# said the value was still a placeholder. The bundled gocryptfs.toml no longer
# spells its hole this way (it declares it in config_placeholders instead),
# but any third-party example still may.
#
# The template string is built INLINE here, never read from the shipped .toml:
# these tests pin the *check*, and must not turn red the day the example's
# path changes.

PLACEHOLDER_CONFIG = {
    "sample_ciphertext": (
        "${MEMDIVER_FIXTURE_ROOT}/gocryptfs/vault/jxSMOg-V7hYDb5UsGpxWxg"
    )
}


def test_arm_with_an_unexpanded_placeholder_names_the_key_and_the_placeholder(
    registry, gocryptfs_source
):
    """No `cryptography` importorskip on purpose.

    The check fires before any sandbox replay, which is the whole point: a
    placeholder is diagnosable from the string alone, so the diagnosis is fast
    and deterministic on any machine.
    """
    entry = registry.upload(filename="gocryptfs.py", content=gocryptfs_source)
    with pytest.raises(OracleConfigInvalid) as excinfo:
        registry.arm(entry.oracle_id, entry.sha256, config=PLACEHOLDER_CONFIG)
    message = str(excinfo.value)
    assert "sample_ciphertext" in message
    assert "${MEMDIVER_FIXTURE_ROOT}" in message
    assert "gocryptfs.py" in message
    assert "Traceback" not in message
    assert registry.get(entry.oracle_id).armed is False


def test_dry_run_on_the_bundled_template_names_the_placeholder(registry):
    """THE reported bug, end to end: load the example with its own template,
    smoke-test it, and get told which key is still a placeholder."""
    entry = registry.load_example("gocryptfs.py", config=PLACEHOLDER_CONFIG)
    with pytest.raises(OracleConfigInvalid) as excinfo:
        registry.dry_run(entry.oracle_id, samples=[b"whatever"])
    message = str(excinfo.value)
    assert "sample_ciphertext" in message
    assert "${MEMDIVER_FIXTURE_ROOT}" in message
    assert "No such file or directory" not in message


def test_load_example_still_accepts_a_placeholder_config_verbatim(registry):
    """Pins the decision NOT to check at upload/load time.

    "Load without arming" is a deliberate park-a-draft escape hatch: the UI
    prefills the form from the template, so refusing the template at load
    would make the Examples tab un-loadable. Arm and dry-run are the only two
    places the value is actually dereferenced.
    """
    entry = registry.load_example("gocryptfs.py", config=PLACEHOLDER_CONFIG)
    assert entry.armed is False
    assert entry.config == PLACEHOLDER_CONFIG


@pytest.mark.parametrize(
    "value",
    [
        17,
        True,
        None,
        "/abs/path/to/blob",
        "a$b",              # a bare $ is legal in a POSIX filename
        "$MEMDIVER_ROOT/x",  # unbraced: not the form our templates use
        "",
    ],
)
def test_find_unexpanded_placeholder_ignores_ordinary_values(value):
    assert _find_unexpanded_placeholder({"sample_ciphertext": value}) is None


def test_find_unexpanded_placeholder_on_an_empty_config():
    assert _find_unexpanded_placeholder({}) is None


@pytest.mark.parametrize(
    "value,expected",
    [
        ("${A}", "${A}"),
        ("x${A_1}y", "${A_1}"),
        ("${MEMDIVER_FIXTURE_ROOT}/gocryptfs/blob", "${MEMDIVER_FIXTURE_ROOT}"),
    ],
)
def test_find_unexpanded_placeholder_finds_the_braced_form(value, expected):
    assert _find_unexpanded_placeholder({"k": value}) == ("k", expected)


def test_find_unexpanded_placeholder_is_deterministic_across_two_hits():
    """sorted() so the same config always accuses the same key."""
    config = {"zeta": "${Z}", "alpha": "${A}"}
    assert _find_unexpanded_placeholder(config) == ("alpha", "${A}")


def test_describe_config_keys_wording():
    assert _describe_config_keys({}) == "no config values supplied"
    assert _describe_config_keys({"b": 1, "a": 2}) == "config keys: a, b"


def test_arm_gocryptfs_end_to_end_with_a_real_sample(
    registry, gocryptfs_source, tmp_path
):
    """The whole point of the feature: a real config makes the real oracle arm."""
    pytest.importorskip("cryptography")
    sample = _fake_gocryptfs_sample(tmp_path / "jxSMOg-V7hYDb5UsGpxWxg")
    entry = registry.upload(filename="gocryptfs.py", content=gocryptfs_source)
    armed = registry.arm(
        entry.oracle_id,
        entry.sha256,
        config={"sample_ciphertext": str(sample)},
    )
    assert armed.armed is True
    assert armed.config == {"sample_ciphertext": str(sample)}
    assert registry.require_armed(entry.oracle_id).config["sample_ciphertext"]


def test_arm_rejects_a_sample_that_is_too_short(registry, gocryptfs_source, tmp_path):
    """The oracle's own ValueError reaches the user, still as a readable error."""
    pytest.importorskip("cryptography")
    short = tmp_path / "too_short"
    short.write_bytes(b"\x00" * 8)
    entry = registry.upload(filename="gocryptfs.py", content=gocryptfs_source)
    with pytest.raises(OracleConfigInvalid, match="too short"):
        registry.arm(
            entry.oracle_id, entry.sha256, config={"sample_ciphertext": str(short)}
        )


def test_upload_still_rejects_a_hang_in_build_oracle(registry, monkeypatch):
    """The lenient probe is not a no-op: the case it touches is still blocked.

    ``build_oracle`` is exactly where a tolerated exception now falls through,
    so a *hang* in the same function is the sharpest proof the containment half
    survived. Body reused from
    ``tests/test_oracle.py::test_sandbox_rejects_hang_in_build_oracle``. The
    real sandbox runs; only its wall-clock budget is shortened, so the test
    does not sit out the 10s default.
    """
    import memdiver.api.services.oracle_registry as reg_mod

    real = reg_mod.validate_oracle_sandboxed

    def _fast(path, config=None, **kw):
        return real(path, config, timeout_s=0.5, cpu_s=30)

    monkeypatch.setattr(reg_mod, "validate_oracle_sandboxed", _fast)
    hanging = "def build_oracle(cfg):\n    while True:\n        pass\n"
    with pytest.raises(OracleRegistryError, match="wall-clock"):
        registry.upload(filename="hang.py", content=hanging.encode())
    # ...and the rejected file is not left behind in the oracle dir.
    assert list((registry.require_enabled()).glob("*.py")) == []


def test_upload_still_rejects_a_hang_at_import(registry, monkeypatch):
    """Body reused from ``tests/test_oracle.py::test_sandbox_rejects_hang_at_import``."""
    import memdiver.api.services.oracle_registry as reg_mod

    real = reg_mod.validate_oracle_sandboxed

    def _fast(path, config=None, **kw):
        return real(path, config, timeout_s=0.5, cpu_s=30)

    monkeypatch.setattr(reg_mod, "validate_oracle_sandboxed", _fast)
    hanging = "while True:\n    pass\n\ndef verify(c): return True\n"
    with pytest.raises(OracleRegistryError, match="wall-clock"):
        registry.upload(filename="hang.py", content=hanging.encode())


def test_upload_accepts_a_config_and_reports_it(registry):
    entry = registry.upload(
        filename="needy.py",
        content=ORACLE_SHAPE2_REQUIRED_KEY.encode(),
        config={"required_tag": "magic!"},
    )
    assert entry.config == {"required_tag": "magic!"}
    assert entry.to_dict()["config"] == {"required_tag": "magic!"}
    # Supplying it at upload is enough to arm in one step.
    assert registry.arm(entry.oracle_id, entry.sha256).armed is True


def test_set_config_stores_a_copy(registry):
    entry = registry.upload(
        filename="needy.py", content=ORACLE_SHAPE2_REQUIRED_KEY.encode()
    )
    supplied = {"required_tag": "magic!"}
    registry.set_config(entry.oracle_id, supplied)
    supplied["required_tag"] = "tampered"
    assert registry.get(entry.oracle_id).config == {"required_tag": "magic!"}
    registry.arm(entry.oracle_id, entry.sha256)


def test_set_config_on_an_unknown_oracle_raises(registry):
    with pytest.raises(OracleNotFound):
        registry.set_config("deadbeef", {"a": 1})


def test_dry_run_uses_the_entrys_config(registry):
    """dry_run hardcoded {} and therefore exploded on exactly these oracles."""
    entry = registry.upload(
        filename="needy.py",
        content=ORACLE_SHAPE2_REQUIRED_KEY.encode(),
        config={"required_tag": "magic!"},
    )
    report = registry.dry_run(entry.oracle_id, samples=[b"magic!", b"bogus!"])
    assert report["passes"] == 1
    assert report["fails"] == 1


# ---------- bundled examples: config template + server-side load -------------


def test_examples_expose_the_sibling_toml_as_a_config_template(registry):
    """Shape-2 examples are useless without their parameters, so ship them."""
    examples = {e["filename"]: e for e in registry.list_examples()}
    template = examples["gocryptfs.py"]["config_template"]
    assert template is not None
    # The shipped value is the SHAPE of an answer, not an answer: a path on
    # nobody's machine. It is passed through verbatim (rewriting it would hide
    # what the example is asking for)...
    assert template["sample_ciphertext"].startswith("/absolute/path/to/your/")
    # ...and the server names it as a hole, because that value no longer looks
    # like a placeholder to a regex — which is exactly how it came to be
    # submitted as a real path.
    assert "sample_ciphertext" in examples["gocryptfs.py"]["config_placeholders"]
    # The reserved [memdiver] table is memdiver's own automation metadata. Left
    # in the template the UI renders it as a config row and submits it to
    # build_oracle(), which never asked for it.
    assert "memdiver" not in template
    # An example with no sibling .toml reports None rather than {}.
    assert examples["generic_aes_gcm.py"]["config_template"] is None
    assert examples["generic_aes_gcm.py"]["config_placeholders"] == []


def test_load_example_registers_through_the_upload_path(registry):
    entry = registry.load_example("gocryptfs.py")
    assert entry.filename == "gocryptfs.py"
    assert entry.shape == 2
    # Stored under a uuid inside the oracle dir, at 0o600, exactly like upload.
    assert entry.path.parent == registry.require_enabled()
    assert entry.path.name == f"{entry.oracle_id}.py"
    assert (entry.path.stat().st_mode & 0o777) == 0o600
    assert entry.armed is False


def test_load_example_accepts_a_config(registry, tmp_path):
    pytest.importorskip("cryptography")
    sample = _fake_gocryptfs_sample(tmp_path / "cipher_blob")
    entry = registry.load_example(
        "gocryptfs.py", config={"sample_ciphertext": str(sample)}
    )
    assert registry.arm(entry.oracle_id, entry.sha256).armed is True


@pytest.mark.parametrize(
    "bad",
    [
        "../conftest.py",
        "../../pyproject.toml",
        "/etc/passwd",
        "_private.py",
        "nope.py",
        "",
    ],
)
def test_load_example_refuses_anything_not_in_the_enumeration(registry, bad):
    """Path traversal: the loadable set is exactly the advertised set."""
    with pytest.raises(OracleNotFound):
        registry.load_example(bad)


def test_load_example_requires_the_registry_to_be_enabled(disabled_registry):
    with pytest.raises(OracleDisabled):
        disabled_registry.load_example("gocryptfs.py")


# ---------- HTTP surface for the above ---------------------------------------


def test_router_load_example_arm_and_run(tmp_path):
    """Load the bundled example over HTTP, then arm it with a real config."""
    pytest.importorskip("cryptography")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from memdiver.api.routers.oracles import router
    from memdiver.api.services.oracle_registry import init_oracle_registry

    examples_dir = Path(__file__).parent.parent / "docs" / "oracle" / "examples"
    init_oracle_registry(oracle_dir=tmp_path / "oracles", examples_dir=examples_dir)
    try:
        app = FastAPI()
        app.include_router(router, prefix="/api/oracles")
        client = TestClient(app)

        listed = client.get("/api/oracles/examples").json()["examples"]
        gocryptfs = next(e for e in listed if e["filename"] == "gocryptfs.py")
        assert gocryptfs["config_template"]["sample_ciphertext"].startswith(
            "/absolute/path/to/your/"
        )
        assert "sample_ciphertext" in gocryptfs["config_placeholders"]
        assert "memdiver" not in gocryptfs["config_template"]

        loaded = client.post("/api/oracles/examples/gocryptfs.py/load")
        assert loaded.status_code == 200, loaded.text
        body = loaded.json()
        assert body["shape"] == 2
        assert body["armed"] is False
        assert body["config"] == {}

        # Arming with an unexpanded ${VAR} placeholder is a readable 400.
        # Spelled inline rather than taken from the shipped template: the
        # bundled example states its hole in config_placeholders now, but a
        # third-party example may still ship a ${VAR}, and that is the case
        # this guard exists for.
        bad = client.post(
            f"/api/oracles/{body['id']}/arm",
            json={
                "sha256": body["sha256"],
                "config": {
                    "sample_ciphertext": (
                        "${MEMDIVER_FIXTURE_ROOT}/gocryptfs/jxSMOg-V7hYDb5UsGpxWxg"
                    )
                },
            },
        )
        assert bad.status_code == 400, bad.text
        # Names the key AND the placeholder: "(sample_ciphertext)" alone used
        # to read as "this key is wrong" rather than "this key is unfilled".
        assert "sample_ciphertext" in bad.json()["detail"]
        assert "${MEMDIVER_FIXTURE_ROOT}" in bad.json()["detail"]

        # Dry-run is the surface users reach first, so it must say the same
        # thing. Loaded WITH the placeholder config (the reported bug) and
        # built inline, so this leg does not depend on the shipped .toml.
        drafted = client.post(
            "/api/oracles/examples/gocryptfs.py/load",
            json={
                "config": {
                    "sample_ciphertext": (
                        "${MEMDIVER_FIXTURE_ROOT}/gocryptfs/jxSMOg-V7hYDb5UsGpxWxg"
                    )
                }
            },
        )
        assert drafted.status_code == 200, drafted.text
        dry = client.post(
            f"/api/oracles/{drafted.json()['id']}/dry-run",
            json={"samples_b64": [base64.b64encode(b"candidate").decode()]},
        )
        assert dry.status_code == 400, dry.text
        assert "sample_ciphertext" in dry.json()["detail"]
        assert "${MEMDIVER_FIXTURE_ROOT}" in dry.json()["detail"]

        sample = _fake_gocryptfs_sample(tmp_path / "cipher_blob")
        good = client.post(
            f"/api/oracles/{body['id']}/arm",
            json={
                "sha256": body["sha256"],
                "config": {"sample_ciphertext": str(sample)},
            },
        )
        assert good.status_code == 200, good.text
        assert good.json()["armed"] is True
        assert good.json()["config"]["sample_ciphertext"] == str(sample)
    finally:
        reset_oracle_registry()


# ---------- suggest-config: the dataset already knows the ciphertext ---------


@contextmanager
def _oracle_client(tmp_path: Path):
    """A TestClient over the oracles router, with the singleton always reset.

    ``init_oracle_registry`` installs a PROCESS-wide registry; leaking one
    leaves the next test reading a ``tmp_path`` pytest has already deleted, so
    the teardown is the reason this helper exists at all.
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from memdiver.api.routers.oracles import router
    from memdiver.api.services.oracle_registry import init_oracle_registry

    examples_dir = Path(__file__).parent.parent / "docs" / "oracle" / "examples"
    init_oracle_registry(oracle_dir=tmp_path / "oracles", examples_dir=examples_dir)
    try:
        app = FastAPI()
        app.include_router(router, prefix="/api/oracles")
        yield TestClient(app)
    finally:
        reset_oracle_registry()


def _make_corpus_run(
    dataset_root: Path,
    run_id: str = "run_0001",
    *,
    cipher: str = "aes",
    content_names: tuple = ("jxSMOg-V7hYDb5UsGpxWxg",),
    vault_declaration: str = "run_0001/cipher",
) -> Path:
    """Build one synthetic corpus run; returns the dump path inside it.

    Synthesised here rather than pointed at the author's private dataset so
    the HTTP contract is provable on a machine that has never seen it. The
    declared vault defaults to the DATASET-ROOT-RELATIVE ``run_0001/cipher``
    spelling the shipped corpus actually writes (the bare ``cipher`` form
    resolves too, but is not what the HTTP layer meets in the field).
    """
    run_dir = dataset_root / run_id
    vault = run_dir / "cipher"
    vault.mkdir(parents=True)
    # Vault metadata, not content: the .toml excludes both by name, and a
    # suggestion that offered one of them would decrypt to nothing.
    (vault / "gocryptfs.conf").write_text("{}")
    (vault / "gocryptfs.diriv").write_bytes(b"\x00" * 16)
    for name in content_names:
        (vault / name).write_bytes(b"ciphertext")

    dump = run_dir / "memslicer.msl"
    dump.write_bytes(b"\x00" * 64)
    payload = {
        "run_id": run_id,
        "cipher": cipher,
        "vault_cipher_dir": vault_declaration,
    }
    (run_dir / "meta.json").write_text(json.dumps(payload))
    return dump


def test_router_suggest_config_404s_on_an_unknown_example(tmp_path):
    """Same resolution rule as /load, so traversal is a 404 rather than a read."""
    with _oracle_client(tmp_path) as client:
        unknown = client.post(
            "/api/oracles/examples/nope.py/suggest-config",
            json={"source_paths": []},
        )
        assert unknown.status_code == 404, unknown.text
        traversal = client.post(
            "/api/oracles/examples/..%2F..%2Fpyproject.toml/suggest-config",
            json={"source_paths": []},
        )
        assert traversal.status_code == 404, traversal.text


def test_router_suggest_config_is_200_when_nothing_is_derivable(tmp_path):
    """Underivable is the field's ORDINARY state, so it must not be an error.

    A 4xx here would make the wizard render a failure banner for a dump that
    simply lives outside any corpus — which is most dumps.
    """
    with _oracle_client(tmp_path) as client:
        nothing_selected = client.post(
            "/api/oracles/examples/gocryptfs.py/suggest-config",
            json={"source_paths": []},
        )
        assert nothing_selected.status_code == 200, nothing_selected.text
        assert nothing_selected.json()["config"] == {}
        assert nothing_selected.json()["blocked_reason"] is None

        lonely = tmp_path / "lonely.msl"
        lonely.write_bytes(b"\x00" * 64)
        no_meta = client.post(
            "/api/oracles/examples/gocryptfs.py/suggest-config",
            json={"source_paths": [str(lonely)]},
        )
        assert no_meta.status_code == 200, no_meta.text
        body = no_meta.json()
        assert body["config"] == {}
        assert body["blocked_reason"] is None
        # The dump is still echoed: the UI says which selection it answered.
        assert body["reference_dump"] == str(lonely)
        assert body["reference_run"] is None


@pytest.mark.parametrize("vault_declaration", ["run_0001/cipher", "cipher"])
def test_router_suggest_config_derives_the_ciphertext_from_the_run(
    tmp_path, vault_declaration
):
    """The happy path: the value the user was being asked to retype.

    Both declaration spellings are exercised because the shipped corpus writes
    the dataset-root-relative one (``run_0001/cipher``) while the bare
    ``cipher`` form resolves against the run dir — the HTTP layer must not
    care which a dataset chose.
    """
    dump = _make_corpus_run(tmp_path / "corpus", vault_declaration=vault_declaration)
    with _oracle_client(tmp_path) as client:
        r = client.post(
            "/api/oracles/examples/gocryptfs.py/suggest-config",
            json={"source_paths": [str(dump)]},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["config"] == {
            "sample_ciphertext": str(
                tmp_path / "corpus" / "run_0001" / "cipher" / "jxSMOg-V7hYDb5UsGpxWxg"
            )
        }
        assert body["reference_run"] == "run_0001"
        assert body["reference_dump"] == str(dump)
        # Provenance is the answer to "where did this come from?", which the
        # analyst has to be able to check without leaving the wizard.
        assert "run_0001" in body["provenance"]
        assert "memslicer.msl" in body["provenance"]
        assert body["blocked_reason"] is None
        assert body["warnings"] == []


def test_router_suggest_config_blocks_a_cipher_the_oracle_cannot_verify(tmp_path):
    """An xchacha run fails every candidate, which reads as "key not present"."""
    dump = _make_corpus_run(tmp_path / "corpus", cipher="xchacha")
    with _oracle_client(tmp_path) as client:
        r = client.post(
            "/api/oracles/examples/gocryptfs.py/suggest-config",
            json={"source_paths": [str(dump)]},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        # Blocked, not filled: a prefilled config here would manufacture a run
        # that is guaranteed to report nothing, and say nothing about why.
        assert body["config"] == {}
        assert body["blocked_reason"] is not None
        assert "xchacha" in body["blocked_reason"]
        assert body["reference_run"] == "run_0001"


def test_router_load_example_rejects_traversal_with_404(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from memdiver.api.routers.oracles import router
    from memdiver.api.services.oracle_registry import init_oracle_registry

    examples_dir = Path(__file__).parent.parent / "docs" / "oracle" / "examples"
    init_oracle_registry(oracle_dir=tmp_path / "oracles", examples_dir=examples_dir)
    try:
        app = FastAPI()
        app.include_router(router, prefix="/api/oracles")
        client = TestClient(app)
        r = client.post("/api/oracles/examples/..%2F..%2Fpyproject.toml/load")
        assert r.status_code == 404
        r = client.post("/api/oracles/examples/nope.py/load")
        assert r.status_code == 404
        assert not list((tmp_path / "oracles").glob("*.py"))
    finally:
        reset_oracle_registry()


def test_router_load_example_is_503_when_disabled(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from memdiver.api.routers.oracles import router
    from memdiver.api.services.oracle_registry import init_oracle_registry

    examples_dir = Path(__file__).parent.parent / "docs" / "oracle" / "examples"
    init_oracle_registry(oracle_dir=None, examples_dir=examples_dir)
    try:
        app = FastAPI()
        app.include_router(router, prefix="/api/oracles")
        client = TestClient(app)
        r = client.post("/api/oracles/examples/gocryptfs.py/load")
        assert r.status_code == 503
    finally:
        reset_oracle_registry()


def test_router_arm_without_a_config_key_still_works(tmp_path):
    """``config`` is optional on /arm — the Shape-1 flow is untouched."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from memdiver.api.routers.oracles import router
    from memdiver.api.services.oracle_registry import init_oracle_registry

    examples_dir = Path(__file__).parent.parent / "docs" / "oracle" / "examples"
    init_oracle_registry(oracle_dir=tmp_path / "oracles", examples_dir=examples_dir)
    try:
        app = FastAPI()
        app.include_router(router, prefix="/api/oracles")
        client = TestClient(app)
        up = client.post(
            "/api/oracles/upload",
            files={"file": ("my.py", ORACLE_SHAPE1.encode(), "text/x-python")},
        ).json()
        r = client.post(f"/api/oracles/{up['id']}/arm", json={"sha256": up["sha256"]})
        assert r.status_code == 200, r.text
        assert r.json()["armed"] is True
    finally:
        reset_oracle_registry()


def test_dry_run_on_an_unconfigured_oracle_is_a_readable_4xx_not_a_500(tmp_path):
    """Smoke-testing before filling in the form is a user mistake, not a crash.

    ``load_oracle`` raises ``OracleLoadError``, which the router does not map —
    so it used to escape as a 500. Now that a Shape-2 oracle with a required
    key can actually be uploaded, this path is reachable from the UI.
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from memdiver.api.routers.oracles import router
    from memdiver.api.services.oracle_registry import init_oracle_registry

    examples_dir = Path(__file__).parent.parent / "docs" / "oracle" / "examples"
    init_oracle_registry(oracle_dir=tmp_path / "oracles", examples_dir=examples_dir)
    try:
        app = FastAPI()
        app.include_router(router, prefix="/api/oracles")
        client = TestClient(app)
        up = client.post(
            "/api/oracles/upload",
            files={
                "file": (
                    "needy.py",
                    ORACLE_SHAPE2_REQUIRED_KEY.encode(),
                    "text/x-python",
                )
            },
        ).json()
        r = client.post(
            f"/api/oracles/{up['id']}/dry-run",
            json={"samples_b64": [base64.b64encode(b"magic!").decode()]},
        )
        assert r.status_code == 400, r.text
        assert "required_tag" in r.json()["detail"]
    finally:
        reset_oracle_registry()
