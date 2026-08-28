"""HTTP-layer tests for api.routers.dataset (prefix ``/api/dataset``).

The dataset router wraps ``mcp_server.tools`` for protocol/phase/run
discovery and dataset scanning. We point every settings-controlled
directory at ``tmp_path`` (mirroring ``test_api_sessions.py``) so the app
boots in isolation, then exercise the discovery endpoints against real
directories created under ``tmp_path``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from memdiver.api.config import get_settings
from memdiver.api.main import create_app


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
# GET /api/dataset/protocols
# ---------------------------------------------------------------------------


def test_list_protocols_non_empty(client):
    """The protocol registry returns a non-empty list under ``protocols``."""
    r = client.get("/api/dataset/protocols")
    assert r.status_code == 200, r.text
    body = r.json()
    assert "protocols" in body
    assert isinstance(body["protocols"], list)
    assert len(body["protocols"]) >= 1


# ---------------------------------------------------------------------------
# GET /api/dataset/runs
# ---------------------------------------------------------------------------


def test_list_runs_shape(client, isolated_env):
    """A root containing a run-style subdir returns a ``runs`` list."""
    root = isolated_env / "dataset_root"
    root.mkdir()
    # A directory named like a legacy run dir (<lib>_run_<ver>_<n>).
    (root / "openssl_run_3.3_1").mkdir()

    r = client.get("/api/dataset/runs", params={"root": str(root)})
    assert r.status_code == 200, r.text
    body = r.json()
    assert "runs" in body
    assert isinstance(body["runs"], list)


def test_list_runs_404_on_file(client, isolated_env):
    """Pointing ``root`` at a plain file (not a dir) yields 404."""
    f = isolated_env / "not_a_dir.txt"
    f.write_text("hello")

    r = client.get("/api/dataset/runs", params={"root": str(f)})
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# GET /api/dataset/phases
# ---------------------------------------------------------------------------


def test_list_phases_shape_or_graceful(client, isolated_env):
    """A library dir returns phases/runs keys, or a graceful error dict."""
    lib = isolated_env / "openssl_lib"
    lib.mkdir()

    r = client.get("/api/dataset/phases", params={"library_dir": str(lib)})
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body, dict)
    # Either the success shape (phases + runs) or a graceful error.
    assert ("phases" in body and "runs" in body) or "error" in body


# ---------------------------------------------------------------------------
# POST /api/dataset/scan
# ---------------------------------------------------------------------------


def test_scan_minimal_root(client, isolated_env):
    """Scanning a minimal dataset root returns 200 with a dict body."""
    root = isolated_env / "scan_root"
    root.mkdir()

    r = client.post("/api/dataset/scan", json={"root": str(root)})
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body, dict)


# ---------------------------------------------------------------------------
# GET /api/dataset/runs -- _iter_run_dirs branch coverage
# ---------------------------------------------------------------------------


def test_list_runs_root_itself_is_run_dir(client, isolated_env):
    """When ``root`` itself parses as a legacy run dir, it is the sole run."""
    root = isolated_env / "openssl_run_33_1"
    root.mkdir()

    r = client.get("/api/dataset/runs", params={"root": str(root)})
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["runs"]) == 1
    entry = body["runs"][0]
    assert entry["path"] == str(root)
    assert entry["meta"] is None
    assert entry["dumps"] == []


def test_list_runs_skips_hidden_dirs(client, isolated_env):
    """A dot-prefixed child directory is never treated as a run, even if its
    name would otherwise parse as a legacy run dir."""
    root = isolated_env / "dataset_root_hidden"
    root.mkdir()
    (root / ".hidden_run_33_1").mkdir()

    r = client.get("/api/dataset/runs", params={"root": str(root)})
    assert r.status_code == 200, r.text
    assert r.json()["runs"] == []


def test_list_runs_legacy_child_with_dump_and_meta(client, isolated_env):
    """A legacy-named child run dir with a real dump + meta.json is fully
    shaped: dumps carry path/kind/size/phase, meta carries the parsed fields."""
    root = isolated_env / "dataset_root_populated"
    root.mkdir()
    run_dir = root / "openssl_run_33_1"
    run_dir.mkdir()
    dump_bytes = b"\x00" * 128
    (run_dir / "session.msl").write_bytes(dump_bytes)
    meta_payload = {
        "run_id": "openssl_run_33_1",
        "cipher": "aes-128-gcm",
        "password": "hunter2",
        "master_key_hex": "aa" * 16,
        "aslr_base": "0x400000",
        "pid": 4242,
        "dumps": {"msl": {"path": "openssl_run_33_1/session.msl", "size": len(dump_bytes)}},
    }
    (run_dir / "meta.json").write_text(json.dumps(meta_payload))

    r = client.get("/api/dataset/runs", params={"root": str(root)})
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["runs"]) == 1
    entry = body["runs"][0]
    assert entry["path"] == str(run_dir)
    assert entry["meta"]["cipher"] == "aes-128-gcm"
    assert entry["meta"]["master_key"] == "aa" * 16
    assert entry["meta"]["dumps"]["msl"]["size"] == len(dump_bytes)
    assert len(entry["dumps"]) == 1
    assert entry["dumps"][0]["kind"] == "msl"
    assert entry["dumps"][0]["size"] == len(dump_bytes)
    assert entry["dumps"][0]["phase"] == "full_msl"


def test_list_runs_dataset_style_child_without_legacy_name(client, isolated_env):
    """A child dir that doesn't match the legacy ``<lib>_run_<v>_<n>`` name is
    still surfaced when it looks like a dataset run (meta.json + known dump
    suffix)."""
    root = isolated_env / "dataset_root_style"
    root.mkdir()
    run_dir = root / "run_0001"
    run_dir.mkdir()
    dump_bytes = b"\xab" * 64
    (run_dir / "capture.gcore.core").write_bytes(dump_bytes)
    (run_dir / "meta.json").write_text(json.dumps({
        "run_id": "run_0001",
        "cipher": "chacha20-poly1305",
        "password": "pw",
        "master_key_hex": "bb" * 8,
        "aslr_base": 0,
        "pid": 999,
        "dumps": {},
    }))

    r = client.get("/api/dataset/runs", params={"root": str(root)})
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["runs"]) == 1
    entry = body["runs"][0]
    assert entry["path"] == str(run_dir)
    assert entry["meta"]["cipher"] == "chacha20-poly1305"
    assert len(entry["dumps"]) == 1
    assert entry["dumps"][0]["kind"] == "gcore"


# ---------------------------------------------------------------------------
# _load_run_entry -- direct unit tests for the load_run_meta fallback branch
# ---------------------------------------------------------------------------


def test_load_run_entry_meta_fallback_when_discovery_returns_none(tmp_path, monkeypatch):
    """When ``RunDiscovery.load_run_directory`` can't classify the directory
    (returns ``None``) but a ``meta.json`` is present, ``_load_run_entry``
    falls back to a minimal synthesised :class:`RunDirectory`."""
    from memdiver.api.routers.dataset import _load_run_entry
    from memdiver.core.discovery import RunDiscovery

    run_dir = tmp_path / "opaque_run"
    run_dir.mkdir()
    (run_dir / "meta.json").write_text(json.dumps({
        "run_id": "opaque",
        "cipher": "aes-256-gcm",
        "password": "pw",
        "master_key_hex": "cc" * 4,
        "aslr_base": "0x1000",
        "pid": 55,
        "dumps": {},
    }))

    monkeypatch.setattr(RunDiscovery, "load_run_directory", staticmethod(lambda *a, **k: None))

    result = _load_run_entry(run_dir)

    assert result is not None
    assert result["path"] == str(run_dir)
    assert result["meta"]["run_id"] == "opaque"
    assert result["meta"]["cipher"] == "aes-256-gcm"
    assert result["dumps"] == []


def test_load_run_entry_returns_none_when_unclassifiable(tmp_path, monkeypatch):
    """When ``RunDiscovery`` can't classify the directory and there's no
    ``meta.json`` either, ``_load_run_entry`` returns ``None`` so the caller
    silently skips it."""
    from memdiver.api.routers.dataset import _load_run_entry
    from memdiver.core.discovery import RunDiscovery

    run_dir = tmp_path / "nothing_here"
    run_dir.mkdir()

    monkeypatch.setattr(RunDiscovery, "load_run_directory", staticmethod(lambda *a, **k: None))

    assert _load_run_entry(run_dir) is None


# ---------------------------------------------------------------------------
# _dump_to_dict -- direct unit tests
# ---------------------------------------------------------------------------


def test_dump_to_dict_existing_file(tmp_path):
    """A dump file that exists on disk reports its real size."""
    from memdiver.api.routers.dataset import _dump_to_dict
    from memdiver.core.models import DumpFile

    f = tmp_path / "region.gdb_raw.bin"
    f.write_bytes(b"\x01" * 10)
    dump = DumpFile(path=f, timestamp="", phase_prefix="full", phase_name="gdb_raw", kind="gdb_raw")

    result = _dump_to_dict(dump)

    assert result == {
        "path": str(f),
        "kind": "gdb_raw",
        "size": 10,
        "phase": "full_gdb_raw",
    }


def test_dump_to_dict_stat_oserror_yields_zero_size():
    """An ``OSError`` raised while stat-ing the dump path is swallowed and
    reported as size 0 rather than propagating to the caller."""
    from memdiver.api.routers.dataset import _dump_to_dict
    from memdiver.core.models import DumpFile

    class _ExplodingPath:
        """Duck-types ``Path`` just enough to force the except branch."""

        def exists(self):
            return True

        def stat(self):
            raise OSError("permission denied")

        def __str__(self):
            return "/fake/exploding/path"

    dump = DumpFile(
        path=_ExplodingPath(), timestamp="", phase_prefix="full",
        phase_name="msl", kind="msl",
    )

    result = _dump_to_dict(dump)

    assert result["size"] == 0
    assert result["path"] == "/fake/exploding/path"


# ---------------------------------------------------------------------------
# _meta_to_dict -- direct unit tests
# ---------------------------------------------------------------------------


def test_meta_to_dict_none_returns_none():
    """``None`` meta (legacy runs without meta.json) serialises to ``None``."""
    from memdiver.api.routers.dataset import _meta_to_dict

    assert _meta_to_dict(None) is None


def test_meta_to_dict_non_dataclass_returns_none():
    """A non-dataclass value is rejected defensively rather than crashing."""
    from memdiver.api.routers.dataset import _meta_to_dict

    assert _meta_to_dict(object()) is None


def test_meta_to_dict_full_payload():
    """A real :class:`DatasetMeta` serialises with hex master key, string
    source_path, and a dumps sub-dict keyed by dump kind."""
    from memdiver.api.routers.dataset import _meta_to_dict
    from memdiver.core.dataset_metadata import DatasetMeta, DumpRef

    meta = DatasetMeta(
        run_id="run1",
        cipher="aes-128-gcm",
        password="hunter2",
        master_key_hex="aabb",
        master_key=b"\xaa\xbb",
        aslr_base=0x400000,
        pid=1234,
        dumps={"gcore": DumpRef(path=Path("/tmp/x.core"), size=42)},
        source_path=Path("/tmp/meta.json"),
    )

    result = _meta_to_dict(meta)

    assert result["run_id"] == "run1"
    assert result["master_key"] == "aabb"
    assert result["source_path"] == str(Path("/tmp/meta.json"))
    assert result["dumps"] == {"gcore": {"path": str(Path("/tmp/x.core")), "size": 42}}


# ---------------------------------------------------------------------------
# GET /api/dataset/runs -- the ``capture`` block
#
# ``load_run_directory`` populates ``RunDirectory.capture_path`` /
# ``capture_status``; the endpoint used to discard both, so the run<->capture
# correlation reached no surface at all and "unreadable" was unobservable.
# ---------------------------------------------------------------------------


def _run_with_capture(root: Path, name: str, capture_bytes: bytes | None) -> Path:
    """A legacy-named run dir, optionally with ``run_data/traffic.pcap``."""
    from memdiver.core.discovery import CAPTURE_SUBDIR

    run_dir = root / name
    run_dir.mkdir(parents=True)
    (run_dir / "20240101_120000_000001_pre_handshake.dump").write_bytes(b"\x00" * 64)
    if capture_bytes is not None:
        capture_dir = run_dir / CAPTURE_SUBDIR
        capture_dir.mkdir()
        (capture_dir / "traffic.pcap").write_bytes(capture_bytes)
    return run_dir


def test_list_runs_capture_present(client, isolated_env):
    """A run owning a non-empty capture reports its path and ``present``."""
    root = isolated_env / "capture_present_root"
    run_dir = _run_with_capture(root, "openssl_run_13_1", b"\xd4\xc3\xb2\xa1")

    r = client.get("/api/dataset/runs", params={"root": str(root)})
    assert r.status_code == 200, r.text
    capture = r.json()["runs"][0]["capture"]
    assert capture["status"] == "present"
    assert capture["path"] == str(run_dir / "run_data" / "traffic.pcap")


def test_list_runs_capture_absent(client, isolated_env):
    """No capture -> ``absent`` with a null path (never omitted)."""
    root = isolated_env / "capture_absent_root"
    _run_with_capture(root, "openssl_run_13_2", None)

    r = client.get("/api/dataset/runs", params={"root": str(root)})
    assert r.status_code == 200, r.text
    capture = r.json()["runs"][0]["capture"]
    assert capture == {"path": None, "status": "absent"}


def test_list_runs_capture_unreadable(client, isolated_env):
    """A zero-byte capture is surfaced as ``unreadable``, not ``absent``.

    This is the state that no consumer could observe before the endpoint
    forwarded the fields.
    """
    root = isolated_env / "capture_unreadable_root"
    run_dir = _run_with_capture(root, "openssl_run_13_3", b"")

    r = client.get("/api/dataset/runs", params={"root": str(root)})
    assert r.status_code == 200, r.text
    capture = r.json()["runs"][0]["capture"]
    assert capture["status"] == "unreadable"
    # The offending file is still named so the operator can find it.
    assert capture["path"] == str(run_dir / "run_data" / "traffic.pcap")


def test_list_runs_capture_from_meta_declaration(client, isolated_env):
    """A ``capture`` key in meta.json is honoured end-to-end over HTTP."""
    root = isolated_env / "capture_meta_root"
    run_dir = root / "openssl_run_13_4"
    run_dir.mkdir(parents=True)
    (run_dir / "test_capture.msl").write_bytes(b"MSL0" + b"\x00" * 44)
    (run_dir / "pcaps").mkdir()
    (run_dir / "pcaps" / "session.pcapng").write_bytes(b"\x0a\x0d\x0d\x0a")
    (run_dir / "meta.json").write_text(
        json.dumps(
            {
                "run_id": "openssl_run_13_4",
                "cipher": "AES-256-GCM",
                "password": "pw",
                "master_key_hex": "ab" * 32,
                "aslr_base": 0,
                "pid": 1,
                "dumps": {},
                "capture": "pcaps/session.pcapng",
            }
        )
    )

    r = client.get("/api/dataset/runs", params={"root": str(root)})
    assert r.status_code == 200, r.text
    capture = r.json()["runs"][0]["capture"]
    assert capture["status"] == "present"
    assert capture["path"] == str(run_dir / "pcaps" / "session.pcapng")


def test_list_runs_capture_on_meta_only_fallback_entry(isolated_env, monkeypatch):
    """The hand-built meta-only fallback entry also carries a capture block.

    ``_load_run_entry`` rebuilds a ``RunDirectory`` by hand when
    ``load_run_directory`` declines the directory; that path must probe too, or
    it would report ``absent`` for a run that plainly owns a capture.
    """
    from memdiver.api.routers.dataset import _load_run_entry
    from memdiver.core.discovery import RunDiscovery

    run_dir = isolated_env / "not_a_run_shape"
    run_dir.mkdir()
    (run_dir / "meta.json").write_text(
        json.dumps(
            {
                "run_id": "x",
                "cipher": "c",
                "password": "p",
                "master_key_hex": "aa" * 16,
                "aslr_base": 0,
                "pid": 1,
                "dumps": {},
            }
        )
    )
    (run_dir / "run_data").mkdir()
    (run_dir / "run_data" / "traffic.pcap").write_bytes(b"\xd4\xc3\xb2\xa1")

    # Force the fallback branch: the real loader accepts this directory (it has
    # a meta.json), so stub it out to drive the meta-only reconstruction.
    monkeypatch.setattr(
        RunDiscovery, "load_run_directory", staticmethod(lambda *a, **k: None)
    )
    entry = _load_run_entry(run_dir)
    assert entry is not None
    assert entry["dumps"] == []  # proof we took the hand-built fallback
    assert entry["capture"]["status"] == "present"
    assert entry["capture"]["path"] == str(run_dir / "run_data" / "traffic.pcap")
