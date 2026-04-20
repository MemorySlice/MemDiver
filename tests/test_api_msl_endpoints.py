"""Happy-path tests for the 10 new /api/inspect MSL table endpoints.

Covers the spec-defined table blocks (/module-index, /processes,
/connections, /handles) and the 6 speculative-layout ext endpoints
(/thread-contexts, /file-descriptors, /network-connections, /env-blocks,
/security-tokens, /system-context).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from fastapi.testclient import TestClient

from api.main import create_app
from tests.fixtures.generate_msl_fixtures import generate_msl_file


@pytest.fixture
def client():
    return TestClient(create_app())


@pytest.fixture
def msl_path(tmp_path):
    p = tmp_path / "inspect_test.msl"
    p.write_bytes(generate_msl_file())
    return str(p)


# -- Spec-defined table endpoints --

def test_get_module_index(client, msl_path):
    resp = client.get("/api/inspect/module-index", params={"msl_path": msl_path})
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 2
    assert data[0]["path"] == "/usr/lib/libssl.so"
    assert data[0]["base_addr"] == 0x00400000
    assert "module_uuid" in data[0]


def test_get_processes(client, msl_path):
    resp = client.get("/api/inspect/processes", params={"msl_path": msl_path})
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 2
    p0 = data[0]
    assert p0["pid"] == 1234
    assert p0["ppid"] == 1
    assert p0["uid"] == 1000
    assert p0["is_target"] is True
    assert p0["exe_name"] == "/usr/bin/target"
    assert p0["cmd_line"] == "target --flag"
    assert p0["user"] == "alice"


def test_get_connections(client, msl_path):
    resp = client.get("/api/inspect/connections", params={"msl_path": msl_path})
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 2
    c0 = data[0]
    assert c0["pid"] == 1234
    assert c0["family"] == 0x02  # AF_INET
    assert c0["protocol"] == 0x06  # TCP
    assert c0["local_addr"] == "127.0.0.1"
    assert c0["local_port"] == 443
    assert c0["remote_addr"] == "8.8.8.8"
    assert c0["remote_port"] == 55123
    c1 = data[1]
    assert c1["family"] == 0x0A  # AF_INET6
    # Spec-compliant v6 addr should format via ipaddress
    assert ":" in c1["local_addr"]


def test_get_handles(client, msl_path):
    resp = client.get("/api/inspect/handles", params={"msl_path": msl_path})
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 3
    assert data[0]["handle_type_name"] == "File"
    assert data[0]["path"] == "/var/log/target.log"
    assert data[1]["handle_type_name"] == "Socket"
    assert data[2]["handle_type_name"] == "Other"  # spec Table 24


# -- Ext (speculative) endpoints --

def test_get_thread_contexts(client, msl_path):
    resp = client.get("/api/inspect/thread-contexts", params={"msl_path": msl_path})
    assert resp.status_code == 200
    data = resp.json()
    assert data["spec_reserved"] is True
    assert "note" in data
    assert isinstance(data["entries"], list)
    assert len(data["entries"]) == 1


def test_get_file_descriptors(client, msl_path):
    resp = client.get("/api/inspect/file-descriptors", params={"msl_path": msl_path})
    assert resp.status_code == 200
    data = resp.json()
    assert data["spec_reserved"] is True
    assert len(data["entries"]) == 1


def test_get_network_connections(client, msl_path):
    resp = client.get("/api/inspect/network-connections", params={"msl_path": msl_path})
    assert resp.status_code == 200
    data = resp.json()
    assert data["spec_reserved"] is True
    assert len(data["entries"]) == 1


def test_get_env_blocks(client, msl_path):
    resp = client.get("/api/inspect/env-blocks", params={"msl_path": msl_path})
    assert resp.status_code == 200
    data = resp.json()
    assert data["spec_reserved"] is True
    assert len(data["entries"]) == 1


def test_get_security_tokens(client, msl_path):
    resp = client.get("/api/inspect/security-tokens", params={"msl_path": msl_path})
    assert resp.status_code == 200
    data = resp.json()
    assert data["spec_reserved"] is True
    assert len(data["entries"]) == 1


def test_get_system_context(client, msl_path):
    resp = client.get("/api/inspect/system-context", params={"msl_path": msl_path})
    assert resp.status_code == 200
    data = resp.json()
    assert data["incomplete"] is True
    assert len(data["entries"]) == 1


# -- Error paths --

def test_not_msl_suffix_rejected(client, tmp_path):
    not_msl = tmp_path / "file.dump"
    not_msl.write_bytes(b"not msl")
    for endpoint in ("module-index", "processes", "connections", "handles",
                     "thread-contexts", "file-descriptors",
                     "network-connections", "env-blocks", "security-tokens",
                     "system-context"):
        resp = client.get(f"/api/inspect/{endpoint}", params={"msl_path": str(not_msl)})
        assert resp.status_code == 400, endpoint


def test_missing_file_404(client, tmp_path):
    missing = tmp_path / "does_not_exist.msl"
    resp = client.get("/api/inspect/processes", params={"msl_path": str(missing)})
    assert resp.status_code == 404
