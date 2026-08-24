"""Tests for the ``export.keylog`` capability (Wireshark NSS key-log export).

Covers the ``keylog_result`` producer end-to-end: it renders recovered secrets
into the NSS ``SSLKEYLOGFILE`` format, counts lines, optionally writes a file,
and raises ``CapabilityError`` (INVALID_INPUT) on malformed hex / missing keys.
A thin API-route test mirrors the sibling ``/auto-export`` coverage.
"""

from __future__ import annotations

import pytest

from memdiver.app.tools_pipeline import keylog_result
from memdiver.core.service_errors import CapabilityError, ErrorCategory


# A pair of well-formed CLIENT_RANDOM / secret dicts (hex strings).
_CR1 = "aa" * 32
_SECRET1 = "bb" * 48
_CR2 = "cc" * 32
_SECRET2 = "dd" * 48


def _secret(secret_type: str, client_random: str, secret: str) -> dict:
    return {"secret_type": secret_type, "client_random": client_random, "secret": secret}


def test_happy_path_line_count_and_content():
    """Two secrets → two NSS lines with the exact
    ``<LABEL> <client_random_hex> <secret_hex>`` shape and a trailing newline."""
    secrets = [
        _secret("CLIENT_HANDSHAKE_TRAFFIC_SECRET", _CR1, _SECRET1),
        _secret("SERVER_TRAFFIC_SECRET_0", _CR2, _SECRET2),
    ]
    result = keylog_result(secrets=secrets)

    assert result["count"] == 2
    assert result["output_path"] is None
    lines = result["keylog"].splitlines()
    assert lines == [
        f"CLIENT_HANDSHAKE_TRAFFIC_SECRET {_CR1} {_SECRET1}",
        f"SERVER_TRAFFIC_SECRET_0 {_CR2} {_SECRET2}",
    ]
    # The body ends in a newline (Wireshark-friendly).
    assert result["keylog"].endswith("\n")


def test_empty_secrets_yields_zero_count_and_empty_body():
    result = keylog_result(secrets=[])
    assert result["count"] == 0
    assert result["keylog"] == ""
    assert result["output_path"] is None


def test_output_path_writes_file(tmp_path):
    """When ``output_path`` is given the key log is written there verbatim and
    the returned ``output_path`` echoes the request."""
    out = tmp_path / "session.keylog"
    secrets = [_secret("CLIENT_RANDOM", _CR1, _SECRET1)]

    result = keylog_result(secrets=secrets, output_path=str(out))

    assert result["output_path"] == str(out)
    assert result["count"] == 1
    assert out.exists()
    assert out.read_text() == result["keylog"]
    assert out.read_text() == f"CLIENT_RANDOM {_CR1} {_SECRET1}\n"


def test_malformed_hex_raises_invalid_input():
    secrets = [_secret("CLIENT_RANDOM", "not-hex", _SECRET1)]
    with pytest.raises(CapabilityError) as exc_info:
        keylog_result(secrets=secrets)
    assert exc_info.value.category == ErrorCategory.INVALID_INPUT


def test_odd_length_hex_raises_invalid_input():
    # bytes.fromhex rejects odd-length strings.
    secrets = [_secret("CLIENT_RANDOM", _CR1, "abc")]
    with pytest.raises(CapabilityError) as exc_info:
        keylog_result(secrets=secrets)
    assert exc_info.value.category == ErrorCategory.INVALID_INPUT


def test_missing_key_raises_invalid_input():
    secrets = [{"secret_type": "CLIENT_RANDOM", "client_random": _CR1}]  # no 'secret'
    with pytest.raises(CapabilityError) as exc_info:
        keylog_result(secrets=secrets)
    assert exc_info.value.category == ErrorCategory.INVALID_INPUT


def test_non_dict_item_raises_invalid_input():
    with pytest.raises(CapabilityError) as exc_info:
        keylog_result(secrets=["just a string"])
    assert exc_info.value.category == ErrorCategory.INVALID_INPUT


def test_non_canonical_secret_type_raises_invalid_input():
    """A ``secret_type`` that is not a canonical NSS label (e.g. a cipher name)
    is rejected up front — otherwise it would produce a key log Wireshark cannot
    load."""
    secrets = [_secret("AES-256-CBC", _CR1, _SECRET1)]
    with pytest.raises(CapabilityError) as exc_info:
        keylog_result(secrets=secrets)
    assert exc_info.value.category == ErrorCategory.INVALID_INPUT


def test_all_canonical_labels_accepted():
    """Every canonical label across the protocol registry validates through the
    exporter (the same aggregate the key-log parser accepts)."""
    from memdiver.core.keylog import ALL_SECRET_TYPES

    secrets = [_secret(label, _CR1, _SECRET1) for label in sorted(ALL_SECRET_TYPES)]
    result = keylog_result(secrets=secrets)
    assert result["count"] == len(secrets)


def test_keylog_result_reexported_on_library_surface():
    """The producer is reachable via the public ``memdiver.services`` facade."""
    import memdiver.services as services

    assert "keylog_result" in services.__all__
    assert services.keylog_result is keylog_result


# ---------------------------------------------------------------------------
# API route — mirrors the sibling /auto-export + /verify-key coverage.
# ---------------------------------------------------------------------------


def _api_client():
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from memdiver.api.main import create_app

    del fastapi
    return TestClient(create_app())


def test_api_export_keylog_happy_path():
    client = _api_client()
    resp = client.post(
        "/api/analysis/export-keylog",
        json={"secrets": [_secret("CLIENT_RANDOM", _CR1, _SECRET1)]},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert body["keylog"] == f"CLIENT_RANDOM {_CR1} {_SECRET1}\n"
    assert body["output_path"] is None


def test_api_export_keylog_malformed_hex_returns_400():
    client = _api_client()
    resp = client.post(
        "/api/analysis/export-keylog",
        json={"secrets": [_secret("CLIENT_RANDOM", "zz", _SECRET1)]},
    )
    assert resp.status_code == 400
