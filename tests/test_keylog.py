"""Tests for core.keylog module.

Covers KeylogParser.parse with missing files, empty files, malformed lines,
valid TLS 1.2/1.3 entries, template filtering, and deduplication.
"""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.keylog import KeylogParser


def _write_csv(lines):
    """Write keylog lines to a temp CSV and return its Path.

    Each entry in 'lines' becomes a row under the 'line' column header.
    """
    f = tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False)
    f.write("line\n")
    for line in lines:
        f.write(line + "\n")
    f.close()
    return Path(f.name)


# Hex helpers: 64 hex chars = 32 bytes
_CR_HEX = "aa" * 32   # client_random
_SECRET_HEX = "bb" * 32  # secret value


def test_parse_file_not_found():
    """Nonexistent path returns empty list."""
    result = KeylogParser.parse(Path("/tmp/nonexistent_keylog_12345.csv"))
    assert result == []


def test_parse_empty_file():
    """CSV with only header row returns empty list."""
    path = _write_csv([])
    try:
        result = KeylogParser.parse(path)
        assert result == []
    finally:
        os.unlink(path)


def test_parse_malformed_lines():
    """Lines with wrong number of parts are skipped."""
    path = _write_csv([
        "ONLY_ONE_PART",
        "TWO PARTS",
        "FOUR PARTS HERE NOW",
    ])
    try:
        result = KeylogParser.parse(path)
        assert result == []
    finally:
        os.unlink(path)


def test_parse_valid_client_random():
    """Valid CLIENT_RANDOM line produces one TLSSecret."""
    line = f"CLIENT_RANDOM {_CR_HEX} {_SECRET_HEX}"
    path = _write_csv([line])
    try:
        result = KeylogParser.parse(path)
        assert len(result) == 1
        assert result[0].secret_type == "CLIENT_RANDOM"
        assert result[0].client_random == bytes.fromhex(_CR_HEX)
        assert result[0].secret_value == bytes.fromhex(_SECRET_HEX)
    finally:
        os.unlink(path)


def test_parse_tls13_types():
    """All 5 TLS 1.3 secret types are parsed correctly."""
    tls13_types = [
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_TRAFFIC_SECRET_0",
        "SERVER_TRAFFIC_SECRET_0",
        "EXPORTER_SECRET",
    ]
    lines = [f"{stype} {_CR_HEX} {_SECRET_HEX}" for stype in tls13_types]
    path = _write_csv(lines)
    try:
        result = KeylogParser.parse(path)
        assert len(result) == 5
        parsed_types = {s.secret_type for s in result}
        assert parsed_types == set(tls13_types)
    finally:
        os.unlink(path)


def test_parse_template_filtering():
    """Template with secret_types={'CLIENT_RANDOM'} ignores TLS 1.3 lines."""

    class MockTemplate:
        secret_types = {"CLIENT_RANDOM"}

    lines = [
        f"CLIENT_RANDOM {_CR_HEX} {_SECRET_HEX}",
        f"EXPORTER_SECRET {_CR_HEX} {_SECRET_HEX}",
        f"CLIENT_HANDSHAKE_TRAFFIC_SECRET {_CR_HEX} {_SECRET_HEX}",
    ]
    path = _write_csv(lines)
    try:
        result = KeylogParser.parse(path, template=MockTemplate())
        assert len(result) == 1
        assert result[0].secret_type == "CLIENT_RANDOM"
    finally:
        os.unlink(path)


def test_parse_dedup():
    """Two identical lines produce only one secret (deduplicated)."""
    line = f"CLIENT_RANDOM {_CR_HEX} {_SECRET_HEX}"
    path = _write_csv([line, line])
    try:
        result = KeylogParser.parse(path)
        assert len(result) == 1
    finally:
        os.unlink(path)
