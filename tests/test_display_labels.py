"""Tests for core.display_labels module.

Covers get_display_label and get_short_label for TLS 1.2, TLS 1.3,
and unknown/fallback cases.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.display_labels import get_display_label, get_short_label


def test_display_label_client_random():
    """CLIENT_RANDOM with TLS 1.2 returns 'Master Secret (via CLIENT_RANDOM)'."""
    assert get_display_label("CLIENT_RANDOM", "12") == "Master Secret (via CLIENT_RANDOM)"


def test_display_labels_tls13():
    """All 5 TLS 1.3 display labels are correct."""
    expected = {
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET": "Client Handshake Traffic Secret",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET": "Server Handshake Traffic Secret",
        "CLIENT_TRAFFIC_SECRET_0": "Client Traffic Secret 0",
        "SERVER_TRAFFIC_SECRET_0": "Server Traffic Secret 0",
        "EXPORTER_SECRET": "Exporter Secret",
    }
    for secret_type, expected_label in expected.items():
        assert get_display_label(secret_type, "13") == expected_label


def test_display_label_unknown_fallback():
    """Unknown secret type / version pair falls back to the raw secret_type."""
    assert get_display_label("UNKNOWN_TYPE", "99") == "UNKNOWN_TYPE"


def test_short_labels_tls13():
    """Short labels for all TLS 1.3 types match expected values."""
    expected = {
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET": "Client HTS",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET": "Server HTS",
        "CLIENT_TRAFFIC_SECRET_0": "Client TS0",
        "SERVER_TRAFFIC_SECRET_0": "Server TS0",
        "EXPORTER_SECRET": "Exporter",
    }
    for secret_type, expected_label in expected.items():
        assert get_short_label(secret_type, "13") == expected_label
