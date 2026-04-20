"""Tests for core.keylog_templates module.

Covers get_template, list_template_names, and secret type counts
for TLS 1.2, TLS 1.3, and Auto-detect presets.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.keylog_templates import get_template, list_template_names


def test_get_template_tls12():
    """TLS 1.2 template contains only CLIENT_RANDOM."""
    tmpl = get_template("TLS 1.2")
    assert tmpl is not None
    assert tmpl.secret_types == {"CLIENT_RANDOM"}


def test_get_template_nonexistent():
    """Nonexistent template name returns None."""
    assert get_template("nonexistent") is None


def test_list_template_names_auto_first():
    """Auto-detect is the first entry in the template name list."""
    names = list_template_names()
    assert names[0] == "Auto-detect"


def test_template_type_counts():
    """TLS 1.2 has 1 type, TLS 1.3 has 5, SSH 2 has 4, Auto-detect has 10."""
    tls12 = get_template("TLS 1.2")
    tls13 = get_template("TLS 1.3")
    ssh2 = get_template("SSH 2")
    auto = get_template("Auto-detect")
    assert len(tls12.secret_types) == 1
    assert len(tls13.secret_types) == 5
    assert len(ssh2.secret_types) == 4
    assert len(auto.secret_types) == 11  # 1 + 5 + 4 + 1 (AES256_KEY)
