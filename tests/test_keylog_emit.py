"""Tests for NSS key-log emission (core.keylog.format_keylog_lines / write_keylog)."""

from memdiver.core.keylog import KeylogParser, format_keylog_lines, write_keylog
from memdiver.core.models import CryptoSecret


def _secret(t, ident, val):
    return CryptoSecret(secret_type=t, identifier=bytes.fromhex(ident),
                        secret_value=bytes.fromhex(val))


CR = "00" * 32


def test_format_single_line():
    s = _secret("CLIENT_RANDOM", CR, "ab" * 48)
    out = format_keylog_lines([s])
    assert out == f"CLIENT_RANDOM {CR} {'ab' * 48}\n"


def test_format_skips_empty_and_dedupes():
    good = _secret("CLIENT_TRAFFIC_SECRET_0", CR, "cd" * 32)
    empty = CryptoSecret(secret_type="", identifier=b"", secret_value=b"")
    out = format_keylog_lines([good, good, empty])
    assert out.count("\n") == 1  # dedup + skip empty


def test_empty_input_is_empty_string():
    assert format_keylog_lines([]) == ""


def test_roundtrip_emit_then_parse(tmp_path):
    """A written key log parses back to the same secrets (Wireshark-compatible)."""
    secrets = [
        _secret("CLIENT_RANDOM", CR, "11" * 48),
        _secret("CLIENT_TRAFFIC_SECRET_0", "22" * 32, "33" * 32),
        _secret("SERVER_TRAFFIC_SECRET_0", "22" * 32, "44" * 32),
    ]
    path = tmp_path / "keys.log"
    n = write_keylog(secrets, path)
    assert n == 3
    # Parser reads a CSV with a 'line' column; wrap each emitted line so we can
    # prove the emitted content is itself valid NSS keylog content.
    raw = path.read_text().splitlines()
    csv_path = tmp_path / "keys.csv"
    csv_path.write_text("line\n" + "\n".join(raw) + "\n")
    parsed = KeylogParser.parse(csv_path)
    assert {(p.secret_type, p.secret_value) for p in parsed} == {
        (s.secret_type, s.secret_value) for s in secrets
    }
