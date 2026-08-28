"""Tests for core.keylog module.

Covers KeylogParser.parse with missing files, empty files, malformed lines,
valid TLS 1.2/1.3 entries, template filtering, and deduplication; plus
parse_keylog_with_status, which reports WHY a result looks the way it does so a
parse failure is never mistaken for a session that logged nothing.
"""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from memdiver.core.keylog import (
    KEYLOG_STATUS_MISSING,
    KEYLOG_STATUS_OK,
    KEYLOG_STATUS_PARTIAL,
    KEYLOG_STATUS_UNREADABLE,
    KEYLOG_STATUSES,
    KeylogParser,
    parse_keylog_with_status,
)


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


# --------------------------------------------------------------------------- #
# parse_keylog_with_status
#
# KeylogParser.parse flattens every failure into a (possibly empty) list, so an
# unreadable key log is indistinguishable from a session that genuinely logged
# nothing. Downstream that difference decides whether a survival cell reads
# "absent" or "not observed", so it must be typed.
# --------------------------------------------------------------------------- #

def _write_real_shape_csv(rows):
    """Write the REAL corpus CSV shape: header ``id,line``, type inside ``line``."""
    f = tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False)
    f.write("id,line\n")
    for i, line in enumerate(rows, start=1):
        f.write(f"{i},{line}\n")
    f.close()
    return Path(f.name)


def _write_text_csv(content: str) -> Path:
    """Write *content* verbatim (BOMs, blank first lines, no header at all)."""
    f = tempfile.NamedTemporaryFile(
        suffix=".csv", mode="w", encoding="utf-8", delete=False)
    f.write(content)
    f.close()
    return Path(f.name)


def test_statuses_are_the_documented_vocabulary():
    assert set(KEYLOG_STATUSES) == {"ok", "partial", "unreadable", "missing"}


def test_parse_with_status_ok_on_the_real_corpus_csv_shape():
    """Header is ``id,line`` and the secret type lives INSIDE the line field."""
    path = _write_real_shape_csv([f"CLIENT_RANDOM {_CR_HEX} {_SECRET_HEX}"])
    try:
        result = parse_keylog_with_status(path)
        assert result.status == KEYLOG_STATUS_OK
        assert result.ok
        assert result.secrets_available == 1
        assert result.rows_read == 1
        assert result.rows_malformed == 0
        assert result.secrets[0].secret_type == "CLIENT_RANDOM"
    finally:
        os.unlink(path)


def test_parse_with_status_missing_file_is_not_a_zero():
    result = parse_keylog_with_status(Path("/tmp/nonexistent_keylog_98765.csv"))
    assert result.status == KEYLOG_STATUS_MISSING
    assert result.secrets == []
    assert not result.ok


def test_parse_with_status_header_only_file_is_a_genuine_zero():
    """An empty-but-well-formed keylog really did log nothing — that is ``ok``."""
    path = _write_real_shape_csv([])
    try:
        result = parse_keylog_with_status(path)
        assert result.status == KEYLOG_STATUS_OK
        assert result.secrets_available == 0
    finally:
        os.unlink(path)


def test_parse_with_status_empty_file_is_unreadable():
    f = tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False)
    f.close()
    path = Path(f.name)
    try:
        result = parse_keylog_with_status(path)
        assert result.status == KEYLOG_STATUS_UNREADABLE
        assert "header" in result.detail
    finally:
        os.unlink(path)


def test_parse_with_status_missing_line_column_is_unreadable():
    f = tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False)
    f.write("id,payload\n1,CLIENT_RANDOM aa bb\n")
    f.close()
    path = Path(f.name)
    try:
        result = parse_keylog_with_status(path)
        assert result.status == KEYLOG_STATUS_UNREADABLE
        assert "line" in result.detail
    finally:
        os.unlink(path)


def test_parse_with_status_partial_on_a_malformed_row():
    path = _write_real_shape_csv([
        f"CLIENT_RANDOM {_CR_HEX} {_SECRET_HEX}",
        "CLIENT_RANDOM only-two",
        f"CLIENT_RANDOM {_CR_HEX} nothex!!",
    ])
    try:
        result = parse_keylog_with_status(path)
        assert result.status == KEYLOG_STATUS_PARTIAL
        assert result.secrets_available == 1
        assert result.rows_read == 3
        assert result.rows_malformed == 2
    finally:
        os.unlink(path)


def test_parse_with_status_template_filtering_is_not_malformed():
    """A line the template rejects is well formed — the file is still ``ok``."""

    class MockTemplate:
        secret_types = {"CLIENT_RANDOM"}

    path = _write_real_shape_csv([
        f"CLIENT_RANDOM {_CR_HEX} {_SECRET_HEX}",
        f"EXPORTER_SECRET {_CR_HEX} {_SECRET_HEX}",
    ])
    try:
        result = parse_keylog_with_status(path, template=MockTemplate())
        assert result.status == KEYLOG_STATUS_OK
        assert result.rows_malformed == 0
        assert result.secrets_available == 1
    finally:
        os.unlink(path)


def test_parse_with_status_deduplicates_like_parse():
    line = f"CLIENT_RANDOM {_CR_HEX} {_SECRET_HEX}"
    path = _write_real_shape_csv([line, line])
    try:
        result = parse_keylog_with_status(path)
        assert result.secrets_available == 1
        assert result.rows_read == 2
        assert result.status == KEYLOG_STATUS_OK
    finally:
        os.unlink(path)


def test_parse_still_swallows_every_failure_and_returns_hardcoded_secrets():
    """``parse``'s lossy contract, pinned to values rather than to itself.

    Deliberately NOT ``parse(path) == parse_keylog_with_status(path).secrets``:
    ``parse`` *is* that expression, so the comparison is ``x == x`` and cannot
    fail for any implementation. These are the shapes the status API types as
    ``partial`` / ``unreadable``; ``parse`` must keep flattening every one of
    them into a plain (possibly empty) list.
    """
    # A malformed row alongside a good one: the good one survives, the status is
    # thrown away.
    path = _write_real_shape_csv([
        f"CLIENT_RANDOM {_CR_HEX} {_SECRET_HEX}",
        "GARBAGE",
    ])
    try:
        secrets = KeylogParser.parse(path)
        assert len(secrets) == 1
        assert secrets[0].secret_type == "CLIENT_RANDOM"
        assert secrets[0].identifier == bytes.fromhex(_CR_HEX)
        assert secrets[0].secret_value == bytes.fromhex(_SECRET_HEX)
        assert parse_keylog_with_status(path).status == KEYLOG_STATUS_PARTIAL
    finally:
        os.unlink(path)

    # A missing file, a header with no ``line`` column, a headerless file and a
    # file that opens on a blank line all flatten to [].
    assert KeylogParser.parse(Path("/tmp/nonexistent_keylog_98765.csv")) == []
    for content in ("", "id,payload\n1,CLIENT_RANDOM aa bb\n",
                    f"\n1,CLIENT_RANDOM {_CR_HEX} {_SECRET_HEX}\n"):
        path = _write_text_csv(content)
        try:
            assert KeylogParser.parse(path) == []
            assert not parse_keylog_with_status(path).ok
        finally:
            os.unlink(path)


def test_parse_reads_a_bom_prefixed_keylog():
    """A UTF-8 BOM must not cost the file its ``line`` column.

    ``utf-8-sig`` strips the mark; without it the single column is named
    ``\ufeffline``, every row reads as blank, and the file types ``unreadable``.
    """
    path = _write_text_csv(
        "\ufeffline\n" f"CLIENT_RANDOM {_CR_HEX} {_SECRET_HEX}\n")
    try:
        secrets = KeylogParser.parse(path)
        assert len(secrets) == 1
        assert secrets[0].secret_type == "CLIENT_RANDOM"
        assert secrets[0].secret_value == bytes.fromhex(_SECRET_HEX)

        result = parse_keylog_with_status(path)
        assert result.status == KEYLOG_STATUS_OK
        assert (result.rows_read, result.rows_malformed) == (1, 0)
    finally:
        os.unlink(path)


# --------------------------------------------------------------------------- #
# Log surface
#
# ``parse`` runs once per run over a multi-thousand-run corpus, so a structural
# quirk shared by the whole corpus must not become one new WARNING per run from
# a path that was always silent. The status API keeps the richer diagnostics —
# its caller asked for them.
# --------------------------------------------------------------------------- #

def test_parse_stays_silent_on_the_structural_paths(caplog):
    """Only the two historical warnings may reach WARNING from ``parse``."""
    cases = [
        "",                                                    # 0-byte file
        "id,payload\n1,CLIENT_RANDOM aa bb\n",                 # no 'line' column
        f"\n1,CLIENT_RANDOM {_CR_HEX} {_SECRET_HEX}\n",         # leading blank line
        "\ufeffline\n" f"CLIENT_RANDOM {_CR_HEX} {_SECRET_HEX}\n",  # BOM
    ]
    for content in cases:
        path = _write_text_csv(content)
        try:
            with caplog.at_level("WARNING", logger="memdiver.keylog"):
                caplog.clear()
                KeylogParser.parse(path)
            assert caplog.text == "", f"parse warned on {content!r}: {caplog.text}"
        finally:
            os.unlink(path)


def test_parse_still_warns_that_the_file_is_missing(caplog):
    """One of the two warnings ``parse`` always emitted — unchanged."""
    with caplog.at_level("WARNING", logger="memdiver.keylog"):
        KeylogParser.parse(Path("/tmp/nonexistent_keylog_98765.csv"))
    assert "Keylog not found" in caplog.text


def test_parse_with_status_still_reports_the_structural_diagnostics(caplog):
    """The diagnostics are not lost — they belong to the API that types them."""
    path = _write_text_csv("id,payload\n1,CLIENT_RANDOM aa bb\n")
    try:
        with caplog.at_level("WARNING", logger="memdiver.keylog"):
            result = parse_keylog_with_status(path)
        assert "no 'line' column" in caplog.text
        assert result.status == KEYLOG_STATUS_UNREADABLE
    finally:
        os.unlink(path)


# --------------------------------------------------------------------------- #
# Unrecognised secret types (the silent-zero bug)
# --------------------------------------------------------------------------- #

def test_an_unrecognised_secret_type_is_malformed_not_merely_filtered():
    """REGRESSION: a wholly corrupted key log reported ``ok`` with zero secrets.

    ``_is_well_formed_keylog_line`` checked the two hex fields but never the
    type token, while ``_parse_line`` rejects the line on exactly that token. So
    every garbled type was classified "well formed, filtered by the template"
    and the file came back ``ok`` — and ``ok`` means "this session really did
    log this many secrets", i.e. a genuine zero.
    """
    path = _write_real_shape_csv([
        f"CLIENT_TRAFFIC_SECRET_0garbage1 {_CR_HEX} {_SECRET_HEX}",
        f"CLIENT_TRAFFIC_SECRET_0garbage2 {_CR_HEX} {_SECRET_HEX}",
        f"NOT_A_SECRET_TYPE {_CR_HEX} {_SECRET_HEX}",
    ])
    try:
        result = parse_keylog_with_status(path)
        assert result.status == KEYLOG_STATUS_PARTIAL
        assert not result.ok
        assert result.secrets_available == 0
        assert result.rows_read == 3
        assert result.rows_malformed == 3
    finally:
        os.unlink(path)


def test_a_filtered_type_and_an_unknown_type_are_told_apart():
    """The two reasons ``_parse_line`` returns ``None`` must not be conflated."""

    class MockTemplate:
        secret_types = {"CLIENT_RANDOM"}

    path = _write_real_shape_csv([
        f"CLIENT_RANDOM {_CR_HEX} {_SECRET_HEX}",        # kept
        f"EXPORTER_SECRET {_CR_HEX} {_SECRET_HEX}",      # known type, filtered
        f"BOGUS_SECRET {_CR_HEX} {_SECRET_HEX}",         # unknown type, malformed
    ])
    try:
        result = parse_keylog_with_status(path, template=MockTemplate())
        assert result.secrets_available == 1
        assert result.rows_read == 3
        assert result.rows_malformed == 1
        assert result.status == KEYLOG_STATUS_PARTIAL
    finally:
        os.unlink(path)


# --------------------------------------------------------------------------- #
# Aborted reads
# --------------------------------------------------------------------------- #

def test_a_mid_parse_failure_never_reports_clean_counters(monkeypatch, caplog):
    """REGRESSION: two genuinely lost secrets both read as ``rows_malformed=0``.

    The exception path returned the counters accumulated before the failure, so
    a truncated read handed back numbers a consumer reads as a clean parse. The
    row that was lost is charged, so the damage is at least visible.
    """
    path = _write_real_shape_csv([
        f"CLIENT_RANDOM {_CR_HEX} {_SECRET_HEX}",
        f"EXPORTER_SECRET {_CR_HEX} {_SECRET_HEX}",
        f"CLIENT_TRAFFIC_SECRET_0 {_CR_HEX} {_SECRET_HEX}",
    ])
    real_parse_line = KeylogParser._parse_line
    seen = []

    def exploding_parse_line(line, allowed_types=None):
        seen.append(line)
        if len(seen) == 2:
            raise RuntimeError("keylog read aborted")
        return real_parse_line(line, allowed_types=allowed_types)

    monkeypatch.setattr(
        KeylogParser, "_parse_line", staticmethod(exploding_parse_line))
    try:
        with caplog.at_level("WARNING", logger="memdiver.keylog"):
            result = parse_keylog_with_status(path)
        assert result.status == KEYLOG_STATUS_PARTIAL
        assert result.secrets_available == 1
        assert result.rows_read == 2            # the failing row was reached
        assert result.rows_malformed == 1       # ...and is charged as lost
        assert result.rows_malformed <= result.rows_read
        assert "at least 1 row lost" in result.detail
        assert "Error parsing" in caplog.text   # the second historical warning
    finally:
        os.unlink(path)


def test_a_failure_before_the_first_row_charges_no_rows(monkeypatch):
    """Nothing was lost that was ever there — the counters stay at zero."""
    path = _write_real_shape_csv([f"CLIENT_RANDOM {_CR_HEX} {_SECRET_HEX}"])

    def exploding_reader(*args, **kwargs):
        raise RuntimeError("reader exploded")

    import memdiver.core.keylog as keylog_module

    monkeypatch.setattr(keylog_module.csv, "DictReader", exploding_reader)
    try:
        result = parse_keylog_with_status(path)
        assert result.status == KEYLOG_STATUS_UNREADABLE
        assert (result.rows_read, result.rows_malformed) == (0, 0)
        assert "row lost" not in result.detail
    finally:
        os.unlink(path)


def test_parse_result_to_dict_is_json_serialisable():
    import json

    path = _write_real_shape_csv([f"CLIENT_RANDOM {_CR_HEX} {_SECRET_HEX}"])
    try:
        payload = parse_keylog_with_status(path).to_dict()
        assert payload["secret_types"] == ["CLIENT_RANDOM"]
        assert json.loads(json.dumps(payload)) == payload
    finally:
        os.unlink(path)
