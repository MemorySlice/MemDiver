"""IOC precision: positive/negative samples per kind + DuckDB (RE2) vs Python parity."""

from __future__ import annotations

import duckdb
import pytest

from memdiver.analysis.queries import strings as q
from memdiver.analysis.queries.strings import IOC_PATTERNS, ioc_matches

B64 = "Zk9vQmFyMTIzNDU2Nzg5MGFiY2RlZg=="  # 32 chars, padded, mixed
POSITIVE = [
    ("ipv4", "connect 192.168.10.25:443 ok", ["192.168.10.25"]),
    ("ipv4", "10.0.0.1,10.0.0.2 0.0.0.0", ["10.0.0.1", "10.0.0.2", "0.0.0.0"]),
    ("base64", f"key={B64}", [B64]),
    ("base64", "Zk9vQmFyMTIzNDU2Nzg5MGFiY2RlZg", ["Zk9vQmFyMTIzNDU2Nzg5MGFiY2RlZg"]),
    ("hex_run", "id " + "ab" * 20, ["ab" * 20]),
    ("unix_paths", "open /etc/hosts now", ["/etc/hosts"]),
    ("unix_paths", "dir /tmp", ["/tmp"]),
    ("unix_paths", "/opt/openssl/lib64/", ["/opt/openssl/lib64/"]),
]
NEGATIVE = [
    ("ipv4", "1.2.840.113549"), ("ipv4", "3.0.13.1.2"), ("ipv4", "v1.2.3.4"),
    ("ipv4", "1.2.3.4.5"), ("ipv4", "256.1.1.1"), ("ipv4", "01.2.3.4"), ("ipv4", "1.2.3"),
    ("ipv4", "1.2.3.4-beta"),
    ("base64", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"),
    ("base64", "0123456789abcdef0123456789abcdef"),         # pure hex
    ("base64", "extendedCertificateAttributes"),            # identifier, no digit
    ("base64", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),               # one class
    ("base64", "providers/implementations/kdfs/hkdf"),      # relative path
    ("base64", "Zk9vQmFyMTIzNDU2Nzg5MGFiY2RlZg="),          # bad padding length
    ("base64", "Zk9vQmFyMTIz"),                             # too short
    ("hex_run", "ab" * 15), ("hex_run", "a" * 33), ("hex_run", "ab" * 20 + "zz"),
    ("unix_paths", "https://host.example/a/b/c"),
    ("unix_paths", "crypto/dsa/dsa_check.c"),
    ("unix_paths", "/etcetera"), ("unix_paths", "/foo"), ("unix_paths", "/1/2/3"),
    ("unix_paths", "text/html"),
]


@pytest.mark.parametrize("kind,text,expected", POSITIVE)
def test_positive_samples(kind, text, expected):
    assert ioc_matches(text).get(kind) == expected


@pytest.mark.parametrize("kind,text", NEGATIVE)
def test_negative_samples(kind, text):
    assert kind not in ioc_matches(text), text


def test_url_path_not_double_counted_but_url_is():
    hits = ioc_matches("see https://host.example/a/b/c and /var/log/syslog")
    assert hits["unix_paths"] == ["/var/log/syslog"] and len(hits["urls"]) == 1


def test_sql_and_python_agree_on_every_sample():
    texts = [t for _, t, _ in POSITIVE] + [t for _, t in NEGATIVE]
    con = duckdb.connect()
    con.execute("CREATE TABLE strings(capture_id VARCHAR, addr BIGINT, space VARCHAR, "
                "encoding VARCHAR, region_path VARCHAR, value VARCHAR)")
    con.executemany("INSERT INTO strings VALUES ('c', 0, 's', 'ascii', NULL, ?)",
                    [(t,) for t in texts])
    cols = list(IOC_PATTERNS)
    sql = q._sql().replace("DISTINCT * FROM", "DISTINCT * FROM", 1)
    rows = {r[5]: dict(zip(cols, r[6:])) for r in con.execute(sql).fetchall()}
    for text in texts:
        py = ioc_matches(text)
        db = {k: v for k, v in rows.get(text, {}).items() if v}
        assert db == py, text


@pytest.mark.parametrize("text,prefix", [
    ("1.3.6.1", "1.3.6.1"), ("oid 1.3.101.110", "1.3.101"), ("1.3.101.112", "1.3.101"),
    ("2.5.4.10", "2.5.4"), ("2.5.29.15", "2.5.29"), ("1.3.132.0", "1.3.132"),
])
def test_oid_shaped_ipv4_is_kept_but_flagged(text, prefix):
    from memdiver.analysis.queries.strings import ioc_ambiguity
    assert "ipv4" in ioc_matches(text)                      # never dropped
    assert ioc_ambiguity(text) == ("oid_like", prefix)


@pytest.mark.parametrize("text", ["192.168.1.10", "8.8.8.8", "10.0.0.1", "1.50.1.1", "3.5.4.10"])
def test_real_ipv4_is_not_flagged(text):
    from memdiver.analysis.queries.strings import ioc_ambiguity
    assert "ipv4" in ioc_matches(text)
    assert ioc_ambiguity(text) is None


def test_mixed_row_is_not_ambiguous_but_lists_oid_like_values():
    from memdiver.analysis.queries.strings import ioc_ambiguity, oid_like_values
    text = "peer 8.8.8.8 oid 1.3.6.1"
    assert ioc_ambiguity(text) is None
    assert oid_like_values(text) == [("1.3.6.1", "1.3.6.1")]
    assert ioc_ambiguity("oid 1.3.6.1 and 2.5.4.10") == ("oid_like", "1.3.6.1")


def test_unmatchable_840_prefixes_are_not_registered():
    from memdiver.analysis.queries.strings import OID_PREFIXES, ioc_ambiguity
    assert "1.2.840" not in OID_PREFIXES and "2.16.840" not in OID_PREFIXES
    assert ioc_ambiguity("1.2.840.113549") is None


def test_row_of_carries_oid_like_values():
    from types import SimpleNamespace as NS
    from memdiver.app.tools_strings import _row_of
    plan = NS(location=lambda a: NS(space=NS(value="raw"), to_dict=lambda: {}))
    seg = NS(addr=0, va=None, vas=0)
    regions = NS(at=lambda va: None)
    match = NS(offset=0, value="peer 8.8.8.8 oid 1.3.6.1", encoding="ascii", length=24)
    row = _row_of(plan, seg, 0, match, regions)
    assert row["ambiguity"] is None and row["oid_prefix"] is None
    assert row["oid_like_values"] == [{"value": "1.3.6.1", "oid_prefix": "1.3.6.1"}]
