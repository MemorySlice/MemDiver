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
