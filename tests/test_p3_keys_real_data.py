"""P3 proof gate (plan T3.5): key finders -> case lake join, on REAL dumps.

AES leg  - TLS 1.3 corpus (``MEMDIVER_TLS_CORPUS`` = ``.../experiment2_tls_local/data``):
    the AES traffic keys derived from the run's keylog (HKDF-Expand-Label "key") are
    recovered from the ``.msl`` as forward AES key schedules; for openssl_run_13_1 the
    same hits are exported to a case and joined key_hits x heap_chunks x msl_regions.
RSA leg  - Cumulus avml image (``MEMDIVER_IMAGE_CORPUS`` = pakunoda ``dumps/acquired``):
    nginx master pid 2414 -> ``image extract`` -> ``rsa_factor`` finds both primes
    (p * q == n, distinct VAs) -> the same join lands both in in_use user_data chunks
    of ``[heap]``.

Both legs skip cleanly without their env var. Measured: AES ~0.5 s per scan, ~0.7 s join;
RSA leg ~9 s (extract + scan + join); whole file ~22 s.
"""

import glob
import os
from pathlib import Path

import pytest

from memdiver.app.tools_case import case_export_result, case_init_result, case_query_result
from memdiver.app.tools_image import image_extract_process_result
from memdiver.app.tools_keyfinders import keyfinders_scan_result
from memdiver.core.dump_source import open_dump
from memdiver.core.image.view_descriptor import ProfileRef, ViewDescriptor, ViewKind
from memdiver.core.kdf import TLS13HKDF

_TLS = os.environ.get("MEMDIVER_TLS_CORPUS", "")
TLS_ROOT = Path(_TLS) / "TLS13" if _TLS else None
_IMG = os.environ.get("MEMDIVER_IMAGE_CORPUS", "")
IMAGE_ROOT = Path(_IMG) if _IMG else None

CUMULUS = "cumulus-5.10.0_6.1.0-cl-1-amd64_avml"
NGINX_PID = 2414
SHA = "d5" * 32
TRAFFIC_LABELS = ("CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0")
#: (hash, key bytes) of the negotiated AES-GCM suite per library (measured on the corpus).
SUITE = {"openssl": ("sha384", 32), "gnutls": ("sha384", 32), "boringssl": ("sha256", 16)}
RUNS = ["openssl_run_13_1", "openssl_run_13_2", "openssl_run_13_5",
        "boringssl_run_13_1", "boringssl_run_13_2", "gnutls_run_13_1", "gnutls_run_13_2"]

needs_tls = pytest.mark.skipif(
    TLS_ROOT is None or not TLS_ROOT.is_dir(), reason="set MEMDIVER_TLS_CORPUS")
needs_image = pytest.mark.skipif(
    IMAGE_ROOT is None or not all(
        (IMAGE_ROOT / f"{CUMULUS}{ext}").is_file() for ext in (".lime", ".gt.isf.json")),
    reason="set MEMDIVER_IMAGE_CORPUS")


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "home"))


def _run_dir(run):
    return TLS_ROOT / run.rsplit("_run", 1)[0] / run


def _derived_keys(run):
    """label -> hex AES key derived from the run's keylog traffic secrets."""
    digest, size = SUITE[run.rsplit("_run", 1)[0]]
    keys = {}
    for line in (_run_dir(run) / "keylog.csv").read_text().splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] in TRAFFIC_LABELS:
            keys[parts[0]] = TLS13HKDF.hkdf_expand_label(
                bytes.fromhex(parts[2]), "key", b"", size, digest).hex()
    assert set(keys) == set(TRAFFIC_LABELS)
    return keys


def _msl(run):
    found = sorted(glob.glob(str(_run_dir(run) / "dumps" / "msl" / "*.msl")))
    assert found, f"no .msl under {run}"
    return found[0]


def _scan_rows(msl, finder, **kwargs):
    return keyfinders_scan_result(msl, (finder,), heap_policy="annotate", **kwargs).payload["rows"]


def _query(case, sql):
    return case_query_result(str(case), sql, limit=100).payload["rows"]


def _join_sql(finder, key_hexes=None):
    where = f"k.finder='{finder}'"
    if key_hexes:
        where += " AND k.key_hex IN (%s)" % ",".join(f"'{k}'" for k in key_hexes)
    return (
        "SELECT k.va AS va, k.key_hex AS key_hex, c.state AS chunk_state, "
        "CASE WHEN k.va >= c.user_addr AND k.va + k.size <= c.user_addr + c.user_len "
        "THEN 'user_data' ELSE 'header_or_other' END AS role, "
        "r.addr AS vma_start, r.addr + r.size AS vma_end, r.mapped_path AS mapped_path "
        "FROM key_hits k "
        "JOIN heap_chunks c ON k.va >= c.addr AND k.va < c.addr + c.size "
        "JOIN msl_regions r ON k.va >= r.addr AND k.va < r.addr + r.size "
        f"WHERE {where} ORDER BY k.va")


def _row_dicts(rows, columns=("va", "key_hex", "chunk_state", "role", "vma_start",
                              "vma_end", "mapped_path")):
    return [dict(zip(columns, row)) if not isinstance(row, dict) else row for row in rows]


@needs_tls
@pytest.mark.parametrize("run", RUNS)
def test_traffic_keys_found_as_aes_schedules(run):
    keys = _derived_keys(run)
    bits = SUITE[run.rsplit("_run", 1)[0]][1] * 8
    rows = _scan_rows(_msl(run), "aes_schedule")
    found = {r["metadata"]["key_hex"]: r for r in rows}
    for label, key in keys.items():
        assert key in found, f"{run}: {label} AES key not recovered"
        meta = found[key]["metadata"]
        assert (meta["key_bits"], meta["orientation"]) == (bits, "forward")


@needs_tls
def test_aes_keys_join_to_in_use_heap_chunk_and_vma(tmp_path):
    run, case = "openssl_run_13_1", tmp_path / "case"
    keys = _derived_keys(run)
    msl = _msl(run)
    case_init_result(str(case))
    _scan_rows(msl, "aes_schedule", case_dir=str(case))
    case_export_result(str(case), msl)
    rows = _row_dicts(_query(case, _join_sql("aes_schedule", keys.values())))
    by_key = {}
    for row in rows:
        by_key.setdefault(row["key_hex"], row)
    assert set(by_key) == set(keys.values())
    for row in by_key.values():
        assert row["chunk_state"] == "in_use"
        assert row["role"] == "user_data"
        assert row["vma_start"] <= row["va"] < row["vma_end"]


def _view(tmp_path):
    profile = ProfileRef(str(IMAGE_ROOT / f"{CUMULUS}.gt.isf.json"), sha256=SHA, origin="explicit")
    desc = ViewDescriptor(str(IMAGE_ROOT / f"{CUMULUS}.lime"),
                          SHA, ViewKind.PROCESS, pid=NGINX_PID, profile=profile)
    path = tmp_path / "nginx.mdview"
    desc.write(path)
    return path


def _factor_from_dump(msl, va):
    with open_dump(msl) as source:
        data, _ = source.read_range_valid(va - source.va_span_start(), 256, view="va")
    return int.from_bytes(bytes(data), "little")


@needs_image
def test_cumulus_nginx_rsa_primes_found_and_joined_to_heap(tmp_path):
    msl, case = tmp_path / "nginx.msl", tmp_path / "case"
    image_extract_process_result(str(_view(tmp_path)), str(msl))
    case_init_result(str(case))
    rows = _scan_rows(str(msl), "rsa_factor", case_dir=str(case))
    assert len(rows) == 2
    assert len({r["va"] for r in rows}) == 2
    primes = [_factor_from_dump(msl, r["va"]) for r in rows]
    meta = rows[0]["metadata"]
    assert meta["probable_prime"] and meta["modulus_bits"] == 4096
    n = primes[0] * primes[1]
    assert primes[0] != primes[1] and n.bit_length() == meta["modulus_bits"]
    n_bytes = n.to_bytes(meta["modulus_bits"] // 8, "big")
    assert (n_bytes[:8].hex(), n_bytes[-8:].hex()) == (meta["n_head"], meta["n_tail"])

    case_export_result(str(case), str(msl))
    joined = _row_dicts(_query(case, _join_sql("rsa_factor")))
    assert sorted(r["va"] for r in joined) == sorted(r["va"] for r in rows)
    for row in joined:
        assert row["chunk_state"] == "in_use" and row["role"] == "user_data"
        assert row["vma_start"] <= row["va"] < row["vma_end"]
        assert row["mapped_path"] in (None, "", "[heap]")
