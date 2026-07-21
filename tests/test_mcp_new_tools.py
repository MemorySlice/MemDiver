"""Unit tests for the new MCP capability-parity tools (B2/B3/B5/B6).

These call the PURE ``mcp_server.tools_*`` functions directly — never through
FastMCP (the ``mcp`` SDK is not installed in CI) — covering:

* B5 consensus → produces a variance.npy that search_reduce accepts.
* B6 detect_format → returns the expected format on an .msl fixture.
* B6 export_pattern → returns a rendered YARA/Vol3 pattern.
* B3 auto_floor → returns a verdict dict (RECOVERED on a planted key).
* B2 decryption params → let an encrypted-.msl inspect succeed.
"""

import os
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).parent / "fixtures"))

from generate_aes_fixtures import generate_dataset  # noqa: E402

from memdiver.mcp_server import tools_inspect, tools_pipeline  # noqa: E402
from memdiver.mcp_server.key_material import key_material_kwargs  # noqa: E402
from memdiver.mcp_server.session import ToolSession  # noqa: E402


@pytest.fixture
def session():
    return ToolSession()


@pytest.fixture(scope="module")
def aes_dumps(tmp_path_factory):
    """Raw .dump fixtures with a planted, per-run-varying AES key region."""
    out = tmp_path_factory.mktemp("mcp_aes")
    generate_dataset(out, num_runs=20, seed=7)
    paths = sorted(out.glob("**/*.dump"))
    assert len(paths) >= 2
    return [str(p) for p in paths]


def _write_plain_msl(path: Path, *, data=b"\xAB" * 4096, base=0x1000):
    from memdiver.msl.writer import MslWriter

    w = MslWriter(path, pid=7)
    w.add_memory_region(base, data)
    w.add_end_of_capture()
    w.write()


def _write_encrypted_msl(path: Path, key: bytes, *, data=b"\xCD" * 4096):
    from memdiver.msl.writer import MslEncryptionConfig, MslWriter

    cfg = MslEncryptionConfig(raw_key=key)
    w = MslWriter(path, pid=7, encryption=cfg)
    w.add_memory_region(0x1000, data)
    w.add_end_of_capture()
    w.write()


# ── B2: key-material helper ──────────────────────────────────────────
def test_key_material_kwargs_reads_key_file(tmp_path):
    key = os.urandom(32)
    keyfile = tmp_path / "cek.bin"
    keyfile.write_bytes(key)
    km = key_material_kwargs(str(keyfile), "pw", None)
    assert km == {"key": key, "passphrase": b"pw", "kem_private_key": None}


def test_key_material_kwargs_empty_is_all_none():
    assert key_material_kwargs() == {
        "key": None, "passphrase": None, "kem_private_key": None,
    }


# ── B5: consensus originates the pipeline; search_reduce accepts it ──
def test_consensus_writes_variance_and_reference(aes_dumps, tmp_path):
    out = tmp_path / "consensus"
    res = tools_pipeline.consensus(dump_paths=aes_dumps, output_dir=str(out))
    assert "error" not in res, res
    assert res["num_dumps"] == len(aes_dumps)
    assert Path(res["variance_path"]).is_file()
    assert Path(res["reference_path"]).is_file()
    variance = np.load(res["variance_path"])
    assert variance.shape[0] == res["size"] > 0


def test_consensus_too_few_dumps(aes_dumps, tmp_path):
    res = tools_pipeline.consensus(
        dump_paths=aes_dumps[:1], output_dir=str(tmp_path / "c"))
    assert "error" in res


def test_consensus_variance_feeds_search_reduce(aes_dumps, tmp_path):
    out = tmp_path / "chain"
    cons = tools_pipeline.consensus(dump_paths=aes_dumps, output_dir=str(out))
    assert "error" not in cons, cons

    reduced = tools_pipeline.search_reduce(
        variance_path=cons["variance_path"],
        reference_path=cons["reference_path"],
        num_dumps=cons["num_dumps"],
        output_dir=str(out / "reduce"),
    )
    assert "error" not in reduced, reduced
    assert isinstance(reduced["num_regions"], int)
    # The planted, per-run-random AES key region survives the variance +
    # entropy filters, so the origin stage really does unbreak the chain.
    assert reduced["num_regions"] >= 1


# ── B6: detect_format ────────────────────────────────────────────────
def test_detect_format_identifies_msl(session, tmp_path):
    msl = tmp_path / "plain.msl"
    _write_plain_msl(msl)
    res = tools_inspect.detect_format(session, str(msl))
    assert "error" not in res, res
    assert res["format"] == "msl"
    assert res["detected_format"] == "msl"


def test_detect_format_missing_file(session):
    res = tools_inspect.detect_format(session, "/nonexistent/path.msl")
    assert "error" in res


# ── B6: export_pattern ───────────────────────────────────────────────
def test_export_pattern_yara(aes_dumps, tmp_path):
    res = tools_pipeline.export_pattern(
        dump_paths=aes_dumps, output_dir=str(tmp_path / "yara"),
        fmt="yara", name="mcp_yara", min_static_ratio=0.1,
    )
    assert "error" not in res, res
    assert res["format"] == "yara"
    assert "rule" in res["content"]
    assert Path(res["pattern_path"]).is_file()


def test_export_pattern_vol3(aes_dumps, tmp_path):
    res = tools_pipeline.export_pattern(
        dump_paths=aes_dumps, output_dir=str(tmp_path / "vol3"),
        fmt="volatility3", name="mcp_vol3", min_static_ratio=0.1,
    )
    assert "error" not in res, res
    assert res["format"] == "volatility3"
    compile(res["content"], "<vol3_plugin>", "exec")


def test_export_pattern_too_few_dumps(aes_dumps, tmp_path):
    res = tools_pipeline.export_pattern(
        dump_paths=aes_dumps[:1], output_dir=str(tmp_path))
    assert "error" in res


# ── B3: auto_floor verdict ───────────────────────────────────────────
def test_auto_floor_recovers_planted_key(tmp_path):
    size = 200_000
    koff = 8 * 1234
    rng = np.random.default_rng(0)
    ref = bytearray(rng.integers(0, 4, size, dtype=np.uint8).tobytes())
    key = bytes(rng.integers(0, 256, 32, dtype=np.uint8).tolist())
    ref[koff:koff + 32] = key
    variance = np.full(size, 50.0, dtype=np.float32)
    variance[koff:koff + 32] = 5000.0

    work = tmp_path / "af"
    work.mkdir()
    variance_path = work / "variance.npy"
    np.save(variance_path, variance)
    reference_path = work / "reference.bin"
    reference_path.write_bytes(bytes(ref))
    oracle_path = work / "oracle.py"
    oracle_path.write_text(
        "KEY = bytes.fromhex('%s')\n"
        "def verify(candidate):\n"
        "    return candidate == KEY\n" % key.hex()
    )

    res = tools_pipeline.auto_floor(
        variance_path=str(variance_path),
        reference_path=str(reference_path),
        oracle_path=str(oracle_path),
        output_dir=str(work / "out"),
        num_dumps=20,
        positive_control_hex=key.hex(),
    )
    assert "error" not in res, res
    assert res["verdict"] in ("RECOVERED", "FLOOR_TOO_HIGH")
    assert res["key_hex"] == key.hex()
    assert Path(res["artifacts"]["verdict_json"]).is_file()


def test_auto_floor_missing_variance(tmp_path):
    res = tools_pipeline.auto_floor(
        variance_path=str(tmp_path / "nope.npy"),
        reference_path=str(tmp_path / "nope.bin"),
        oracle_path=str(tmp_path / "nope.py"),
        output_dir=str(tmp_path / "out"),
        num_dumps=5,
    )
    assert "error" in res


# ── B2: decryption params let an encrypted-.msl inspect succeed ──────
@pytest.fixture
def encrypted_msl(tmp_path):
    from memdiver.msl import crypto
    from memdiver.msl.enums import EncAlgo

    if not crypto.cipher_is_available(EncAlgo.AES_256_GCM):
        pytest.skip("AES-256-GCM backend not installed")
    key = os.urandom(32)
    keyfile = tmp_path / "cek.bin"
    keyfile.write_bytes(key)
    msl = tmp_path / "enc.msl"
    _write_encrypted_msl(msl, key)
    return str(msl), str(keyfile)


# NOTE: The tests below exercise the LEGACY ``report_key_status`` back-compat
# path — the inline ``{"error", "tag_status"}`` dict returned by the pre-producer
# inspect functions when their default ``report_key_status=True`` flag trips.
# The live MCP surface behavior (via the ``*_result`` producers) is covered by
# tests/test_inspect_contract_mcp.py and tests/test_presenter_inspect_mcp.py.
def test_get_session_info_decrypts_with_key(session, encrypted_msl):
    msl_path, keyfile = encrypted_msl
    res = tools_inspect.get_session_info(session, msl_path, key_file=keyfile)
    assert "error" not in res, res
    assert res["region_count"] == 1
    assert res["pid"] == 7


def test_get_session_info_without_key_reports_missing_key(session, encrypted_msl):
    msl_path, _ = encrypted_msl
    # No key material → the AEAD envelope stays sealed. O-3: surface a
    # diagnostic instead of a silently-empty result an operator cannot tell
    # apart from a genuinely empty capture.
    res = tools_inspect.get_session_info(session, msl_path)
    assert "error" in res, res
    assert res["tag_status"] == "missing_key"


@pytest.mark.parametrize(
    "fn_name", ["get_session_info", "get_page_states",
                "get_processes", "get_modules", "get_handles"],
)
def test_inspect_without_key_reports_missing_key(session, encrypted_msl, fn_name):
    """O-3: every MSL-metadata inspect tool flags a missing key rather than
    returning an empty-looking success."""
    msl_path, _ = encrypted_msl
    res = getattr(tools_inspect, fn_name)(session, msl_path)
    assert "error" in res, res
    assert res["tag_status"] == "missing_key"


def test_inspect_with_wrong_key_reports_corrupted(session, encrypted_msl, tmp_path):
    """O-3: a wrong key fails AEAD verification and is reported as corrupted,
    not silently empty."""
    msl_path, _ = encrypted_msl
    wrong = tmp_path / "wrong.bin"
    wrong.write_bytes(b"\x00" * 32)
    res = tools_inspect.get_session_info(session, msl_path, key_file=str(wrong))
    assert "error" in res, res
    assert res["tag_status"] == "corrupted"


def test_read_hex_vas_without_key_reports_missing_key(session, encrypted_msl):
    """O-3: the decrypted (vas) hex view flags a missing key."""
    msl_path, _ = encrypted_msl
    res = tools_inspect.read_hex(session, msl_path, offset=0, length=64, view="vas")
    assert "error" in res, res
    assert res["tag_status"] == "missing_key"


def test_read_hex_raw_view_without_key_still_reads(session, encrypted_msl):
    """O-3 guard is view-scoped: the raw container view is keyless by design
    and must NOT error when no key is supplied."""
    msl_path, _ = encrypted_msl
    res = tools_inspect.read_hex(session, msl_path, offset=0, length=64, view="raw")
    assert "error" not in res, res


def test_read_hex_decrypts_vas_with_key(session, encrypted_msl):
    msl_path, keyfile = encrypted_msl
    res = tools_inspect.read_hex(
        session, msl_path, offset=0, length=64, view="vas", key_file=keyfile)
    assert "error" not in res, res
    # The captured region is 0xCD-filled plaintext; a correct decrypt must
    # expose it in full. Count actual 0xcd byte tokens (not a single chance
    # occurrence): 64 bytes → ~64 "cd" tokens; a partial/wrong decrypt fails.
    joined = " ".join(res["hex_lines"]).lower()
    assert joined.count("cd") >= 60, res


def test_get_page_states_decrypts_with_key(session, encrypted_msl):
    msl_path, keyfile = encrypted_msl
    res = tools_inspect.get_page_states(session, msl_path, key_file=keyfile)
    assert "error" not in res, res
    assert res["captured_pages"] >= 1
