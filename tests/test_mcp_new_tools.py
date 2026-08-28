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

from generate_aes_fixtures import (  # noqa: E402
    KEY_LENGTH,
    KEY_OFFSET,
    generate_dataset,
)

from memdiver.core.service_errors import (  # noqa: E402
    CapabilityError,
    ErrorCategory,
    FileNotFoundServiceError,
)
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
    with pytest.raises(CapabilityError) as excinfo:
        tools_pipeline.consensus(
            dump_paths=aes_dumps[:1], output_dir=str(tmp_path / "c"))
    assert excinfo.value.category is ErrorCategory.PRECONDITION
    assert excinfo.value.message == "Need at least 2 dumps, got 1"


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
    with pytest.raises(CapabilityError) as excinfo:
        tools_pipeline.export_pattern(
            dump_paths=aes_dumps[:1], output_dir=str(tmp_path))
    assert excinfo.value.category is ErrorCategory.PRECONDITION
    assert excinfo.value.message == "Need at least 2 dumps, got 1"


# ── B6: manual_export_pattern producer (user-offset variant) ─────────
# Region 112..176 spans anchor + planted key + anchor (KEY_OFFSET=128,
# KEY_LENGTH=32), so it carries both static anchors and volatile key bytes.
_MANUAL_OFFSET = KEY_OFFSET - 16
_MANUAL_LENGTH = KEY_LENGTH + 32

_EXPORT_PAYLOAD_KEYS = {"format", "content", "pattern", "region"}
_REGION_KEYS = {"offset", "length", "key_start", "key_end"}


def test_manual_export_pattern_producer_shape(aes_dumps, tmp_path):
    """The new ``manual_export_pattern`` producer returns the same payload
    shape as ``export_pattern`` — a plain dict, never an ``{"error": ...}``
    dict — and writes the rendered pattern when ``output_dir`` is given."""
    res = tools_pipeline.manual_export_pattern(
        dump_paths=aes_dumps,
        offset=_MANUAL_OFFSET,
        length=_MANUAL_LENGTH,
        output_dir=str(tmp_path / "manual"),
        fmt="yara",
        name="mcp_manual",
        min_static_ratio=0.1,
    )
    assert "error" not in res, res
    assert _EXPORT_PAYLOAD_KEYS <= set(res), res
    assert res["format"] == "yara"
    assert "rule" in res["content"]
    assert _REGION_KEYS <= set(res["region"])
    assert res["region"]["offset"] == _MANUAL_OFFSET
    assert res["region"]["length"] == _MANUAL_LENGTH
    assert res["region"]["key_start"] == _MANUAL_OFFSET
    assert res["region"]["key_end"] == _MANUAL_OFFSET + _MANUAL_LENGTH
    assert Path(res["pattern_path"]).is_file()


def test_auto_and_manual_producers_share_payload_shape(aes_dumps):
    """Auto and manual producers agree on their top-level payload keys and on
    the region sub-dict keys, so both surfaces present the same structure."""
    auto = tools_pipeline.export_pattern(
        dump_paths=aes_dumps, fmt="json", name="a", min_static_ratio=0.1,
    )
    manual = tools_pipeline.manual_export_pattern(
        dump_paths=aes_dumps, offset=_MANUAL_OFFSET, length=_MANUAL_LENGTH,
        fmt="json", name="m", min_static_ratio=0.1,
    )
    assert set(auto) == set(manual) == _EXPORT_PAYLOAD_KEYS
    assert set(auto["region"]) == set(manual["region"]) == _REGION_KEYS


def test_manual_export_pattern_too_few_dumps(aes_dumps):
    with pytest.raises(CapabilityError) as excinfo:
        tools_pipeline.manual_export_pattern(
            dump_paths=aes_dumps[:1], offset=_MANUAL_OFFSET,
            length=_MANUAL_LENGTH,
        )
    assert excinfo.value.category is ErrorCategory.PRECONDITION
    assert excinfo.value.message == "Need at least 2 dumps, got 1"


def test_analysis_service_shim_reexports_relocated_symbols():
    """The old ``api.services.analysis_service`` module is a re-export shim:
    every public symbol is the SAME object now defined in the relocated
    ``memdiver.app.export_service`` module."""
    from memdiver.api.services import analysis_service as shim
    from memdiver.app import export_service as es

    for name in (
        "auto_export_pattern", "manual_export_pattern", "AnalysisServiceError",
        "DumpsNotFoundError", "TooFewDumpsError", "NoVolatileRegionsError",
        "EmptyRegionError", "InsufficientStaticError", "UnknownFormatError",
        "SUPPORTED_FORMATS", "_render_content",
    ):
        assert getattr(shim, name) is getattr(es, name), name


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
    with pytest.raises(FileNotFoundServiceError) as excinfo:
        tools_pipeline.auto_floor(
            variance_path=str(tmp_path / "nope.npy"),
            reference_path=str(tmp_path / "nope.bin"),
            oracle_path=str(tmp_path / "nope.py"),
            output_dir=str(tmp_path / "out"),
            num_dumps=5,
        )
    assert excinfo.value.category is ErrorCategory.NOT_FOUND
    assert excinfo.value.message.startswith("File not found:")


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


# ── A4: the exploratory path — N dumps in, ranked candidates out ──────
@pytest.fixture
def isolated_project_db(tmp_path, monkeypatch):
    """``analyze_candidates`` persists by design; keep it out of the
    developer's real ``~/.memdiver`` database."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


def test_analyze_candidates_returns_ranked_regions_inline(
    aes_dumps, isolated_project_db
):
    """No oracle, no capture, no precomputed variance: dump paths in, ranked
    regions out. The regions are INLINE because an MCP agent handed a
    ``candidates_path`` has no way to read it back."""
    res = tools_pipeline.analyze_candidates(
        dump_paths=aes_dumps,
        classes=["structural", "pointer", "key_candidate"],
        min_region=8,
    )
    assert res["num_dumps"] == len(aes_dumps)
    assert res["num_regions"] == len(res["regions"]) >= 1
    assert [r["rank"] for r in res["regions"]] == list(
        range(1, len(res["regions"]) + 1))
    assert res["alignment"]["method"] in ("file_offset", "virtual_address",
                                          "module_offset")
    # The class query resolved the float floor to 0.0 rather than leaving the
    # historical 3000.0 standing and silently re-narrowing the query.
    assert res["thresholds"]["min_variance"] == 0.0


def test_analyze_candidates_rejects_a_single_dump(aes_dumps, isolated_project_db):
    with pytest.raises(CapabilityError) as excinfo:
        tools_pipeline.analyze_candidates(dump_paths=aes_dumps[:1])
    # PRECONDITION, matching `consensus` and the two n-sweep producers, which
    # make the identical "need at least 2 dumps" check. Both categories map to
    # HTTP 400 and CLI exit 2; the point is that one rule has one spelling.
    assert excinfo.value.category is ErrorCategory.PRECONDITION


def test_analyze_candidates_missing_dump_is_not_found(
    aes_dumps, tmp_path, isolated_project_db
):
    with pytest.raises(FileNotFoundServiceError):
        tools_pipeline.analyze_candidates(
            dump_paths=[aes_dumps[0], str(tmp_path / "absent.dump")])
