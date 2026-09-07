"""HTTP-layer tests for api.routers.architect.

Exercise the public REST contract of the architect endpoints with a real
TestClient. Production code is untouched -- we synthesise small dump files
on disk and POST them via the documented payloads.

Every error path of this router now travels the app's single global
``CapabilityError`` handler (``api.main._capability_error_handler``) rather
than a hand-rolled ``HTTPException``. That means the error BODY is
``exc.to_dict()`` -- ``{"error", "code", "category"}`` -- not FastAPI's
``{"detail": ...}``. The status codes are unchanged (NOT_FOUND -> 404,
INVALID_INPUT / PRECONDITION / UNSUPPORTED -> 400), so each error test below
pins BOTH the status and the envelope; :func:`_assert_funnel_body` is the one
place that spells the envelope out.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yara
from fastapi.testclient import TestClient

from memdiver.api.config import get_settings
from memdiver.api.main import create_app
from memdiver.msl import crypto
from memdiver.msl.enums import EncAlgo, KdfType, KeyEncap
from memdiver.msl.writer import MslEncryptionConfig, MslWriter

# A 4 KiB region whose first 32 bytes are the region of interest: a 16-byte
# static prefix shared by both dumps, then 16 bytes that differ. Written at a
# non-zero base address so the .msl memory (flattened-VAS) coordinate 0 is a
# genuinely different place in the file from raw byte 0.
_REGION_BASE = 0x140000
_STATIC_PREFIX = bytes(range(16))
_VOLATILE_TAILS = (b"\x00" * 16, b"\xFF" * 16)


def _region_payload(tail: bytes) -> bytes:
    return _STATIC_PREFIX + tail + b"\x5A" * (4096 - 32)


def _write_msl_pair(
    tmp_path: Path,
    stem: str,
    encryption_key: bytes | None = None,
) -> list[str]:
    """Two ``.msl`` containers holding the same region at ``_REGION_BASE``."""
    paths: list[str] = []
    for i, tail in enumerate(_VOLATILE_TAILS):
        out = tmp_path / f"{stem}_{i}.msl"
        cfg = None
        if encryption_key is not None:
            cfg = MslEncryptionConfig(
                enc_algo=EncAlgo.AES_256_GCM, kdf_type=KdfType.NONE,
                key_encap=KeyEncap.NONE, raw_key=encryption_key,
            )
        writer = MslWriter(out, pid=11, encryption=cfg)
        writer.add_memory_region(_REGION_BASE, _region_payload(tail))
        writer.add_end_of_capture()
        writer.write()
        paths.append(str(out))
    return paths


def _assert_funnel_body(response, *, category: str, contains: str = "") -> dict:
    """Assert ``response`` carries the global funnel envelope, and return it.

    The envelope is exactly ``exc.to_dict()``: the three keys ``error`` /
    ``code`` / ``category`` and nothing else. Asserting the exact key set (not
    merely that ``error`` is present) is what would catch a silent regression
    back to FastAPI's ``{"detail": ...}`` shape, or a stray extra field.
    """
    body = response.json()
    assert set(body) == {"error", "code", "category"}, body
    assert body["category"] == category, body
    assert "detail" not in body, body
    if contains:
        assert contains in body["error"], body
    return body


# ---------------------------------------------------------------------------


@pytest.fixture
def isolated_env(tmp_path: Path, monkeypatch):
    """Redirect every settings-controlled directory into tmp_path."""
    for sub, env in [
        ("oracles", "MEMDIVER_ORACLE_DIR"),
        ("tasks", "MEMDIVER_TASK_ROOT"),
        ("uploads", "MEMDIVER_UPLOAD_DIR"),
        ("sessions", "MEMDIVER_SESSION_DIR"),
    ]:
        d = tmp_path / sub
        d.mkdir()
        monkeypatch.setenv(env, str(d))
    monkeypatch.setenv("MEMDIVER_PIPELINE_MAX_WORKERS", "1")
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


@pytest.fixture
def client(isolated_env):
    app = create_app()
    with TestClient(app) as c:
        yield c


@pytest.fixture
def synthetic_dumps(tmp_path: Path) -> list[str]:
    """Two tiny dumps that share a 16-byte static prefix and diverge after."""
    prefix = bytes(range(16))
    dump_a = prefix + b"\x00" * 16
    dump_b = prefix + b"\xFF" * 16
    paths: list[str] = []
    for i, data in enumerate((dump_a, dump_b)):
        p = tmp_path / f"dump_{i}.bin"
        p.write_bytes(data)
        paths.append(str(p))
    return paths


# ---------------------------------------------------------------------------
# /api/architect/check-static
# ---------------------------------------------------------------------------


def test_check_static_happy_path(client, synthetic_dumps):
    """check-static returns mask + reference hex + ratio + anchors."""
    r = client.post(
        "/api/architect/check-static",
        json={"dump_paths": synthetic_dumps, "offset": 0, "length": 32},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "static_mask" in body
    assert "reference_hex" in body
    assert "static_ratio" in body
    assert "anchors" in body
    assert len(body["static_mask"]) == 32
    # First 16 bytes are identical across both dumps -> all True.
    assert all(body["static_mask"][:16])
    # Last 16 bytes differ -> all False.
    assert not any(body["static_mask"][16:])


def test_check_static_404_on_missing_dump(client, tmp_path):
    """check-static returns 404 if any dump path doesn't exist.

    ``FileNotFoundServiceError`` (NOT_FOUND) through the global funnel: the
    status is the same 404 the hand-rolled ``HTTPException`` produced, the body
    is now the structured envelope.
    """
    missing = str(tmp_path / "does_not_exist.bin")
    r = client.post(
        "/api/architect/check-static",
        json={"dump_paths": [missing, missing], "offset": 0, "length": 16},
    )
    assert r.status_code == 404, r.text
    _assert_funnel_body(r, category="NOT_FOUND", contains="does_not_exist")


def test_check_static_400_on_fewer_than_two_dumps(client, synthetic_dumps):
    """A single dump cannot establish staticness -- INVALID_INPUT -> 400.

    Nothing pinned this branch before the funnel migration, so the arity guard
    could have changed status or message unnoticed.
    """
    r = client.post(
        "/api/architect/check-static",
        json={"dump_paths": synthetic_dumps[:1], "offset": 0, "length": 16},
    )
    assert r.status_code == 400, r.text
    _assert_funnel_body(
        r, category="INVALID_INPUT", contains="at least 2 dump paths",
    )


@pytest.fixture
def msl_dumps(tmp_path: Path) -> list[str]:
    """Two plaintext ``.msl`` dumps -- memory bytes != raw bytes at offset 0."""
    return _write_msl_pair(tmp_path, "plain")


@pytest.fixture
def encrypted_msl_dumps(tmp_path: Path):
    """Two AES-256-GCM encrypted ``.msl`` dumps plus their raw key (hex)."""
    if not crypto.cipher_is_available(EncAlgo.AES_256_GCM):
        pytest.skip("AES-256-GCM backend not installed")
    key = os.urandom(32)
    return _write_msl_pair(tmp_path, "enc", encryption_key=key), key.hex()


def test_check_static_reads_msl_in_memory_space_not_file_space(client, msl_dumps):
    """B4b regression: ``.msl`` offsets are MEMORY offsets, not file offsets.

    The route used to call ``StaticChecker.check``, which does
    ``path.read_bytes()[offset:offset + length]`` -- raw FILE bytes. For a
    ``.msl`` input, file offset 0 is the container's magic header (and, at
    bytes 24..32, its per-dump UUID), not the captured memory at
    ``_REGION_BASE``. So the old code answered HTTP 200 with the header's
    hex and a mask derived from header/UUID bytes.

    Asserting the exact reference hex pins this down: the response must be
    the first dump's MEMORY bytes. This test FAILS against the old
    ``StaticChecker.check`` call (reference_hex would start with the
    ``MEMSLICE`` magic and the mask would be True across bytes 16..24).
    """
    r = client.post(
        "/api/architect/check-static",
        json={"dump_paths": msl_dumps, "offset": 0, "length": 32},
    )
    assert r.status_code == 200, r.text
    body = r.json()

    expected = _region_payload(_VOLATILE_TAILS[0])[:32]
    assert body["reference_hex"] == expected.hex()
    # ... and it is emphatically NOT the container header at file offset 0.
    raw_header = Path(msl_dumps[0]).read_bytes()[:32]
    assert body["reference_hex"] != raw_header.hex()

    assert len(body["static_mask"]) == 32
    assert all(body["static_mask"][:16])
    assert not any(body["static_mask"][16:])
    assert body["static_ratio"] == 0.5
    assert body["anchors"] == [{"start": 0, "length": 16}]


def test_check_static_raw_dumps_unchanged(client, synthetic_dumps):
    """The common raw-dump case is byte-for-byte what it always was.

    ``open_dump`` falls back to ``RawDumpSource`` for an opaque file, whose
    ``read_range`` is a plain file slice -- exactly what ``StaticChecker.check``
    did. Same reference bytes, same mask, same ratio.
    """
    r = client.post(
        "/api/architect/check-static",
        json={"dump_paths": synthetic_dumps, "offset": 0, "length": 32},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    expected = Path(synthetic_dumps[0]).read_bytes()[:32]
    assert body["reference_hex"] == expected.hex()
    assert body["static_mask"] == [True] * 16 + [False] * 16
    assert body["static_ratio"] == 0.5


def test_check_static_decrypts_encrypted_msl_with_key(client, encrypted_msl_dumps):
    """Key material on the request body opens an encrypted container."""
    paths, key_hex = encrypted_msl_dumps
    r = client.post(
        "/api/architect/check-static",
        json={
            "dump_paths": paths, "offset": 0, "length": 32, "key_hex": key_hex,
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    expected = _region_payload(_VOLATILE_TAILS[0])[:32]
    assert body["reference_hex"] == expected.hex()
    assert body["static_mask"] == [True] * 16 + [False] * 16


def test_check_static_locked_encrypted_msl_is_an_error_not_all_static(
    client, encrypted_msl_dumps,
):
    """A locked container must surface, never read back as an empty region.

    An encrypted ``.msl`` opened without a key does NOT raise on read -- it
    reads back zero bytes. Unguarded, ``check_regions`` would then answer 200
    with an empty mask and an empty reference: a vacuous "nothing here"
    indistinguishable from a genuine result. The route raises
    ``EncryptedDumpLockedError`` (PRECONDITION -> 400) instead. That error is
    no longer caught and re-thrown as an ``HTTPException`` by the route -- it
    propagates to the global funnel, so the status is the same 400 and the body
    is the structured envelope carrying the error's stable ``code``.
    """
    paths, _ = encrypted_msl_dumps
    r = client.post(
        "/api/architect/check-static",
        json={"dump_paths": paths, "offset": 0, "length": 32},
    )
    assert r.status_code == 400, r.text
    body = _assert_funnel_body(r, category="PRECONDITION")
    assert "encrypted" in body["error"].lower()
    # The machine-readable code the hand-rolled ``{"detail": ...}`` shape threw
    # away is now on the wire.
    assert body["code"] == "encrypted_dump_locked"


def test_check_static_wrong_key_is_an_error(client, encrypted_msl_dumps):
    """A wrong key fails AEAD verification -- also a 400, never a silent read."""
    paths, _ = encrypted_msl_dumps
    r = client.post(
        "/api/architect/check-static",
        json={
            "dump_paths": paths, "offset": 0, "length": 32,
            "key_hex": ("11" * 32),
        },
    )
    assert r.status_code == 400, r.text
    body = _assert_funnel_body(r, category="PRECONDITION")
    assert body["error"]


def test_check_static_unequal_sizes_mark_tail_non_static(client, tmp_path):
    """A shorter second dump cannot confirm the tail -- it must read False."""
    long_dump = tmp_path / "long.bin"
    short_dump = tmp_path / "short.bin"
    long_dump.write_bytes(bytes(range(32)))
    short_dump.write_bytes(bytes(range(16)))

    r = client.post(
        "/api/architect/check-static",
        json={
            "dump_paths": [str(long_dump), str(short_dump)],
            "offset": 0,
            "length": 32,
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    # Reference is the FIRST (longer) region, so the mask spans 32 positions;
    # the 16 the short dump does not cover cannot be static.
    assert len(body["static_mask"]) == 32
    assert all(body["static_mask"][:16])
    assert not any(body["static_mask"][16:])


# ---------------------------------------------------------------------------
# /api/architect/generate-pattern
# ---------------------------------------------------------------------------


def test_generate_pattern_happy_path(client):
    """generate-pattern returns the pattern dict on a sufficient-static input."""
    reference = bytes(range(16))
    payload = {
        "reference_hex": reference.hex(),
        "static_mask": [True] * 16,
        "name": "api_test",
        "min_static_ratio": 0.3,
    }
    r = client.post("/api/architect/generate-pattern", json=payload)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "api_test"
    assert body["length"] == 16
    assert "wildcard_pattern" in body


def test_generate_pattern_422_on_invalid_payload(client):
    """Missing required fields trigger Pydantic 422 before the handler runs."""
    r = client.post(
        "/api/architect/generate-pattern",
        json={"reference_hex": "deadbeef"},  # static_mask is required
    )
    assert r.status_code == 422


def test_generate_pattern_400_on_invalid_hex(client):
    """A non-hex ``reference_hex`` is INVALID_INPUT -> 400 through the funnel.

    Pydantic accepts the field (it is a plain ``str``), so the failure happens
    in the handler at ``bytes.fromhex`` -- not as a 422.
    """
    r = client.post(
        "/api/architect/generate-pattern",
        json={"reference_hex": "zzzz", "static_mask": [True, True]},
    )
    assert r.status_code == 400, r.text
    _assert_funnel_body(r, category="INVALID_INPUT", contains="Invalid hex")


def test_generate_pattern_400_on_below_threshold(client):
    """Below-threshold static ratio surfaces as a PRECONDITION 400.

    The request is well-formed; the DATA cannot yield a pattern -- hence
    PRECONDITION rather than INVALID_INPUT. Both render 400, so the wire status
    is byte-for-byte what the old ``HTTPException(400, ...)`` produced.
    """
    reference = b"\x00" * 32
    payload = {
        "reference_hex": reference.hex(),
        "static_mask": [True] * 5 + [False] * 27,  # ~15% static, below 0.3
        "name": "below",
        "min_static_ratio": 0.3,
    }
    r = client.post("/api/architect/generate-pattern", json=payload)
    assert r.status_code == 400, r.text
    body = _assert_funnel_body(r, category="PRECONDITION")
    assert "static" in body["error"].lower()


# ---------------------------------------------------------------------------
# /api/architect/export
# ---------------------------------------------------------------------------


def test_export_yara_happy_path(client):
    """export with format=yara returns a YARA rule string."""
    pattern = {
        "name": "exp_test",
        "length": 8,
        "hex_pattern": "00 01 02 03 04 05 06 07",
        "wildcard_pattern": "00 01 02 03 04 05 06 07",
        "static_ratio": 1.0,
        "static_count": 8,
        "volatile_count": 0,
    }
    r = client.post(
        "/api/architect/export",
        json={"pattern": pattern, "format": "yara", "rule_name": "exported"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["format"] == "yara"
    assert "rule exported" in body["content"]


def _only_rule_meta(rule_source: str) -> dict:
    """Compile a single-rule YARA source and return its meta dict."""
    rules = list(yara.compile(source=rule_source))
    assert len(rules) == 1, f"expected exactly one rule, got {len(rules)}"
    return dict(rules[0].meta)


def test_export_yara_forwards_pattern_key_locator(client):
    """GAP C: a posted pattern that carries the locator must export it.

    The endpoint receives a finished pattern dict, so the locator can only
    come from the dict itself -- which is exactly what ``emit-plugin`` and the
    experiment orchestrator put there. Round-tripping such a pattern through
    ``/export`` must not silently drop it.
    """
    pattern = {
        "name": "exp_test",
        "length": 8,
        "wildcard_pattern": "00 01 ?? ?? 04 05 06 07",
        "static_ratio": 0.75,
        "key_offset": 2,
        "key_length": 2,
    }
    r = client.post(
        "/api/architect/export",
        json={"pattern": pattern, "format": "yara", "rule_name": "exported"},
    )
    assert r.status_code == 200, r.text
    meta = _only_rule_meta(r.json()["content"])
    assert meta["key_offset"] == 2
    assert meta["key_length"] == 2


def test_export_vol3_forwards_pattern_key_locator(client):
    """The volatility3 branch builds the rule too -- same forwarding."""
    pattern = {
        "name": "exp_test",
        "length": 8,
        "wildcard_pattern": "00 01 ?? ?? 04 05 06 07",
        "static_ratio": 0.75,
        "key_offset": 2,
        "key_length": 2,
    }
    r = client.post(
        "/api/architect/export",
        json={"pattern": pattern, "format": "volatility3", "rule_name": "Exported"},
    )
    assert r.status_code == 200, r.text
    content = r.json()["content"]
    assert "key_offset = 2" in content
    assert "key_length = 2" in content


def test_export_yara_omits_key_locator_when_pattern_lacks_it(client):
    """A pattern straight from /generate-pattern knows no key position."""
    pattern = {
        "name": "exp_test",
        "length": 8,
        "wildcard_pattern": "00 01 ?? ?? 04 05 06 07",
        "static_ratio": 0.75,
    }
    r = client.post(
        "/api/architect/export",
        json={"pattern": pattern, "format": "yara"},
    )
    assert r.status_code == 200, r.text
    meta = _only_rule_meta(r.json()["content"])
    assert "key_offset" not in meta
    assert "key_length" not in meta


@pytest.mark.parametrize("bad", ["n/a", [1, 2], {"a": 1}, True])
def test_export_yara_survives_hostile_key_locator(client, bad):
    """A non-integral locator in the request body must not 500 the endpoint."""
    pattern = {
        "name": "exp_test",
        "length": 8,
        "wildcard_pattern": "00 01 ?? ?? 04 05 06 07",
        "static_ratio": 0.75,
        "key_offset": bad,
        "key_length": bad,
    }
    r = client.post(
        "/api/architect/export",
        json={"pattern": pattern, "format": "yara"},
    )
    assert r.status_code == 200, r.text
    meta = _only_rule_meta(r.json()["content"])
    assert "key_offset" not in meta
    assert "key_length" not in meta


def test_export_400_on_unknown_format(client):
    """Unknown format strings raise a 400 with a list of supported values.

    ``UnsupportedFormatError`` is a ``CapabilityError``, NOT a ``ValueError``,
    so it is not swallowed by ``export_pattern``'s malformed-pattern handler --
    it reaches the global funnel with category UNSUPPORTED, whose status hint is
    the same 400 the hand-rolled raise used.
    """
    pattern = {"name": "x", "length": 0, "wildcard_pattern": ""}
    r = client.post(
        "/api/architect/export",
        json={"pattern": pattern, "format": "invalid_format"},
    )
    assert r.status_code == 400, r.text
    _assert_funnel_body(r, category="UNSUPPORTED", contains="Unknown format")


def test_export_400_on_malformed_pattern(client):
    """A pattern with no usable byte string is INVALID_INPUT -> 400.

    The exporter raises a plain ``ValueError``; ``export_pattern`` converts it
    to a ``CapabilityError`` (rather than an ``HTTPException``) so the body
    matches every other error this router emits.
    """
    r = client.post(
        "/api/architect/export",
        json={"pattern": {"name": "p", "wildcard_hex": "7f 45"}, "format": "yara"},
    )
    assert r.status_code == 400, r.text
    _assert_funnel_body(
        r, category="INVALID_INPUT", contains="wildcard_pattern",
    )
