"""The ``luks`` format oracle and the two additions it needs in ``secrets/luks.py``.

Every header under tests/fixtures/luks/ was written by a real ``cryptsetup luksFormat``; the
ground truth is the volume key it was formatted with. The inline test runs the oracle the way
a generated plugin does: a fresh ``python -I`` with memdiver and both crypto libraries blocked.
"""

import ast
import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest

from memdiver.oracles import get_format, missing_contract
from memdiver.oracles.embed import BUNDLE_SOURCES_NAME, inline_source, render_bundle
from memdiver.vol3plugins.linux.secrets import luks

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "luks"
L = get_format("luks")
LUKS1 = ["luks1-xts", "luks1-essiv"]
LUKS2 = ["luks2-default", "luks2-4k", "luks2-essiv"]
POISON_ALL = (
    "import sys\n"
    'for _blocked in ("memdiver", "cryptography", "Crypto"):\n'
    "    sys.modules[_blocked] = None\n"
)


def _raw(name):
    return (FIXTURES / ("%s.hdr.bin" % name)).read_bytes()


def _key(name):
    for line in (FIXTURES / ("%s.gt.txt" % name)).read_text().splitlines():
        if line.startswith("volume_key_hex="):
            return bytes.fromhex(line.split("=", 1)[1])
    raise AssertionError(name)


def _flip(key):
    return bytes([key[0] ^ 1]) + key[1:]


# ------------------------------------------------------------------ secrets/luks.py additions


@pytest.mark.parametrize("name", LUKS2)
def test_luks2_from_document_verifies_like_the_parsed_header(name):
    parsed = luks.parse_luks2(_raw(name))
    doc = luks.luks2_from_document(json.loads(parsed.json_text))
    assert doc.complete and not doc.checksum_ok and doc.hdr_size == 0
    assert doc.digests == parsed.digests and doc.segments == parsed.segments
    assert luks.segment_crypto(doc) == luks.segment_crypto(parsed)
    assert luks.verify_volume_key(doc, _key(name)).matched
    assert not luks.verify_volume_key(doc, _flip(_key(name))).matched
    # str and bytes documents parse the same way
    assert luks.luks2_from_document(parsed.json_text).digests == parsed.digests
    assert luks.luks2_from_document(parsed.json_text.encode()).digests == parsed.digests


@pytest.mark.parametrize("bad", [b"[1, 2]", "not json", 42, b"{" * 64 + b"}" * 64])
def test_luks2_from_document_rejects_non_objects(bad):
    with pytest.raises(luks.LuksParseError):
        luks.luks2_from_document(bad)


def test_luks2_from_document_keeps_uuid_only_when_text():
    assert luks.luks2_from_document({"uuid": "abc", "digests": {}}).uuid == "abc"
    assert luks.luks2_from_document({"uuid": 5, "digests": {}}).uuid == ""


@pytest.mark.parametrize("name", LUKS1 + LUKS2)
def test_refused_is_set_only_by_the_iteration_limits(name):
    header = luks.parse_luks(_raw(name))
    key = _key(name)
    assert luks.verify_volume_key(header, key).refused is False
    assert luks.verify_volume_key(header, _flip(key)).refused is False
    capped = luks.verify_volume_key(header, key, max_iterations=10)
    assert not capped.matched and capped.refused
    budget = luks.verify_volume_key(header, key, max_total_iterations=10)
    assert not budget.matched and budget.refused


def test_zero_iterations_is_malformed_not_refused():
    doc = json.loads(luks.parse_luks2(_raw("luks2-default")).json_text)
    for digest in doc["digests"].values():
        digest["iterations"] = 0
    verdict = luks.verify_volume_key(luks.luks2_from_document(doc), _key("luks2-default"))
    assert not verdict.matched and not verdict.refused


def test_quoted_iteration_count_over_the_cap_is_refused():
    doc = json.loads(luks.parse_luks2(_raw("luks2-default")).json_text)
    for digest in doc["digests"].values():
        digest["iterations"] = str(10 ** 9)
    verdict = luks.verify_volume_key(luks.luks2_from_document(doc), _key("luks2-default"))
    assert verdict.refused


def test_volume_key_verdict_default_keeps_positional_construction():
    verdict = luks.VolumeKeyVerdict(False, None, [], "x")
    assert verdict.refused is False


# ------------------------------------------------------------------ the oracle: contract


def test_registered_and_complete():
    assert missing_contract(L) == []
    assert L.KIND == "luks" and L.REQUIRES_PRIMITIVES == ("luks",)
    assert L.COST_US == 200000


def test_source_is_python38_syntax():
    ast.parse(Path(L.__file__).read_text(encoding="utf-8"), feature_version=(3, 8))


# ------------------------------------------------------------------ samples


@pytest.mark.parametrize("name", LUKS1)
def test_luks1_sample_is_the_raw_phdr(name):
    sample = L.make_sample(_raw(name))
    assert sample == _raw(name)[:592]


@pytest.mark.parametrize("name", LUKS2)
def test_luks2_sample_is_compact_json_without_keyslot_kdf(name):
    sample = L.make_sample(_raw(name))
    assert sample.startswith(b"{") and len(sample) <= 8192
    doc = json.loads(sample)
    assert set(doc) <= {"uuid", "digests", "segments", "keyslots"}
    for slot in doc["keyslots"].values():
        assert set(slot) == {"key_size"}  # no kdf salt / area: nothing to crack
    assert L.make_sample(json.loads(luks.parse_luks2(_raw(name)).json_text)) == sample


@pytest.mark.parametrize("bad", [b"LUKS\xba\xbe\x00\x01short", b"LUKS\xba\xbe\x00\x02" + bytes(100),
                                 b"[]", {"digests": {}}, "{}", 7])
def test_make_sample_refuses_what_is_not_a_header(bad):
    with pytest.raises((ValueError, TypeError)):
        L.make_sample(bad)


# ------------------------------------------------------------------ verify


@pytest.mark.parametrize("name", LUKS1 + LUKS2)
@pytest.mark.parametrize("raw_sample", [False, True], ids=["sample", "raw"])
def test_ground_truth_proven_wrong_key_rejected(name, raw_sample):
    o = L.build_oracle({}, _raw(name) if raw_sample else L.make_sample(_raw(name)))
    key = _key(name)
    assert o.unique is True
    assert o.candidate_lengths == (len(key),)
    assert 1000 < o.cost_us < 5_000_000
    good = o.verify(key, {})
    assert good["status"] == "proven", good
    assert good["derived"]["segments"] and good["derived"]["segments"][0]["key_bytes"] == len(key)
    bad = o.verify(_flip(key), {})
    assert bad["status"] == "rejected" and "PBKDF2" in bad["detail"]
    assert o.verify(key[:16], {})["status"] == "rejected"
    assert o.verify("nope", {})["status"] == "error"


@pytest.mark.parametrize("name", ["luks1-xts", "luks2-default"])
def test_iteration_cap_is_an_error_not_a_rejection(name):
    o = L.build_oracle({"max_iterations": 10}, L.make_sample(_raw(name)))
    verdict = o.verify(_key(name), {})
    assert verdict["status"] == "error" and verdict["detail"].startswith("refused")


def test_unsupported_hash_is_refused_at_build_time():
    doc = json.loads(L.make_sample(_raw("luks2-default")))
    for digest in doc["digests"].values():
        digest["hash"] = "whirlpool-not-a-hash"
    with pytest.raises(ValueError, match="unsupported"):
        L.build_oracle({}, json.dumps(doc).encode())


def test_malformed_samples_raise_valueerror():
    with pytest.raises(ValueError):
        L.build_oracle({}, b"garbage")
    with pytest.raises(ValueError):
        L.build_oracle({}, json.dumps({"digests": {"0": {"type": "argon2"}}}).encode())
    with pytest.raises(ValueError):
        L.build_oracle({}, b"")
    raw = bytearray(_raw("luks2-default"))
    raw[5000] ^= 1  # inside the JSON area: the checksum no longer holds
    with pytest.raises(ValueError, match="checksum"):
        L.build_oracle({}, bytes(raw))


def test_missing_primitive_is_an_error_verdict(monkeypatch):
    monkeypatch.delattr(L, "luks")
    o = L.build_oracle({}, L.make_sample(_raw("luks1-xts")))
    verdict = o.verify(_key("luks1-xts"), {})
    assert verdict["status"] == "error" and "luks" in verdict["detail"]


# ------------------------------------------------------------------ prefilter


def test_prefilter_passes_ground_truth_and_rejects_implausible_keys():
    o = L.build_oracle({}, L.make_sample(_raw("luks1-xts")))  # aes-xts, 64-byte key
    key = _key("luks1-xts")
    assert o.prefilter(key) is None
    assert "bytes" in o.prefilter(key[:32])
    assert "zero" in o.prefilter(key[:20] + bytes(8) + key[28:])
    assert "XTS" in o.prefilter(key[:32] + key[:32])
    assert "entropy" in o.prefilter(bytes(range(16)) * 3 + bytes(range(100, 116)))


def test_prefilter_entropy_floor_never_hits_random_keys():
    import os

    o = L.build_oracle({}, L.make_sample(_raw("luks2-essiv")))  # 32-byte key, cbc
    assert o.xts is False
    assert all(o.prefilter(os.urandom(32)) is None for _ in range(20000))


# ------------------------------------------------------------------ inlined, stdlib only


def test_inlined_bundle_proves_with_no_memdiver_and_no_crypto_library(tmp_path):
    lines = ["import base64", f'fmt = load_inlined("luks", {BUNDLE_SOURCES_NAME})']
    for name in ("luks1-essiv", "luks2-4k"):
        sample = base64.b64encode(L.make_sample(_raw(name))).decode()
        lines += [f'o = fmt.build_oracle({{}}, base64.b64decode("{sample}"))',
                  f'k = bytes.fromhex("{_key(name).hex()}")',
                  'print(o.verify(k, {})["status"], o.verify(bytes([k[0] ^ 1]) + k[1:], {})["status"])']
    script = tmp_path / "plugin_like.py"
    script.write_text(POISON_ALL + render_bundle(["luks"]) + "\n".join(lines) + "\n", encoding="utf-8")
    result = subprocess.run([sys.executable, "-I", script.name], cwd=tmp_path,
                            capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == ["proven", "rejected", "proven", "rejected"]


def test_inline_source_carries_the_luks_primitive():
    assert [p.name for p in inline_source("luks").primitives] == ["luks"]


def test_pbkdf2_cost_estimate_uses_the_hash_table():
    assert L.pbkdf2_cost_us("sha256", 100000) == pytest.approx(100000 * L.PBKDF2_US_PER_ITERATION["sha256"])
    assert L.pbkdf2_cost_us("SHA512", 10) == pytest.approx(10 * L.PBKDF2_US_PER_ITERATION["sha512"])
    assert L.pbkdf2_cost_us("unknown", 10) == pytest.approx(10 * max(L.PBKDF2_US_PER_ITERATION.values()))
