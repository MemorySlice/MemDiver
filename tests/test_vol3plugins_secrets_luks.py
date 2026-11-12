"""Tests for ``vol3plugins/linux/secrets/luks.py``.

Every header under ``tests/fixtures/luks/`` was written by a real ``cryptsetup luksFormat``
(see that directory's README for the exact commands); the parser is cross-checked against the
``cryptsetup luksDump`` text stored next to each header, and the volume-key oracle against the
volume key the header was formatted with.  The module is loaded by file path so the tests do
not depend on how (or whether) ``vol3plugins.linux`` is packaged.
"""

import ast
import dataclasses
import importlib.util
import random
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO / "vol3plugins" / "linux" / "secrets" / "luks.py"
FIXTURES = REPO / "tests" / "fixtures" / "luks"

LUKS1_NAMES = ["luks1-xts", "luks1-essiv"]
LUKS2_NAMES = ["luks2-default", "luks2-4k", "luks2-essiv"]
ALL_NAMES = LUKS1_NAMES + LUKS2_NAMES

_STDLIB_ALLOWED = {"base64", "binascii", "dataclasses", "hashlib", "hmac", "json", "re",
                   "struct", "typing"}


def _load_module(name: str):
    spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


luks = _load_module("luks_under_test")


# --------------------------------------------------------------------------- fixture access


def _header_bytes(name: str) -> bytes:
    return (FIXTURES / f"{name}.hdr.bin").read_bytes()


def _ground_truth(name: str) -> dict:
    pairs = (line.split("=", 1) for line in (FIXTURES / f"{name}.gt.txt").read_text().splitlines()
             if line and not line.startswith("#"))
    return {key: value for key, value in pairs}


def _volume_key(name: str) -> bytes:
    return bytes.fromhex(_ground_truth(name)["volume_key_hex"])


def _dump(name: str) -> str:
    return (FIXTURES / f"{name}.dump.txt").read_text()


def _hex_block(section: str, label: str) -> bytes:
    """Hex bytes printed after ``label`` by luksDump, including its continuation lines."""
    lines = section.splitlines()
    for index, line in enumerate(lines):
        if label in line:
            tokens = line.split(label, 1)[1].split()
            for follow in lines[index + 1:]:
                if not re.fullmatch(r"\s*([0-9a-f]{2}\s*)+", follow):
                    break
                tokens += follow.split()
            return bytes.fromhex("".join(tokens))
    raise AssertionError(f"{label!r} not in dump section")


def _scalar(section: str, label: str) -> str:
    match = re.search(re.escape(label) + r"\s*(\S[^\n]*)", section)
    assert match, f"{label!r} not in dump section"
    return match.group(1).strip()


def _flip_bit(data: bytes, index: int, bit: int = 0) -> bytes:
    mutable = bytearray(data)
    mutable[index] ^= 1 << bit
    return bytes(mutable)


@pytest.fixture(scope="module")
def parsed():
    return {name: luks.parse_luks(_header_bytes(name)) for name in ALL_NAMES}


# --------------------------------------------------------------------------- LUKS1 parsing


@pytest.mark.parametrize("name", LUKS1_NAMES)
def test_luks1_fields_match_luksdump(name, parsed):
    header, dump = parsed[name], _dump(name)
    assert isinstance(header, luks.Luks1Header)
    assert header.cipher_name == _scalar(dump, "Cipher name:")
    assert header.cipher_mode == _scalar(dump, "Cipher mode:")
    assert header.hash_spec == _scalar(dump, "Hash spec:")
    assert header.payload_offset_sectors == int(_scalar(dump, "Payload offset:"))
    assert header.key_bytes * 8 == int(_scalar(dump, "MK bits:"))
    assert header.mk_digest == _hex_block(dump, "MK digest:")
    assert header.mk_digest_salt == _hex_block(dump, "MK salt:")
    assert header.mk_digest_iter == int(_scalar(dump, "MK iterations:"))
    assert header.uuid == _scalar(dump, "UUID:")
    assert len(header.mk_digest) == 20 and len(header.mk_digest_salt) == 32


@pytest.mark.parametrize("name", LUKS1_NAMES)
def test_luks1_keyslots_match_luksdump(name, parsed):
    header, dump = parsed[name], _dump(name)
    slot_text = dump.split("Key Slot 0: ENABLED")[1].split("Key Slot 1:")[0]
    assert len(header.keyslots) == 8
    slot0 = header.keyslots[0]
    assert slot0.active and slot0.raw_active == 0x00AC71F3
    assert slot0.iterations == int(_scalar(slot_text, "Iterations:"))
    assert slot0.salt == _hex_block(slot_text, "Salt:")
    assert slot0.key_material_offset == int(_scalar(slot_text, "Key material offset:"))
    assert slot0.stripes == int(_scalar(slot_text, "AF stripes:"))
    assert [slot.active for slot in header.keyslots[1:]] == [False] * 7
    assert all(slot.raw_active == 0x0000DEAD for slot in header.keyslots[1:])


# --------------------------------------------------------------------------- LUKS2 parsing


@pytest.mark.parametrize("name", LUKS2_NAMES)
def test_luks2_binary_header_matches_luksdump(name, parsed):
    header, dump = parsed[name], _dump(name)
    assert isinstance(header, luks.Luks2Header)
    assert header.version == 2 and header.magic == luks.LUKS_MAGIC and not header.is_secondary
    assert header.hdr_size == int(_scalar(dump, "Metadata area:").split()[0]) == 16384
    assert header.seqid == int(_scalar(dump, "Epoch:"))
    assert header.uuid == _scalar(dump, "UUID:")
    assert (header.label, header.subsystem) == ("", "")
    assert header.checksum_alg == "sha256" and header.hdr_offset == 0
    assert header.complete and header.json_error is None
    assert len(header.salt) == 64 and len(header.csum) == 64


@pytest.mark.parametrize("name", LUKS2_NAMES)
def test_luks2_json_sections_match_luksdump(name, parsed):
    header, dump = parsed[name], _dump(name)
    keyslot_text = dump.split("Keyslots:")[1].split("Tokens:")[0]
    digest_text = dump.split("Digests:")[1]
    slot = header.keyslots["0"]
    assert slot["key_size"] * 8 == int(_scalar(keyslot_text, "Key:").split()[0])
    assert int(slot["area"]["offset"]) == int(_scalar(keyslot_text, "Area offset:").split()[0])
    assert int(slot["area"]["size"]) == int(_scalar(keyslot_text, "Area length:").split()[0])
    assert slot["kdf"]["type"] == _scalar(keyslot_text, "PBKDF:") == "argon2id"
    digest = header.digests["0"]
    assert digest["type"] == "pbkdf2" and digest["hash"] == _scalar(digest_text, "Hash:")
    assert digest["iterations"] == int(_scalar(digest_text, "Iterations:"))
    assert luks.base64.b64decode(digest["salt"]) == _hex_block(digest_text, "Salt:")
    assert luks.base64.b64decode(digest["digest"]) == _hex_block(digest_text, "Digest:")
    assert header.digests["0"]["keyslots"] == ["0"] and header.digests["0"]["segments"] == ["0"]
    assert set(header.config) >= {"json_size", "keyslots_size"}
    assert header.tokens == {}


@pytest.mark.parametrize("name", LUKS2_NAMES)
def test_luks2_checksum_ok_on_primary_and_secondary(name):
    data = _header_bytes(name)
    primary = luks.parse_luks2(data)
    secondary = luks.parse_luks2(data[primary.hdr_size:])
    assert primary.checksum_ok is True and secondary.checksum_ok is True
    assert secondary.is_secondary and secondary.magic == luks.LUKS2_SECONDARY_MAGIC
    assert secondary.hdr_offset == primary.hdr_size
    assert (secondary.seqid, secondary.uuid, secondary.digests) == (
        primary.seqid, primary.uuid, primary.digests)
    assert luks.parse_luks(data[primary.hdr_size:]).checksum_ok is True


@pytest.mark.parametrize("name", LUKS2_NAMES)
def test_luks2_checksum_false_after_one_byte_json_flip(name):
    data = _header_bytes(name)
    digest_b64 = luks.parse_luks2(data).digests["0"]["digest"].encode()
    position = data.index(digest_b64) + 3  # inside the base64 digest, still valid JSON
    flipped = bytearray(data)
    flipped[position] = ord("B") if flipped[position] != ord("B") else ord("C")
    header = luks.parse_luks2(bytes(flipped))
    assert header.json_error is None, "flip must leave the JSON parseable"
    assert header.checksum_ok is False
    assert header.digests["0"]["digest"] != luks.parse_luks2(data).digests["0"]["digest"]


@pytest.mark.parametrize("area", ["json", "binary"])
def test_luks2_checksum_false_after_other_corruption(area):
    data = _header_bytes("luks2-default")
    index = 4096 if area == "json" else 16  # '{' of the JSON / low byte of seqid
    header = luks.parse_luks2(_flip_bit(data, index, bit=1))
    assert header.checksum_ok is False
    if area == "json":
        assert header.json_error and header.keyslots == {} and header.segments == {}


def test_luks2_truncated_buffer_is_incomplete_not_an_error():
    header = luks.parse_luks2(_header_bytes("luks2-default")[:4096])
    assert header.complete is False and header.checksum_ok is False
    assert header.uuid and header.json_text is None and header.digests == {}
    verdict = luks.verify_volume_key(header, _volume_key("luks2-default"))
    assert verdict.matched is False and "unavailable" in verdict.detail


@pytest.mark.parametrize("name", ALL_NAMES)
def test_parse_luks_dispatches_on_version(name, parsed):
    expected = luks.Luks1Header if name.startswith("luks1") else luks.Luks2Header
    assert type(luks.parse_luks(_header_bytes(name))) is expected
    assert type(luks.parse_luks(bytearray(_header_bytes(name)))) is expected


def test_parse_errors():
    good = _header_bytes("luks1-xts")
    with pytest.raises(luks.LuksParseError):
        luks.parse_luks(b"\0" * 4096)
    with pytest.raises(luks.LuksParseError):
        luks.parse_luks1(good[:300])
    with pytest.raises(luks.LuksParseError):
        luks.parse_luks(good[:6] + b"\x00\x03" + good[8:])  # version 3
    with pytest.raises(luks.LuksParseError):
        luks.parse_luks2(good)  # LUKS1 bytes are not LUKS2
    with pytest.raises(luks.LuksParseError):
        luks.parse_luks1(_header_bytes("luks2-default"))
    bad_size = bytearray(_header_bytes("luks2-default"))
    bad_size[8:16] = (12345).to_bytes(8, "big")
    with pytest.raises(luks.LuksParseError):
        luks.parse_luks2(bytes(bad_size))


# --------------------------------------------------------------------------- the oracle


@pytest.mark.parametrize("name", ALL_NAMES)
def test_correct_volume_key_matches(name, parsed):
    verdict = luks.verify_volume_key(parsed[name], _volume_key(name))
    assert verdict.matched is True
    assert verdict.digest_id == "0"
    assert verdict.segments == luks.segment_crypto(parsed[name])
    assert verdict.detail


@pytest.mark.parametrize("name", ALL_NAMES)
@pytest.mark.parametrize("where", ["first", "last"])
def test_one_bit_flipped_key_does_not_match(name, where, parsed):
    key = _volume_key(name)
    wrong = _flip_bit(key, 0 if where == "first" else len(key) - 1, bit=0 if where == "first" else 7)
    verdict = luks.verify_volume_key(parsed[name], wrong)
    assert verdict.matched is False and verdict.digest_id is None and verdict.segments == []
    assert "PBKDF2" in verdict.detail  # it really ran the oracle, it did not reject on length


@pytest.mark.parametrize("name", ALL_NAMES)
def test_wrong_length_key_is_rejected_without_running_pbkdf2(name, parsed, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("PBKDF2 must not run for a wrong-length key")

    monkeypatch.setattr(luks.hashlib, "pbkdf2_hmac", forbidden)
    key = _volume_key(name)
    for wrong in (key[:-1], key + b"\0", key[: len(key) // 2], b"\0" * 1, b""):
        verdict = luks.verify_volume_key(parsed[name], wrong)
        assert verdict.matched is False
        assert "length" in verdict.detail or verdict.detail == "empty key"


def test_key_of_another_header_does_not_match(parsed):
    assert luks.verify_volume_key(parsed["luks2-default"], _volume_key("luks1-xts")).matched is False
    assert luks.verify_volume_key(parsed["luks1-xts"], _volume_key("luks2-4k")).matched is False


@pytest.mark.parametrize("name", ALL_NAMES)
def test_verification_is_fast_enough_for_a_scan_loop(name, parsed):
    started = time.perf_counter()
    luks.verify_volume_key(parsed[name], _volume_key(name))
    assert time.perf_counter() - started < 2.0


def test_verify_accepts_bytearray_and_memoryview_keys(parsed):
    key = _volume_key("luks1-essiv")
    assert luks.verify_volume_key(parsed["luks1-essiv"], bytearray(key)).matched
    assert luks.verify_volume_key(parsed["luks1-essiv"], memoryview(key)).matched


def test_iteration_cap_rejects_hostile_headers_before_pbkdf2(parsed, monkeypatch):
    monkeypatch.setattr(luks.hashlib, "pbkdf2_hmac", lambda *a, **k: pytest.fail("ran PBKDF2"))
    luks1 = dataclasses.replace(parsed["luks1-xts"], mk_digest_iter=4_000_000_000)
    assert luks.verify_volume_key(luks1, _volume_key("luks1-xts")).matched is False
    base = parsed["luks2-default"]
    digests = {"0": dict(base.digests["0"], iterations=4_000_000_000)}
    luks2 = dataclasses.replace(base, digests=digests)
    verdict = luks.verify_volume_key(luks2, _volume_key("luks2-default"))
    assert verdict.matched is False and "iterations" in verdict.detail


def test_unsupported_hash_is_a_verdict_not_an_exception(parsed):
    luks1 = dataclasses.replace(parsed["luks1-xts"], hash_spec="no-such-hash")
    verdict = luks.verify_volume_key(luks1, _volume_key("luks1-xts"))
    assert verdict.matched is False and "unsupported hash" in verdict.detail
    base = parsed["luks2-default"]
    luks2 = dataclasses.replace(base, digests={"0": dict(base.digests["0"], hash="no-such-hash")})
    assert "unsupported hash" in luks.verify_volume_key(luks2, _volume_key("luks2-default")).detail


def test_luks2_without_a_pbkdf2_digest_cannot_verify(parsed):
    base = parsed["luks2-default"]
    other = dataclasses.replace(base, digests={"0": dict(base.digests["0"], type="hmac")})
    verdict = luks.verify_volume_key(other, _volume_key("luks2-default"))
    assert verdict.matched is False and "no pbkdf2 digest" in verdict.detail


def test_luks2_picks_the_matching_digest_among_several(parsed):
    base = parsed["luks2-default"]
    decoy = dict(base.digests["0"], segments=["7"], keyslots=["0"])
    decoy["digest"] = luks.base64.b64encode(b"\1" * 32).decode()
    header = dataclasses.replace(base, digests={"0": decoy, "1": base.digests["0"]})
    verdict = luks.verify_volume_key(header, _volume_key("luks2-default"))
    assert verdict.matched and verdict.digest_id == "1"
    assert [seg["segment"] for seg in verdict.segments] == ["0"]


def test_verify_never_raises_on_a_non_header_or_non_bytes_key(parsed):
    assert luks.verify_volume_key(object(), b"k" * 32).matched is False
    assert luks.verify_volume_key(parsed["luks1-xts"], 12345).matched is False
    assert luks.verify_volume_key(parsed["luks1-xts"], "text").matched is False


# ----------------------------------------------- hostile (carved-from-memory) headers


def _luks2_with_json(document_text: bytes, name: str = "luks2-default") -> bytes:
    data = bytearray(_header_bytes(name))
    area = document_text + b"\0"
    data[4096:4096 + len(area)] = area
    return bytes(data)


def _hostile_header(digests=None, segments=None, keyslots=None):
    base = luks.parse_luks2(_header_bytes("luks2-default"))
    return dataclasses.replace(
        base, digests=digests if digests is not None else base.digests,
        segments=segments if segments is not None else base.segments,
        keyslots=keyslots if keyslots is not None else base.keyslots)


@pytest.mark.parametrize("payload", [b"[" * 200000, b'{"a":' * 50000, b"[" * 33 + b"]" * 33])
def test_deeply_nested_json_is_a_json_error_not_recursionerror(payload):
    header = luks.parse_luks2(_luks2_with_json(payload))
    assert header.json_error and header.keyslots == {} and header.checksum_ok is False


@pytest.mark.parametrize("constant", [b"Infinity", b"-Infinity", b"NaN", b"1e400"])
def test_non_finite_json_numbers_are_rejected(constant):
    header = luks.parse_luks2(_luks2_with_json(b'{"digests": {"0": {"iterations": ' + constant + b"}}}"))
    assert header.json_error and header.digests == {}


def test_hostile_numbers_never_escape_segment_crypto_or_verify():
    inf = float("inf")
    base = luks.parse_luks2(_header_bytes("luks2-default"))
    segment = dict(base.segments["0"], sector_size=inf, iv_tweak=inf, offset=inf, size=inf)
    digest = dict(base.digests["0"], iterations=inf)
    header = _hostile_header(segments={"0": segment}, digests={"0": digest})
    entry = luks.segment_crypto(header)[0]
    assert entry["sector_size"] == 512 and entry["offset_bytes"] == 0
    assert luks.verify_volume_key(header, _volume_key("luks2-default")).matched is False
    for bad in (True, 1.5, -5, 10**30, "1e5", None, [1]):
        digest = dict(base.digests["0"], iterations=bad)
        assert luks.verify_volume_key(_hostile_header(digests={"0": digest}),
                                      _volume_key("luks2-default")).matched is False


@pytest.mark.parametrize("bad_id", ["\u00b2", "9" * 5000, "\u0663", "-1", " 1"])
def test_odd_ids_do_not_break_ordering(bad_id):
    base = luks.parse_luks2(_header_bytes("luks2-default"))
    digests = {"0": base.digests["0"], bad_id: dict(base.digests["0"])}
    segments = {"0": base.segments["0"], bad_id: dict(base.segments["0"])}
    header = _hostile_header(digests=digests, segments=segments)
    assert luks.verify_volume_key(header, _volume_key("luks2-default")).matched is True
    assert [e["segment"] for e in luks.segment_crypto(header)][0] == "0"


@pytest.mark.parametrize("alg", ["shake_128", "shake_256", "md5", "bogus", "", "sha3_256"])
def test_unlisted_checksum_algorithms_give_checksum_false(alg):
    data = bytearray(_header_bytes("luks2-default"))
    data[72:104] = alg.encode().ljust(32, b"\0")
    header = luks.parse_luks2(bytes(data))
    assert header.checksum_ok is False


@pytest.mark.parametrize("digest_len", [0, 1, 8, 15, 65, 200])
def test_digest_length_outside_16_to_64_is_rejected(digest_len):
    base = luks.parse_luks2(_header_bytes("luks2-default"))
    digest = dict(base.digests["0"], digest=luks.base64.b64encode(b"\0" * digest_len).decode())
    verdict = luks.verify_volume_key(_hostile_header(digests={"0": digest}), _volume_key("luks2-default"))
    assert verdict.matched is False and "digest length" in verdict.detail


def test_one_byte_digest_cannot_false_positive():
    base = luks.parse_luks2(_header_bytes("luks2-default"))
    rng = random.Random(3)
    for _ in range(300):
        key = rng.randbytes(64)
        pbkdf2 = luks.hashlib.pbkdf2_hmac("sha256", key, b"s", 1, 1)
        digest = dict(base.digests["0"], iterations=1, salt=luks.base64.b64encode(b"s").decode(),
                      digest=luks.base64.b64encode(pbkdf2).decode())
        assert luks.verify_volume_key(_hostile_header(digests={"0": digest}), key).matched is False


def test_digest_count_and_total_iteration_budget_bound_the_cost(monkeypatch):
    calls = []
    monkeypatch.setattr(luks.hashlib, "pbkdf2_hmac", lambda *a, **k: calls.append(a[3]) or b"\0" * a[4])
    base = luks.parse_luks2(_header_bytes("luks2-default"))
    many = {str(i): dict(base.digests["0"], iterations=10_000_000) for i in range(50)}
    verdict = luks.verify_volume_key(_hostile_header(digests=many), _volume_key("luks2-default"))
    assert verdict.matched is False and "budget" in verdict.detail
    assert sum(calls) <= luks.DEFAULT_MAX_TOTAL_ITERATIONS and len(calls) <= luks.MAX_PBKDF2_DIGESTS
    calls.clear()
    cheap = {str(i): dict(base.digests["0"], iterations=10) for i in range(50)}
    verdict = luks.verify_volume_key(_hostile_header(digests=cheap), _volume_key("luks2-default"))
    assert len(calls) == luks.MAX_PBKDF2_DIGESTS and "not tried" in verdict.detail


@pytest.mark.parametrize("hash_spec", ["whirlpool", "ripemd160", "shake_128", "", "\x00x"])
def test_unsupported_luks1_hashes_are_a_verdict(parsed, hash_spec):
    header = dataclasses.replace(parsed["luks1-xts"], hash_spec=hash_spec)
    verdict = luks.verify_volume_key(header, _volume_key("luks1-xts"))
    assert verdict.matched is False
    assert "unsupported hash" in verdict.detail or "PBKDF2" in verdict.detail


@pytest.mark.parametrize("junk", [None, "text", 5, object()])
def test_parsers_raise_only_luksparseerror_on_non_bytes(junk):
    for function in (luks.parse_luks, luks.parse_luks1, luks.parse_luks2, luks.segment_crypto):
        with pytest.raises(luks.LuksParseError):
            function(junk)


# --------------------------------------------------------------------------- find_luks_headers


def _noise(length: int, seed: int = 7) -> bytes:
    return random.Random(seed).randbytes(length)


@pytest.mark.parametrize("name", ALL_NAMES)
def test_find_header_at_odd_offset_in_random_bytes(name):
    blob = _header_bytes(name)
    offset = 12345
    image = _noise(offset) + blob + _noise(20000, seed=8)
    expected = [offset] if name.startswith("luks1") else [offset, offset + 16384]
    assert luks.find_luks_headers(image) == expected
    assert luks.find_luks_headers(image, base=0x7F000000) == [0x7F000000 + o for o in expected]
    assert luks.find_luks_headers(bytearray(image)) == expected
    assert luks.find_luks_headers(memoryview(image)) == expected


def test_find_reports_luks2_secondary_magic_with_its_own_offset():
    image = _noise(999) + _header_bytes("luks2-4k")
    hits = luks.find_luks_headers(image)
    assert [image[hit:hit + 6] for hit in hits] == [luks.LUKS_MAGIC, luks.LUKS2_SECONDARY_MAGIC]


@pytest.mark.parametrize("version", [b"\x00\x01", b"\x00\x02", b"\x00\x03", b"\xff\xff"])
def test_find_ignores_lone_magic_followed_by_garbage(version):
    for seed in range(100):
        rng = random.Random(seed)
        image = rng.randbytes(777) + luks.LUKS_MAGIC + version + rng.randbytes(2000)
        assert luks.find_luks_headers(image) == []
        image = rng.randbytes(31) + luks.LUKS2_SECONDARY_MAGIC + version + rng.randbytes(2000)
        assert luks.find_luks_headers(image) == []


def test_find_ignores_truncated_and_zeroed_headers():
    real = _header_bytes("luks1-xts")
    assert luks.find_luks_headers(real[:100]) == []
    assert luks.find_luks_headers(real[:591]) == []  # one byte short of the 592-byte phdr
    assert luks.find_luks_headers(real[:592]) == [0]
    assert luks.find_luks_headers(luks.LUKS_MAGIC) == []
    assert luks.find_luks_headers(b"") == []
    zeroed = real[:8] + b"\0" * 584
    assert luks.find_luks_headers(zeroed) == []


def test_find_rejects_valid_version_with_corrupt_fields():
    real = bytearray(_header_bytes("luks1-xts"))
    bad_slot = bytearray(real)
    bad_slot[208:212] = b"\x12\x34\x56\x78"  # keyslot state word neither enabled nor disabled
    bad_uuid = bytearray(real)
    bad_uuid[168:172] = b"zzzz"
    bad_name = bytearray(real)
    bad_name[8] = 0x01  # control character in the cipher name
    for corrupt in (bad_slot, bad_uuid, bad_name):
        assert luks.find_luks_headers(bytes(corrupt)) == []
    two = bytearray(_header_bytes("luks2-default"))
    two[8:16] = (999).to_bytes(8, "big")  # hdr_size not a power of two in range
    assert luks.find_luks_headers(bytes(two)).count(0) == 0


# --------------------------------------------------------------------------- segment_crypto


@pytest.mark.parametrize("name", LUKS1_NAMES)
def test_segment_crypto_luks1_matches_luksdump(name, parsed):
    dump = _dump(name)
    (segment,) = luks.segment_crypto(parsed[name])
    assert segment["cipher"] == f"{_scalar(dump, 'Cipher name:')}-{_scalar(dump, 'Cipher mode:')}"
    assert segment["sector_size"] == 512 and segment["iv_tweak"] == 0
    assert segment["offset_bytes"] == int(_scalar(dump, "Payload offset:")) * 512
    assert segment["key_bytes"] * 8 == int(_scalar(dump, "MK bits:"))
    assert segment["size"] is None and segment["type"] == "crypt"


@pytest.mark.parametrize("name", LUKS2_NAMES)
def test_segment_crypto_luks2_matches_luksdump(name, parsed):
    dump = _dump(name)
    segment_text = dump.split("Data segments:")[1].split("Keyslots:")[0]
    keyslot_text = dump.split("Keyslots:")[1].split("Tokens:")[0]
    (segment,) = luks.segment_crypto(parsed[name])
    assert segment["cipher"] == _scalar(segment_text, "cipher:")
    assert segment["sector_size"] == int(_scalar(segment_text, "sector:").split()[0])
    assert segment["offset_bytes"] == int(_scalar(segment_text, "offset:").split()[0])
    assert "(whole device)" in segment_text and segment["size"] is None
    assert segment["key_bytes"] * 8 == int(_scalar(keyslot_text, "Key:").split()[0])
    assert segment["segment"] == "0" and segment["digest_id"] == "0" and segment["iv_tweak"] == 0
    assert segment["type"] == "crypt"


def test_segment_crypto_distinguishes_the_4k_sector_fixture(parsed):
    sizes = {name: luks.segment_crypto(parsed[name])[0]["sector_size"] for name in LUKS2_NAMES}
    assert sizes == {"luks2-default": 512, "luks2-4k": 4096, "luks2-essiv": 512}


def test_segment_crypto_skips_non_crypt_segments_and_survives_hostile_json(parsed):
    base = parsed["luks2-default"]
    segments = {
        "0": base.segments["0"],
        "1": {"type": "linear", "offset": "0", "size": "4096"},
        "2": dict(base.segments["0"], size="65536", flags=["backup-previous"]),
        "3": dict(base.segments["0"], flags="not-a-list", offset="garbage", iv_tweak=None),
    }
    header = dataclasses.replace(base, segments=segments, digests={"0": {"segments": 5, "keyslots": "x"}})
    entries = luks.segment_crypto(header)
    assert [entry["segment"] for entry in entries] == ["0", "2", "3"]
    assert entries[1]["size"] == 65536 and entries[1]["flags"] == ["backup-previous"]
    assert entries[2]["flags"] == [] and entries[2]["offset_bytes"] == 0
    assert all(entry["key_bytes"] is None and entry["digest_id"] is None for entry in entries)


# --------------------------------------------------------------------------- parse_cipher_spec

# (spec, key_size, cipher, chainmode, ivmode, ivopts, key_parts, crypto_api_name)
CIPHER_SPEC_TABLE = [
    ("aes-xts-plain64", None, "aes", "xts", "plain64", None, 1, "xts(aes)"),
    ("aes-cbc-essiv:sha256", None, "aes", "cbc", "essiv", "sha256", 1, "essiv(cbc(aes),sha256)"),
    ("aes-cbc-essiv:sha512", None, "aes", "cbc", "essiv", "sha512", 1, "essiv(cbc(aes),sha512)"),
    ("aes-cbc-plain", None, "aes", "cbc", "plain", None, 1, "cbc(aes)"),
    ("aes", None, "aes", "cbc", "plain", None, 1, "cbc(aes)"),  # bare name == cbc-plain
    ("aes-plain", None, "aes", "cbc", "plain", None, 1, "cbc(aes)"),  # legacy compat rule
    ("aes-ecb", None, "aes", "ecb", None, None, 1, "ecb(aes)"),
    ("aes-ecb-plain64", None, "aes", "ecb", None, None, 1, "ecb(aes)"),  # ecb has no IV
    ("serpent-xts-plain64", None, "serpent", "xts", "plain64", None, 1, "xts(serpent)"),
    ("twofish-cbc-benbi", None, "twofish", "cbc", "benbi", None, 1, "cbc(twofish)"),
    ("aes-cbc-null", None, "aes", "cbc", "null", None, 1, "cbc(aes)"),
    ("aes-xts-plain64be", None, "aes", "xts", "plain64be", None, 1, "xts(aes)"),
    ("aes-cbc-eboiv", None, "aes", "cbc", "eboiv", None, 1, "cbc(aes)"),
    ("aes:2-cbc-plain64", None, "aes", "cbc", "plain64", None, 2, "cbc(aes)"),
    ("aes:64-cbc-lmk", None, "aes", "cbc", "lmk", None, 64, "cbc(aes)"),
    ("aes:64-cbc-lmk", 1024, "aes", "cbc", "lmk", None, 64, "cbc(aes)"),  # 64 equal keys
    ("aes:64-cbc-lmk", 1040, "aes", "cbc", "lmk", None, 65, "cbc(aes)"),  # + IV seed key
    ("aes-cbc-tcw", None, "aes", "cbc", "tcw", None, 3, "cbc(aes)"),  # 1 key + IV + whitening
    ("aes-xts-elephant", None, "aes", "xts", "elephant", None, 2, "xts(aes)"),
    ("capi:xts(aes)-plain64", None, "aes", "xts", "plain64", None, 1, "xts(aes)"),
    ("capi:cbc(aes)-essiv:sha256", None, "aes", "cbc", "essiv", "sha256", 1, "essiv(cbc(aes),sha256)"),
    ("capi:xts(aes)", None, "aes", "xts", None, None, 1, "xts(aes)"),
    ("capi:cbc(aes)-lmk", None, "aes", "cbc", "lmk", None, 64, "cbc(aes)"),
    ("capi:cbc(aes)-lmk", 1040, "aes", "cbc", "lmk", None, 65, "cbc(aes)"),
    ("capi:cbc(aes)-tcw", None, "aes", "cbc", "tcw", None, 3, "cbc(aes)"),
    ("capi:authenc(hmac(sha256),xts(aes))-random", None, None, None, "random", None, 1,
     "authenc(hmac(sha256),xts(aes))"),
    ("capi:essiv(cbc(aes),sha256)-plain64", None, None, None, "plain64", None, 1,
     "essiv(cbc(aes),sha256)"),
]


@pytest.mark.parametrize("row", CIPHER_SPEC_TABLE, ids=[row[0] + f"|{row[1]}" for row in CIPHER_SPEC_TABLE])
def test_parse_cipher_spec_table(row):
    spec, key_size, cipher, chainmode, ivmode, ivopts, key_parts, api_name = row
    parsed_spec = luks.parse_cipher_spec(spec, key_size)
    assert parsed_spec == luks.CipherSpec(cipher=cipher, chainmode=chainmode, ivmode=ivmode,
                                          ivopts=ivopts, key_parts=key_parts,
                                          crypto_api_name=api_name)


@pytest.mark.parametrize("spec", [
    "aes-xts",                  # IV mechanism required
    "aes-cbc-essiv",            # Digest algorithm missing for ESSIV mode
    "aes-cbc-nonsense",         # Invalid IV mode
    "aes:3-cbc-plain",          # key count not a power of two
    "aes:0-cbc-plain",
    "aes:x-cbc-plain",
    "aes:2x-cbc-plain",
    "aes:-cbc-plain",
    "xts(aes)-plain64",         # parentheses are only legal behind capi:
    "aes--plain64",             # empty chain mode
    "-xts-plain64",             # empty cipher
    "capi:xts(aes)-essiv",      # ESSIV without a digest
    "capi:xts(aes)-bogus",
    "capi:xts(aes)-",
    "aes-" + "x" * 130 + "-plain",   # >= CRYPTO_MAX_ALG_NAME
    "",
])
def test_parse_cipher_spec_rejects_what_dm_crypt_rejects(spec):
    with pytest.raises(ValueError):
        luks.parse_cipher_spec(spec)


@pytest.mark.parametrize("name,api_name", [
    ("luks1-xts", "xts(aes)"), ("luks1-essiv", "essiv(cbc(aes),sha256)"),
    ("luks2-default", "xts(aes)"), ("luks2-4k", "xts(aes)"), ("luks2-essiv", "essiv(cbc(aes),sha256)"),
])
def test_cipher_specs_of_real_headers_map_to_crypto_api_names(name, api_name, parsed):
    (segment,) = luks.segment_crypto(parsed[name])
    spec = luks.parse_cipher_spec(segment["cipher"], segment["key_bytes"])
    assert spec.crypto_api_name == api_name and spec.key_parts == 1 and spec.cipher == "aes"


# --------------------------------------------------------------------------- portability


def _module_tree() -> ast.Module:
    return ast.parse(MODULE_PATH.read_text())


def test_module_imports_are_stdlib_only_and_absolute():
    imported = set()
    for node in ast.walk(_module_tree()):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "relative imports break source-inlining"
            imported.add((node.module or "").split(".")[0])
    assert imported <= _STDLIB_ALLOWED
    assert imported <= set(sys.stdlib_module_names)


def test_module_level_imports_are_stdlib_only():
    top_level = [node for node in _module_tree().body if isinstance(node, (ast.Import, ast.ImportFrom))]
    assert top_level, "expected module-level imports"
    names = {(a.name if isinstance(node, ast.Import) else node.module).split(".")[0]
             for node in top_level for a in (node.names if isinstance(node, ast.Import) else [node])}
    assert names <= _STDLIB_ALLOWED


def test_module_never_reads___file__():
    names = [node.id for node in ast.walk(_module_tree()) if isinstance(node, ast.Name)]
    attrs = [node.attr for node in ast.walk(_module_tree()) if isinstance(node, ast.Attribute)]
    assert "__file__" not in names + attrs


def test_module_pasted_alone_runs_without_memdiver(tmp_path):
    solo = tmp_path / "solo"
    solo.mkdir()
    (solo / "luks.py").write_text(MODULE_PATH.read_text())
    driver = tmp_path / "driver.py"
    driver.write_text(
        "import sys\n"
        "ns = {'__name__': 'pasted'}\n"
        "exec(compile(open(sys.argv[1]).read(), 'luks.py', 'exec'), ns)\n"
        "h = ns['parse_luks'](open(sys.argv[2], 'rb').read())\n"
        "v = ns['verify_volume_key'](h, bytes.fromhex(sys.argv[3]))\n"
        "assert not [m for m in sys.modules if m.split('.')[0] in ('memdiver', 'volatility3')]\n"
        "print(v.matched, v.digest_id, ns['segment_crypto'](h)[0]['cipher'])\n"
    )
    result = subprocess.run(
        [sys.executable, "-I", str(driver), str(solo / "luks.py"),
         str(FIXTURES / "luks2-default.hdr.bin"), _ground_truth("luks2-default")["volume_key_hex"]],
        capture_output=True, text=True, timeout=60, cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == ["True", "0", "aes-xts-plain64"]
