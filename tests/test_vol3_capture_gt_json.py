"""Tests for tools/vol3_capture/gt_json.py (capture ground-truth sidecar builder).

The pahole fixtures are real ``pahole -C`` output taken from the x86_64 4-level
capture's secrets.tar.gz (Ubuntu 24.04, kernel 6.8.0-136-generic).
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "tests" / "fixtures" / "vol3_capture"


def _load_gt_json():
    spec = importlib.util.spec_from_file_location(
        "vol3_capture_gt_json", REPO / "tools" / "vol3_capture" / "gt_json.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gt = _load_gt_json()


def _parse(name: str) -> dict:
    return gt.parse_pahole((FIXTURES / f"pahole_{name}.txt").read_text())


def test_crypt_config_flexible_key_array_offset():
    layout = _parse("crypt_config")["crypt_config"]
    assert layout["size"] == 888
    assert layout["members"]["key"]["offset"] == 888
    assert layout["members"]["key_size"]["offset"] == 208
    assert layout["members"]["authenc_key"]["offset"] == 880


def test_wg_device_aligned_attribute_member_is_named():
    layout = _parse("wg_device")["wg_device"]
    assert layout["size"] == 1344
    assert len(layout["members"]) == 24
    assert layout["members"]["encrypt_queue"]["offset"] == 64
    assert layout["members"]["static_identity"]["offset"] == 856
    assert layout["members"]["incoming_port"]["offset"] == 1296


def test_union_member_recorded_but_not_its_variants():
    layout = _parse("ecryptfs_auth_tok")["ecryptfs_auth_tok"]
    assert layout["size"] == 740
    assert set(layout["members"]) == {
        "version", "token_type", "flags", "session_key", "reserved", "token"}
    assert layout["members"]["token"]["offset"] == 628


def test_noise_handshake_has_key_material_members():
    members = _parse("noise_handshake")["noise_handshake"]["members"]
    for name in ("ephemeral_private", "remote_static", "chaining_key", "hash"):
        assert name in members
        assert isinstance(members[name]["offset"], int)


@pytest.mark.parametrize(("decl", "name"), [
    ("struct crypt_queue         encrypt_queue __attribute__((__aligned__(64)))", "encrypt_queue"),
    ("u8                         key[]", "key"),
    ("struct net_device *        dev", "dev"),
    ("void                       (*fn)(int)", "fn"),
    ("unsigned int               flag:1", "flag"),
    ("} token", "token"),
])
def test_member_name(decl, name):
    assert gt._member_name(decl) == name


def test_ecryptfs_fekek_signature_known_vector():
    # ecryptfs-add-passphrase "test" prints sig d395309aaad4de06.
    _, signature = gt.ecryptfs_fekek("test")
    assert signature == "d395309aaad4de06"


def test_parse_wg_dump_interface_and_peers():
    priv = "YAZV5LezT3s" + "A" * 32  # 43 chars + '=' -> 32 bytes
    dump = "\n".join([
        f"wg0\t{priv}=\tPUB=\t51820\toff",
        "wg0\tPEERB=\tPSK" + "A" * 40 + "=\t10.199.0.2:51820\t10.200.0.2/32\t1793986957\t10\t20\t5",
        "wg0\tPEERC=\t(none)\t192.0.2.1:51820\t10.200.0.3/32\t0\t0\t148\t5",
    ])
    (record,) = gt.parse_wg_dump(dump, "gtwgA", {"role": "initiator"})
    assert record["netns"] == "gtwgA" and record["role"] == "initiator"
    assert len(bytes.fromhex(record["private_key_hex"])) == 32
    assert [p["latest_handshake_unix"] for p in record["peers"]] == [1793986957, 0]
    assert record["peers"][1]["preshared_key_hex"] is None


def test_finalize_folds_fragments_into_schema(tmp_path):
    frags, out = tmp_path / "f.jsonl", tmp_path / "secrets.json"
    gt.cmd_key(str(frags), "k1", "test", "00ff", "unit")
    gt.cmd_gap(str(frags), "veracrypt", "no build")
    gt.cmd_kernel(str(frags), "paging", '{"page_table_levels": 5}')
    gt.cmd_btf(str(frags), "btf:dm_crypt", str(FIXTURES / "pahole_crypt_config.txt"))
    gt.cmd_finalize(str(frags), str(out), "x86_64")
    doc = json.loads(out.read_text())
    assert doc["schema"] == "memdiver-secrets-gt/1"
    assert doc["keys"][0]["length"] == 2
    assert doc["gaps"] == [{"item": "veracrypt", "reason": "no build"}]
    assert doc["kernel"]["paging"]["page_table_levels"] == 5
    assert doc["btf_offsets"]["crypt_config"]["members"]["key"] == {
        "offset": 888, "size": 0, "decl": "u8                         key[]"}
    for section in ("dmcrypt", "wireguard", "fscrypt", "ecryptfs", "gocryptfs", "ssh"):
        assert doc[section] == []
