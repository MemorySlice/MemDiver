"""Capture v2 additions to tools/vol3_capture (guest-side helpers, host-testable parts).

fscrypt v1 descriptor derivation + legacy ``logon fscrypt:`` payload, the SSH Tier A
sidecar record built from the paramiko ground-truth peer's events, and shell syntax of
the stage / export scripts.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

CAPTURE_DIR = Path(__file__).resolve().parents[1] / "tools" / "vol3_capture"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"_vol3_capture_{name}", CAPTURE_DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


fscrypt_helper = _load("fscrypt_helper")
gt_json = _load("gt_json")

# --- fscrypt -----------------------------------------------------------------------------


def test_v1_descriptor_matches_openssl_double_sha512():
    # Reference computed independently: openssl dgst -sha512 -binary twice, first 8 bytes.
    assert fscrypt_helper.v1_descriptor(bytes(range(64))) == "04334e23057a6e2d"


def test_v1_descriptor_is_16_hex_digits():
    assert len(fscrypt_helper.v1_descriptor(b"\xff" * 64)) == 16


def test_legacy_key_payload_layout():
    raw = bytes(range(64))
    payload = fscrypt_helper.legacy_key_payload(raw)
    assert len(payload) == 72
    mode, body, size = struct.unpack("<I64sI", payload)
    assert (mode, body, size) == (1, raw, 64)


def test_legacy_key_payload_short_key_is_zero_padded():
    payload = fscrypt_helper.legacy_key_payload(b"\x01" * 32)
    assert payload[4:36] == b"\x01" * 32 and payload[36:68] == b"\0" * 32
    assert struct.unpack_from("<I", payload, 68)[0] == 32


@pytest.mark.parametrize("raw", [b"", b"\0" * 65])
def test_legacy_key_payload_rejects_bad_sizes(raw):
    with pytest.raises(ValueError):
        fscrypt_helper.legacy_key_payload(raw)


def test_fscrypt_helper_cli_descriptor_and_payload(tmp_path):
    key = tmp_path / "k"
    key.write_bytes(bytes(range(64)))
    out = subprocess.run(["python3", str(CAPTURE_DIR / "fscrypt_helper.py"), "descriptor", str(key)],
                         capture_output=True, text=True, check=True).stdout.strip()
    assert out == "04334e23057a6e2d"
    payload = tmp_path / "p"
    subprocess.run(["python3", str(CAPTURE_DIR / "fscrypt_helper.py"), "legacy-payload",
                    str(key), str(payload)], check=True)
    assert payload.read_bytes() == fscrypt_helper.legacy_key_payload(bytes(range(64)))


# --- SSH Tier A ----------------------------------------------------------------------------

K_INT = "eb4cd633443279fba5cf157aced2e3f896cdb9c41827bc2327ab98f2bcd2e819"
H = "589bc2c926793af8a8047c7fca834e606f56cb913a41e022748df954ae30b9f2"
CLIENT_LOG = (
    "negotiated kex=curve25519-sha256@libssh.org cipher_out=aes256-ctr cipher_in=aes256-ctr "
    "hmac_out=hmac-sha2-256 hmac_in=hmac-sha2-256\n"
    "exec output: memdiver-gt-server exec: echo memdiver-libssh-session\n"
    "READY pid=881 libssh=0.10.6/openssl/zlib\n"
)


def _events(h: str = H, k_int: str = K_INT) -> list[dict]:
    keys = {"A": "11" * 16, "B": "22" * 16, "C": "33" * 32, "D": "44" * 32,
            "E": "55" * 32, "F": "66" * 32}
    out: list[dict] = []
    for letter in "BDFACE":   # paramiko's derivation order is not alphabetical
        out.append({"event": "compute_key", "server_pid": 873, "letter": letter,
                    "key_hex": keys[letter], "K_int_hex": k_int,
                    "K_mpint_hex": "00000021" + "00" + k_int, "H_hex": h, "session_id_hex": H,
                    "hash": "sha256", "agreed": {}})
    out.append({"event": "negotiated", "server_pid": 873, "cipher_c2s": "aes256-ctr",
                "cipher_s2c": "aes256-ctr", "mac_c2s": "hmac-sha2-256",
                "mac_s2c": "hmac-sha2-256", "paramiko_version": "2.12.0"})
    return out


def test_client_log_fields():
    fields = gt_json._client_log_fields(CLIENT_LOG)
    assert fields["pid"] == "881" and fields["libssh"] == "0.10.6/openssl/zlib"
    assert fields["kex"] == "curve25519-sha256@libssh.org" and fields["cipher_out"] == "aes256-ctr"


def test_ssh_tier_a_record_fields():
    rec = gt_json.ssh_tier_a_record(_events(), CLIENT_LOG, 881, 873)
    assert rec["pid"] == 881 and rec["pid_from_client_log"] == 881 and rec["server_pid"] == 873
    assert rec["version"] == "0.10.6/openssl/zlib" and rec["server_version"] == "2.12.0"
    assert rec["kex"] == "curve25519-sha256@libssh.org"
    assert rec["cipher_c2s"] == rec["cipher_s2c"] == "aes256-ctr"
    assert rec["K_int_hex"] == K_INT and rec["K_hex"].startswith("00000021")
    assert rec["H_hex"] == rec["session_id_hex"] == H
    assert list(rec["keys"]) == list("ABCDEF") and rec["keys"]["C"] == "33" * 32
    assert rec["rekeyed"] is False


def test_ssh_tier_a_record_uses_latest_key_exchange():
    rekey_h = "ab" * 32
    rec = gt_json.ssh_tier_a_record(_events() + _events(h=rekey_h, k_int="01" * 32),
                                    CLIENT_LOG, 881)
    assert rec["H_hex"] == rekey_h and rec["K_int_hex"] == "01" * 32
    assert rec["session_id_hex"] == H and rec["rekeyed"] is True
    assert rec["server_pid"] == 873   # falls back to the events' server pid


def test_ssh_tier_a_record_requires_a_key_exchange():
    with pytest.raises(ValueError):
        gt_json.ssh_tier_a_record([{"event": "negotiated"}], CLIENT_LOG, 1)


@pytest.mark.parametrize("value,min_len,expected", [
    ("abc", 4, "0abc"), ("abc", 2, "0abc"), ("ab", 4, "00ab"), ("1234", 2, "1234"),
])
def test_even_hex(value, min_len, expected):
    assert gt_json._even_hex(value, min_len) == expected


def test_cmd_ssh_tier_a_writes_record_and_keys(tmp_path):
    events = tmp_path / "events.jsonl"
    events.write_text("\n".join(json.dumps(e) for e in _events(k_int="ff" * 31)) + "\n")
    log = tmp_path / "client.log"
    log.write_text(CLIENT_LOG)
    frags, out = tmp_path / "frags.jsonl", tmp_path / "secrets.json"
    gt_json.cmd_ssh_tier_a(str(frags), str(events), str(log), "881", "873")
    gt_json.cmd_finalize(str(frags), str(out), "x86_64")
    doc = json.loads(out.read_text())
    assert len(doc["ssh_tier_a"]) == 1 and doc["ssh_tier_a"][0]["pid"] == 881
    keys = {k["id"]: k for k in doc["keys"]}
    assert keys["ssh_tier_a.K"]["hex"] == "00" + "ff" * 31 and keys["ssh_tier_a.K"]["length"] == 32
    assert keys["ssh_tier_a.C"]["kind"] == "ssh-enc_c2s"
    assert set(keys) == {"ssh_tier_a.K", "ssh_tier_a.session_id"} | {
        f"ssh_tier_a.{c}" for c in "ABCDEF"}


def test_finalize_always_has_ssh_tier_a_section(tmp_path):
    out = tmp_path / "secrets.json"
    gt_json.cmd_finalize(str(tmp_path / "none.jsonl"), str(out), "x86_64")
    assert json.loads(out.read_text())["ssh_tier_a"] == []


# --- shell scripts -------------------------------------------------------------------------


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
@pytest.mark.parametrize("script", ["secrets_stage.sh", "export_containers.sh"])
def test_scripts_parse(script):
    subprocess.run(["bash", "-n", str(CAPTURE_DIR / script)], check=True)


def test_tier_a_sources_present():
    src = (CAPTURE_DIR / "ssh_tier_a" / "libssh_client.c").read_text()
    assert "READY pid=%d libssh=%s" in src and "sleep(idle_s)" in src
    server = (CAPTURE_DIR / "ssh_tier_a" / "gt_server.py").read_text()
    assert "_compute_key" in server and "K_mpint_hex" in server
