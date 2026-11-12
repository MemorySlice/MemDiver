"""``linux.keyring`` (``vol3plugins/linux/keyring.py``).

Unit tests lay out synthetic ``struct key`` / ``user_key_payload`` / ``ecryptfs_auth_tok`` /
``fscrypt_key`` memory in a vol3 ``BufferDataLayer`` at the LP64 6.8 offsets (the fallback
table, which the corpus test checks against the real ISF).  The corpus test runs stock ``vol``
with a private ``--cache-path`` on the x86_64 acquired-secrets capture (``MEMDIVER_SECRETS_CORPUS`` =
absolute path of the capture dir) and is skipped cleanly when the env var is unset, the capture is
absent or the ``vol`` entry point is absent.
"""

import hashlib
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("volatility3")

from volatility3.framework import contexts  # noqa: E402
from volatility3.framework.layers import physical  # noqa: E402

from memdiver.vol3plugins.linux import dmcrypt, keyring  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
KL = keyring.KeyLayout()
# Synthetic, made-up FEKEK for the pure unit tests (the real capture's key is read from its
# ``*.secrets.json`` sidecar at test time, never written here).  The signature is derived with
# hashlib directly (ecryptfs-utils ``generate_passphrase_sig``: SHA-512(FEKEK)[:8] as hex), not
# via the code under test.
FEKEK = bytes((i * 7 + 3) & 0xFF for i in range(64))
FEKEK_SIG = hashlib.sha512(FEKEK).hexdigest()[:16]


# --------------------------------------------------------------------------- synthetic memory


class Mem:
    """A little-endian LP64 address space in a bytearray (addresses start at BASE)."""

    BASE = 0x10000

    def __init__(self, size: int = 0x8000) -> None:
        self.buf = bytearray(size)
        self.cursor = 0x100
        self.types = {}

    def alloc(self, size: int, align: int = 64) -> int:
        self.cursor = (self.cursor + align - 1) & ~(align - 1)
        address = self.BASE + self.cursor
        self.cursor += size
        return address

    def put(self, address: int, data: bytes) -> None:
        start = address - self.BASE
        self.buf[start:start + len(data)] = data

    def pack(self, address: int, fmt: str, value: int) -> None:
        self.put(address, struct.pack("<" + fmt, value))

    def string(self, text: str) -> int:
        address = self.alloc(len(text) + 1, 8)
        self.put(address, text.encode() + b"\0")
        return address

    def key_type(self, name: str) -> int:
        if name not in self.types:
            ktype = self.alloc(168)
            self.pack(ktype + KL["key_type.name"], "Q", self.string(name))
            self.types[name] = ktype
        return self.types[name]

    def key(self, serial: int, type_name: str, description: str, payload_ptr: int = 0,
            datalen: int = 0, state: int = 1, flags: int = 0) -> int:
        key = self.alloc(224)
        self.pack(key + KL["key.usage"], "I", 1)
        self.pack(key + KL["key.serial"], "I", serial)
        self.pack(key + KL["key.type"], "Q", self.key_type(type_name))
        self.pack(key + KL["key.description"], "Q", self.string(description))
        self.pack(key + KL["key.payload"], "Q", payload_ptr)
        self.pack(key + KL["key.datalen"], "H", datalen)
        self.pack(key + KL["key.state"], "h", state)
        self.pack(key + KL["key.flags"], "Q", flags)
        self.pack(key + KL["key.perm"], "I", 0x3F010000)
        self.pack(key + KL["key.expiry"], "q", keyring.TIME64_MAX)
        return key

    def user_payload(self, data: bytes, at: int = 0) -> int:
        payload = at or self.alloc(24 + len(data))
        self.pack(payload + KL["user_key_payload.datalen"], "H", len(data))
        self.put(payload + KL["user_key_payload.data"], data)
        return payload

    def user_key(self, serial: int, type_name: str, description: str, data: bytes) -> int:
        return self.key(serial, type_name, description, self.user_payload(data), len(data))

    def link(self, node_key: int, left: int = 0, right: int = 0) -> None:
        node = node_key + KL["key.serial_node"]
        self.pack(node + KL["rb_node.rb_left"], "Q", left + KL["key.serial_node"] if left else 0)
        self.pack(node + KL["rb_node.rb_right"], "Q", right + KL["key.serial_node"] if right else 0)

    def root(self, key: int) -> int:
        root = self.alloc(8)
        self.pack(root, "Q", key + KL["key.serial_node"])
        return root

    def reader(self) -> dmcrypt.SafeReader:
        context = contexts.Context()
        layer = physical.BufferDataLayer(context, "cfg", "mem", bytes(self.BASE) + bytes(self.buf))
        context.add_layer(layer)
        return dmcrypt.SafeReader(layer, 8, "little")


def auth_tok(fekek: bytes, signature: str, token_type: int = 0) -> bytes:
    tok = bytearray(740)
    struct.pack_into("<HH", tok, 0, 4, token_type)
    pw = KL["ecryptfs_auth_tok.token"]
    struct.pack_into("<I", tok, pw + KL["ecryptfs_password.key_bytes"], len(fekek))
    start = pw + KL["ecryptfs_password.fekek"]
    tok[start:start + len(fekek)] = fekek
    sig = signature.encode() + b"\0"
    tok[pw + KL["ecryptfs_password.signature"]:pw + KL["ecryptfs_password.signature"] + len(sig)] = sig
    return bytes(tok)


def fscrypt_key(raw: bytes, mode: int = 1) -> bytes:
    return struct.pack("<I", mode) + raw.ljust(64, b"\0") + struct.pack("<I", len(raw))


def decoder(mem: Mem) -> keyring.Keyring:
    plugin = object.__new__(keyring.Keyring)
    plugin.reader, plugin.kl = mem.reader(), KL
    return plugin


def walk(mem: Mem, root: int, dm_keys=None):
    plugin = decoder(mem)
    records = list(keyring.iter_keys(plugin.reader, KL, root))
    for record in records:
        plugin._decode(record, dm_keys or {})
    return {r.serial: r for r in records}


# --------------------------------------------------------------------------- oracles


def test_ecryptfs_signature_is_sha512_of_the_fekek():
    assert keyring.ecryptfs_signature(FEKEK) == FEKEK_SIG


# Pinned vectors of the v1 descriptor algorithm (first 8 bytes of SHA-512(SHA-512(raw[64])),
# e2fsprogs misc/e4crypt.c generate_key_ref_str / fscryptctl / fscrypt ComputeKeyDescriptor),
# computed once with an independent hashlib one-liner -- not with the plugin.
FSCRYPT_VECTORS = (
    (bytes(range(64)), "04334e23057a6e2d"),
    # the capture's fscrypt v1 master key (secrets.json); its staged descriptor was random
    (bytes.fromhex("e82027c7bf9104d5ed91a655ee7935aaf0cdbbedcee751374546013a26eeecc2"
                   "60278bd9ad7c60a331364edad2fd2a50fac63c238d282d6baf640ec6f87611b3"), "6d17da8fbf8b3de5"),
)


@pytest.mark.parametrize("raw,descriptor", FSCRYPT_VECTORS)
def test_fscrypt_v1_descriptor_matches_pinned_vectors(raw, descriptor):
    assert keyring.fscrypt_v1_descriptor(raw) == descriptor


def test_fscrypt_descriptor_hashes_the_full_raw_buffer_even_for_a_short_key():
    raw = bytes(range(1, 33))  # a 32-byte key: raw[32:64] stays zero and is still hashed
    descriptor = keyring.fscrypt_v1_descriptor(raw.ljust(64, b"\0"))
    mem = Mem()
    key = mem.user_key(40, "logon", "fscrypt:" + descriptor, fscrypt_key(raw))
    mem.link(key)
    record = walk(mem, mem.root(key))[40]
    assert record.status == "proven" and record.secret == raw


# --------------------------------------------------------------------------- walk


def _three_keys(mem: Mem):
    a = mem.key(0x10, "keyring", "_ses")
    b = mem.user_key(0x20, "user", "invocation_id", bytes(range(16)))
    c = mem.key(0x30, "keyring", ".builtin_trusted_keys")
    mem.link(b, left=a, right=c)
    mem.link(a)
    mem.link(c)
    return a, b, c


def test_rb_walk_is_in_serial_order():
    mem = Mem()
    _, b, _ = _three_keys(mem)
    assert list(walk(mem, mem.root(b))) == [0x10, 0x20, 0x30]


def test_rb_walk_survives_a_cycle_and_yields_each_key_once():
    mem = Mem()
    a, b, c = _three_keys(mem)
    mem.link(c, right=b)  # c.rb_right -> the root: a cycle
    mem.link(a, left=b)  # and a back edge on the left spine
    root = mem.root(b)  # written before the reader snapshots the buffer
    serials = [r.serial for r in keyring.iter_keys(mem.reader(), KL, root)]
    assert sorted(serials) == [0x10, 0x20, 0x30] and len(serials) == 3


def test_rb_walk_is_size_bounded():
    mem = Mem()
    _, b, _ = _three_keys(mem)
    nodes = list(keyring.iter_key_nodes(mem.reader(), KL, b + KL["key.serial_node"], limit=1))
    assert len(nodes) <= 2


def test_key_fields_and_proc_keys_line():
    mem = Mem()
    key = mem.key(0x3E2D7CC0, "keyring", "_uid.0", flags=1 << 2 | 1 << 9)
    mem.pack(key + KL["key.gid"], "I", 0xFFFFFFFF)
    mem.pack(key + KL["key.perm"], "I", 0x1F3F0000)
    mem.pack(key + KL["key.keys"] + KL["assoc_array.nr_leaves_on_tree"], "Q", 1)
    mem.pack(key + KL["key.usage"], "I", 3)
    mem.link(key)
    record = walk(mem, mem.root(key))[0x3E2D7CC0]
    assert record.semantics == "keyring members=1"
    assert keyring.flag_names(record.flags) == "IN_QUOTA|UID_KEYRING"
    assert keyring.proc_keys_line(record) == (
        "3e2d7cc0 I--Q---     3 perm 1f3f0000     0 65534 keyring   _uid.0: 1")


# --------------------------------------------------------------------------- payloads


def test_user_payload_is_decoded_and_labelled():
    mem = Mem()
    key = mem.user_key(5, "user", "invocation_id", bytes(range(16)))
    mem.link(key)
    record = walk(mem, mem.root(key))[5]
    assert (record.payload, record.status, record.semantics) == (bytes(range(16)), "decoded", "user 16B")
    assert record.describe == "invocation_id: 16"


def test_truncated_payload_is_flagged_not_decoded():
    mem = Mem(0x2000)  # payload data runs past the end of the layer
    payload = mem.BASE + len(mem.buf) - 24 - 100
    mem.pack(payload + KL["user_key_payload.datalen"], "H", 740)
    key = mem.key(6, "user", FEKEK_SIG, payload, 740)
    mem.link(key)
    record = walk(mem, mem.root(key))[6]
    assert record.status == "truncated" and len(record.payload) == 100
    assert "100/740" in record.detail and "ecryptfs" not in record.semantics


def test_payload_datalen_disagreement_is_unverified():
    mem = Mem()
    key = mem.user_key(7, "user", "x", b"abcd")
    mem.pack(key + KL["key.datalen"], "H", 5)
    mem.link(key)
    record = walk(mem, mem.root(key))[7]
    assert record.status == "unverified" and "!=" in record.detail


def test_ecryptfs_auth_tok_is_proven_by_its_signature():
    mem = Mem()
    key = mem.user_key(8, "user", FEKEK_SIG, auth_tok(FEKEK, FEKEK_SIG))
    mem.link(key)
    record = walk(mem, mem.root(key))[8]
    assert record.status == "proven" and record.secret == FEKEK
    assert "[ecryptfs-sig]" in record.semantics


def test_forged_ecryptfs_signature_does_not_prove():
    forged = bytes(64 - 1) + b"\x01"
    mem = Mem()
    key = mem.user_key(9, "user", FEKEK_SIG, auth_tok(forged, FEKEK_SIG))
    mem.link(key)
    record = walk(mem, mem.root(key))[9]
    assert record.status == "unverified" and "ecryptfs-sig:mismatch" in record.semantics


def test_740_byte_payload_without_a_password_token_is_plain_user_data():
    mem = Mem()
    key = mem.user_key(10, "user", FEKEK_SIG, auth_tok(FEKEK, FEKEK_SIG, token_type=1))
    mem.link(key)
    assert walk(mem, mem.root(key))[10].semantics == "user 740B"


def test_fscrypt_v1_logon_key_proven_only_when_the_descriptor_is_derived():
    raw, desc = FSCRYPT_VECTORS[0]
    mem = Mem()
    good = mem.user_key(11, "logon", "fscrypt:" + desc, fscrypt_key(raw))
    other = mem.user_key(12, "logon", "ext4:0011223344556677", fscrypt_key(raw))
    mem.link(good, right=other)
    mem.link(other)
    records = walk(mem, mem.root(good))
    assert records[11].status == "proven" and records[11].secret == raw
    assert "[fscrypt-desc]" in records[11].semantics
    assert records[12].status == "decoded" and "desc-not-derived" in records[12].semantics


def test_dmcrypt_logon_key_is_proven_only_by_a_proven_dmcrypt_key():
    uuid = "73c6796f-1414-4d08-b89b-188c63b45537"
    volume_key = bytes(range(64))
    mem = Mem()
    key = mem.user_key(13, "logon", "cryptsetup:%s-d0" % uuid, volume_key)
    mem.link(key)
    root = mem.root(key)
    plain = uuid.replace("-", "")
    cases = {(dmcrypt.PROVEN, volume_key): ("proven", "dmcrypt-cross"),
             (dmcrypt.UNVERIFIED, volume_key): ("decoded", "dmcrypt-unproven"),
             (dmcrypt.PROVEN, bytes(64)): ("decoded", "dmcrypt-mismatch")}
    for (status, dm_key), (want, label) in cases.items():
        record = walk(mem, root, {plain: [(dm_key, status)]})[13]
        assert record.status == want and label in record.semantics
    assert "no-dm-device" in walk(mem, root, {})[13].semantics


def test_link_vk_to_keyring_user_key_is_cross_proven_like_the_logon_one():
    """``cryptsetup --link-vk-to-keyring`` links the volume key as a ``user`` key (real v2 capture)."""
    uuid = "0bb25ab7-14db-4dd4-bc4e-3a4cb112d121"
    volume_key = bytes(range(1, 65))
    mem = Mem()
    key = mem.user_key(15, "user", "cryptsetup:%s-d0" % uuid, volume_key)
    mem.link(key)
    root = mem.root(key)
    record = walk(mem, root, {uuid.replace("-", ""): [(volume_key, dmcrypt.PROVEN)]})[15]
    assert record.status == "proven" and "[dmcrypt-cross]" in record.semantics
    assert record.semantics.startswith("dmcrypt-volume-key uuid=%s seg=0 512bit" % uuid)
    wrong = walk(mem, root, {uuid.replace("-", ""): [(bytes(64), dmcrypt.PROVEN)]})[15]
    assert wrong.status == "decoded" and "dmcrypt-mismatch" in wrong.semantics


def test_is_cryptsetup_volume_key_needs_user_or_logon_and_the_name():
    def record(type_name, description):
        return keyring.KeyRecord(address=0, serial=1, usage=1, type_name=type_name, description=description,
                                 uid=0, gid=0, perm=0, state=1, flags=0, datalen=64, expiry=0, last_used=0,
                                 payload_ptr=0, description_raw=description.encode())
    name = "cryptsetup:0bb25ab7-14db-4dd4-bc4e-3a4cb112d121-d0"
    assert keyring.is_cryptsetup_volume_key(record("user", name))
    assert keyring.is_cryptsetup_volume_key(record("logon", name))
    assert not keyring.is_cryptsetup_volume_key(record("keyring", name))
    assert not keyring.is_cryptsetup_volume_key(record("user", "cryptsetup:not-a-uuid-d0"))


def test_fscrypt_user_claim_and_trusted_are_labelled_without_payload():
    mem = Mem()
    claim = mem.key(14, ".fscrypt", "960e5b8aa2300e8d22c53d830dffb1bc.uid.0")
    trusted = mem.key(15, "trusted", "kmk", datalen=32)
    mem.link(claim, right=trusted)
    mem.link(trusted)
    records = walk(mem, mem.root(claim))
    assert records[14].semantics.startswith("fscrypt-v2-user-claim id=960e5b8a")
    assert records[15].semantics.startswith("trusted") and records[15].payload is None


# --------------------------------------------------------------------------- review fixes


def test_non_ascii_description_is_kept_and_never_matches_a_label():
    mem = Mem()
    key = mem.user_key(20, "user", "café-key", b"x")
    fake = mem.user_key(21, "logon", "fscrypt:0011223344556677", fscrypt_key(bytes(64)))
    mem.link(key, right=fake)
    mem.link(fake)
    records = walk(mem, mem.root(key))
    assert records[20].description == "café-key" and records[20].describe == "café-key: 1"
    assert records[20].description_raw == "café-key".encode()
    record = records[21]
    record.description_raw = b"fscrypt:00112233445566\xe97"  # undecodable byte: no ASCII match
    assert keyring.decode_fscrypt_v1(KL, record) is False


def test_description_just_before_an_unreadable_page_is_read():
    mem = Mem(0x2000)
    text = "cryptsetup:73c6796f-1414-4d08-b89b-188c63b45537-d0"
    address = mem.BASE + len(mem.buf) - len(text) - 1  # NUL is the layer's last byte
    mem.put(address, text.encode() + b"\0")
    key = mem.key(22, "logon", "x")
    mem.pack(key + KL["key.description"], "Q", address)
    mem.link(key)
    record = walk(mem, mem.root(key))[22]
    assert record.description == text and "dmcrypt-volume-key" not in record.semantics  # no payload


def test_unterminated_string_is_none():
    mem = Mem(0x2000)
    address = mem.BASE + len(mem.buf) - 8
    mem.put(address, b"ABCDEFGH")
    assert keyring.read_cstring(mem.reader(), address, 64) is None


@pytest.mark.parametrize("expiry,now,text", [
    (0, 1000, "perm"), (1000, 1000, "expd"), (1045, 1000, "45s"), (1000 + 300, 1000, "5m"),
    (1000 + 3 * 3600, 1000, "3h"), (1000 + 2 * 86400, 1000, "2d"), (1000 + 15 * 86400, 1000, "2w"),
    (1234, None, "exp@1234")])
def test_proc_timeout_like_the_kernel(expiry, now, text):
    assert keyring.proc_timeout(expiry, now) == text


def test_keyctl_line_keeps_the_4_wide_timeout_column():
    record = keyring.KeyRecord(address=0, serial=1, usage=1, type_name="user", description="d",
                               uid=0, gid=0, perm=0, state=1, flags=0, datalen=0, expiry=1060,
                               last_used=0, payload_ptr=0, describe="d: 0")
    assert keyring.proc_keys_line(record, 1000) == (
        "00000001 I------     1   1m 00000000     0     0 user      d: 0")


class _Task:
    def __init__(self, cred, pid, comm="t"):
        self._cred, self.pid, self._comm = cred, pid, comm

    @property
    def cred(self):
        if self._cred is None:
            raise TypeError("smeared cred")
        return self._cred

    @property
    def comm(self):
        name = self._comm

        class _C:
            def cast(self, *args, **kwargs):
                return name
        return _C()


def test_one_smeared_task_does_not_abort_holder_attribution():
    mem = Mem()
    ses = mem.key(30, "keyring", "_ses")
    mem.link(ses)
    cred = mem.alloc(184)
    mem.pack(cred + KL["cred.session_keyring"], "Q", ses)
    root = mem.root(ses)
    reader = mem.reader()
    records = list(keyring.iter_keys(reader, KL, root))
    tasks = [_Task(None, 1), _Task(cred, 2, "sshd"), _Task(cred, 3, "bash")]
    assert keyring.attribute_holders(reader, KL, records, tasks) == 1
    assert records[0].holders == ["sshd(2)", "bash(3)"]


def test_dmcrypt_cross_check_survives_a_type_error(monkeypatch):
    plugin = object.__new__(keyring.Keyring)
    plugin._context, plugin._config_path = contexts.Context(), "plugins.Keyring"
    record = keyring.KeyRecord(address=0, serial=1, usage=1, type_name="logon",
                               description="cryptsetup:73c6796f-1414-4d08-b89b-188c63b45537-d0",
                               uid=0, gid=0, perm=0, state=1, flags=0, datalen=64, expiry=0,
                               last_used=0, payload_ptr=0,
                               description_raw=b"cryptsetup:73c6796f-1414-4d08-b89b-188c63b45537-d0")

    def boom():
        raise TypeError("NoneType is not subscriptable")
    monkeypatch.setattr(plugin, "_dmcrypt_plugin", boom)
    assert plugin._dmcrypt_keys([record]) == {}


# --------------------------------------------------------------------------- layout


class _Template:
    def __init__(self, members):
        self.vol = {"members": members}


def test_find_member_descends_into_anonymous_unions():
    inner = _Template({"type": (16, None), "description": (32, None)})
    union = _Template({"index_key": (0, None), "unnamed_field_0": (0, inner)})
    key = _Template({"serial": (4, None), "unnamed_field_2": (144, union)})
    assert keyring.find_member(None, key, "description") == 176
    assert keyring.find_member(None, key, "serial") == 4
    assert keyring.find_member(None, key, "missing") is None


# --------------------------------------------------------------------------- real capture


CAPTURE_DIR = Path(os.environ.get("MEMDIVER_SECRETS_CORPUS", "") or "/nonexistent")
X86_STEM = "ubuntu-24.04-secrets-x86-4level_6.8.0-136-generic"


def _proc_keys(text: str):
    rows = {}
    for line in text.splitlines():
        fields = line.split(None, 8)
        rows[fields[0]] = (fields[7], fields[8].split(":")[0] if fields[7] != "asymmetri" else fields[8])
    return rows


def test_real_x86_capture_through_stock_vol(tmp_path):
    vol = Path(sys.executable).parent / "vol"
    tarball = CAPTURE_DIR / (X86_STEM + ".secrets.tar.gz")
    if not (vol.is_file() and all((CAPTURE_DIR / (X86_STEM + e)).is_file()
                                  for e in (".lime", ".isf.json", ".secrets.json")) and tarball.is_file()):
        pytest.skip("x86_64 acquired-secrets capture or the stock vol entry point not present")
    import tarfile
    with tarfile.open(tarball) as archive:
        truth_text = archive.extractfile("artefacts/proc_keys.txt").read().decode()
    symbols = tmp_path / "sym" / "linux"
    symbols.mkdir(parents=True)
    (symbols / (X86_STEM + ".json")).symlink_to(CAPTURE_DIR / (X86_STEM + ".isf.json"))
    (tmp_path / "cache").mkdir()  # private identifier cache
    command = [str(vol), "-q", "-r", "json", "-s", str(tmp_path / "sym"), "-p", str(REPO / "vol3plugins"),
               "-f", str(CAPTURE_DIR / (X86_STEM + ".lime")), "--cache-path", str(tmp_path / "cache"),
               "-o", str(tmp_path), "linux.keyring", "--export", "keyctl"]
    result = subprocess.run(command, capture_output=True, text=True, cwd=str(tmp_path), timeout=900)
    assert result.returncode == 0, result.stderr[-2000:]
    rows = json.loads(result.stdout)
    truth, mine = _proc_keys(truth_text), _proc_keys((tmp_path / "keyring.proc_keys.txt").read_text())
    # /proc/keys was read at staging time: a session keyring and its unit's invocation_id were
    # garbage-collected before the dump.  Everything else must be there with type + description.
    assert len([s for s in truth if s not in mine]) <= 2
    assert all(mine[s] == truth[s] for s in truth if s in mine)
    sidecar = json.loads((CAPTURE_DIR / (X86_STEM + ".secrets.json")).read_text())["ecryptfs"][0]
    tok = [r for r in rows if r["Description"] == sidecar["fekek_signature"]]
    assert len(tok) == 1 and tok[0]["Status"] == "proven"
    assert tok[0]["Payload"].startswith(sidecar["fekek_hex"][:64])
    assert all(r["Status"] != "proven" or "[" in r["Semantics"] for r in rows)


def _isf_offset(types, type_name, member, depth=0):
    fields = types[type_name]["fields"]
    if member in fields:
        return fields[member]["offset"]
    for name, spec in fields.items():
        if name.startswith("unnamed_field") and depth < 4:
            inner = _isf_offset(types, spec["type"]["name"], member, depth + 1)
            if inner is not None:
                return spec["offset"] + inner
    return None


def test_fallback_table_equals_the_capture_isf():
    isf = CAPTURE_DIR / (X86_STEM + ".isf.json")
    if not isf.is_file():
        pytest.skip("x86_64 capture ISF not present")
    types = json.loads(isf.read_text())["user_types"]
    for key, (type_name, member, fallback) in keyring._FIELDS.items():
        assert _isf_offset(types, type_name, member) == fallback, key
    assert types["ecryptfs_auth_tok"]["size"] == KL.sizes["ecryptfs_auth_tok"]
    assert types["fscrypt_key"]["size"] == KL.sizes["fscrypt_key"]
