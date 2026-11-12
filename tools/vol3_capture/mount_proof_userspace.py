#!/usr/bin/env python3
"""Mount proof helpers: hash checks, the claim table, and userspace decryption.

Used by ``mount_proof.sh`` (inside the ``mount_proof/`` Docker image) to prove that keys
recovered from a memory image by the vol3plugins open the capture's real encrypted
containers. Every key comes from a plugin export; the capture sidecar is never read here.

Subcommands (all append one JSON line per target to ``--results``):

``hashcheck``   sha256 every file ``samples.sha256`` lists for a target under a mounted root.
``dm-fallback`` decrypt a dm-crypt data area in userspace from an ``--export dmsetup`` line
                (no device mapper, no privileges), then pull the files out of the plaintext
                image with ``debugfs`` (ext4) or ``mcopy`` (vfat) and hash-check them.
``ecryptfs``    decrypt eCryptfs lower files with the per-file FEKs of ``--export fek``.
``fscrypt-v2``  decrypt fscrypt v2 files from the HKDF-PRK HMAC-SHA512 midstates that
                ``linux.fscrypt --export json`` recovers (the kernel wipes the v2 master key,
                so the kernel cannot be given this key; the files are read from the image).
``table``       print the claim table of a results file.

Glue for ``mount_proof.sh``: ``dm-line`` (table with the device replaced / keyring ref),
``fscrypt-v1`` (add or remove the proven v1 keys with FS_IOC_ADD/REMOVE_ENCRYPTION_KEY),
``proven-key`` (the proven key of a synthesized plugin's JSON rows), ``daemon-pid``.

This module is independent of vol3plugins (its own SHA-512 compression function; AES from
``cryptography``, imported only where a decryption runs).
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
import struct
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

SECTOR = 512
GUEST_PREFIX = "/mnt/gt_"

# --------------------------------------------------------------------------- samples / results


def target_of(guest_path: str) -> tuple:
    """``/mnt/gt_fscrypt/v1/a.txt`` -> ``("fscrypt_v1", "a.txt")``."""
    if not guest_path.startswith(GUEST_PREFIX):
        raise ValueError("not a planted sample path: %r" % guest_path)
    parts = guest_path[len(GUEST_PREFIX):].split("/")
    if len(parts) < 2 or not all(parts):
        raise ValueError("not a planted sample path: %r" % guest_path)
    return "_".join(parts[:-1]), parts[-1]


def parse_samples(text: str) -> dict:
    """``samples.sha256`` -> ``{target: {file name: sha256}}``."""
    targets: dict = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        digest, path = line.split(None, 1)
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("bad sha256 line: %r" % line)
        target, name = target_of(path.strip())
        targets.setdefault(target, {})[name] = digest
    return targets


@dataclass
class Result:
    target: str
    method: str
    matched: int
    expected: int
    note: str = ""
    missing: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.expected > 0 and self.matched == self.expected


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def match_by_name(root: Path, expected: dict) -> tuple:
    """Hash ``root/<name>`` for each expected name: ``(matched, missing names)``."""
    missing = [name for name, digest in sorted(expected.items())
               if not (root / name).is_file() or sha256_file(root / name) != digest]
    return len(expected) - len(missing), missing


def match_by_content(blobs: list, expected: dict) -> tuple:
    """For files whose names are unknown (encrypted): which expected digests occur at all."""
    present = {hashlib.sha256(blob).hexdigest() for blob in blobs}
    missing = [name for name, digest in sorted(expected.items()) if digest not in present]
    return len(expected) - len(missing), missing


def append_result(path: Path, result: Result) -> None:
    with open(path, "a") as handle:
        handle.write(json.dumps(asdict(result)) + "\n")


def load_results(path: Path) -> list:
    if not path.is_file():
        return []
    return [Result(**json.loads(line)) for line in path.read_text().splitlines() if line.strip()]


def render_table(results: list) -> str:
    rows = [("target", "method", "files", "result", "note")]
    for res in results:
        rows.append((res.target, res.method, "%d/%d" % (res.matched, res.expected),
                     "MATCH" if res.ok else "FAIL", res.note))
    widths = [max(len(row[i]) for row in rows) for i in range(4)]
    lines = ["  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row[:4])) + "  " + row[4]
             for row in rows]
    return "\n".join(line.rstrip() for line in lines)


# --------------------------------------------------------------------------- dm-crypt table


@dataclass
class DmTable:
    name: str
    start: int
    length: int
    cipher: str
    key: str
    iv_offset: int
    device: str
    offset: int
    options: list

    @property
    def sector_size(self) -> int:
        for opt in self.options:
            if opt.startswith("sector_size:"):
                return int(opt.split(":", 1)[1])
        return SECTOR

    @property
    def keyring_ref(self) -> tuple:
        """``:64:logon:cryptsetup:...`` -> ``(64, "logon", "cryptsetup:...")``; else ``()``."""
        if not self.key.startswith(":"):
            return ()
        size, ktype, desc = self.key[1:].split(":", 2)
        return int(size), ktype, desc

    def line(self, device: str = "") -> str:
        fields = [self.start, self.length, "crypt", self.cipher, self.key, self.iv_offset,
                  device or self.device, self.offset]
        if self.options:
            fields += [len(self.options)] + self.options
        return " ".join(str(f) for f in fields)


def parse_dmsetup_line(text: str) -> DmTable:
    """One ``linux.dmcrypt --export dmsetup`` line (``name: <table>``) or a bare table."""
    name, _, table = text.strip().rpartition(": ")
    parts = table.split()
    if len(parts) < 8 or parts[2] != "crypt":
        raise ValueError("not a dm-crypt table: %r" % text)
    options = []
    if len(parts) > 8:
        count = int(parts[8])
        options = parts[9:9 + count]
        if len(options) != count:
            raise ValueError("truncated optional arguments: %r" % text)
    return DmTable(name, int(parts[0]), int(parts[1]), parts[3], parts[4], int(parts[5]),
                   parts[6], int(parts[7]), options)


def parse_dmsetup_export(text: str) -> dict:
    tables = [parse_dmsetup_line(line) for line in text.splitlines() if line.strip()]
    return {table.name: table for table in tables}


# --------------------------------------------------------------------------- dm-crypt userspace


def _aes_cipher(algorithm_mode):
    from cryptography.hazmat.primitives.ciphers import Cipher

    return Cipher(*algorithm_mode)


def dm_sector_decryptor(cipher: str, key: bytes):
    """``(iv_sector, ciphertext) -> plaintext`` for the dm cipher specs the captures use."""
    from cryptography.hazmat.primitives.ciphers import algorithms, modes

    if cipher == "aes-xts-plain64":
        return lambda sector, data: _aes_cipher(
            (algorithms.AES(key), modes.XTS(struct.pack("<Q", sector) + bytes(8)))
        ).decryptor().update(data)
    if cipher == "aes-cbc-essiv:sha256":
        salt = _aes_cipher((algorithms.AES(hashlib.sha256(key).digest()), modes.ECB())).encryptor()

        def cbc(sector: int, data: bytes) -> bytes:
            iv = salt.update(struct.pack("<Q", sector) + bytes(8))
            return _aes_cipher((algorithms.AES(key), modes.CBC(iv))).decryptor().update(data)
        return cbc
    raise ValueError("unsupported dm cipher %r" % cipher)


def decrypt_dm_image(image: Path, table: DmTable, key: bytes, out: Path) -> int:
    """Write the plaintext of ``table`` over ``image`` to ``out`` (sparse); return units done.

    IV sector = target sector (512-B units, as dm-crypt without ``iv_large_sectors``) plus
    ``iv_offset``. All-zero ciphertext units (never written) stay zero.
    """
    if "iv_large_sectors" in table.options:
        raise ValueError("iv_large_sectors is not supported")
    decrypt, unit = dm_sector_decryptor(table.cipher, key), table.sector_size
    done = 0
    with open(image, "rb") as src, open(out, "wb") as dst:
        dst.truncate(table.length * SECTOR)
        src.seek(table.offset * SECTOR)
        for index in range(table.length * SECTOR // unit):
            data = src.read(unit)
            if len(data) < unit:
                break
            if data.count(0) != unit:
                dst.seek(index * unit)
                dst.write(decrypt(table.iv_offset + index * unit // SECTOR, data))
                done += 1
    return done


def extract_fs(image: Path, fstype: str, out: Path) -> None:
    """Copy every file of a plaintext ext4/vfat image to ``out`` without mounting."""
    out.mkdir(parents=True, exist_ok=True)
    if fstype == "ext4":
        _run(["debugfs", "-R", "rdump / %s" % out, str(image)])
    elif fstype == "vfat":
        _run(["mcopy", "-s", "-n", "-i", str(image), "::/*", str(out)])
    else:
        raise ValueError("no unprivileged extractor for %r" % fstype)


def _run(argv: list) -> str:
    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout


# --------------------------------------------------------------------------- eCryptfs userspace


def parse_fek_csv(text: str) -> dict:
    """``linux.ecryptfs --export fek`` CSV -> ``{lower file name: FEK bytes}``."""
    return {Path(row["lower_path"]).name: bytes.fromhex(row["fek_hex"])
            for row in csv.DictReader(io.StringIO(text))}


def ecryptfs_header(lower: bytes) -> tuple:
    """``(plaintext size, extent size, header bytes)`` of an eCryptfs lower file."""
    if len(lower) < 26:
        raise ValueError("lower file too short for an eCryptfs header")
    size, = struct.unpack(">Q", lower[:8])
    extent_size, header_extents = struct.unpack(">IH", lower[20:26])
    return size, extent_size, extent_size * header_extents


def ecryptfs_extent_iv(root_iv: bytes, extent: int) -> bytes:
    """Kernel ``ecryptfs_derive_iv``: MD5(root_iv || "%lld" zero-padded to 16 B)[:16]."""
    number = str(extent).encode().ljust(16, b"\0")
    return hashlib.md5(root_iv + number, usedforsecurity=False).digest()[:16]


def ecryptfs_decrypt(lower: bytes, fek: bytes) -> bytes:
    """AES-CBC per extent, root IV = MD5(FEK)[:16]; truncated to the header's file size."""
    from cryptography.hazmat.primitives.ciphers import algorithms, modes

    size, extent_size, start = ecryptfs_header(lower)
    root_iv = hashlib.md5(fek, usedforsecurity=False).digest()[:16]
    plain = bytearray()
    for extent in range((size + extent_size - 1) // extent_size):
        chunk = lower[start + extent * extent_size:start + (extent + 1) * extent_size]
        iv = ecryptfs_extent_iv(root_iv, extent)
        plain += _aes_cipher((algorithms.AES(fek), modes.CBC(iv))).decryptor().update(chunk)
    return bytes(plain[:size])


# --------------------------------------------------------------------------- fscrypt v2 userspace

_K512 = [int(x, 16) for x in """
428a2f98d728ae22 7137449123ef65cd b5c0fbcfec4d3b2f e9b5dba58189dbbc 3956c25bf348b538
59f111f1b605d019 923f82a4af194f9b ab1c5ed5da6d8118 d807aa98a3030242 12835b0145706fbe
243185be4ee4b28c 550c7dc3d5ffb4e2 72be5d74f27b896f 80deb1fe3b1696b1 9bdc06a725c71235
c19bf174cf692694 e49b69c19ef14ad2 efbe4786384f25e3 0fc19dc68b8cd5b5 240ca1cc77ac9c65
2de92c6f592b0275 4a7484aa6ea6e483 5cb0a9dcbd41fbd4 76f988da831153b5 983e5152ee66dfab
a831c66d2db43210 b00327c898fb213f bf597fc7beef0ee4 c6e00bf33da88fc2 d5a79147930aa725
06ca6351e003826f 142929670a0e6e70 27b70a8546d22ffc 2e1b21385c26c926 4d2c6dfc5ac42aed
53380d139d95b3df 650a73548baf63de 766a0abb3c77b2a8 81c2c92e47edaee6 92722c851482353b
a2bfe8a14cf10364 a81a664bbc423001 c24b8b70d0f89791 c76c51a30654be30 d192e819d6ef5218
d69906245565a910 f40e35855771202a 106aa07032bbd1b8 19a4c116b8d2d0c8 1e376c085141ab53
2748774cdf8eeb99 34b0bcb5e19b48a8 391c0cb3c5c95a63 4ed8aa4ae3418acb 5b9cca4f7763e373
682e6ff3d6b2b8a3 748f82ee5defb2fc 78a5636f43172f60 84c87814a1f0ab72 8cc702081a6439ec
90befffa23631e28 a4506cebde82bde9 bef9a3f7b2c67915 c67178f2e372532b ca273eceea26619c
d186b8c721c0c207 eada7dd6cde0eb1e f57d4f7fee6ed178 06f067aa72176fba 0a637dc5a2c898a6
113f9804bef90dae 1b710b35131c471b 28db77f523047d84 32caab7b40c72493 3c9ebe0a15c9bebc
431d67c49c100d4c 4cc5d4becb3e42b6 597f299cfc657e2a 5fcb6fab3ad6faec 6c44198c4a475817
""".split()]
SHA512_IV = [int(x, 16) for x in """
6a09e667f3bcc908 bb67ae8584caa73b 3c6ef372fe94f82b a54ff53a5f1d36f1
510e527fade682d1 9b05688c2b3e6c1f 1f83d9abfb41bd6b 5be0cd19137e2179""".split()]
_M64 = (1 << 64) - 1


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (64 - n))) & _M64


def sha512_compress(state: list, block: bytes) -> list:
    """One FIPS 180-4 SHA-512 compression of a 128-byte block."""
    w = list(struct.unpack(">16Q", block))
    for t in range(16, 80):
        s0 = _rotr(w[t - 15], 1) ^ _rotr(w[t - 15], 8) ^ (w[t - 15] >> 7)
        s1 = _rotr(w[t - 2], 19) ^ _rotr(w[t - 2], 61) ^ (w[t - 2] >> 6)
        w.append((w[t - 16] + s0 + w[t - 7] + s1) & _M64)
    a, b, c, d, e, f, g, h = state
    for t in range(80):
        t1 = (h + (_rotr(e, 14) ^ _rotr(e, 18) ^ _rotr(e, 41)) + ((e & f) ^ (~e & g))
              + _K512[t] + w[t]) & _M64
        t2 = ((_rotr(a, 28) ^ _rotr(a, 34) ^ _rotr(a, 39)) + ((a & b) ^ (a & c) ^ (b & c))) & _M64
        a, b, c, d, e, f, g, h = (t1 + t2) & _M64, a, b, c, (d + t1) & _M64, e, f, g
    return [(x + y) & _M64 for x, y in zip(state, (a, b, c, d, e, f, g, h))]


def sha512_resume(state: list, done: int, message: bytes) -> bytes:
    """Finish SHA-512 from a chaining state after ``done`` (block-aligned) bytes."""
    total = done + len(message)
    padded = message + b"\x80" + bytes((111 - total) % 128) + struct.pack(">QQ", 0, total * 8)
    for off in range(0, len(padded), 128):
        state = sha512_compress(state, padded[off:off + 128])
    return struct.pack(">8Q", *state)


def parse_midstate(hex_text: str) -> list:
    """64-byte state hex (eight big-endian words, as ``linux.fscrypt`` exports) -> words."""
    raw = bytes.fromhex(hex_text)
    if len(raw) != 64:
        raise ValueError("a SHA-512 state is 64 bytes, got %d" % len(raw))
    return list(struct.unpack(">8Q", raw))


def hmac_sha512_midstates(ipad: list, opad: list, message: bytes) -> bytes:
    return sha512_resume(opad, 128, sha512_resume(ipad, 128, message))


def fscrypt_v2_file_key(ipad: list, opad: list, nonce: bytes, size: int = 64) -> bytes:
    """HKDF-Expand(PRK, "fscrypt\\0" || HKDF_CONTEXT_PER_FILE_ENC_KEY(2) || nonce), T(1)."""
    if size > 64:
        raise ValueError("only T(1) is implemented")
    return hmac_sha512_midstates(ipad, opad, b"fscrypt\0\x02" + nonce + b"\x01")[:size]


def parse_fscrypt_context(blob: bytes) -> dict:
    """ext4 ``c`` xattr (``fscrypt_context_v1``/``_v2``) -> version, modes, flags, ref, nonce."""
    if blob[:1] == b"\x02" and len(blob) == 40:
        return {"version": 2, "contents": blob[1], "filenames": blob[2], "flags": blob[3],
                "key_ref": blob[8:24].hex(), "nonce": blob[24:40]}
    if blob[:1] == b"\x01" and len(blob) == 28:
        return {"version": 1, "contents": blob[1], "filenames": blob[2], "flags": blob[3],
                "key_ref": blob[4:12].hex(), "nonce": blob[12:28]}
    raise ValueError("not an fscrypt context (%d bytes)" % len(blob))


def fscrypt_xts_decrypt(key: bytes, blocks: list, block_size: int) -> bytes:
    """AES-256-XTS per filesystem block; IV = logical block number (le64), no IV flags."""
    from cryptography.hazmat.primitives.ciphers import algorithms, modes

    plain = bytearray()
    for lblk, data in enumerate(blocks):
        tweak = struct.pack("<Q", lblk) + bytes(8)
        plain += _aes_cipher((algorithms.AES(key), modes.XTS(tweak))).decryptor().update(data)
    return bytes(plain)


def parse_debugfs_ls(text: str) -> list:
    """``debugfs -R 'ls -l DIR'`` -> ``[(inode, mode, size)]`` of regular files."""
    files = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 6 and parts[0].isdigit() and parts[1].startswith("100"):
            files.append((int(parts[0]), parts[1], int(parts[5])))
    return files


def parse_debugfs_blocks(text: str) -> list:
    return [int(tok) for tok in text.split() if tok.isdigit()]


def _ext4_block_size(image: Path) -> int:
    with open(image, "rb") as handle:
        handle.seek(1024 + 24)
        log, = struct.unpack("<I", handle.read(4))
    return 1024 << log


def fscrypt_v2_files(image: Path, directory: str, ipad: list, opad: list, key_ref: str) -> list:
    """Decrypt every regular file of ``directory`` whose v2 policy names ``key_ref``."""
    block_size, out = _ext4_block_size(image), []
    for ino, _mode, size in parse_debugfs_ls(_run(["debugfs", "-R", "ls -l %s" % directory,
                                                   str(image)])):
        with tempfile.NamedTemporaryFile() as tmp:
            _run(["debugfs", "-R", "ea_get -f %s <%d> c" % (tmp.name, ino), str(image)])
            ctx = parse_fscrypt_context(Path(tmp.name).read_bytes())
        if ctx["version"] != 2 or ctx["key_ref"] != key_ref:
            continue
        nums = parse_debugfs_blocks(_run(["debugfs", "-R", "blocks <%d>" % ino, str(image)]))
        with open(image, "rb") as handle:
            blocks = [_read_at(handle, num * block_size, block_size) for num in nums]
        key = fscrypt_v2_file_key(ipad, opad, ctx["nonce"])
        out.append(fscrypt_xts_decrypt(key, blocks, block_size)[:size])
    return out


def _read_at(handle, offset: int, size: int) -> bytes:
    handle.seek(offset)
    return handle.read(size)


# --------------------------------------------------------------------------- kernel / plugin glue

FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR = 1
FS_IOC_ADD_ENCRYPTION_KEY = 0xC0506617      # _IOWR('f', 23, struct fscrypt_add_key_arg)  (80 B)
FS_IOC_REMOVE_ENCRYPTION_KEY = 0xC0406618   # _IOWR('f', 24, struct fscrypt_remove_key_arg) (64 B)


def fscrypt_v1_key_spec(descriptor_hex: str) -> bytes:
    """``struct fscrypt_key_specifier`` (40 B) naming a v1 policy's 8-byte descriptor."""
    descriptor = bytes.fromhex(descriptor_hex)
    if len(descriptor) != 8:
        raise ValueError("a v1 descriptor is 8 bytes")
    return struct.pack("<II", FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR, 0) + descriptor.ljust(32, b"\0")


def fscrypt_add_key_arg(descriptor_hex: str, raw: bytes) -> bytes:
    """``struct fscrypt_add_key_arg`` + raw key: key_spec, raw_size, key_id=0, 8 reserved u32."""
    return fscrypt_v1_key_spec(descriptor_hex) + struct.pack("<II", len(raw), 0) + bytes(32) + raw


def fscrypt_v1_ioctl(mount: str, descriptor_hex: str, raw: bytes = b"", remove: bool = False) -> None:
    import fcntl
    import os

    if remove:
        arg = bytearray(fscrypt_v1_key_spec(descriptor_hex) + bytes(24))
        request = FS_IOC_REMOVE_ENCRYPTION_KEY
    else:
        arg, request = bytearray(fscrypt_add_key_arg(descriptor_hex, raw)), FS_IOC_ADD_ENCRYPTION_KEY
    fd = os.open(mount, os.O_RDONLY)
    try:
        fcntl.ioctl(fd, request, arg)
    finally:
        os.close(fd)


def proven_key(rows: list, label_prefix: str = "oracle:") -> str:
    """The single distinct proven ``KeyHex`` of a synthesized plugin's JSON rows (else '')."""
    keys = {row["KeyHex"] for row in rows if str(row.get("Proven", "")).startswith(label_prefix)}
    if len(keys) > 1:
        raise ValueError("more than one distinct proven key: %s" % sorted(keys))
    return keys.pop() if keys else ""


def daemon_pid(ps_text: str, command: str) -> int:
    """PID of the first ``ps -ef`` row whose command starts with ``command``."""
    for line in ps_text.splitlines():
        parts = line.split(None, 7)
        if len(parts) == 8 and parts[1].isdigit() and parts[7].startswith(command):
            return int(parts[1])
    raise ValueError("no %r process in the snapshot" % command)


# --------------------------------------------------------------------------- CLI


def _expected(args) -> dict:
    targets = parse_samples(Path(args.samples).read_text())
    if args.target not in targets:
        raise SystemExit("target %r not in %s (have %s)" % (args.target, args.samples,
                                                            sorted(targets)))
    return targets[args.target]


def _record(args, matched: int, expected: dict, missing: list, note: str = "") -> int:
    res = Result(args.target, args.method, matched, len(expected), note, missing)
    append_result(Path(args.results), res)
    print("%s %s %d/%d %s" % (res.target, res.method, res.matched, res.expected,
                              "MATCH" if res.ok else "FAIL missing=%s" % missing))
    return 0 if res.ok else 1


def cmd_hashcheck(args) -> int:
    expected = _expected(args)
    matched, missing = match_by_name(Path(args.root), expected)
    return _record(args, matched, expected, missing, args.note)


def cmd_dm_fallback(args) -> int:
    expected = _expected(args)
    table = parse_dmsetup_export(Path(args.dmsetup).read_text())[args.name]
    key = Path(args.key_file).read_bytes()
    work = Path(args.work)
    work.mkdir(parents=True, exist_ok=True)
    plain = work / (args.name + ".plain.img")
    units = decrypt_dm_image(Path(args.image), table, key, plain)
    extract_fs(plain, args.fs, work / (args.name + ".files"))
    matched, missing = match_by_name(work / (args.name + ".files"), expected)
    note = "%s; %d units decrypted; %s" % (table.cipher, units, args.note)
    return _record(args, matched, expected, missing, note.strip("; "))


def cmd_ecryptfs(args) -> int:
    expected = _expected(args)
    feks, out = parse_fek_csv(Path(args.fek_csv).read_text()), Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, fek in feks.items():
        (out / name).write_bytes(ecryptfs_decrypt((Path(args.lower) / name).read_bytes(), fek))
    matched, missing = match_by_name(out, expected)
    return _record(args, matched, expected, missing, "%d FEKs from --export fek" % len(feks))


def cmd_fscrypt_v2(args) -> int:
    expected = _expected(args)
    entries = [e for e in json.loads(Path(args.fscrypt_json).read_text())
               if e.get("policy_version") == "v2" and e.get("hkdf_prk_midstates")]
    blobs = []
    for entry in entries:
        mid = entry["hkdf_prk_midstates"]
        blobs += fscrypt_v2_files(Path(args.image), args.dir, parse_midstate(mid["ipad_sha512_state_hex"]),
                                  parse_midstate(mid["opad_sha512_state_hex"]), entry["key_ref_hex"])
    matched, missing = match_by_content(blobs, expected)
    note = "HKDF-PRK midstates; %d files decrypted; matched by content (names encrypted)" % len(blobs)
    return _record(args, matched, expected, missing, note)


def cmd_dm_line(args) -> int:
    table = parse_dmsetup_export(Path(args.dmsetup).read_text())[args.name]
    if args.keyref:
        ref = table.keyring_ref
        print("%s %s" % (ref[1], ref[2]) if ref else "")
    else:
        print(table.line(args.device))
    return 0


def cmd_fscrypt_v1(args) -> int:
    entries = [e for e in json.loads(Path(args.fscrypt_json).read_text())
               if e.get("policy_version") == "v1" and e.get("master_key_hex")
               and str(e.get("status", "")).startswith("oracle:")]
    for entry in entries:
        fscrypt_v1_ioctl(args.mount, entry["key_ref_hex"], bytes.fromhex(entry["master_key_hex"]),
                         remove=args.remove)
        print("%s v1 key %s" % ("removed" if args.remove else "added", entry["key_ref_hex"]))
    return 0 if entries else 1


def cmd_proven_key(args) -> int:
    key = proven_key(json.loads(Path(args.rows).read_text()))
    print(key)
    return 0 if key else 1


def cmd_daemon_pid(args) -> int:
    print(daemon_pid(Path(args.ps).read_text(), args.command))
    return 0


def cmd_table(args) -> int:
    results = load_results(Path(args.results))
    print(render_table(results))
    return 0 if results and all(r.ok for r in results) else 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    common = argparse.ArgumentParser(add_help=False)
    for flag in ("--samples", "--target", "--method", "--results"):
        common.add_argument(flag, required=True)
    common.add_argument("--note", default="")
    hc = sub.add_parser("hashcheck", parents=[common])
    hc.add_argument("--root", required=True)
    dm = sub.add_parser("dm-fallback", parents=[common])
    for flag in ("--image", "--dmsetup", "--name", "--key-file", "--fs", "--work"):
        dm.add_argument(flag, required=True)
    ec = sub.add_parser("ecryptfs", parents=[common])
    for flag in ("--lower", "--fek-csv", "--out"):
        ec.add_argument(flag, required=True)
    fs = sub.add_parser("fscrypt-v2", parents=[common])
    for flag in ("--image", "--dir", "--fscrypt-json"):
        fs.add_argument(flag, required=True)
    dl = sub.add_parser("dm-line", help="table line with the device replaced, or --keyref")
    for flag in ("--dmsetup", "--name"):
        dl.add_argument(flag, required=True)
    dl.add_argument("--device", default="")
    dl.add_argument("--keyref", action="store_true")
    f1 = sub.add_parser("fscrypt-v1", help="add/remove the proven v1 keys via the fscrypt ioctl")
    for flag in ("--fscrypt-json", "--mount"):
        f1.add_argument(flag, required=True)
    f1.add_argument("--remove", action="store_true")
    pk = sub.add_parser("proven-key", help="the proven KeyHex of a synthesized plugin's JSON")
    pk.add_argument("--rows", required=True)
    dp = sub.add_parser("daemon-pid", help="PID of a command in ps_at_dump.txt")
    dp.add_argument("--ps", required=True)
    dp.add_argument("--command", required=True)
    tb = sub.add_parser("table")
    tb.add_argument("--results", required=True)
    return parser


COMMANDS = {"hashcheck": cmd_hashcheck, "dm-fallback": cmd_dm_fallback, "ecryptfs": cmd_ecryptfs,
            "fscrypt-v2": cmd_fscrypt_v2, "dm-line": cmd_dm_line, "fscrypt-v1": cmd_fscrypt_v1,
            "proven-key": cmd_proven_key, "daemon-pid": cmd_daemon_pid, "table": cmd_table}


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    return COMMANDS[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
