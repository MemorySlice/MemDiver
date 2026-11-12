#!/usr/bin/env python3
"""Minimal fscrypt v1/v2 setup via ioctls (runs IN the guest, as root).

Stand-in for ``fscryptctl``, which is not packaged for every distro (Ubuntu
24.04 ships only the higher-level ``fscrypt`` tool). Uses the filesystem
keyring (FS_IOC_ADD_ENCRYPTION_KEY) for BOTH policy versions, so the master
key lives in the superblock keyring and survives the SSH session that planted
it -- a v1 key added to a session keyring would not.

  add-key MOUNTPOINT KEYFILE v1 DESCRIPTOR_HEX   -> prints the descriptor
  add-key MOUNTPOINT KEYFILE v2                  -> prints the kernel identifier
  set-policy DIR v1 DESCRIPTOR_HEX
  set-policy DIR v2 IDENTIFIER_HEX
  descriptor KEYFILE                             -> prints SHA-512(SHA-512(raw))[:8]
  legacy-payload KEYFILE OUTFILE                 -> writes struct fscrypt_key
                                                    (for `keyctl padd logon fscrypt:<desc>`)

Contents mode AES-256-XTS (1), filenames mode AES-256-CTS (4), flags 0x2
(PAD_16) -- the fscrypt defaults.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import struct
import sys

FS_IOC_SET_ENCRYPTION_POLICY = 0x800C6613      # _IOR('f', 19, fscrypt_policy_v1)
FS_IOC_ADD_ENCRYPTION_KEY = 0xC0506617         # _IOWR('f', 23, fscrypt_add_key_arg)
KEY_SPEC_TYPE_DESCRIPTOR = 1
KEY_SPEC_TYPE_IDENTIFIER = 2
MODE_AES_256_XTS = 1
MODE_AES_256_CTS = 4
POLICY_FLAGS_PAD_16 = 0x2
ADD_KEY_HEADER = struct.Struct("<II32sII32s")  # key_spec(40) raw_size key_id reserved
FSCRYPT_MODE_AES_256_XTS = 1
LEGACY_KEY = struct.Struct("<I64sI")           # struct fscrypt_key {u32 mode; u8 raw[64]; u32 size}


def v1_descriptor(raw: bytes) -> str:
    """The conventional v1 key descriptor: first 8 bytes of SHA-512(SHA-512(raw)).

    This is what e4crypt, fscryptctl and fscrypt compute; the kernel never checks it,
    so a random descriptor is legal but unprovable from the key alone.
    """
    return hashlib.sha512(hashlib.sha512(raw).digest()).digest()[:8].hex()


def legacy_key_payload(raw: bytes, mode: int = FSCRYPT_MODE_AES_256_XTS) -> bytes:
    """Payload of a legacy ``logon fscrypt:<descriptor>`` key (72 bytes)."""
    if not 0 < len(raw) <= 64:
        raise ValueError(f"fscrypt raw key must be 1..64 bytes, got {len(raw)}")
    return LEGACY_KEY.pack(mode, raw.ljust(64, b"\0"), len(raw))


def add_key(mountpoint: str, keyfile: str, version: str, descriptor_hex: str = "") -> str:
    with open(keyfile, "rb") as fh:
        raw = fh.read()
    if version == "v1":
        spec_type, spec = KEY_SPEC_TYPE_DESCRIPTOR, bytes.fromhex(descriptor_hex).ljust(32, b"\0")
    else:
        spec_type, spec = KEY_SPEC_TYPE_IDENTIFIER, b"\0" * 32
    arg = bytearray(ADD_KEY_HEADER.pack(spec_type, 0, spec, len(raw), 0, b"\0" * 32) + raw)
    fd = os.open(mountpoint, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.ioctl(fd, FS_IOC_ADD_ENCRYPTION_KEY, arg, True)
    finally:
        os.close(fd)
    _, _, out_spec, _, _, _ = ADD_KEY_HEADER.unpack_from(bytes(arg))
    return out_spec[:8].hex() if version == "v1" else out_spec[:16].hex()


def set_policy(directory: str, version: str, key_ref_hex: str) -> None:
    key_ref = bytes.fromhex(key_ref_hex)
    if version == "v1":
        policy = struct.pack("<BBBB8s", 0, MODE_AES_256_XTS, MODE_AES_256_CTS,
                             POLICY_FLAGS_PAD_16, key_ref)
    else:
        policy = struct.pack("<BBBB4s16s", 2, MODE_AES_256_XTS, MODE_AES_256_CTS,
                             POLICY_FLAGS_PAD_16, b"\0" * 4, key_ref)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.ioctl(fd, FS_IOC_SET_ENCRYPTION_POLICY, policy)
    finally:
        os.close(fd)


def _read(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "descriptor":
        print(v1_descriptor(_read(sys.argv[2])))
    elif len(sys.argv) == 4 and sys.argv[1] == "legacy-payload":
        with open(sys.argv[3], "wb") as out:
            out.write(legacy_key_payload(_read(sys.argv[2])))
    elif len(sys.argv) >= 4 and sys.argv[1] == "add-key":
        print(add_key(*sys.argv[2:6]))
    elif len(sys.argv) == 5 and sys.argv[1] == "set-policy":
        set_policy(*sys.argv[2:5])
    else:
        sys.exit(__doc__)
