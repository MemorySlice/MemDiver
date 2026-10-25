"""AES constants (FIPS-197) shared by the key-schedule finder and its tests."""

import numpy as np

SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")

#: Round constants Rcon[1..10] (index 0 unused).
RCON = bytes([0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36])

#: Key length in 32-bit words (Nk) -> number of rounds (Nr).
ROUNDS = {4: 10, 6: 12, 8: 14}

SBOX_NP = np.frombuffer(SBOX, dtype=np.uint8)
#: xtime(a): multiplication by 2 in GF(2^8).
XTIME = bytes(((a << 1) ^ (0x1B if a & 0x80 else 0)) & 0xFF for a in range(256))
XTIME_NP = np.frombuffer(XTIME, dtype=np.uint8)


def schedule_words(nk: int) -> int:
    """Total 32-bit words in the expanded schedule: 4 * (Nr + 1)."""
    return 4 * (ROUNDS[nk] + 1)


def expand_key(key: bytes) -> bytes:
    """FIPS-197 KeyExpansion: the forward (encryption) schedule of *key*."""
    nk = len(key) // 4
    words = [bytes(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, schedule_words(nk)):
        temp = words[i - 1]
        if i % nk == 0:
            temp = bytes(SBOX[b] for b in temp[1:] + temp[:1])
            temp = bytes([temp[0] ^ RCON[i // nk]]) + temp[1:]
        elif nk > 6 and i % nk == 4:
            temp = bytes(SBOX[b] for b in temp)
        words.append(bytes(a ^ b for a, b in zip(words[i - nk], temp)))
    return b"".join(words)


def mix_column(col: bytes) -> bytes:
    """MixColumns on one 4-byte column (one round-key word)."""
    out = []
    for b in range(4):
        a0, a1, a2, a3 = (col[(b + k) % 4] for k in range(4))
        out.append(XTIME[a0] ^ XTIME[a1] ^ a1 ^ a2 ^ a3)
    return bytes(out)


def inv_mix_column(col: bytes) -> bytes:
    """InvMixColumns on one column: MixColumns applied three times (MC^4 == id)."""
    return mix_column(mix_column(mix_column(col)))


def inverse_layout(forward: bytes) -> bytes:
    """The OpenSSL / AES-NI decryption schedule of a forward schedule.

    Round keys in reverse order; InvMixColumns on every round key but the
    first and the last (``AES_set_decrypt_key``, ``aesni_set_decrypt_key``).
    """
    nr = len(forward) // 16 - 1
    rounds = [forward[16 * r:16 * r + 16] for r in range(nr + 1)][::-1]
    for r in range(1, nr):
        rounds[r] = b"".join(inv_mix_column(rounds[r][4 * c:4 * c + 4]) for c in range(4))
    return b"".join(rounds)
