# LUKS header fixtures

Real headers written by `cryptsetup luksFormat` -- none of them is hand-built. They back
`tests/test_vol3plugins_secrets_luks.py` (parser, volume-key digest oracle, `segment_crypto`).

| fixture          | LUKS | cipher (dm form)       | key bits | hash   | sector | header bytes kept |
|------------------|------|------------------------|----------|--------|--------|-------------------|
| `luks1-xts`      | 1    | `aes-xts-plain64`      | 512      | sha256 | 512    | 4096 (`phdr`)     |
| `luks1-essiv`    | 1    | `aes-cbc-essiv:sha256` | 256      | sha1   | 512    | 4096 (`phdr`)     |
| `luks2-default`  | 2    | `aes-xts-plain64`      | 512      | sha256 | 512    | 32768 (2 copies)  |
| `luks2-4k`       | 2    | `aes-xts-plain64`      | 512      | sha512 | 4096   | 32768 (2 copies)  |
| `luks2-essiv`    | 2    | `aes-cbc-essiv:sha256` | 256      | sha256 | 512    | 32768 (2 copies)  |

Per fixture, four files (total ~ 105 KiB, every file <= 32 KiB):

* `<name>.hdr.bin`  -- the header region only: LUKS1 = bytes 0..4095 (the 592-byte `phdr` plus
  padding; keyslot key material starts at sector 8 = byte 4096 and is not kept); LUKS2 = bytes
  0..32767 = primary binary header + JSON area (0..16383) **and** the secondary copy
  (16384..32767, magic `SKUL`). The keyslot area (from byte 32768) is not kept.
* `<name>.dump.txt` -- `cryptsetup luksDump <image>` output; the tests cross-check the parser
  against it (cipher, sector size, offsets, digests, salts, iteration counts, UUID).
* `<name>.gt.txt`   -- ground truth as `key=value` lines: `volume_key_hex` (the master key the
  header was formatted with) and `passphrase`. Not `.json`: the repo `.gitignore` ignores `*.json`.
  `git check-ignore -v tests/fixtures/luks/*` reports nothing (none ignored).

## How they were made

Tool: `cryptsetup 2.7.0` (Ubuntu 24.04 `cryptsetup-bin 2.7.0-1ubuntu4.2`, arm64) in a throwaway
container; no device mapper, no `open` -- `luksFormat` on regular files only:

```sh
docker run --rm -v "$PWD":/w ubuntu:24.04 bash /w/gen.sh
```

`gen.sh` (volume keys and passphrases are pre-written into `/w`, see below):

```sh
apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq cryptsetup-bin
cd /w
# (1) luks1-xts
truncate -s 8M luks1-xts.img
cryptsetup luksFormat --batch-mode --type luks1 --cipher aes-xts-plain64 --key-size 512 \
  --hash sha256 --iter-time 2000 --volume-key-file luks1-xts.vk --key-file luks1-xts.pass luks1-xts.img
# (2) luks1-essiv
truncate -s 8M luks1-essiv.img
cryptsetup luksFormat --batch-mode --type luks1 --cipher aes-cbc-essiv:sha256 --key-size 256 \
  --hash sha1 --iter-time 2000 --volume-key-file luks1-essiv.vk --key-file luks1-essiv.pass luks1-essiv.img
# (3) luks2-default  (--sector-size 512 explicit: 2.7.0 otherwise picks 4096 for a file on a 4 KiB fs)
truncate -s 16M luks2-default.img
cryptsetup luksFormat --batch-mode --type luks2 --cipher aes-xts-plain64 --key-size 512 --hash sha256 \
  --sector-size 512 --pbkdf argon2id --pbkdf-memory 65536 --pbkdf-parallel 1 --iter-time 500 \
  --luks2-metadata-size 16k --luks2-keyslots-size 258048 \
  --volume-key-file luks2-default.vk --key-file luks2-default.pass luks2-default.img
# (4) luks2-4k
truncate -s 16M luks2-4k.img
cryptsetup luksFormat --batch-mode --type luks2 --cipher aes-xts-plain64 --key-size 512 --hash sha512 \
  --sector-size 4096 --pbkdf argon2id --pbkdf-memory 65536 --pbkdf-parallel 1 --iter-time 500 \
  --luks2-metadata-size 16k --luks2-keyslots-size 258048 \
  --volume-key-file luks2-4k.vk --key-file luks2-4k.pass luks2-4k.img
# (5) luks2-essiv
truncate -s 16M luks2-essiv.img
cryptsetup luksFormat --batch-mode --type luks2 --cipher aes-cbc-essiv:sha256 --key-size 256 --hash sha256 \
  --sector-size 512 --pbkdf argon2id --pbkdf-memory 65536 --pbkdf-parallel 1 --iter-time 500 \
  --luks2-metadata-size 16k --luks2-keyslots-size 258048 \
  --volume-key-file luks2-essiv.vk --key-file luks2-essiv.pass luks2-essiv.img
for f in luks1-xts luks1-essiv luks2-default luks2-4k luks2-essiv; do
  cryptsetup luksDump $f.img > $f.dump.txt
  cryptsetup luksDump --dump-volume-key --batch-mode --key-file $f.pass $f.img > $f.vkdump.txt
done
```

Volume keys and passphrases are deterministic (so the container run is reproducible apart from
cryptsetup's random salts/UUIDs). For `name` in the table and `n` = key bytes (64, 32, 64, 64, 32):

```python
seed = f"memdiver-luks-fixture:{name}".encode()
key = b"".join(hashlib.sha256(seed + bytes([i])).digest() for i in range(2))[:n]   # -> <name>.vk
passphrase = f"memdiver-fixture-passphrase-{name}"                                  # -> <name>.pass, no newline
```

The `<name>.hdr.bin` files are the first 4096 (LUKS1) / 32768 (LUKS2) bytes of each image
(`head -c N <name>.img`); `<name>.dump.txt` is the `luksDump` output unchanged.

The volume key in `<name>.gt.txt` was checked against `cryptsetup luksDump --dump-volume-key`
(unlocking with the passphrase) for all five images: byte-identical.

## Volume keys (all throwaway)

```
luks1-xts      594efc0395e3b35e732bfa98b6c42d79458c52b1bd31740028c87d8f822b9db96ca38b94fe276231b6b86db5bc40fbc25e4df4aa7fbf100cecc17daa39819248
luks1-essiv    5787dca4bed9baf5740d53ca1cfde6bfbe5297b13f288d624958ae517a296e0d
luks2-default  272a8deb001cf0893f6cc9c20ae1d7a6333ac498b04ac769706428a3bd4c9884414a1f32c8a844156c1a80abe7127eb0d18b44b68a420e7ec70818044a07ad97
luks2-4k       afbef50d0f2c099eb64a8ba973e80d39b00f1b4de57386e4a0b178a2bade74c2755dfec0ee24481b6d47306b980a116535160ba68e1e7934df3748f4227cead7
luks2-essiv    3905e57727579618d6327011781a69b4c9535639f7482c1fe118afb933aee1e9
```

## PBKDF2 digest iteration counts (cryptsetup benchmarks ~125 ms of PBKDF2 per header)

LUKS1 `MK iterations`: luks1-xts 154931 (sha256), luks1-essiv 142469 (sha1). LUKS2 digest
`Iterations`: luks2-default 125788 (sha256), luks2-4k 170889 (sha512), luks2-essiv 344473
(sha256). (Keyslot iterations/argon2 cost are irrelevant to the digest oracle.) One
`verify_volume_key` call is 15-50 ms on the dev machine, so no low-iteration variant and no `slow` marker are needed.
