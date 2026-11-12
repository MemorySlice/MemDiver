# Volatility 3 samples

Small, public demo inputs for MemDiver's Volatility 3 plugins. With them you can check
the entry's claims without any private data. `make validate` runs every claim; the claims
that use these samples need no environment variable.

All files here are demo data. The two gocryptfs master keys, the SSH session keys and the WireGuard keys (incl. the preshared key) of the two wireguard-go slices are public on purpose: they are
listed in `samples.json` as the ground truth that the plugin output is compared with.
`SHA256SUMS` covers every sample file (`sha256sum -c SHA256SUMS`, or
`shasum -a 256 -c SHA256SUMS` on macOS).

## Files

| File | Size | What it is |
|---|---|---|
| `gocryptfs_aes.msl.gz` | 0.6 MB (71 MB unpacked) | Process slice of a running `gocryptfs` daemon (cipher aes-gcm, PID 65219), cut down to the one region that holds the master key: the Go heap arena at `0xc000000000` (68 MiB, mostly zero pages, which is why gzip shrinks it so much). |
| `gocryptfs_xchacha.msl.gz` | 0.6 MB (71 MB unpacked) | The same for a second session with its own key (cipher xchacha20-poly1305, PID 65361). It is the second training run for synthesis. |
| `gocryptfs_aes.oracle`, `gocryptfs_xchacha.oracle` | 344 B, 361 B | The vault oracle sample of each session: the `FeatureFlags` of its `gocryptfs.conf` plus the first block of one encrypted file. A candidate key is "proven" only when it authenticates that block. The sample has no `EncryptedKey` or scrypt parameters, so there is nothing to crack. |
| `gocryptfs_aes_tampered.msl.gz` | 0.6 MB | The aes slice with ONE byte flipped (xor 0x01): the first byte of the first of the two in-memory copies of the key (VA `0xc0000bc220`). |
| `gocryptfs_aes_encrypted.msl` | 0.5 MB | The aes slice rewritten with zstd-compressed regions and AES-256-GCM container encryption (MSL spec section 10, raw key). |
| `gocryptfs_aes_encrypted.msl.key` | 32 B | The raw content-encryption key of that file (a public demo key). |
| `plugins/memdiver_gocryptfs.py` | 120 KB | The plugin MemDiver synthesized from the two slices: an anchor locator, an entropy fallback and the gocryptfs oracle inlined (hash-checked) with pure-Python AES/ChaCha fallbacks. It runs under stock Volatility 3 with no MemDiver and no crypto library. It holds no key; the recipe keeps only a sha256. |
| `plugins/memdiver_gocryptfs.recipe.json` | 2.5 KB | The recipe the plugin was rendered from. |
| `ssh_libssh_client.msl.gz` | 67 KB (0.66 MB unpacked) | Heap and stack of a libssh 0.10.6 client (Debian bookworm, PID 15 in its container) with an open session: curve25519-sha256, aes256-ctr, hmac-sha2-256. `memdiver.ssh.SSHKeys` proves all six keys A-F (Tier A). |
| `ssh_wolfssh_client.msl.gz` | 11 KB (0.48 MB unpacked) | The same for a wolfSSH 1.4.20 client (wolfSSL 5.7.6, built from source), same algorithms. |
| `wireguard_go_initiator.msl.gz` | 0.12 MB (32 MB unpacked) | The Go heap arena of a `wireguard-go` 0.0.20250522 initiator (linux/arm64, PID 42 in its container) caught right after it sent a rekey initiation: static identity, the peer's handshake in `initiationCreated` with its ephemeral, and the current keypair. `memdiver.wireguard_go.WireGuardGo` proves the static key (`oracle:x25519-pubkey`), the peer key (`oracle:x25519-dh-consistency`) and the ephemeral (`oracle:noise-chaining-key`); the two transport keys are reported `unverified`. |
| `build_wireguard_go_sample.py` | | How the wireguard-go slice was made (needs MemDiver and the private corpus). |
| `wireguard_go_psk.msl.gz` | 0.12 MB (32 MB unpacked) | The Go heap arena of a `wireguard-go` 0.0.20250522 responder configured with a `PresharedKey` (linux/arm64, PID 42 in its container) caught right after it created the handshake response: the peer's handshake is in `responseCreated`, so the PSK is an input of its chaining key. `memdiver.wireguard_go.WireGuardGo` proves the static key (`oracle:x25519-pubkey`), the peer key (`oracle:x25519-dh-consistency`), the ephemeral AND the preshared key (`oracle:noise-chaining-key`). |
| `build_wireguard_go_psk_sample.py` | | How the wireguard-go PSK slice was made (needs MemDiver and the private corpus). |
| `samples.json` | 8 KB | Provenance and ground truth for each sample: source sha256, kept regions, PID, key VAs, the flipped offset. |
| `build_samples.py` | | How the files above were made (needs MemDiver and the private corpus). |

## Provenance

* **Capture:** `memslicer` (MemDiver's companion live-process acquisition tool) attached to
  the `gocryptfs` daemon (`/usr/bin/gocryptfs`, gocryptfs 2.4.0, Go) on Linux x86_64 and
  wrote one `.msl` slice per session: about 110 regions and 210 MB each. The capture does not
  record the kernel version; a process slice holds only the process's own address space.
  Sessions `run_0001` (aes-gcm) and `run_0002` (xchacha) of a 95-session gocryptfs corpus;
  the sha256 of each original slice is in `samples.json`.
* **Filtering:** `memdiver.msl.importer.import_msl_passthrough(..., materialize=True)` with a
  region selection that keeps exactly the regions containing the key, which is the Go heap
  arena. Nothing inside a region is changed: the arena's 17,408 pages are kept byte for byte.
  The process identity, module list and end-of-capture blocks are copied, a VAS map of all
  original regions is added, and the import provenance block records the selection. The BLAKE3
  integrity chain of the result is valid (`msl.info` prints `Integrity valid`).
* **gzip** is only a wrapper for the repository: `gunzip -k` gives back the `.msl` byte for
  byte (its sha256 is `msl_sha256` in `samples.json`).
* **Tamper demo:** a copy of the aes slice with the byte at file offset 778208 xor 0x01.
* **Encrypted demo:** the aes slice rewritten by MemDiver's MSL materializer with zstd regions
  and `MslEncryptionConfig(raw_key=...)`.
* **SSH slices:** a throwaway Docker rig (linux/arm64): each client connects to a Paramiko
  server whose `_compute_key` hook logged the six derived keys of the same session (the
  ground truth in `samples.json` under `ssh`), runs one command and stays idle; then
  `memslicer acquire <pid> -b gdb --scope heap,stack` (memslicer 0.5.2). The rig's login is a
  demo `testuser`/`password` pair that exists nowhere else.
* **wireguard-go slice:** a Docker rig (linux/arm64) ran two `wireguard-go` processes
  (0.0.20250522, Go 1.25, no PSK) under Delve; at each lifecycle breakpoint it wrote a flat
  process dump plus a maps sidecar, and the keylog from inside the process (the ground truth
  in `samples.json` under `wireguard_go`). The initiator's `post_rekey_start` dump of run
  `run_20260808_125548` was converted with `msl.importer.import_regioned_raw` and cut down,
  with a region selection, to the one region holding every key (the Go heap arena at
  `0x4000000000`, kept byte for byte).
* **wireguard-go PSK slice:** the same rig, run with `WG_PRESHARED_KEY` (32 bytes from
  `openssl rand`) on both peers; the keylog's `WG_PRESHARED_KEY` line is the PSK ground truth
  (`samples.json` under `wireguard_go_psk`). The responder's `pre_keys_installed` dump of run
  `run_20261112_124707_psk` (handshake in `responseCreated`) was converted and cut down the same
  way.
* **Plugin:** `memdiver vol3 synthesize` (library: `synthesize_vol3_plugin`) on the two slices,
  with one key and one oracle sample per slice; its own verdict was `proven` on both.

## What to run

First unpack the slices:

```sh
gunzip -k samples/*.msl.gz
```

### Preferred: with MemDiver installed

`pip install memdiver` also installs Volatility 3. `memdiver vol3 plugin-dir` prints the
installed `vol3plugins` directory (from a clone, `vol3plugins` works too). `-p` takes several
directories separated by `;` on every OS.

```sh
P="$(memdiver vol3 plugin-dir);samples/plugins"

# The .msl layer: process identity, page states, integrity chain
vol -p "$P" -f samples/gocryptfs_aes.msl msl.info

# The synthesized plugin proves the key (2 rows, Proven = oracle:gocryptfs-gcm, Scope = msl:65219)
vol -p "$P" -f samples/gocryptfs_aes.msl memdiver_gocryptfs.MemDiverSynthGocryptfs \
    --oracle-sample samples/gocryptfs_aes.oracle

# The same plugin on the other session and cipher (Scope = msl:65361)
vol -p "$P" -f samples/gocryptfs_xchacha.msl memdiver_gocryptfs.MemDiverSynthGocryptfs \
    --oracle-sample samples/gocryptfs_xchacha.oracle

# Tamper evidence: msl.info says "Integrity BROKEN"; the flipped key copy is "rejected"
vol -p "$P" -f samples/gocryptfs_aes_tampered.msl msl.info
vol -p "$P" -f samples/gocryptfs_aes_tampered.msl memdiver_gocryptfs.MemDiverSynthGocryptfs \
    --oracle-sample samples/gocryptfs_aes.oracle --show-unverified

# Encrypted .msl: same rows as the plaintext slice, but only with the key file
MEMDIVER_MSL_KEY_FILE=samples/gocryptfs_aes_encrypted.msl.key \
    vol -p "$P" -f samples/gocryptfs_aes_encrypted.msl memdiver_gocryptfs.MemDiverSynthGocryptfs \
    --oracle-sample samples/gocryptfs_aes.oracle

# Synthesize the plugin yourself (prints proven=True; the keys are read from stdin)
python -c "import json; m = json.load(open('samples/samples.json'))['slices']; \
print(m['aes']['master_key_hex']); print(m['xchacha']['master_key_hex'])" |
memdiver vol3 synthesize --name memdiver_gocryptfs --oracle-kind gocryptfs-gcm --key-hex-file - \
    --oracle-sample samples/gocryptfs_aes.oracle --oracle-sample samples/gocryptfs_xchacha.oracle \
    samples/gocryptfs_aes.msl samples/gocryptfs_xchacha.msl
```

### Bare stock Volatility 3 (no MemDiver, no crypto library)

```sh
python3 -m venv /tmp/vol-bare && /tmp/vol-bare/bin/pip install volatility3   # 2.27.0 or 2.28.2
/tmp/vol-bare/bin/vol -p "vol3plugins;samples/plugins" -f samples/gocryptfs_aes.msl \
    memdiver_gocryptfs.MemDiverSynthGocryptfs --oracle-sample samples/gocryptfs_aes.oracle
```

The `.msl` is stacked by the slim pure-Python reader in `vol3plugins/`, so Scope is still
`msl:65219`. The oracle logs one WARNING that it uses pure-Python crypto: this is correct, just
slower. Plain `pip install volatility3` brings no `cryptography`; `volatility3[full]` brings
`pycryptodome`, which the oracle uses when present. Encrypted and compressed `.msl` files
need MemDiver (the layer fails with one line saying `pip install memdiver`).

### The `msl.*` plugins (bare vol too)

`msl.info`, `msl.vasmap`, `msl.pagemap`, `msl.modules`, `msl.keyhints`, `msl.threads` and
`msl.verify` describe the container itself. They read a plaintext, uncompressed `.msl` with
the slim reader when MemDiver is absent, with identical rows.

```sh
P="vol3plugins"                          # or: $(memdiver vol3 plugin-dir)
vol -p "$P" -f samples/ssh_libssh_client.msl msl.pagemap      # page-state runs (spec table 35)
vol -p "$P" -f samples/gocryptfs_aes.msl msl.modules          # base, size, path, disk hash
vol -p "$P" -f samples/ssh_libssh_client.msl msl.threads --verbose   # pc/sp/fp + every register
vol -p "$P" -f capture.msl msl.keyhints --dump                # KEY_HINT rows; keyhint_<n>.bin
vol -p "$P" -f samples/gocryptfs_aes_tampered.msl msl.verify  # verdict row: tampered
```

`msl.verify` prints one row per block (`ok` or `link broken`) and a final `verdict` row. A
PrevHash chain breaks at the block *after* the modified one: on the tampered sample the
single `link broken` row is the VAS_MAP, and its Detail names the MEMORY_REGION before it.
The default chain is BLAKE3, which needs the `blake3` package (installed with MemDiver):
a bare vol gives `not verified` with "needs memdiver (BLAKE3...)"; SHA-256 and SHA-512/256
chains verify with the standard library alone. `msl.pagemap --region <index|uuid>` selects one
region.

### SSH session keys (no MemDiver needed)

```sh
vol -p vol3plugins -f samples/ssh_libssh_client.msl memdiver.ssh.SSHKeys
vol -p vol3plugins -f samples/ssh_wolfssh_client.msl memdiver.ssh.SSHKeys --export keylog
```

Six rows each, Tier A, `Proven = oracle:ssh-kdf-consistency`: K, H and session_id found in
the process re-derive (RFC 4253) keys found in the same memory. `--export keylog` writes
`ssh_keys.newkeys.log` in the OpenSSH keylog-patch `NEWKEYS` format.

### WireGuard keys of wireguard-go (no MemDiver needed)

```sh
vol -p vol3plugins -f samples/wireguard_go_initiator.msl memdiver.wireguard_go.WireGuardGo
vol -p vol3plugins -f samples/wireguard_go_initiator.msl memdiver.wireguard_go.WireGuardGo \
    --export keylog
```

Five rows: the static private key (`oracle:x25519-pubkey`), the peer public key
(`oracle:x25519-dh-consistency`), the in-flight ephemeral (`oracle:noise-chaining-key`) and the
send/receive keys (`unverified`: no memory-only oracle exists for transport keys).
`--export keylog` writes `wireguard_go.keylog` in Wireshark's WireGuard grammar plus
`wireguard_go.wg-transport.json`; `--export showconf` writes a `wg showconf` file.

```sh
vol -p vol3plugins -f samples/wireguard_go_psk.msl memdiver.wireguard_go.WireGuardGo --export keylog
```

Four rows on the PSK slice: static, peer, ephemeral and the `preshared` key, the last two
`oracle:noise-chaining-key` (the responder's chaining key, recomputed from the ephemeral and the
PSK, equals the one in memory); the keylog has a `PRESHARED_KEY` line right after the ephemeral.

### All claims

```sh
make validate
```

The claims that use these samples always run. The captures of a real Linux machine
(dm-crypt, WireGuard, keyring, fscrypt, eCryptfs, 5-level paging) are too large for the
repository; with `MEMDIVER_SECRETS_CORPUS` pointing at them, their claims run too. Set
`MEMDIVER_VOL3_ALT_VOL_PY` to a second Volatility 3 tree's `vol.py` to run every claim on both
versions, and `MEMDIVER_VOL3_BARE_VOL` to a bare `vol` (as above) for claim C-SYN2. The claim
definitions are in the docstring of `tests/test_vol3plugins_corpus_gate.py`.
