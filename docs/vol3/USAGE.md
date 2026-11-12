# Volatility 3 Plugin Usage Guide

## Quick Start

### Installation

```bash
pip install memdiver                         # installs volatility3 too
P="$(memdiver vol3 plugin-dir)"              # the vol3plugins directory

vol -p "$P" -h                               # lists the plugins below
```

From a clone, use `-p MemDiver/vol3plugins` instead. Several directories are joined with `;` (`-p "$P;/my/plugins"`) on every OS.

### Common shape of a command

```bash
# A Linux kernel image: needs an ISF for the kernel
vol -p "$P" -s /path/to/symbols --offline -f ubuntu.lime linux.dmcrypt

# A process capture (.msl): no symbols needed
vol -p "$P" -f capture.msl memdiver.ssh.SSHKeys
```

Always pass a fresh `--cache-path` when several Volatility processes run at once; the shared cache can race under concurrency. Every plugin accepts the plugin names with or without the class suffix (`linux.dmcrypt` and `linux.dmcrypt.DmCrypt` are the same).

### The proof column

All plugins that recover keys print a proof status next to every key: `proven` or an `oracle:<kind>` label, `unverified`, or `rejected`. The meaning is in the [overview](README.md#what-proven-means) and the oracle details are in [Technical details](TECHNICAL_DETAILS.md). Files written by `--export` go to the directory given by Volatility's `-o` option.

---

## Plugin: linux.dmcrypt

### Description

Lists active dm-crypt devices and recovers each volume key from memory. It walks the device-mapper structures, finds the `crypt_config` of every `crypt` target (a kernel-module type with no ISF entry), and reads the raw key out of the expanded AES-XTS or AES-CBC key schedule in the crypto transform. With the LUKS2 keyring path the kernel wipes `crypt_config.key` after setup, which is why the schedule is the source of truth.

Handles LUKS1, LUKS2 and VeraCrypt volumes opened through dm-crypt.

### Requirements

- A Linux kernel image and its ISF. x86_64 is the judged architecture (4-level and 5-level paging). AArch64 works only through a third-party Volatility fork.
- Offsets of `crypt_config` and the device-mapper core structures. Sources, in order: the kernel's own in-memory BTF (trusted only when the symbol walk and all cross-checks pass), an exact entry in the built-in table, `--offsets`. A guessed offset on the key path never produces `proven`.
- No crypto library. For the page-cache proof the plugin needs the loop or block device pages to be resident.

### Options

| Option | Description |
|---|---|
| `--offsets FILE` | JSON with `crypt_config` (and optional dm core) member offsets; a capture sidecar works |
| `--export {masterkey,dmsetup,json,cryptsetup}` | write raw key files (proven keys only), `dmsetup` lines, a JSON report, or open scripts |
| `--export-unverified` | with `--export masterkey`, also write keys that are not proven |
| `--verbose` | add `Status`, `Driver`, `Detail`, `O2` and `O3` columns |
| `--btf-method {auto,symbols,both,off}` | module struct offsets from in-memory BTF: `auto`/`symbols` = walk only, `both` = walk plus a physical header scan that must agree, `off` = table or `--offsets` only |

### Examples

```bash
# Every device, its key and proof
vol -p "$P" -s symbols --offline -f ubuntu.lime linux.dmcrypt

# Lines byte-compatible with `dmsetup table --showkeys`
vol -p "$P" -s symbols --offline -f ubuntu.lime -o out linux.dmcrypt --export dmsetup

# Per device: a raw key file and a cryptsetup open script
vol -p "$P" -s symbols --offline -f ubuntu.lime -o out linux.dmcrypt --export cryptsetup
```

### Output Columns (Table Format)

| Column | Description |
|---|---|
| `Name`, `UUID`, `DM` | dm device name, dm UUID, `major:minor` |
| `Target` | target type (`crypt`) |
| `Cipher`, `IV`, `SectorSize` | cipher string, IV mode, sector size |
| `Device` | underlying device |
| `KeySize`, `Key` | key length in bytes and the key in hex |
| `Source` | where the key came from (for example `tfm-schedule`) |
| `Oracle` | the proof label, for example `O1+O2+O3:luks-digest+xfs` |
| `Offset(V)` | virtual address of the `crypt_config` |

The proof labels combine up to three oracles. `O1`: the key equals round key 0 of the AES schedule inside the transform. `O2`: PBKDF2 of the key equals the digest in the LUKS header found in memory. `O3`: ciphertext pages of the backing device decrypt to the resident plaintext page, or to a recognised filesystem head. VeraCrypt has no header digest that memory can check, so it is proven by `O1+O3`. The `Status` column (verbose) is one of `proven`, `unverified` (optionally `:xts-order` or `:defaulted-offsets`), `conflict`, `rejected:luks-digest` or `none`.

### Exports

| Mode | File | Content |
|---|---|---|
| `masterkey` | `dmcrypt.<name>.masterkey` | raw key, proven keys only |
| `dmsetup` | `dmcrypt.dmsetup.txt` | one `dmsetup table --showkeys` line per device |
| `json` | `dmcrypt.json` | full report including the `o3` field |
| `cryptsetup` | `<stem>.volume-key`, `<stem>.open.sh` | LUKS: `cryptsetup open --type luksN --volume-key-file`; plain: `--type plain`; VeraCrypt: a `dmsetup create` replay, because tcrypt needs the header password |

```{note}
A LUKS2 `dmsetup` line refers to its key by keyring name (`:64:logon:cryptsetup:<uuid>-d0`) instead of hex. To replay it, load the recovered master key into the keyring under exactly that name first. The `cryptsetup` export does not have this problem. On containers, VeraCrypt replay also needs `DM_DISABLE_UDEV=1`.
```

---

## Plugin: linux.wireguard

### Description

Lists WireGuard interfaces and peers of the in-kernel implementation and recovers their keys from memory alone. It walks every network namespace for `net_device` objects whose link ops are `wireguard`, derives `wg_device` from the device private area, and locates the static identity with a self-validating test (a 64-byte block where `X25519(block[32:64])·G == block[0:32]`).

Recovered: interface private and public keys, peers, preshared keys, in-flight ephemeral private keys, endpoints, allowed IPs, listen port, handshake state, and transport (send/receive) keys with their provenance.

### Requirements

- A Linux kernel image with an ISF; x86_64 judged.
- WireGuard struct offsets from the in-memory BTF, an exact built-in entry (60 x86_64 kernel entries from distribution module BTF), or `--offsets`.
- No crypto library (the X25519 ladder falls back to pure Python; `cryptography` only speeds it up).

### Options

| Option | Description |
|---|---|
| `--offsets FILE` | JSON with WireGuard module struct offsets (a capture sidecar works) |
| `--export {keylog,showconf,json}` | write a Wireshark key log plus transport JSON, `wg showconf` files, or a JSON report |
| `--export-unverified` | also export material that is not proven (transport keys never are) |
| `--verbose` | add a `Detail` column: offset provenance, counters, origin |
| `--btf-method {auto,symbols,both,off}` | as for `linux.dmcrypt` |

### Examples

```bash
vol -p "$P" -s symbols --offline -f ubuntu.lime linux.wireguard
vol -p "$P" -s symbols --offline -f ubuntu.lime -o out linux.wireguard --export showconf
vol -p "$P" -s symbols --offline -f ubuntu.lime -o out linux.wireguard --export keylog
```

### Output Columns (Table Format)

| Column | Description |
|---|---|
| `Interface`, `NetNS` | interface name and network namespace id |
| `ListenPort` | listen port |
| `LocalPrivate`, `LocalPublic` | the interface static key pair |
| `Peer`, `PSK`, `Ephemeral` | peer public key, preshared key, in-flight ephemeral private key |
| `Endpoint`, `AllowedIPs` | peer endpoint and allowed IPs |
| `HandshakeState`, `Slot` | handshake state; which keypair slot a transport key came from |
| `LocalIndex`, `RemoteIndex`, `Initiator` | session indices and role |
| `SendKey`, `RecvKey`, `Birthdate`, `Valid` | transport keys and their provenance |
| `Status`, `Verified` | row status and the proof label |
| `Offset(V)` | virtual address of the structure |

### Exports

| Mode | Files |
|---|---|
| `keylog` | `wireguard.keylog` in Wireshark's WireGuard grammar (`LOCAL_STATIC_PRIVATE_KEY`, `REMOTE_STATIC_PUBLIC_KEY`, `LOCAL_EPHEMERAL_PRIVATE_KEY`, `PRESHARED_KEY`; the PSK line follows its ephemeral line, and without a resident ephemeral the PSK appears as a comment) and `wireguard.wg-transport.json` (provenance only, no key bytes) |
| `showconf` | `wireguard.<netns>.<ifname>.conf` in `wg showconf` format |
| `json` | `wireguard.json` |

The kernel wipes ephemerals at session start, so an ephemeral key exists only while a handshake is in flight. The preshared key is reported `PSK:bound-to-proven-peer`: it sits in the handshake of a peer whose identity is proven, but no memory-only oracle can judge the PSK itself.

---

## Plugin: linux.keyring

### Description

Walks the kernel key serial tree and decodes every key payload. For each key it reports type, description, owner, permissions, state, and a `Semantics` interpretation: `user`/`logon` payloads, fscrypt v1 master keys (`logon fscrypt:<descriptor>`), cryptsetup volume keys (`user cryptsetup:<uuid>-d0`), and eCryptfs authentication tokens.

Three cross-proofs promote a decoded payload to `proven`: the eCryptfs token signature, the dm-crypt volume key (agreement with `linux.dmcrypt` for the same device), and the fscrypt v1 descriptor (`SHA-512(SHA-512(key))[:8]`).

### Requirements

A Linux kernel image with an ISF. fscrypt v1 and v2 master keys live in the superblock keyring, not in the key serial tree: use `linux.fscrypt` for them.

### Options

| Option | Description |
|---|---|
| `--export keyctl` | write `keyring.proc_keys.txt` in `/proc/keys` format (every key, not filtered by reader permission as the live file is) |
| `--dump-dir` | write every readable payload and decoded secret to the output directory |
| `--no-dmcrypt-cross` | skip the `linux.dmcrypt` cross-check of cryptsetup volume keys |
| `--verbose` | full payloads plus `Holders` (tasks whose credentials hold the keyring) and `Detail` |

### Examples

```bash
vol -p "$P" -s symbols --offline -f ubuntu.lime linux.keyring
vol -p "$P" -s symbols --offline -f ubuntu.lime -o out linux.keyring --export keyctl --dump-dir
```

### Output Columns (Table Format)

`Serial`, `Type`, `Description`, `UID`, `GID`, `Perm`, `State`, `Flags`, `Datalen`, `Expiry`, `LastUsed`, `Semantics`, `Status`, `Payload`, `Offset(V)`; verbose adds `Holders` and `Detail`.

---

## Plugin: linux.fscrypt

### Description

Lists fscrypt master keys of every superblock keyring and proves them. It walks `super_blocks`, then `s_master_keys` (the `fscrypt_keyring` hash table), then each `fscrypt_master_key` and its `mk_decrypted_inodes`.

- **v1 policy:** the raw 64-byte master key is in memory. It is proven by re-deriving every open inode's per-file key and comparing it with the AES schedule in the inode's transform (`+per-file-schedule`), and by the descriptor oracle when the descriptor was derived from the key.
- **v2 policy:** the kernel wipes the raw key and keeps only the HKDF state. The plugin recovers the HMAC-SHA512 inner and outer midstates from the hash transform and re-derives the key identifier from them (`oracle:identifier`).

### Requirements

A Linux kernel image with an ISF for kernel 6.1 or later (older kernels get an explicit `error:unsupported-pre-6.1-keyring`). Structure offsets come from the ISF; an announced guess never proves.

### Options

| Option | Description |
|---|---|
| `--export json` | write `fscrypt.json`: v1 raw keys, v2 midstates, per-inode checks |
| `--verbose` | add a `Detail` column and one child row per decrypted inode |

### Examples

```bash
vol -p "$P" -s symbols --offline -f ubuntu.lime linux.fscrypt --verbose
vol -p "$P" -s symbols --offline -f ubuntu.lime -o out linux.fscrypt --export json
```

### Output Columns (Table Format)

`Superblock`, `Device`, `FsType`, `Policy` (v1 or v2), `KeyRef` (descriptor or identifier), `Modes`, `KeySize`, `KeyHex` (v1 master key), `Secret`, `Inodes` (matched/total decrypted inodes), `Proven`, `Offsets` (provenance), `Offset(V)`.

---

## Plugin: linux.ecryptfs

### Description

Lists eCryptfs files and recovers each per-file encryption key (FEK). It walks eCryptfs superblocks, their inodes, and `ecryptfs_inode_info.crypt_stat`, and joins every row to `linux.keyring` through the mount's authentication-token signature.

Proofs combine: the root IV rule (`MD5(FEK)[:iv_bytes] == root_iv`, applied only for 16-byte IVs), the AES key schedule in the transform, and the tag-3 packet in the lower file's first page, which unwraps to the FEK under the keyring-proven FEKEK.

### Options

| Option | Description |
|---|---|
| `--export {json,fek,fekek}` | `ecryptfs.json` (one entry per file, keys included), `ecryptfs_fek.csv` (proven FEKs), `ecryptfs_fekek.txt` (keyring-proven FEKEKs) |
| `--no-schedule` | skip the transform key-schedule proof |
| `--btf-method {auto,symbols,both,off}` | as for `linux.dmcrypt` |

### Examples

```bash
vol -p "$P" -s symbols --offline -f ubuntu.lime linux.ecryptfs
vol -p "$P" -s symbols --offline -f ubuntu.lime -o out linux.ecryptfs --export fek
```

### Output Columns (Table Format)

`Mount`, `Source`, `Superblock`, `Inode`, `Path`, `Size`, `LowerInode`, `LowerInodeAddr`, `LowerPath`, `Cipher`, `KeySize`, `KeyHex`, `KeySigs`, `MountAuthTok`, `Proven`, `Detail`, `Offsets`, `CryptStat(V)`. A typical proven row ends in `oracle:ecryptfs-root-iv+tfm-schedule+ecryptfs-tag3`. If the tag-3 check fails while the root IV passes, the FEK stays proven but `MountAuthTok` flags that the pairing with the keyring token is not confirmed.

---

## Plugin: linux.btf_layouts

### Description

Reads the kernel's own in-memory BTF and lists the layouts of module structures (default set: WireGuard, `dm_crypt`, `dm_mod`). `linux.wireguard`, `linux.dmcrypt` and `linux.ecryptfs` use the same code when they need offsets. The result is **trusted only when it comes from the `btf_modules` symbol walk with all cross-checks passing**. A result found only by scanning for BTF headers is shown for information and never trusted.

### Options

| Option | Description |
|---|---|
| `--module NAME` | module whose BTF to read (`vmlinux` for the base BTF) |
| `--struct NAME [NAME ...]` | struct names (default: the plugin set) |
| `--method {auto,symbols,scan,both}` | `symbols` = walk, `scan` = BTF header scan, `auto` = walk else scan, `both` = both must agree |
| `--export` | write `btf_offsets.<module>.json`, accepted by `--offsets` of the other plugins |

### Example

```bash
vol -p "$P" -s symbols --offline -f ubuntu.lime -o out linux.btf_layouts --module wireguard --export
```

---

## Plugin: memdiver.ssh

### Description

Recovers SSH session keys from processes and proves them from memory. It reads the writable mappings of the selected processes, locates implementation-specific structures, and reports encryption keys, IVs and MAC keys per direction. Keys are graded in tiers:

| Tier | Meaning | `Proven` |
|---|---|---|
| A | The exchange secret `K`, hash `H` and `session_id` are in memory, and at least two RFC 4253 keys derived from them are found in the same memory | `oracle:ssh-kdf-consistency` |
| B | OpenSSH `newkeys`/`sshenc` structure is valid and client and sshd agree per direction, but `K` is wiped | `unverified` |
| C | An AES schedule or a ChaCha20 state pair is resident (Dropbear, libssh2) | `unverified` |

Implementations: OpenSSH, Dropbear, libssh, wolfSSH, Paramiko, and Go `x/crypto/ssh`.

### Requirements

A `.msl` process capture, or a Linux image (with ISF) plus `--pid`. Without `--pid` on an image, every `ssh`, `sshd` and `dropbear` task is scanned. No MemDiver and no crypto library: `hashlib` does the key derivation.

### Options

| Option | Description |
|---|---|
| `--pid PID [PID ...]` | process IDs |
| `--implementation {auto,openssh,dropbear,libssh,wolfssh,paramiko,go}` | only run the locators of one implementation |
| `--all-regions` | also read non-writable mappings |
| `--max-mb N` | read at most N MiB per process |
| `--show-unbound` | also list AES schedules that no SSH structure binds (tier C) |
| `--export {json,keylog}` | `ssh_keys.json`, or `ssh_keys.newkeys.log` in the OpenSSH keylog-patch `NEWKEYS` format |
| `--export-unverified` | also export keys that are not proven |

### Examples

```bash
vol -p "$P" -f samples/ssh_libssh_client.msl memdiver.ssh.SSHKeys
vol -p "$P" -f samples/ssh_wolfssh_client.msl -o out memdiver.ssh.SSHKeys --export keylog
vol -p "$P" -s symbols --offline -f ubuntu.lime memdiver.ssh.SSHKeys --pid 11559
```

### Output Columns (Table Format)

`PID`, `Process`, `Implementation`, `Tier`, `Direction`, `Kind` (key, IV or MAC with a letter A-F where applicable), `Cipher`, `KeyHex`, `Length`, `Address`, `Copies`, `Proven`, `Scope` (`process:<pid>`, `msl:<pid>` or `physical`), `Detail`. The `Detail` column says whether lengths and algorithm names were negotiated (read from memory) or inferred.

---

## Plugin: memdiver.wireguard_go

### Description

Recovers keys of userspace WireGuard: the `wireguard-go` daemon and programs built on its `device` package (Tailscale, wireguard-android, wireguard-apple). Rows:

| Kind | Proof |
|---|---|
| `static-private` | `oracle:x25519-pubkey`: `X25519(private)·G` equals the public key stored right after it |
| `peer-public` | `oracle:x25519-dh-consistency`: `X25519(static_private, remoteStatic) == precomputedStaticStatic` |
| `ephemeral-private` | `oracle:noise-chaining-key` when the handshake is in `initiationCreated` (chaining key recomputed), else `unverified` |
| `preshared` | `oracle:noise-chaining-key` in a `responseCreated` handshake; `bound:peer-handshake` when bound to a proven peer of a trusted handshake; else `unverified` |
| `send`, `receive` | always `unverified` (no memory-only oracle for transport keys) |

A peer counts as trusted only with the device back-pointer and the mac1-key adjacency. `rejected` appears only for a trusted structure that contradicts its own proof.

### Options

| Option | Description |
|---|---|
| `--pid PID [PID ...]` | process IDs (default on an image: `wireguard-go`, `tailscaled`, `com.wireguard*`) |
| `--all-regions`, `--max-mb N` | as for `memdiver.ssh` |
| `--no-fallback` | skip the layout-free adjacency search for handshakes that no `Peer.device` back-pointer reaches |
| `--export {json,showconf,keylog}` | `wireguard_go.json`, `wireguard_go.<pid>.<n>.conf`, or `wireguard_go.keylog` plus `wireguard_go.wg-transport.json` |
| `--export-unverified` | also export material that is not proven |

### Examples

```bash
vol -p "$P" -f samples/wireguard_go_initiator.msl memdiver.wireguard_go.WireGuardGo
vol -p "$P" -f samples/wireguard_go_psk.msl -o out memdiver.wireguard_go.WireGuardGo --export keylog
```

### Output Columns (Table Format)

`PID`, `Process`, `Kind`, `Key`, `Peer`, `Slot`, `LocalIndex`, `RemoteIndex`, `Address`, `Copies`, `Proven`, `Locator`, `Scope`, `Detail`.

---

## The msl plugins

### Description

Describe the Memory Slice (`.msl`) container itself, so a capture can be inspected without leaving Volatility. They run under a bare Volatility 3 on plaintext, uncompressed captures. See [The .msl layer](MSL_LAYER.md).

| Plugin | Output |
|---|---|
| `msl.info` | process identity, OS and architecture, region and page-state totals, integrity (`Variable`, `Value`) |
| `msl.vasmap` | one row per region: `Start(V)`, `End(V)`, `Size`, `Protection`, `Type`, `PageState`, `Captured`, `Module/Path` |
| `msl.pagemap` | page-state runs: `Region`, `UUID`, `Start(V)`, `End(V)`, `State`, `Pages`, `Bytes`, `Content`, `Basis`. Option `--region INDEX_OR_UUID` |
| `msl.modules` | `Base`, `Size`, `Name`, `Path`, `Version`, `DiskHash`, `Source` |
| `msl.keyhints` | `Hint`, `Region`, `Offset`, `VA`, `Length`, `KeyType`, `Protocol`, `Confidence`, `State`, `Note`, `Readable`. Option `--dump` writes `keyhint_<n>.bin` |
| `msl.threads` | `TID`, `Name`, `State`, `Arch`, `Flags`, `PC`, `SP`, `FP`, `Regs`, `Started`. Option `--verbose` adds every register |
| `msl.verify` | per-block rows (`Scope`, `Index`, `Offset`, `Type`, `Length`, `Result`, `Detail`) and a final `verdict` row |

### Examples

```bash
vol -p "$P" -f samples/ssh_libssh_client.msl msl.pagemap
vol -p "$P" -f samples/gocryptfs_aes.msl msl.modules
vol -p "$P" -f samples/ssh_libssh_client.msl msl.threads --verbose
vol -p "$P" -f samples/gocryptfs_aes_tampered.msl msl.verify
```

`msl.verify` prints `ok` or `link broken` per block and a verdict (`valid`, `tampered`, or `not verified`). The hash chain breaks at the block after the modified one: on the tampered sample the single `link broken` row is the VAS_MAP, and its `Detail` names the MEMORY_REGION before it. A BLAKE3 chain (the default) needs the `blake3` package; on a bare Volatility the verdict is `not verified` with a note, while SHA-256 and SHA-512/256 chains verify with the standard library.

---

## Synthesized plugins

### Description

A synthesized plugin is a single `.py` file named after `--name`, with a class `MemDiverSynth<Name>`. It finds a key with an anchor pattern (and an entropy fallback), then lets an inlined oracle decide `Proven`. Details are in [Plugin synthesis](SYNTHESIS.md). The repository ships one, `samples/plugins/memdiver_gocryptfs.py`, which proves gocryptfs master keys.

### Options of a synthesized plugin

| Option | Description |
|---|---|
| `--pid PID [PID ...]` | process IDs to scan (on a kernel image) |
| `--oracle-sample PATH` | oracle evidence: a packed sample or a raw artefact (for gocryptfs, one encrypted file with its `gocryptfs.conf`); required when the recipe has no inline sample |
| `--oracle-param KEY=VALUE` | oracle parameter override (repeatable) |
| `--exhaustive` | run every locator even after a proof |
| `--show-unverified` | also print unproven candidates |
| `--oracle-budget SECONDS` | cap on time spent in the oracle (default 120; 0 = unlimited). Candidates left over are `unverified` with a `budget:` detail, never `rejected` |
| `--export`, `--export-path` | write a JSON report |

### Output Columns

`KeyOffset`, `KeyHex`, `KeyEntropy`, `KeyLength`, `PatternOffset`, `StaticRatio`, `Proven`, `Scope` (`msl:<pid>`, `process:<pid>` or `physical`), `Detail`.

### Example

```bash
vol -p "$P;samples/plugins" -f samples/gocryptfs_aes.msl \
    memdiver_gocryptfs.MemDiverSynthGocryptfs --oracle-sample samples/gocryptfs_aes.oracle
```

---

## Command: memdiver vol3 synthesize

Builds a plugin from a key located in one or more captures and verifies it. Keys are secrets: prefer `--key-hex-file FILE` (or `-` for stdin) over `--key-hex`, which is visible in the process list. No key is echoed, and the key is never written into the plugin or recipe, only its SHA-256.

```bash
python -c "import json; m = json.load(open('samples/samples.json'))['slices']; \
print(m['aes']['master_key_hex']); print(m['xchacha']['master_key_hex'])" |
memdiver vol3 synthesize --name memdiver_gocryptfs --oracle-kind gocryptfs-gcm --key-hex-file - \
    --oracle-sample samples/gocryptfs_aes.oracle --oracle-sample samples/gocryptfs_xchacha.oracle \
    samples/gocryptfs_aes.msl samples/gocryptfs_xchacha.msl
```

| Option | Description |
|---|---|
| `--name NAME` | plugin name (a Python identifier) |
| `--oracle-kind KIND` | the format oracle: one of the [seven kinds](SYNTHESIS.md#the-seven-format-kinds) |
| `--key-hex HEX`, `--key-hex-file FILE`, `--hit HIT` | the key, one per dump or one for all |
| `--oracle-sample PATH`, `--oracle-param KEY=VALUE` | oracle evidence and parameters |
| `--context N` | bytes either side of the key that the anchor is measured over |
| `--verify-on TARGET`, `--no-verify` | verify targets (default `msl`) or skip verification |
| `--allow-high-entropy-context` | accept an anchor that may embed another secret |
| `--full-image IMAGE`, `--pid PID`, `--full-image-sample PATH`, `--full-image-key-hex-file FILE`, `-s DIR` | also run the new plugin under `vol` on a full image |
| `--case CASE_DIR` | store the plugin in a case |
| `--key-file`, `--passphrase`, `--kem-key-file` | key material for encrypted `.msl` input |

The exit code is 0 when every verify target proved the key (or none ran) and 3 otherwise.

`memdiver vol3 exec --image IMAGE [-p DIR] [-s DIR] PLUGIN [ARGS...]` runs a plugin by name under the stock launcher. Options go before the plugin name; Volatility global options after it are refused.

---

## Output Files

All `--export` files are written by Volatility's own file mechanism into the `-o` directory. Files that contain key material are the point of the export; treat them as secrets.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `linux.pslist` shows 0 rows on a 5-level-paging image | stock Volatility 3 2.27 has no LA57 support; pass `-p "$P"` so the bundled stacker applies |
| Offsets reported as `guessed` or rows are `unverified` | the kernel has no exact table entry and no trusted in-memory BTF; supply `--offsets` from a capture sidecar or `linux.btf_layouts --export` |
| `.msl` fails with `pip install memdiver` | the capture is encrypted or compressed; the slim reader handles plaintext, uncompressed files only |
| An encrypted `.msl` fails to stack with one log line naming the remedy | set `MEMDIVER_MSL_KEY_FILE` (or `MEMDIVER_MSL_KEM_KEY_FILE`, `MEMDIVER_MSL_PASSPHRASE`) |
| `--pid` seems ignored on a synthesized plugin | check the `Scope` column: `physical` means the scan ran over the raw layer |
| Second Volatility run behaves differently | use a fresh `--cache-path` per concurrent run |
