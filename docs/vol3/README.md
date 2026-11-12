# MemDiver Volatility 3 Plugins: Secrets in Memory, Proven

Volatility 3 plugins that recover cryptographic keys from Linux memory images and process captures, and **prove every key** with an oracle that uses only the encrypted artefact or the memory itself. Never network traffic.

## Abstract

MemDiver turns a secret found in a process slice into a Volatility 3 plugin: locate it in a `.msl` capture, prove it with a format-native oracle (LUKS key digest, AEAD tag, filesystem superblock, X25519 self-consistency, SSH KDF consistency), and synthesize a plugin that finds and proves the same secret in any full memory image. The entry demonstrates this on Linux encryption vaults (LUKS/dm-crypt, VeraCrypt, gocryptfs, fscrypt, eCryptfs), WireGuard and SSH.

The suite has two halves:

- **Kernel and process plugins**, written by hand: `linux.dmcrypt`, `linux.wireguard`, `linux.keyring`, `linux.fscrypt`, `linux.ecryptfs`, `memdiver.ssh`, `memdiver.wireguard_go`, and the layer and inspection plugins for the Memory Slice format (`msl.*`).
- **Plugin synthesis**: `memdiver vol3 synthesize` writes a single-file plugin that carries its own oracle and runs under stock Volatility 3 with no MemDiver and no crypto library installed.

Everything described here is checked by `make validate`. Each claim has an ID, ground truth that does not come from the plugin, and a result in a printed claim table (see [Validation](VALIDATION.md)).

## What is different

1. **First Volatility 3 plugins for several secret stores.** As of a survey on 2026-11-06 we found no Volatility 3 plugin for WireGuard, dm-crypt/LUKS, the Linux kernel keyring, fscrypt, eCryptfs or FUSE vaults such as gocryptfs. (This is a literature and repository survey, not an exhaustive search.)
2. **Every row carries a proof status.** The `Proven` / `Oracle` / `Verified` column says `oracle:<kind>` (proven), `rejected` (the oracle contradicts the candidate) or `unverified` (no oracle applies). The oracle is memory-only or disk-only. Network traffic is never used.
3. **Module structures without module symbols.** `crypt_config` (dm-crypt) and `wg_device` (WireGuard) live in kernel modules, so no kernel ISF contains them. The plugins find them with self-validating locators (AES round key 0 equals the raw key; `X25519(private)·G` equals the stored public key; HKDF identifier re-derivation) and read struct layouts from the kernel's own in-memory BTF.
4. **Synthesis with an embedded oracle.** A recipe locates the key, an oracle inlined into the plugin source and hash-checked on load decides `Proven`, and the plugin is self-tested at emit time.
5. **Reproducible validation.** Two x86_64 reference captures with ground-truth sidecars, small in-repo `.msl` samples with a `SHA256SUMS` file, and a one-command gate.

## Plugin overview

| Plugin | Recovers | Strongest proof (label) |
|---|---|---|
| `linux.dmcrypt` | dm-crypt volume keys: LUKS1, LUKS2, VeraCrypt | key schedule in the tfm context plus LUKS header digest plus page-cache decryption (`O1+O2+O3`) |
| `linux.wireguard` | interface identities, peers, preshared keys, in-flight ephemerals; transport keys with provenance | `X25519` self-consistency, MAC1 key, recomputed Noise chaining key |
| `linux.keyring` | every key in `key_serial_tree`, decoded payloads | cross-proofs: eCryptfs signature, dm-crypt volume key, fscrypt v1 descriptor |
| `linux.fscrypt` | fscrypt v1 master keys, v2 HKDF state | v1 descriptor, v2 identifier re-derived from HMAC-SHA512 midstates, per-file key equals inode schedule |
| `linux.ecryptfs` | per-file encryption keys (FEK), FEKEK | `MD5(FEK) == root_iv`, tfm schedule, tag-3 packet unwrap |
| `linux.btf_layouts` | struct layouts from the kernel's in-memory BTF | symbol walk with all cross-checks |
| `memdiver.ssh` | SSH session keys: OpenSSH, Dropbear, libssh, wolfSSH, Paramiko, Go | RFC 4253 key derivation checked against the same memory (`oracle:ssh-kdf-consistency`) |
| `memdiver.wireguard_go` | wireguard-go (and Tailscale-style) static keys, peers, PSK, ephemerals | `x25519-pubkey`, `x25519-dh-consistency`, `noise-chaining-key` |
| `msl.info`, `msl.vasmap`, `msl.pagemap`, `msl.modules`, `msl.keyhints`, `msl.threads`, `msl.verify` | the Memory Slice container itself | hash-chain verification (`msl.verify`) |
| synthesized plugins | any key a recipe can locate and an oracle can judge | seven format oracles, see [Synthesis](SYNTHESIS.md) |

The suite also ships two stackers: one that stacks `.msl` captures as Volatility layers, and one that adds 5-level paging (LA57) support when Volatility itself does not have it yet.

## Installation

### Prerequisites

- Volatility 3, version 2.27 or later. Versions 2.27.0 and 2.28.2 are the ones tested (see [Compatibility](COMPATIBILITY.md)).
- A Linux memory image (LiME) and an ISF symbol file for the target kernel, for the kernel plugins. The process plugins and `msl.*` need only a `.msl` capture or a process dump.

### Recommended: `pip install memdiver`

```bash
pip install memdiver            # also installs volatility3
vol -p "$(memdiver vol3 plugin-dir)" -h
```

`memdiver vol3 plugin-dir` prints the installed `vol3plugins` directory. The plugin directory imports only the standard library and `volatility3` at module level, so `vol -h` stays fast (0.39 to 0.43 s measured with the msl plugins present). MemDiver is imported lazily and only when an encrypted or compressed `.msl` needs it.

### From a clone, without MemDiver

```bash
git clone https://github.com/MemorySlice/MemDiver
vol -p MemDiver/vol3plugins -f image.lime linux.dmcrypt
```

The kernel plugins and the process plugins need neither MemDiver nor a crypto library: AES, ChaCha20, X25519, HKDF and the SSH KDF all exist as pure-Python fallbacks. A bare Volatility 3 reads plaintext, uncompressed `.msl` files through a slim reader (see [The .msl layer](MSL_LAYER.md)). `-p` takes several directories separated by `;` on every OS.

## Quick start on the in-repo samples

`samples/` holds small public demo inputs (2.4 MB in total) with their ground truth in `samples.json` and a checksum list. The full description is in [samples/README.md](https://github.com/MemorySlice/MemDiver/blob/main/samples/README.md).

```bash
gunzip -k samples/*.msl.gz
P="$(memdiver vol3 plugin-dir);samples/plugins"

# The .msl layer: process identity, page states, integrity chain
vol -p "$P" -f samples/gocryptfs_aes.msl msl.info

# A synthesized plugin proves the gocryptfs master key (2 rows, Proven = oracle:gocryptfs-gcm)
vol -p "$P" -f samples/gocryptfs_aes.msl memdiver_gocryptfs.MemDiverSynthGocryptfs \
    --oracle-sample samples/gocryptfs_aes.oracle

# SSH session keys of a libssh client: six Tier A rows
vol -p "$(memdiver vol3 plugin-dir)" -f samples/ssh_libssh_client.msl memdiver.ssh.SSHKeys

# wireguard-go keys, with a Wireshark keylog
vol -p "$(memdiver vol3 plugin-dir)" -f samples/wireguard_go_psk.msl \
    memdiver.wireguard_go.WireGuardGo --export keylog

# Tamper evidence: one flipped byte
vol -p "$(memdiver vol3 plugin-dir)" -f samples/gocryptfs_aes_tampered.msl msl.verify
```

The tampered sample ends in a `verdict` row `tampered`, and the plugin prints the damaged copy of the key as `rejected` while the intact copy stays proven. The kernel plugins need the 4.3 GB reference captures, which are not in the repository; see [Validation](VALIDATION.md).

Check the samples before using them:

```bash
cd samples && sha256sum -c SHA256SUMS      # macOS: shasum -a 256 -c SHA256SUMS
```

## What `Proven` means

| Status | Meaning |
|---|---|
| `oracle:<kind>` or a plugin-specific label such as `O1+O2+O3:luks-digest+xfs` | An independent check passed: a MAC, a digest stored in the artefact, a filesystem structure, or a derivation that must hold inside the same memory. |
| `unverified` | No oracle applies, or an offset was guessed. The value is shown but not claimed. Transport keys of WireGuard are always `unverified`. |
| `rejected` | The oracle contradicts the candidate. A budget or a guessed offset never produces `rejected`, only `unverified`. |

A guessed or user-supplied structure offset on the key path can never yield `proven`. The page [Technical details](TECHNICAL_DETAILS.md) lists what each oracle can and cannot establish.

## Honest limits

The detailed list is in [Technical details](TECHNICAL_DETAILS.md#known-limits). The short version:

- Stock Volatility 3 has no AArch64 Linux layer, so the judged images are x86_64 (4-level and 5-level paging). The AArch64 capture was a development corpus read through a third-party fork.
- Paramiko drops the shared secret `K` after key exchange, so it has no proof. libssh2 and AES-SIV (gocryptfs) are synthetic-only. OpenSSH and Dropbear on the x86 images are `unverified` because `K` is wiped.
- The fscrypt 6.16+ and hardware-wrapped paths, eCryptfs tag-1 and AES-128/192, and the WireGuard PSK paths of wireguard-go are tested with synthetic data only.
- The kernel WireGuard preshared key is `bound-to-proven-peer`, not oracle-proven. WireGuard transport keys have no memory-only oracle.
- The no-symbols fallbacks for dm-crypt and WireGuard (scan the physical layer without any layout) are not implemented. The plugins use ISF offsets, an exact built-in table or the kernel's own BTF, and say which.
- The oracle step `O3` (page-cache proof for dm-crypt) is not available on AArch64.
- Plugin path arguments (for example `--offsets`, `--oracle-sample`) are read as given. They are not sandboxed by Volatility.

## Related tooling

MemDiver itself is a broader memory-analysis platform with a web UI and AI integration; none of that is needed for, or part of, this entry.

## Documentation

| Document | Content |
|---|---|
| [USAGE.md](USAGE.md) | per-plugin options, examples, output columns, exports |
| [TECHNICAL_DETAILS.md](TECHNICAL_DETAILS.md) | oracle taxonomy, walks, proof semantics, limits |
| [SYNTHESIS.md](SYNTHESIS.md) | recipe v2, locators, inlined oracles, self-test |
| [MSL_LAYER.md](MSL_LAYER.md) | `.msl` as a Volatility layer, `msl.*` |
| [VALIDATION.md](VALIDATION.md) | claim table, `make validate`, mount proof |
| [COMPATIBILITY.md](COMPATIBILITY.md) | versions, kernels, platforms |
| [UPSTREAM.md](UPSTREAM.md) | LA57 pull requests |
