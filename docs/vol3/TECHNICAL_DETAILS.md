# MemDiver Volatility 3 Plugins: Technical Architecture and Implementation

## Introduction

This document describes how the plugins find secrets and, above all, **what each proof establishes**. A recovered byte string is only evidence until something independent confirms it. The suite therefore separates two jobs. A *locator* proposes candidates (a structure walk, a pattern, an entropy scan). An *oracle* alone decides the proof status. A weak locator costs time; it can never produce a false proof.

All numbers below come from the execution log of the project ([`docs/dev/contest_progress.md`](https://github.com/MemorySlice/MemDiver/blob/main/docs/dev/contest_progress.md)) or from the plugin source. Items not verified on real data are marked as such.

## Oracle taxonomy

| Class | Mechanism | Formats and uses in this suite | False-positive rate of a wrong key |
|---|---|---|---|
| A. MAC / AEAD recomputation | a tag or HMAC over stored ciphertext | gocryptfs (AES-GCM, XChaCha20-Poly1305, AES-SIV), generic AEAD | 2^-128 for a 16-byte tag |
| B. Key digest | PBKDF2 of the key stored in a header | LUKS1 `mkDigest`, LUKS2 `digests` | 2^-160 or smaller |
| C. Plaintext structure | decrypt a sector or block, check for filesystem structure | dm-crypt and VeraCrypt data areas (`xts-fsmagic`): ext4, XFS, FAT, NTFS, LVM2, swap, GPT, btrfs | scored in bits; proof threshold 64 bits by default |
| D. Key self-consistency (memory only) | derive and compare inside the same dump | AES round key 0 equals the raw key (dm-crypt `O1`); `X25519(priv)·G` equals the stored public key; `X25519(priv, remote)` equals the precomputed secret; Noise chaining key recomputation; SSH keys A-F from `(K, H, session_id)`; fscrypt HKDF identifier and per-file key; eCryptfs `MD5(FEK) == root_iv` | structural: a wrong candidate does not satisfy a one-way relation to bytes elsewhere in memory |
| E. Network traffic | | **not used anywhere in this suite** | |

Notes on the table:

- Class C is never used alone for a LUKS key; it adds evidence to class B. It is the proof for VeraCrypt, whose header is encrypted under a key derived from the password and therefore cannot check a master key recovered from memory (which is why a `veracrypt-header` oracle was dropped from the design).
- AES-GCM and (X)ChaCha20-Poly1305 are not key-committing. "Proven" means "this key authenticates the sample"; for a sample written by real software the key is unique, but an adversarially built sample could authenticate under two keys.
- The `xts-fsmagic` oracle rejects a wrong key only when the filesystem is named in its parameters; with an unknown filesystem the verdict is `error`, never `rejected`. 1,000 random keys on real decrypted pages gave 1,000 `rejected` (filesystem named) or 1,000 `error` (unknown), and 0 `proven` either way.

### Proof statuses

| Status | Used when | Never used when |
|---|---|---|
| `proven` (`oracle:<kind>`) | an independent check passed and every offset on the key path came from the ISF, an exact table entry, or trusted in-memory BTF | an offset on the key path was guessed or user-supplied without a built-in confirmation |
| `unverified` | no oracle applies, evidence is not resident, a budget ran out, or an offset was guessed | |
| `rejected` | a trusted structure contradicts its own proof (for example a Tier A SSH structure whose `K` does not derive its own keys) | a time budget ended, an offset was guessed, an unknown filesystem was assumed |
| `conflict` (kernel plugins) | two independent oracles disagree | |

The consequence of the last two rows is intentional: wrong offsets are silent failures in Volatility 3, so a plugin that guesses an offset may say `unverified` and may never say `rejected` or `proven`.

## Linux kernel image plugins

### Shared infrastructure

Kernel-module structures (`crypt_config`, `wg_device`, `wg_peer`, `noise_handshake`, `noise_keypair`, and related) are not in a kernel's vmlinux ISF. The plugins get their layouts from three sources, in this order:

1. **Trusted in-memory BTF.** `linux.btf_layouts` walks the kernel's `btf_modules` list through the ISF (many cross-checks) and parses the module's BTF out of the image. A header-scan fallback exists, but a scan-only result is **never trusted**, because a planted blob could forge it. A failed walk check disqualifies trust.
2. **An exact built-in table entry** keyed by architecture and kernel release (`uname -r`, read from `linux_banner`). There are 60 exact x86_64 WireGuard entries (Ubuntu 5.15 GA, Ubuntu 6.8 and HWE up to 7.0, Debian 12, RHEL 9.1 to 9.8, Fedora 41 to 45), each derived from the distribution package's module BTF and checked against `pahole` (all 122 members of 11 structs). They fall into 8 distinct layouts, constant within every sampled series; the key-path offsets are identical in all 8. dm-crypt has exact entries for `("x86_64", "6.8.0-136-generic")` and the AArch64 twin (38 of 38 members checked against `pahole`).
3. **`--offsets FILE`** (a capture sidecar works).

Every offset carries a provenance label (`btf-memory`, `table`, `isf`, `derived`). A key found through a `derived` offset is `unverified`. The test-only variable `MEMDIVER_TEST_HIDE_OFFSET_TABLE=1` hides the table so that the BTF path is exercised; it prints a `TEST ONLY` warning.

Other shared pieces: a kernel list and red-black tree walker with cycle and size caps, an ISF member resolver, a `SafeReader` that turns unreadable pages into absent data, and a stdlib-only primitive set (`aes`, `chacha`, `x25519`, `hkdf_midstate`, `luks`, `fsmagic`, `pagecache`, `ssh_kdf`, `noise`) with known-answer tests (FIPS-197, SP 800-38A, IEEE 1619 XTS, GCM test cases, RFC 7748 including 1000 iterations, RFC 4231 through midstates, RFC 5869).

Pure-Python timings (CPython 3.11, Apple silicon): XTS over 4 KiB 3.8 ms, GCM over 4 KiB 4.5 ms, one X25519 1.6 ms (1.3 ms budget value in the oracle), one SHA-512 compression 0.12 ms.

### linux.dmcrypt

**Walk.** `name_rb_tree` (fallback `_minor_idr`) to `hash_cell` to `mapped_device.map` to `dm_table.targets[]` to every `dm_target` whose type name is `crypt`; `dm_target.private` is the `crypt_config`. When `dm_mod` is a module (RHEL and Alma ISFs have no device-mapper types), the core layout comes from the module's symbols and BTF instead, with warnings.

**Self-validating locator.** A `crypt_config` candidate must pass: the `dm_dev` name is `major:minor`, the cipher string matches what dm-crypt accepts, the key size, key parts and sector size are plausible, and `tfms[0]`'s `crypto_alg.cra_name` equals the crypto-API name the cipher string parses to.

**Key recovery.** The raw key is rebuilt from the AES schedules (`struct crypto_aes_ctx`) inside the transform context. A driver layout table is tried first, then a bounded scan of the context and of the transforms it points to (templates such as `xts(aes)`, `essiv(...)` and simd/cryptd wrappers keep their keys one hop away). With LUKS2's default keyring path the kernel wipes `crypt_config.key`, so the schedule is the only source; `Source` says which one was used. For CBC-ESSIV the data key is the schedule whose SHA-256 equals another schedule in the same device (the IV key).

**Oracles.**

- **O1** (always): every key part's full `key_enc || key_dec || key_length` must equal what the kernel's own AES key-expansion produces from it. A zeroed context never passes, because the schedule of the all-zero key is not zero.
- **O2** (when a LUKS header is resident): the physical layer is scanned for LUKS headers (only when a LUKS device with a recovered key exists). A header binds to a device by UUID (`hash_cell.uuid` is `CRYPT-LUKS<n>-<uuid>-<name>`), then PBKDF2 of the key is compared with the header digest. LUKS2 JSON areas that are not contiguous with their binary header are re-paired by the header checksum. Hostile headers are bounded: digests of 16 to 64 bytes, at most 8 digests, a 40 million total-iteration budget, and an iteration cap of 20 million.
- **O3** (page cache): the ciphertext source is the loop device's backing file mapping, read from `lo_offset + start*512` (with a `lo_disk` back-check), or the block-device mapping otherwise; the plaintext source is the whole-disk `part0`. Pair mode first (ciphertext pages decrypt to a resident plaintext page), then filesystem-magic on unit 0; at most 8 page reads and 16 units. A mismatch counts only when the decryption is noise, so a stale page never rejects a correct key. Pages are found through an xarray walk with a mapping check (114 stale LUKS2 slots on the real capture pointed at pages now owned by another file and are filtered) and pointer canonicalisation, because Volatility masks pointers to the address width.

`decide()` keeps O2 primary. O3 adds evidence and never rejects an O2-proven key; with O2 not applicable, an O3 pass proves the key and settles the XTS half order. Measured O3 cost: 0.001 to 0.010 s per device.

**Results on the real capture** (x86_64 4-level and 5-level, Volatility 2.27.0 and 2.28.2, all four identical): LUKS1 `O1+O2+O3:luks-digest+xfs` (decryption reaches XFS, 105 bits), LUKS2 `O1+O2+O3:luks-digest+pagecache-pair`, VeraCrypt `O1+O3:pagecache-pair` (before O3 it was `O1:schedule`). `--export dmsetup` is byte-identical to the guest's `dmsetup table --showkeys`.

An earlier bug is worth recording because only a real run found it: on x86 the LUKS1 `O1` initially failed because the ESSIV assembler picked the IV-key schedule (SHA-256 of the key, in a separate `aes-aesni` cipher) as the data key.

### linux.wireguard

**Walk.** `net_namespace_list` to every `struct net` to `dev_base_head` to each `net_device` whose `rtnl_link_ops->kind` is `wireguard`; `wg_device = netdev_priv(dev) = dev + ALIGN(sizeof(net_device), 32)`, accepted only when the back-pointer `wg_device.dev == dev` holds. The module's own `device_list` is walked too and merged. `wg_device.peer_list` leads to each `wg_peer` (back-pointer `wg_peer.device`), its `noise_handshake`, its three keypair slots (back-pointer `entry.peer`), its endpoint and its `allowedips_list`. `sizeof(net_device)` differs by kernel: a measured table gives 2512 bytes for Ubuntu 6.8.0-31 to -117 and 2544 for -136 and -149; the ISF always wins.

**Proofs (memory only).**

| Name | Check |
|---|---|
| `O_id` | `X25519(static_private)·G == static_public`, after a clamp prefilter; if the table offset fails, the 64-byte block `{public, private}` is searched in the `wg_device` allocation. A forged block whose public is not f(private) is a `conflict`. |
| `O_mac1` | `BLAKE2s("mac1----" ‖ static_public) == cookie_checker.message_mac1_key` (device) and the same over the peer public (peer): binds a public key to a second, independent location |
| `O_dh` | `X25519(static_private, remote_static) == precomputed_static_static`, with small-order and non-canonical rejection. A proven identity plus `O_dh` proves the peer public key. |
| `O_ck` | the Noise_IKpsk2 chaining key is recomputed for a handshake in flight. `CREATED_INITIATION` proves the local ephemeral; `CONSUMED_INITIATION` proves only the remote ephemeral, and the stale local one stays `unverified` |

**Preshared key.** No oracle judges it. It is reported `PSK:bound-to-proven-peer` when it sits in the handshake of a proven peer and its offset is backed by a built-in BTF entry or trusted in-memory BTF (in-memory BTF is trusted like a table entry by decision). A user-supplied `--offsets` value that differs from the built-in entry makes the PSK `unverified`.

**Transport keys** (`noise_keypair.sending` and `.receiving`) have no memory-only oracle: the chaining key they derive from is zeroed when the session begins. They are always `unverified` and reported with provenance (`is_valid`, birthdate age, index pairing, and the mirror keypair when both tunnel ends are in the same image).

**Zeroing semantics** explain missing material. `handshake_zero()` wipes the ephemeral keys, hash and chaining key as soon as a session begins, so an ephemeral private key exists only while a handshake is in flight (for example an unreachable peer being retried). `remote_static`, `precomputed_static_static` and `preshared_key` persist for the peer's lifetime. Peers are freed with `kfree_sensitive()`. All keypairs are wiped after 540 s without a new handshake.

**Results on the real capture:** two interfaces and two identities proven (`O_id`, `O_mac1`, back-pointer), three of three peers proven, the in-flight ephemeral of a third peer proven by `O_ck`, two `PSK:bound-to-proven-peer`, transport keys `unverified`. Every exported key was found verbatim in the guest's own record. Wall time is about 7 s on a warm cache (in-memory BTF adds about 0.3 to 0.6 s: 7.0 to 7.3 s against 6.7 s with it off).

### linux.keyring

The walk reads the `key_serial_tree`, then each `struct key` with offsets from the ISF, then `key_type.name`. Payload decoders: `user` and `logon` (`user_key_payload`), 740-byte eCryptfs `auth_token`, `struct fscrypt_key` for `logon fscrypt:<descriptor>`, and cryptsetup volume keys. On the first real capture 65 of 67 keys of the guest's `/proc/keys` were reproduced by serial, type and description (the two missing were probably garbage-collected before the dump), plus 11 other users' keyrings that `/proc/keys` hides from root. Cross-proofs:

- eCryptfs: the token's signature (`ecryptfs-sig`) and the FEKEK equal the ground truth.
- dm-crypt: a `user cryptsetup:<uuid>-d0` key (present when LUKS2 is opened with `--link-vk-to-keyring`) is compared with the key `linux.dmcrypt` proves. A bug found on the second capture: the first version accepted only `logon` keys, but cryptsetup links a `user` key.
- fscrypt v1: the descriptor equals `SHA-512(SHA-512(key))[:8]`, the one-way rule used by `e4crypt`, `fscryptctl` and `fscrypt`.

### linux.fscrypt

**Walk.** `super_blocks` to `s_master_keys` (`fscrypt_keyring` hash table) to `fscrypt_master_key` to `mk_decrypted_inodes`.

**v1.** The raw key is resident. The per-file key is derived again from it and the inode's nonce and compared with the AES schedule in the inode's transform (`+per-file-schedule`). When the descriptor was derived from the key, it is checked too (`descriptor`).

**v2 and HKDF midstates.** The kernel wipes the raw master key and keeps only `HKDF-Extract`'s output as a keyed HMAC-SHA512 transform. The plugin reads the inner and outer SHA-512 midstates out of the hash transform. Three layouts exist by kernel: `hmac_pads` (up to 6.6), `hmac_ctx` (6.7 to 6.16, 208/209-byte state) and `hmac_sha512_key` (6.17 and later). It re-derives the key identifier with `HKDF-Expand` context 1 from the midstates and compares it with `mk_spec.identifier` (`oracle:identifier`), then re-derives each file's key (context 2 with the file's nonce) and compares it with the inode schedule. The SHA-512 compression with midstate injection is a short stdlib routine (0.12 ms per compression). The userspace mount proof decrypts a v2 directory from these midstates alone (see [Validation](VALIDATION.md#mount-proof-c-mount1)).

**Real results:** both captures, both Volatility versions: v1 and v2 proven, 5 of 5 inodes per policy, v1 key, v2 midstates and identifier all equal the ground truth. On the second capture the v1 descriptor oracle also fires (`oracle:descriptor+per-file-schedule`), because that capture's descriptor was derived from the key.

### linux.ecryptfs

**Walk.** superblocks whose `s_type->name == "ecryptfs"` to `s_inodes` to `ecryptfs_inode_info.crypt_stat`. **Root IV:** `MD5(FEK)[:iv_bytes] == root_iv` (applied only for `iv_bytes == 16`; for other sizes the rule proved wrong FEKs 86 times in 20,000 and 0 times after the restriction). **Tag 3:** the lower file's page 0 (read through the page-cache walk) carries an encrypted FEK packet; it unwraps under the FEKEK, whose signature the keyring row proves. The tag-3 pass binds a keyring token to the file, so a tag-3 failure with a passing root IV keeps the FEK proven but marks the pairing unconfirmed in `MountAuthTok`. Any guessed offset or size demotes the row to `unverified`, never `rejected`.

**Real results:** 16 of 16 rows (4 files, 2 captures, 2 Volatility versions) `oracle:ecryptfs-root-iv+tfm-schedule+ecryptfs-tag3`; the salt and tag-11 signature equal the sidecar; page 0 was resident in 16 of 16.

### Stackers: 5-level paging (LA57)

`LinuxLA57IntelStacker` (stacking order 36, after the stock `LinuxIntelStacker` at 35 and the VMCOREINFO stacker at 34) acts only on the exact stock `LinuxIntel32e` or `Intel32e` classes and steps aside if the installed Volatility already defines `intel.LinuxIntel32e_LA57`. Two layer classes exist: `LinuxIntel32eLA57` (46-bit page-frame numbers, conditional) and `Intel32eLA57` (52-bit, the VMCOREINFO path the reference capture uses). A banner and `init_task.comm` read-back decides whether the 5-level layer is right; the tie case reads `__pgtable_l5_enabled`. The layer pickles through a module-level rebuild factory, so `--parallelism processes` works as long as `memdiver` is importable in the worker processes. Replaying a saved configuration (`-c`) needs `-p`, as the class lives in this directory.

Corpus result against upstream pull request #1991 is in [Upstream](UPSTREAM.md). With the stacker, stock Volatility 2.27 on the 5-level reference capture lists 155 processes in 6.8 s, with PID and name columns identical to the pull request build; on the 10 four-level images nothing changes.

## Process plugins

### memdiver.ssh

The plugin reads the writable mappings of a process (keys never live in read-only file mappings) up to `--max-mb`. Each implementation has a locator:

| Implementation | Structure | Tier on the evidence we have |
|---|---|---|
| libssh | `ssh_crypto_struct`: `shared_secret`, `secret_hash`, `session_id`, six raw keys in one struct | A, proven on a Docker capture and on the x86 full image |
| wolfSSH | `WOLFSSH.k`, `.h`, `.sessionId` | A, proven |
| Go `x/crypto/ssh` | `kexResult{H, K, SessionID}` and the ChaCha20-Poly1305 cipher (length key first) | A, proven |
| Paramiko | `Transport.K`, `.H`, `.session_id` | no proof: Paramiko drops `K` after NEWKEYS |
| OpenSSH | `newkeys[MODE_MAX]` to `sshenc{key_len, iv_len, block_size, key, iv}` | B, `unverified` (client and sshd agree per direction; `K` is wiped) |
| Dropbear | ChaCha20 state pair or AES schedule | C, `unverified` |
| libssh2 | AES schedule | C; tested with synthetic data only |

**The Tier A oracle** (`ssh-kdf-consistency`). Given `K` (as mpint), `H` and `session_id` found together, derive the six keys A to F of RFC 4253 section 7.2 with `hashlib`, and count how many of them occur in the same memory. Two or more distinct letters mean `proven`: each match is a prefix of at least 96 bits of an independent SHA-2 output, so two cannot match by chance. Zero matches from a trusted structure give `rejected`. Exactly one match is "inconclusive" and never promoted. IV, key and MAC lengths are taken from the negotiated cipher (see below), not from how far a memory match ran; an early version took lengths from the match and produced a 32-byte IV where the ground truth is 16.

**Negotiated algorithms.** For libssh the `kex_methods` string-pointer array near the anchor names the algorithms; for OpenSSH the `sshenc` record at the matched key does. Both are reported as `lengths: negotiated(libssh|openssh)` in `Detail`. Go and wolfSSH remain `inferred`, because Go's algorithm names live in `.rodata`, which the writable-only scan does not read.

**Real results.** Tier A proven with keys equal to the implementation's own ground truth: Go x/crypto (ChaCha20-Poly1305 and AES-GCM), libssh A to F, wolfSSH A to F, on arm64 Docker `.msl` captures. On the x86_64 full image, a libssh 0.10.6 client (aes256-ctr, hmac-sha2-256) gives 6 of 6 `oracle:ssh-kdf-consistency`, byte-equal to the guest's record (0.1 to 0.2 s of plugin analysis); its Paramiko peer gives 0 rows, as expected. On the x86 LiME images OpenSSH is Tier B and Dropbear Tier C, all `unverified`.

### memdiver.wireguard_go

The plugin finds the `Device.staticIdentity` structure by a layout-free adjacency (the public key sits right after the private key), then the peers' `Handshake` structures through the `Peer.device` back-pointer, with a layout-free adjacency fallback (`--no-fallback` disables it). Offsets come from wireguard-go commit f333402 and were checked against memory. A peer is *trusted* when both the device back-pointer and the mac1-key adjacency hold.

Proofs: `x25519-pubkey` (static key), `x25519-dh-consistency` (peer), and `noise-chaining-key` (ephemeral in `initiationCreated`, and the PSK in `responseCreated`, because the PSK is an input of that chaining key). Transport keys are always `unverified`; the PSK is `bound:peer-handshake` only when bound to a trusted, proven peer.

**Exit criterion met:** on all 112 archive dumps (4 runs, 2 roles, 14 lifecycle dumps each) the static key and the peer are proven and equal the in-process keylog; 0 rejected. A real PSK run (a rig run with a configured preshared key) gives the PSK as `oracle:noise-chaining-key` equal to the ground truth in the 2 responder `responseCreated` dumps. Initiator ephemerals in consumed-handshake dumps are `unverified`, as expected.

## The .msl layer and slim reader

See [The .msl layer](MSL_LAYER.md).

## Oracle cost budget

Every format oracle declares `COST_US`, the measured cost of verifying one wrong candidate, plus optional `prefilter` and `unique`. The synthesized-plugin template uses them as follows.

- `--oracle-budget SECONDS` (default 120; 0 means unlimited) counts only oracle time and is armed once per run.
- Candidates are filtered, passed through the oracle's prefilter, and ordered: anchor hits first, then locator order, then entropy candidates. The plugin logs one estimate line, then verifies until the budget runs out.
- Leftovers become `unverified` with a `budget:` detail. When the oracle declares itself `unique` (one key per artefact, as for gocryptfs) and a key is already proven, the rest are `unverified` with `skipped: key already proven`. A budget never produces `rejected`.

Measured on real data: `--oracle-budget 0.001` leaves 196,686 candidates `unverified` and the 2 proven rows unchanged. Wrong-key verification cost of the gocryptfs oracle (AES-GCM / XChaCha20 / AES-SIV): `cryptography` 5.8 / 12.6 / 14.9 µs, `pycryptodome` 47 / 27 / 116 µs, pure Python 159 / 106 / 402 µs. The worst entropy sweep on pure Python (89,000 candidates) took 16 s. The LUKS oracle is the expensive one (`COST_US = 200000`, one PBKDF2 per candidate), which is why it runs only on prefiltered candidates.

## Known limits

Collected from the "open" lines of the execution log. None of these changes a `proven` row; they bound what the suite can find.

**Platform**

- Stock Volatility 3 (2.27.0, 2.28.x, and PR #1991) has no AArch64 Linux layer. The only one we know is a third-party fork, `volatility3-arm64` of eurecom-s3, which we used for development. The judged images are x86_64.
- AArch64 is development-only. `O3` (page-cache proof) needs `page.to_paddr`, which Volatility does not have on AArch64, so `O3` is not applicable there.
- A Linux image whose kernel has no `kallsyms` cannot be fixed on Volatility 2.27: no kernel layer is built at all.

**dm-crypt and keyring**

- The no-symbols fallback (find AES schedules in the physical layer and pair them without any layout) is **not implemented** for `linux.dmcrypt`; the plugin needs ISF offsets, a table entry or trusted in-memory BTF.
- A LUKS2 `dmsetup` replay needs the recovered key to be loaded into the keyring under the name in the table line.
- AES-192-XTS (48-byte keys) is listed by `xts-fsmagic` but the `aes` primitive cannot decrypt it.
- No `cryptsetup:` logon key survives in the key tree on the first captures (cryptsetup unlinks it), so the first dm-crypt cross-proof ran on injected records; on the second capture the linked `user` key makes it real.
- The `veracrypt-header` oracle was cut: the header is encrypted under a password-derived key. VeraCrypt is proven through `xts-fsmagic` and `O3`.

**WireGuard**

- The no-symbols fallback is **not implemented** for `linux.wireguard` either.
- The kernel preshared key is `bound-to-proven-peer`, not oracle-proven (no in-flight handshake exists on the captures). Transport keys have no memory-only oracle. No kernel WireGuard keylog exists on the capture (it would need kprobe or eBPF), so the transport keys have no ground truth.
- wireguard-go: the PSK paths other than the real `responseCreated` case, the rejected paths, the `--pid` image mode and x86_64 or Tailscale layouts were tested with synthetic data only.

**fscrypt and eCryptfs**

- The fscrypt 6.16 and later paths (`bytes` and `is_hw_wrapped` handling, hardware-wrapped keys under identifier context 8, the 6.17 and 6.18 layouts) were tested with faked structures only. `DIRECT_KEY` and `IV_INO_LBLK` per-mode keys are not checked.
- eCryptfs: the tag-1, AES-128, AES-192, two-byte length, xattr-metadata, non-resident and pairing-fail paths are synthetic-only. On the second capture the lower file's page 0 was not resident, so tag-3 does not fire there.

**SSH**

- Paramiko drops `K` after NEWKEYS and therefore has no proof. libssh2 is synthetic-only. OpenSSH and Dropbear on the x86 images are `unverified`. There is no x86 Tier A capture for Go or wolfSSH.

**Synthesis**

- A recipe locator is an anchor pattern or an entropy scan. The kinds `yara`, `artifact_window`, `aes_schedule`, `pubkey_adjacency` and `kernel_struct` are reserved and not implemented. The candidate layout is a single key.
- Only gocryptfs has a captured full-image proof of synthesis (`--pid` on a kernel image). The LUKS oracle works end to end but needed `--allow-high-entropy-context` for LUKS1 and a 1,024-byte context for LUKS2 (which gives a YARA rule libyara will not match).
- Static oracle context values are JSON, so oracles that need byte context would need hex decoding; cancellation is checked between steps only.

**Interface**

- Plugin path arguments such as `--offsets` and `--oracle-sample` are not sandboxed by Volatility; they are read as given. The wrapper `memdiver vol3 exec` refuses Volatility global options and `;` in paths, but passes a plugin's own path arguments through unchecked.
- A scan of a `.msl` misses a needle that starts in captured bytes and ends in NotResident pages (Volatility's scanners do not carry overlap across non-contiguous segments). Reads across that edge are correct.
