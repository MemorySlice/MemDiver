# Validation Guide

## Introduction

Every claim in this documentation is checked by an automated gate. A *claim* has an ID, runs a real plugin under a real `vol`, and compares the output with ground truth that does **not** come from the plugin: the guest's own `dmsetup table --showkeys`, `wg show all dump`, `/proc/keys`, the implementations' own key hooks, or the keys written into the capture sidecar before the dump. `make validate` runs the gate and prints a claim table (claim, Volatility version, result, seconds).

## Data

| Data | Size | Where | What it holds |
|---|---|---|---|
| In-repo samples | 2.4 MB | [`samples/`](https://github.com/MemorySlice/MemDiver/tree/main/samples) | gocryptfs aes and xchacha `.msl` slices, a tampered and an encrypted copy, vault oracle samples, libssh and wolfSSH slices, two wireguard-go slices (one with a preshared key), the synthesized plugin; ground truth in `samples.json`, hashes in `SHA256SUMS` |
| Reference capture, x86_64 4-level paging | 4.29 GB LiME plus 64.5 MB ISF | external | Ubuntu 24.04, kernel 6.8.0-136-generic, 4 GiB RAM, ground-truth sidecar `secrets.json` and `secrets.tar.gz`. Planted: LUKS2, LUKS1, VeraCrypt, WireGuard (3 peers, PSK, a rekey, an in-flight handshake), fscrypt v1 and v2, eCryptfs, gocryptfs, OpenSSH and Dropbear sessions; `gaps` is empty |
| Reference capture v2b, 4-level | same size | external | as above, plus three sibling groups (4 forked dropbear sessions, 4 re-exec OpenSSH connections, 3 independent gocryptfs daemons) with per-process page-frame ground truth, plus a derived fscrypt v1 descriptor and a `logon fscrypt:<descriptor>` key, LUKS2 opened with `--link-vk-to-keyring`, a libssh 0.10.6 client against a Paramiko peer (Tier A ground truth), and `containers.tar` (178 MB) with the real encrypted images and 28 sample files for the mount proof |
| Reference capture, 5-level (LA57) | same size | external | the 4-level twin on a CPU model with five-level paging; sidecar records `cpuinfo_la57` true and mappings above 2^47 |
| SSH capture sessions | | external (`MEMDIVER_SSH_CORPUS`) | `.msl` client slices of Go, libssh, wolfSSH and Paramiko with `gt.json` from the implementations' own hooks |
| wireguard-go archive | 112 dumps | external (`MEMDIVER_WG_GO_CORPUS`) | 4 runs, 2 roles, 14 lifecycle dumps each, with in-process keylogs |
| gocryptfs corpus | 95 sessions | external | used for the synthesis sweep (95 of 95 proven) |

The reference captures were made with the capture rig in [`tools/vol3_capture/`](https://github.com/MemorySlice/MemDiver/tree/main/tools/vol3_capture) (a QEMU guest, a planting script, LiME, `pahole` for layouts). Under TCG emulation on an Apple-silicon host the 4-level capture took 53 minutes and the 5-level one 3 hours 23 minutes. Zenodo record for the three published x86_64 images (v1 4-level, v1 LA57 and v2b, a superset of v2; v2 itself is not published): TODO (maintainer fills in the DOI after upload).

## Running the gate

```bash
make validate
```

This is `python -m pytest -q -p no:cacheprovider -rs tests/test_vol3plugins_corpus_gate.py`.

### Without any corpus

The claims that use only `samples/` and the repository run with no environment variable: `C-MSL1` to `C-MSL4`, `C-SYN1`, `C-IMP1`, `C-SSH1` (in-repo slices) and `C-WGGO1` and `C-WGGO2` (in-repo slices). Every capture-backed claim skips cleanly, with the reason printed. Nothing ever fails for want of a corpus. `C-SYN2` needs a bare Volatility (below).

### With the corpora

```bash
export MEMDIVER_SECRETS_CORPUS=/path/to/acquired_secrets     # the x86_64 captures
export MEMDIVER_SSH_CORPUS=/path/to/ssh_corpus               # <session>/gt.json
export MEMDIVER_WG_GO_CORPUS=/path/to/WireGuard/archive      # run_*/<role>/{dumps,keylogs}
export MEMDIVER_VOL3_ALT_VOL_PY=/path/to/volatility3-2.28.2/vol.py   # second tree: every claim runs on both
export MEMDIVER_VOL3_BARE_VOL=/path/to/bare-venv/bin/vol     # vol without MemDiver and without crypto: C-SYN2, C-MSL4 bare part
make validate
```

| Variable | Purpose |
|---|---|
| `MEMDIVER_VOL3_VOL` (or `MEMDIVER_VOL3_BIN`) | the stock `vol` (an executable or a `vol.py`); default: the `vol` beside the interpreter, else on `PATH` |
| `MEMDIVER_VOL3_ALT_VOL_PY` | a second Volatility 3 tree; every claim runs once per tree present |
| `MEMDIVER_VOL3_BARE_VOL` | a `vol` whose Python has neither MemDiver nor a crypto library |
| `MEMDIVER_SECRETS_CORPUS` | directory with `<stem>.{lime,isf.json,secrets.json,secrets.tar.gz}` of the captures |
| `MEMDIVER_SSH_CORPUS`, `MEMDIVER_WG_GO_CORPUS` | the SSH and wireguard-go corpora |
| `MEMDIVER_GOCRYPTFS_CORPUS` | the gocryptfs `.msl` dataset (directory holding `run_0001/`); unit tests only |
| `MEMDIVER_VOL3_ARM64_FORK` | a Volatility 3 tree with an AArch64 layer, for the optional aarch64 capture tests; unit tests only |

Every Volatility run gets a fresh, pre-created `--cache-path`. A bare Volatility is created with `python3 -m venv bare && bare/bin/pip install volatility3`. When `MEMDIVER_VOL3_VOL` points at the bare environment, `C-MSL1` to `C-MSL3` fail on purpose, because `msl.info` and the integrity row need MemDiver.

The claim table at the end of a run looks like:

```text
claim    vol              result    seconds
C-DM1    2.27.0           passed        ...
C-DM1    2.28.2           passed        ...
...
```

## The claims

| ID | What passing proves | Data |
|---|---|---|
| `C-MSL1` | Layer parity: stock `vol` stacks the `.msl` slice, and `regexscan.RegExScan` finds the master key at exactly the addresses where MemDiver's own reader finds it and where `samples.json` says; `msl.info` reports the captured PID, one region and `Integrity valid` | samples |
| `C-MSL2` | Encrypted `.msl`: with the key file, the encrypted, zstd-compressed copy gives the same plugin rows (offset, key, proof, scope) as the plaintext slice; without the key no row is proven | samples |
| `C-MSL3` | Tamper evidence: one flipped byte makes `msl.info` report `Integrity BROKEN` and the plugin print that copy `rejected`, while the intact copy stays `oracle:gocryptfs-gcm` | samples |
| `C-MSL4` | The `msl.*` plugins equal what MemDiver's reader decodes (page-state runs, modules, thread ids, hint count); `msl.verify` says `valid` on intact slices and `tampered` on the tampered one, naming the VAS_MAP block after the modified region. Under a bare `vol` the plugins give identical rows, and `msl.verify` says `not verified: needs memdiver (BLAKE3` | samples |
| `C-SYN1` | Synthesis: a plugin built from the two in-repo slices (aes-gcm and xchacha, one key each) has a `proven` verdict; run under `vol` on each slice it proves exactly that slice's key at exactly its key addresses, scope `msl:<pid>` | samples |
| `C-SYN2` | No-MemDiver path: the committed `samples/plugins/memdiver_gocryptfs.py`, under a stock `vol` with neither MemDiver nor a crypto library (pure-Python oracle), proves both slices' keys | samples, bare vol |
| `C-IMP1` | Import hygiene: no module-level import outside the standard library and `volatility3` in any `vol3plugins/**` file or the sample plugin (AST rule); `vol -p vol3plugins -h` best of three under 1.5 s and lists our plugins; importing every plugin the Volatility way leaves no `memdiver` module loaded | repository |
| `C-DM1` | `linux.dmcrypt`: every dm-crypt device of the capture (LUKS1, LUKS2, VeraCrypt) is found and its key equals the guest's ground truth byte for byte; `--export dmsetup` is identical to `dmsetup table --showkeys` | capture |
| `C-DM2` | every key is `proven`: LUKS keys by `O1+O2[+O3]:luks-digest[+evidence]`, VeraCrypt by `O1+O3:<fs\|pagecache-pair>`, never by `O1` alone | capture |
| `C-DM3` | with the built-in offset table hidden (`MEMDIVER_TEST_HIDE_OFFSET_TABLE=1`) the offsets come from the kernel's in-memory BTF and the dmsetup export is still identical | capture |
| `C-WG1` | `linux.wireguard`: both interfaces' private keys, every peer public key, endpoint, allowed IPs and the PSK equal `wg show all dump`; identities and peers `proven`; no guessed offsets | capture |
| `C-WG2` | the in-flight handshake is proven through `O_ck`; the PSK is `PSK:bound-to-proven-peer`; transport keys are `unverified` and never claimed proven | capture |
| `C-WG3` | the keylog export follows Wireshark's WireGuard grammar (only the four key types, 44-character base64, a PSK only right after an ephemeral line); static private keys equal the ground truth; the transport JSON holds no key bytes | capture |
| `C-KR1` | `linux.keyring` reproduces the guest's `/proc/keys` (type and description; at most 2 keys garbage-collected before the dump) and proves the eCryptfs token (`ecryptfs-sig`) whose payload starts with the ground-truth FEKEK | capture |
| `C-KR2` | on capture v2b the `user cryptsetup:<uuid>-d0` key is `proven` by `[dmcrypt-cross]` and equals the sidecar's volume key and the key `linux.dmcrypt` proves; the `logon fscrypt:<descriptor>` key decodes as `struct fscrypt_key`, equals the v1 master key, and its descriptor is `SHA-512(SHA-512(raw))[:8]` (recomputed with `hashlib`) | capture v2b |
| `C-FS1` | `linux.fscrypt` v1: master key equals the ground truth, proven by per-file key re-derivation against every open inode's schedule | capture |
| `C-FS2` | v2: the HKDF HMAC-SHA512 midstates equal those computed from the ground-truth key, and the key identifier is re-derived from them | capture |
| `C-FS3` | the per-file proof is complete (every decrypted inode of both policies matched, `m == n > 0`); policy, device, filesystem type, modes and flags equal the ground truth; offsets from the ISF | capture |
| `C-FS4` | v1 descriptor cross-check on capture v2b: `oracle:descriptor+per-file-schedule`, descriptor equals `SHA-512(SHA-512(key))[:8]` and the sidecar | capture v2b |
| `C-EC1` | `linux.ecryptfs`: every open file's FEK is proven by `oracle:ecryptfs-root-iv+tfm-schedule`; mount point, lower directory and token signature equal the ground truth; the token joins a `keyring proven` row | capture |
| `C-EC2` | tag-3 inside the plugin: on both x86 captures every FEK row ends `+ecryptfs-tag3`; `--export fekek` equals the ground truth; `--export fek` equals the tag-3 packets recovered by stock `linux.pagecache.InodePages --dump` and decrypted with the ground-truth FEKEK | capture |
| `C-LA57` | on the 5-level twin, with `-p vol3plugins`, `linux.pslist` lists at least 100 processes including the gocryptfs daemon, and `linux.dmcrypt` gives the same ground-truth keys, all proven | capture (5-level) |
| `C-SSH1` | `memdiver.ssh.SSHKeys`: in-repo libssh and wolfSSH slices give Tier A `oracle:ssh-kdf-consistency` for all six keys A to F, equal to `samples.json`. Both x86 captures: OpenSSH client and post-auth sshd give Tier B rows with identical keys across the two processes, all `unverified`; Dropbear's Tier C pairs equal its OpenSSH client's keys. With `MEMDIVER_SSH_CORPUS`: every Go, libssh and wolfSSH slice gives Tier A with at least two letters and every proven key equal to the ground truth; Paramiko gives no proven row | samples, capture, SSH corpus |
| `C-SSH2` | `memdiver.ssh.SSHKeys --pid` on the x86 v2b full image: the libssh 0.10.6 client gives Tier A for all six keys, byte-equal and equal in length to the sidecar's, with negotiated cipher and MAC names; its Paramiko peer gives no proven row | capture v2b |
| `C-WGGO1` | `memdiver.wireguard_go.WireGuardGo`: in-repo slice gives static key, peer, ephemeral proven and transport keys `unverified`, all equal to `samples.json`; with `MEMDIVER_WG_GO_CORPUS`, on every archive run the static key and the peer are proven and equal the in-process keylog, no row is `rejected`, every transport key equals the keylog and is `unverified` | samples, wireguard-go archive |
| `C-WGGO2` | preshared key on real data: the PSK slice gives static, peer, ephemeral and `preshared` rows, the last two `oracle:noise-chaining-key`, each equal to `samples.json`; the keylog has `PRESHARED_KEY` right after the ephemeral line | samples |
| `C-MOUNT1` | the mount proof below | capture v2b and Docker |

The authoritative wording of each claim is the docstring of [`tests/test_vol3plugins_corpus_gate.py`](https://github.com/MemorySlice/MemDiver/blob/main/tests/test_vol3plugins_corpus_gate.py).

## Mount proof (C-MOUNT1)

Proving a key by an oracle is one thing; using it is the strongest check. [`tools/vol3_capture/mount_proof.sh`](https://github.com/MemorySlice/MemDiver/blob/main/tools/vol3_capture/mount_proof.sh) runs the plugins on the capture v2b image and, in Docker, opens the capture's **real** encrypted containers with only the keys the plugins exported. The sidecar is read afterwards, as the answer key. Each planted file's SHA-256 must equal `samples.sha256`, and no loop device may be left behind.

```bash
tools/vol3_capture/mount_proof.sh \
  --stem "$MEMDIVER_SECRETS_CORPUS/ubuntu-24.04-secrets-x86-4level-v2b_6.8.0-136-generic" \
  --work /path/to/scratch/mount_proof        # about 200 MB of scratch
```

Result (stock Volatility 2.27.0, about 160 s including the plugin runs): **12 methods across 7 targets, 28 of 28 planted files hash-match.**

| Target | Method | Files matched |
|---|---|---|
| LUKS1 (XFS) | kernel `dmsetup` line from `--export dmsetup`; generated `cryptsetup` script from `--export cryptsetup` | 4/4 each |
| LUKS2 (ext4) | kernel `dmsetup` line (master key loaded under the keyring name); generated `cryptsetup` script; unprivileged userspace dm-crypt (`debugfs rdump`) | 4/4 each |
| VeraCrypt (vfat) | kernel `dmsetup` line; generated script (a `dmsetup` replay); unprivileged userspace dm-crypt (`mcopy`) | 4/4 each |
| fscrypt v1 | kernel `FS_IOC_ADD_ENCRYPTION_KEY` with the recovered master key | 4/4 |
| fscrypt v2 | userspace: per-file keys HKDF-expanded from the recovered midstates (the kernel cannot take midstates, and wipes the v2 master key) | 4/4 |
| eCryptfs | userspace: per-file FEKs from `--export fek` (the LinuxKit kernel in Docker has no eCryptfs) | 4/4 |
| gocryptfs | `gocryptfs -ro -masterkey`, key from the synthesized `samples/plugins/memdiver_gocryptfs.py --pid 9908` | 4/4 |

Notes and limits:

- The kernel half runs in a privileged container. It needs a working `docker info`; otherwise the claim skips.
- The LUKS2 `dmsetup` line names its key by keyring reference, so a replay must first load the recovered master key under that name. The VeraCrypt replay needs `DM_DISABLE_UDEV=1` in containers.
- The userspace paths use AES from the `cryptography` package and an independent SHA-512, so they do not depend on the plugins' code.
- Run on Volatility 2.27.0 and on the 4-level v2 capture only. `shellcheck` was not available for the shell scripts.
- No dm-crypt plugin bug was found by the mount proof; it found a leaked loop device in its own first version, which was fixed.

## How a judge reproduces

1. **Samples only (minutes, no downloads).** `pip install memdiver`, then the commands in [Quick start](README.md#quick-start-on-the-in-repo-samples) or `make validate` from a clone.
2. **Bare Volatility.** Create a venv with only `volatility3`, run the committed plugin against `samples/gocryptfs_aes.msl`: the key is proven with the pure-Python oracle, scope `msl:65219`, and the oracle logs one warning that it uses pure Python. Run the same plugin on the tampered sample: only one proven row.
3. **Kernel plugins.** Fetch the reference captures and run the gate in one step: `make validate CORPUS_FETCH=1 CORPUS_RECORD=<Zenodo record id, URL or DOI> CORPUS_DIR=/path/with/15GB/free` (or `CORPUS_MIRROR=/local/copy/of/the/record` instead of `CORPUS_RECORD`). [`scripts/fetch_contest_corpus.py`](https://github.com/MemorySlice/MemDiver/blob/main/scripts/fetch_contest_corpus.py) downloads the record, refuses it unless every file matches `SHA256SUMS`, decompresses the `.xz` files, lays the captures out under the names the gate expects and prints the `export MEMDIVER_SECRETS_CORPUS=...` line; `VALIDATE_ARGS='-k C_DM1'` runs a subset. Or run one plugin by hand, for example:

```bash
mkdir -p symbols/linux && cp ubuntu-24.04-secrets-x86-4level_6.8.0-136-generic.isf.json symbols/linux/
vol -p "$(memdiver vol3 plugin-dir)" -s symbols --offline \
    -f ubuntu-24.04-secrets-x86-4level_6.8.0-136-generic.lime linux.dmcrypt
```

   Then compare the `Key` column with `dmsetup_table_showkeys.txt` in `secrets.tar.gz`.
4. **Mount proof.** Needs Docker; see above.

## Measured figures quoted in this documentation

| Figure | Value | Source |
|---|---|---|
| `vol -p vol3plugins -h` | 0.39 to 0.43 s (best of three 0.54 s earlier, before the msl plugins) | gate claim `C-IMP1` and log |
| dmcrypt on the 4-level capture, stock 2.27 | about 25 s warm | log |
| wireguard on the 4-level capture, stock 2.27 | 6.8 to 7.3 s warm | log |
| stock 2.28.2 cold run | about 74 s (ISF schema validation); 90.7 s for `linux.dmcrypt` on the first cold run | log |
| gocryptfs full-image proof | 74 s cold, 7 s warm | log |
| whole gate with every corpus variable set | 72 tests passed on 2026-11-11, before the later claims `C-KR2`, `C-FS4`, `C-EC2`, `C-SSH2`, `C-WGGO2`, `C-MOUNT1` were added; 8 m 47 s for the earlier 36-test version | log |
