# vol3_capture — plant known secrets before a Linux memory dump

Capture-campaign tooling for the MemDiver "secrets in memory → synthesized
Volatility 3 plugins" work. It turns any Linux VM memory capture into a
**labelled** one: a guest-side script plants secrets whose values are known,
keeps them live while the dump is taken, and writes a ground-truth sidecar
that the plugins and residency checks are scored against.

Works with any QEMU/LiME (or LEMON/AVML) acquisition rig:

1. boot the guest and get a root shell (SSH is assumed below),
2. copy this directory into the guest and run `secrets_stage.sh` as root,
3. acquire memory **immediately** afterwards (do not reboot, unmount, or
   drop caches; the planted mounts, mappings and sessions must stay live),
4. copy `secrets.json` (+ `secrets.tar.gz`) back next to the dump as
   `<dump>.secrets.json` / `<dump>.secrets.tar.gz`.

```sh
scp -r tools/vol3_capture guest:~/vol3_capture
ssh guest 'sudo bash ~/vol3_capture/secrets_stage.sh --out /var/tmp/memdiver-secrets'
ssh guest 'sudo insmod lime.ko "path=/var/tmp/dump.lime format=lime"'   # your rig's dump step
scp guest:/var/tmp/memdiver-secrets/secrets.json   dump.secrets.json
scp guest:/var/tmp/memdiver-secrets/secrets.tar.gz dump.secrets.tar.gz
python3 tools/vol3_capture/residency_check.py dump.lime dump.secrets.json
```

## Files

| file | runs on | purpose |
| --- | --- | --- |
| `secrets_stage.sh` | guest (root) | plants items 1–9, records ground truth, writes the sidecar |
| `gt_json.py` | guest | sidecar builder (fragments → `secrets.json`), pahole/`wg` parsers, eCryptfs FEKEK derivation |
| `fscrypt_helper.py` | guest | fscrypt v1/v2 key-add + set-policy via ioctls (stand-in for `fscryptctl`, unpackaged on Ubuntu 24.04) |
| `residency_check.py` | host | counts raw occurrences of every `keys[]` secret (and AES-XTS halves) in a dump |
| `ssh_tier_a/libssh_client.c` | guest (built there with `libssh-dev`) | item 8b: libssh client that completes one key exchange, then stays connected and idle |
| `ssh_tier_a/gt_server.py` | guest | item 8b: paramiko server peer that logs K, H, session_id, keys A–F and the negotiated algorithms |
| `export_containers.sh` | guest (root), **after** the dump | packs the encrypted images/dirs + `samples.sha256` into a sparse `containers.tar` for a later mount proof |
| `paging_probe.py` | guest | page-table depth (4 vs 5 levels) for `kernel.paging` |
| `mount_proof.sh` | host (Docker) | mount proof: plugin-recovered keys open the exported containers (see "Mount proof") |
| `mount_proof/Dockerfile`, `mount_proof/kernel_proof.sh` | Docker (privileged) | runner image; kernel dm-crypt/fscrypt/FUSE half of the proof |
| `mount_proof_userspace.py` | host + Docker | hash checks, claim table, userspace dm-crypt/eCryptfs/fscrypt-v2 decryption |

Guest requirements: bash, python3 (stdlib only), and — unless `--no-install` —
`apt-get` plus network access. Tested on Ubuntu 24.04 arm64 (kernel
6.8.0-136-generic). Other distros: install the packages listed in
`install_packages()` yourself and pass `--no-install`.

## Options

```
secrets_stage.sh [--out DIR] [--state DIR] [--wg-rekey-wait SECS] [--no-install] [--skip LIST]
  --out DIR           sidecar dir (default /var/tmp/memdiver-secrets): secrets.json,
                      secrets.tar.gz, stage.log, artefacts/
  --state DIR         disk-backed dir for loop images + key files (default /var/lib/memdiver-gt)
  --wg-rekey-wait N   wait up to N s for one WireGuard rekey (default 135; 0 = no wait)
  --skip LIST         comma list of luks2,luks1,veracrypt,wireguard,fscrypt,ecryptfs,gocryptfs,ssh,ssh_tier_a,btf
```

The script is idempotent: key material and images persist in `--state`; an
existing mapping, mount, netns or session is reused and only re-recorded. Each
item runs isolated — a failure becomes a `gaps[]` entry instead of aborting.
It never drops caches.

## What gets planted

| # | item | setup | key ground truth |
| --- | --- | --- | --- |
| 1 | LUKS2 | 64 MiB loop file, `aes-xts-plain64`, 512-bit key from `--volume-key-file`, argon2id, ext4, mounted at `/mnt/gt_luks2`, files written. Opened with `--link-vk-to-keyring @u::%user:cryptsetup:<uuid>-d0` (cryptsetup ≥ 2.7; otherwise the same key is added with `keyctl padd user`) | volume key (both AES-256 halves); `dmsetup table --showkeys`; `luksDump`. cryptsetup loads LUKS2 keys via the kernel keyring, so the table shows `:64:logon:cryptsetup:<uuid>-d0` instead of hex (`key_in_kernel_keyring: true`), and unlinks that logon key afterwards. The linked **user** key in root's user keyring stays: `keyring_vk {description, type, key_id, keyring, method, describe, payload_matches_volume_key}` |
| 2 | LUKS1 | 320 MiB loop (`--direct-io=off`), `aes-cbc-essiv:sha256`, 256-bit key, XFS at `/mnt/gt_luks1` | volume key; hex key in the dm table |
| 3 | VeraCrypt | 64 MiB container (AES, SHA-512, FAT) created with the official `veracrypt` console .deb from launchpad (URL + sha256 recorded in `artefacts/veracrypt_source.txt`), opened with `cryptsetup open --type tcrypt --veracrypt`, mounted at `/mnt/gt_veracrypt` | volume key from the dm table. If no VeraCrypt build exists for the distro/arch, the item is recorded in `gaps[]` and **not** faked |
| 4 | WireGuard | netns `gtwgA` ↔ `gtwgB` over veth, PSK on that pair, persistent ping traffic; `gtwgA` has a third peer C whose endpoint (192.0.2.1, TEST-NET-1) never answers → a handshake permanently in flight; waits for one rekey (REKEY_AFTER_TIME 120 s) | static private keys A/B (C's private key is generated but never configured), PSK, `wg show all dump` of both namespaces, `rekey_observed` |
| 5 | fscrypt | 128 MiB ext4 `-O encrypt` loop at `/mnt/gt_fscrypt`, `v1/` (descriptor) and `v2/` (identifier) directories, AES-256-XTS / AES-256-CTS, both keys in the **filesystem** keyring (survives the SSH session). The v1 descriptor is **derived**: SHA-512(SHA-512(master key))[:8], as e4crypt/fscryptctl/fscrypt do. The v1 key is also added the legacy way, as `logon fscrypt:<descriptor>` (payload `struct fscrypt_key {u32 mode=1; u8 raw[64]; u32 size=64}`) in root's user keyring | 64-byte master keys, v1 descriptor (`descriptor_derived`, `descriptor_derivation`), `legacy_logon_key {description, type, key_id, keyring, payload}`, kernel-computed v2 identifier |
| 6 | eCryptfs | `mount -t ecryptfs` with explicit options, passphrase key, AES-256 | passphrase, FEKEK (salt `0011223344556677`, 65536×SHA-512) and its signature, cross-checked against the live `ecryptfs_sig` mount option |
| 7 | gocryptfs | `-init` + mount at `/mnt/gt_gocryptfs` with a known password | 32-byte master key (via `gocryptfs-xray -dumpmasterkey`; `-init` hides it off a tty), cipher dir, daemon PIDs |
| 8 | SSH | user `gtuser`; OpenSSH client → OpenSSH server on 127.0.0.1:22 and → dropbear on 127.0.0.1:2022, both `-N`, detached | client/server PIDs, kex / host-key / cipher names from the client's `-v` log. Session keys are **not** available without instrumentation (recorded as such). No traffic is captured |
| 8b | SSH Tier A | `ssh_tier_a/libssh_client.c` built in the guest (`gcc … -lssh`, Ubuntu `libssh-dev`), connected to `ssh_tier_a/gt_server.py` (Ubuntu `python3-paramiko`) on 127.0.0.1:2200; curve25519-sha256, aes256-ctr, hmac-sha2-256, password auth, one exec, then idle (7 days) | `ssh_tier_a[]`: client pid, server pid, versions, negotiated algorithms, `K_hex` (mpint), `K_int_hex`, `H_hex`, `session_id_hex`, keys A–F; also `keys[]` entries `ssh_tier_a.{K,session_id,A..F}`. The values come from the paramiko peer's own `_compute_key`, not from the client |
| 9 | layouts | `pahole -C` over `/sys/kernel/btf/*`. WireGuard: `wg_device`, `wg_peer`, `noise_handshake`, `noise_keypair`, `noise_static_identity`, `noise_keypairs`, `noise_symmetric_key`, `cookie_checker`, `cookie`, `index_hashtable_entry`, `allowedips_node`. dm: `crypt_config` plus dm core `mapped_device`, `dm_table`, `dm_target`, `dm_dev`, `hash_cell` (from `dm_mod` when it is a module, else `vmlinux`). Also `fscrypt_master_key`, `ecryptfs_crypt_stat`, `ecryptfs_auth_tok`. Raw `/sys/kernel/btf/{dm_crypt,dm_mod,wireguard}` copies. `paging_probe.py` records page-table depth | `btf_offsets{}` (`{size, members: {name: {offset, size, decl}}}`; a struct pahole cannot find becomes a `btf:<struct>` gap); `uname -a`, `/proc/cmdline`, `lsmod`, `kernel.paging` |
| 10 | global | — | `dmsetup table --showkeys`, `keyctl show @u/@s`, `/proc/keys`, `losetup -a`, mounts, `ps -efww` |

Long-lived processes (pings, dropbear, SSH clients, gocryptfs) are started with
`setsid` and redirected stdio so that they outlive the SSH session that ran the
script and do not hold it open.

## Sidecar schema `memdiver-secrets-gt/1`

`secrets.json` (one object):

```jsonc
{
  "schema": "memdiver-secrets-gt/1",
  "created_utc": "2026-11-06T17:18:51Z",
  "kernel": {"release", "version", "uname_a", "cmdline"},
  "arch": "aarch64",
  "dmcrypt": [{                     // items 1-3
    "name", "type",                 // luks2 | luks1 | tcrypt-veracrypt
    "cipher", "key_bytes", "volume_key_hex",
    "key_halves_hex": [],           // XTS only: [data_key, tweak_key]
    "key_in_kernel_keyring", "keyring_ref", "passphrase",
    "backing_file", "loop_device", "dm_device", "mountpoint", "fs",
    "dm_table_showkeys"}],
  "wireguard": [{                   // one per interface, from `wg show all dump`
    "netns", "interface", "private_key_b64", "private_key_hex", "public_key_b64",
    "listen_port", "fwmark", "role", "rekey_observed", "first_handshake_unix",
    "peers": [{"public_key_b64", "preshared_key_b64", "preshared_key_hex", "endpoint",
               "allowed_ips", "latest_handshake_unix", "rx_bytes", "tx_bytes",
               "persistent_keepalive"}]}],
  "keys": [{                        // flat list of every raw secret, for residency scans
    "id", "kind", "hex", "length", "source", "note"}],
  "fscrypt": [{"policy_version", "mountpoint", "directory", "backing_file", "loop_device",
               "key_ref_kind", "key_ref_hex", "master_key_hex", "contents_mode",
               "filenames_mode", "flags", "keyring"}],
  "ecryptfs": [{"lower_dir", "mountpoint", "passphrase", "cipher", "key_bytes", "salt_hex",
                "fekek_hex", "fekek_signature", "mounted_sig", "signature_matches"}],
  "gocryptfs": [{"cipher_dir", "mountpoint", "password", "master_key_hex",
                 "daemon_pids", "info"}],
  "ssh": [{"server", "port", "user", "client_pid", "server_pids", "authenticated",
           "kex_algorithm", "host_key_algorithm", "cipher_s2c", "cipher_c2s",
           "server_version", "session_keys"}],
  "ssh_tier_a": [{"implementation", "version", "role", "pid", "pid_from_client_log",
                  "server_implementation", "server_pid", "server_version", "kex", "hash",
                  "cipher_c2s", "cipher_s2c", "mac_c2s", "mac_s2c", "K_hex", "K_int_hex",
                  "H_hex", "session_id_hex", "rekeyed", "keys": {"A".."F"},
                  "K_encoding", "keys_note", "gt_source"}],   // capture v2+
  "btf_offsets": {"<struct>": {"size", "source",          // e.g. "btf:dm_crypt"
                   "members": {"<name>": {"offset", "size", "decl"}}}},
  "gaps": [{"item", "reason"}]      // anything that could not be planted, and why
}
```

Capture v2 adds (all additive; older sidecars simply lack them):
`dmcrypt[luks2].keyring_vk`, `fscrypt[v1].{descriptor_derived, descriptor_derivation,
legacy_logon_key}` and the `ssh_tier_a[]` section.

`secrets.tar.gz` holds `artefacts/` (pahole text, BTF blobs, `luksDump`,
`tcryptDump`, dm tables, `wg` dumps, keyctl/proc-keys, SSH client logs,
`gocryptfs.conf`, raw key files under `keys/`) and `stage.log`.

All keys are generated per capture and are test material only. Treat the
sidecar as sensitive anyway: it is a complete key ledger for its dump.

## Container export for a mount proof (capture v2)

`secrets_stage.sh` also writes `OUT/samples.sha256`: `sha256sum` lines for every
plaintext sample file it planted (LUKS2, LUKS1, VeraCrypt, fscrypt v1/v2,
eCryptfs, gocryptfs), with their guest paths. **After** the dump,
`export_containers.sh` syncs, briefly `fsfreeze`s the planted block-backed
mounts, and writes `OUT/containers.tar` (GNU tar `--sparse`):

| member | what |
| --- | --- |
| `luks2.img`, `luks1.img`, `veracrypt.hc`, `fscrypt.img` | the encrypted backing images (headers included) |
| `ecryptfs_lower/`, `gocryptfs_cipher/` | eCryptfs lower directory, gocryptfs cipher directory (with `gocryptfs.conf`) |
| `samples.sha256` | expected plaintext digests |
| `containers_manifest.json` | `memdiver-containers/1`: per member kind, size, allocated bytes, sha256 (per file for dirs) |

The capture rig fetches it as `<stem>.containers.tar` (opt-in flag
`--secrets-export-containers`) and records `secrets_containers_path` /
`secrets_containers_sha256` in `.meta.json`. The secrets tarball is unchanged.

## Mount proof prerequisites (Docker probe, 2026-11-12)

Checked on the Apple Silicon host with Docker Desktop 29.7.2 (LinuxKit kernel
6.12.76), `docker run --rm --privileged -v /dev:/dev ubuntu:24.04`:

| check | linux/arm64 (native) | linux/amd64 (emulated userspace, same kernel) |
| --- | --- | --- |
| `dmsetup version` | library 1.02.185, driver 4.48.0 | same |
| `/proc/crypto` | `xts(aes)` (`xts-aes-ce`, `xts-aes-neonbs`), `cbc(aes)`, `essiv(cbc(aes),sha256)` | same (kernel is shared) |
| `losetup -f` | `/dev/loop0` | same |
| 16 MiB `cryptsetup luksFormat --type luks2` + `open` + `mkfs.ext4` + `mount` + write/read | works (needs `--luks2-metadata-size 16k --luks2-keyslots-size 1m`; the default 16 MiB LUKS2 header leaves no data area) | not run (cryptsetup path proven on arm64; raw path below run on both) |
| raw `dmsetup create` with an explicit hex key, `aes-xts-plain64` (64 B) and `aes-cbc-essiv:sha256` (32 B), `mkfs.ext4` + `mount` | works | works |

Gotchas: (1) there is no udev in the container, so after `dmsetup create` the
`/dev/mapper/<name>` node is missing — use `dmsetup create --noudevsync` and then
`dmsetup mknodes <name>` (cryptsetup creates its node itself). (2) Container
network goes through Docker Desktop's proxy: `apt` needs
`Acquire::http::Proxy "http://http.docker.internal:3128";`. (3) Loop devices and
dm targets are the Docker VM's, shared by all containers — always `cryptsetup
close` / `dmsetup remove` / `losetup -d` afterwards. (4) Keyrings are not
namespaced: keys added in a container land in the Docker VM's root user keyring.

## Mount proof

`mount_proof.sh` proves end to end that keys recovered from the memory image open the
capture's real encrypted containers. Every key comes from a plugin export; the
`secrets.json` sidecar is never read (it is only the answer key).

```sh
tools/vol3_capture/mount_proof.sh \
  --stem "$MEMDIVER_SECRETS_CORPUS/ubuntu-24.04-secrets-x86-4level-v2_6.8.0-136-generic" \
  --work /path/to/scratch/mount_proof        # needs ~200 MB; MEMDIVER_VOL3_VOL=<vol> optional
```

1. Extracts `<stem>.containers.tar` (sparse) and runs, in parallel, on `<stem>.lime`:
   `linux.dmcrypt --export dmsetup|cryptsetup|masterkey`, `linux.fscrypt --export json`,
   `linux.ecryptfs --export fek`, and the committed synthesized plugin
   `samples/plugins/memdiver_gocryptfs.py --pid <gocryptfs daemon from ps_at_dump>
   --oracle-sample <containers>/gocryptfs_cipher --export` (`--plugins DIR` reuses outputs).
2. Builds `mount_proof/Dockerfile` (ubuntu:24.04 + cryptsetup, dmsetup, e2fsprogs, xfsprogs,
   mtools, gocryptfs, keyutils, python3-cryptography; `fscryptctl` is not packaged for noble,
   so fscrypt keys go through the raw ioctl).
3. Privileged container (`mount_proof/kernel_proof.sh`), every image attached read-only:
   - dm-crypt, path A: `dmsetup create --noudevsync --readonly` with the exact
     `--export dmsetup` table, only the backing `major:minor` replaced. LUKS2's live table
     names its key by keyring reference (`:64:logon:cryptsetup:<uuid>-d0`), so the
     `--export masterkey` bytes are loaded under that description (`keyctl padd logon … @s`)
     and unlinked right after the table load.
   - dm-crypt, path B: the generated `--export cryptsetup` script with only `DEVICE=` (or the
     VeraCrypt table's `major:minor`) changed, run with `DM_DISABLE_UDEV=1`.
   - mount `-o ro` (XFS: `ro,norecovery`) and hash every planted file.
   - fscrypt v1: mount `fscrypt.img`, `FS_IOC_ADD_ENCRYPTION_KEY` with the recovered master
     key (filesystem keyring, removed afterwards), read `v1/`.
   - gocryptfs: `gocryptfs -ro -masterkey <proven key>` (FUSE).
4. Unprivileged container (`mount_proof_userspace.py`, AES from `cryptography`, own SHA-512):
   LUKS2 (ext4, `debugfs rdump`) and VeraCrypt (vfat, `mcopy`) decrypted from the dmsetup
   line alone; eCryptfs lower files decrypted with the per-file FEKs (the LinuxKit kernel
   has no eCryptfs); fscrypt v2 files decrypted with per-file keys HKDF-expanded from the
   recovered HMAC-SHA512 midstates (the kernel wipes the v2 master key, so no kernel path
   exists; names stay encrypted, so files match by content).
5. Prints the claim table and exits 0 only if every row matched. The EXIT traps release
   every mount, map, key and loop device (the Docker VM's, shared).

Result on capture v2 (stock vol 2.27.0, 2026-11-12; ~160 s, plugins included):

| target | method | files |
| --- | --- | --- |
| luks1 (XFS) | dmsetup / cryptsetup-script | 4/4 / 4/4 |
| luks2 (ext4) | dmsetup (+ keyring key) / cryptsetup-script / userspace-dm | 4/4 each |
| veracrypt (vfat) | dmsetup / cryptsetup-script (dmsetup replay) / userspace-dm | 4/4 each |
| fscrypt v1 | kernel ioctl | 4/4 |
| fscrypt v2 | userspace HKDF midstates | 4/4 |
| eCryptfs | userspace FEK | 4/4 |
| gocryptfs | `-masterkey` FUSE | 4/4 |

Claim C-MOUNT1 in `tests/test_vol3plugins_corpus_gate.py` runs it (skips without the v2
stem or `docker info`); `tests/test_vol3_capture_mount_proof.py` unit-tests the logic.

## Sibling groups (capture v2b, `--siblings`)

Opt-in item 11 (`secrets_stage.sh --siblings`; through the capture rig:
`--secrets-stage-args "--siblings"`). It plants several live instances of one
binary in the same image, so that one image can stand in for N captures of a
process. Every v2 item is still planted; without the flag the sidecar is
unchanged.

| group | shape (`expected_shape`) | setup | members (`role`) |
| --- | --- | --- | --- |
| `dropbear` | `forked` | a dedicated `dropbear -F` listener on 127.0.0.1:2023, 4 connections | `listener` + 4 forked `session` children |
| `openssh` | `reexec` | a dedicated `/usr/sbin/sshd -D` on 127.0.0.1:2201 (not the system sshd), 4 connections | `listener` + per connection a `monitor` (`sshd: gtuser [priv]`) and its post-auth `session` child, linked by `conn_id` |
| `gocryptfs` | `independent` | 3 separate vaults `${STATE}/sib_gocryptfs_cipher_N` mounted at `/mnt/gt_sib_gocryptfs_N` | one `daemon` per mount |

Each SSH connection is made by `siblings/gt_ssh_client.py`, a paramiko client
(user `gtuser`, ed25519 key; curve25519-sha256, aes256-ctr, hmac-sha2-256). It
opens no channel and stays idle, and it logs K, H, session_id and keys A–F
through the same `Transport._compute_key` hook as `ssh_tier_a/gt_server.py`.
Both ends of a session derive the same keys, so these are the server
session's keys. The server processes of a connection are found from its
socket: `sibling_frames.py discover` matches the client's local port in
`/proc/net/tcp*`, finds the socket's holders, and walks up to the listener.

Right before the sidecar is written (the last stage step, seconds before the
dump), `sibling_frames.py collect` records each member. It reads only pages
that are already present, so it faults nothing in. Each `siblings[]` entry has:

- `group`, `role`, `conn_id`, `expected_shape`, `pid`, `ppid`, `comm`, `exe`, `cmdline`
- `build_id` + `build_id_kind` (`gnu`, else `go`): from the PT_NOTE segments of `/proc/<pid>/exe`
- `start_time` (unix; from `btime` + stat field 22) and `start_time_ticks`
- `alive`, `snapshot_time`
- `ssh` (SSH members): `client_pid`, `client_port`, `server_port`, `kex`, `hash`, `cipher_*`, `mac_*`, `K_hex` (mpint), `K_int_hex`, `H_hex`, `session_id_hex`, `keys {A..F}`, `session_keys {c2s, s2c: {cipher, mac, iv_hex, enc_key_hex, mac_key_hex}}`
- `gocryptfs` (gocryptfs members): `mountpoint`, `cipher_dir`, `password`, `master_key_hex`, `cipher`, `feature_flags`, `daemon_pid`, `own_process`
- `frames[]`: one entry per (secret occurrence, page) of that member's own secrets (SSH: bare K and keys A–F; gocryptfs: the master key), found in the member's present rw mappings via `/proc/<pid>/mem`. Each entry is `{secret, va, occurrence_va, page_va, pfn, pagemap_flags {raw, present, swapped, file_or_shared_anon, exclusive, soft_dirty, pfn}, kpagecount, kpageflags, kpageflags_names}`. An occurrence that crosses a page boundary gives one entry per page.
- `frames_summary` (`frames`, `distinct_pfns`, `present`, `exclusive`, `shared_kpagecount_gt1`, `secrets_found`) and `frames_scan` (mappings and bytes scanned, seconds, errors)
- `smaps_rollup` (parsed, kB) + `smaps_rollup_text`

Each connection's secrets are also in `keys[]` as `siblings.<conn_id>.<name>`.
The plan and the raw collector output are in `artefacts/siblings_{plan,collected}.json`.
Listeners hold no session secret, so their `frames[]` is empty. An empty
`frames[]` on an OpenSSH monitor is a finding, not a bug: the post-auth keys
live in the session child.

## Building the ISF (symbol table) for the dump

`dwarf2json linux --elf <debug vmlinux>` needs about 5 GB RSS for an Ubuntu
6.8 kernel, so running it inside a 4 GiB guest gets it OOM-killed. Build it on
the host instead, from the same kernel's debug-symbol package. On Ubuntu that
is `linux-image-unsigned-$(uname -r)-dbgsym` from `ddebs.ubuntu.com`; extract
`./usr/lib/debug/boot/vmlinux-$(uname -r)` from its `data.tar.xz`, then run:

```sh
dwarf2json linux --elf vmlinux-6.8.0-136-generic > dump.isf.json
```

For a recapture of the **same** kernel build, skip the build entirely: the
capture rig's `--isf-from <existing .isf.json>` copies an existing ISF to the new
stem when that ISF's `linux_banner` occurs verbatim in the new dump (otherwise it
warns and builds as usual). In-guest dwarf2json under x86_64 TCG ran > 1 h for
capture v2 before it was stopped.

The debug vmlinux already carries `linux_banner` as `constant_data`, so no
System.map is needed. The banner in the ISF matched the dump byte-for-byte
(3 hits). On aarch64, use a Volatility 3 build with working arm64 support. With this
capture and a correct ISF, stock vol3 2.27.0 printed the pslist header but no
rows, and another stock install reported `Unsatisfied requirement
plugins.PsList.kernel.symbol_table_name`. Both are layer/translation problems
on aarch64, not ISF mismatches. With an arm64-capable tree (2.10.0-based), `linux.pslist` matched 140/143 PIDs from the
`ps -efww` snapshot (the 3 misses are the snapshot's own short-lived SSH
session), and `linux.lsmod` lists `dm_crypt`, `wireguard` and `xfs`.

## Reference captures (2026-11-06)

All three were taken with LEMON on Ubuntu 24.04 cloud images (noble
`release-20260801`, kernel `6.8.0-136-generic`) with 4096 MiB of guest RAM.
Every secrets stage finished with `gaps: []`. Each capture produced `<stem>.lime`,
`.isf.json`, `.meta.json`, `.ps_at_dump.txt`, `.secrets.json` and
`.secrets.tar.gz` in a single directory. The ISFs were built on the host from
the dbgsym vmlinux, because in-guest dwarf2json runs out of memory at 4 GiB.

| stem | arch / accel | paging (`kernel.paging`) | `.lime` | `.isf.json` | wall time |
| --- | --- | --- | --- | --- | --- |
| `ubuntu-24.04-secrets_6.8.0-136-generic` | aarch64, HVF, `-cpu host` | n/a (arm64) | 4,289,069,248 B | 56.7 MB | ~15 min |
| `ubuntu-24.04-secrets-x86-4level_6.8.0-136-generic` | x86_64, TCG, `-cpu max,la57=off` | 4 levels (`cpuinfo_la57` false, no VA above 2^47) | 4,294,409,312 B | 64.5 MB | 53 min |
| `ubuntu-24.04-secrets-x86-4level-v2_6.8.0-136-generic` (2026-11-12, capture v2) | x86_64, TCG, `-cpu max,la57=off` | 4 levels | 4,294,409,312 B | 64.5 MB (v1 ISF reused: identical banner, 6 verbatim hits) | 30 min to dump + export |
| `ubuntu-24.04-secrets-x86-la57_6.8.0-136-generic` | x86_64, TCG, `-cpu max` | 5 levels (`cpuinfo_la57` true, mmap above 2^47 honoured) | 4,294,409,312 B | 64.5 MB | 3 h 23 min |

What each capture showed under Volatility 3:

- **x86_64 4-level.** Stock vol3 `linux.pslist` returns rows: 150/150
  snapshot PIDs once the snapshot's own SSH session is excluded. `linux.lsmod`
  lists `dm_crypt` and `wireguard`.
- **x86_64 4-level v2.** Adds the derived fscrypt v1 descriptor + legacy
  logon key, the LUKS2 volume key as a `user` key in root's keyring, SSH Tier A
  (libssh client pid 11559, paramiko peer 11544) and `<stem>.containers.tar`.
  Stock vol3 2.27 `linux.pslist`: 151/155 snapshot PIDs (misses: the snapshot's
  own SSH session ×3 and one kworker).
- **x86_64 LA57.** Stock vol3 returns 0 rows. A vol3 build with LA57 support
  (5-level page-table detection) returns rows.
- **aarch64.** Stock vol3 (2.27.0, 2.28.x) has **no AArch64 translation
  layer**, so it cannot analyse the arm64 capture at all. Only an
  arm64-capable fork can (144 rows, `dm_crypt`/`wireguard` in lsmod). Stock
  vol3 2.28.2 is the judged environment, so the x86_64 4-level capture is the
  primary evaluation image.

## Known gaps

- OpenSSH/dropbear session keys, WireGuard ephemeral/session keys and
  per-file fscrypt / eCryptfs FEKs are derived inside the kernel or the process
  and are not exported; only their inputs (static keys, PSK, master keys,
  FEKEK) are. The SSH Tier A pair (item 8b, capture v2+) is the exception: its
  peer logs K, H and the derived keys.
- No WireGuard handshake keylog: the in-kernel WireGuard has no keylog hook, so
  it would need kprobe/eBPF instrumentation of the Noise handshake. Not done.
- VeraCrypt depends on an official console build for the guest's
  distro/version/arch; without one the item is a recorded gap.
- `fscryptctl` is not packaged on Ubuntu 24.04, hence `fscrypt_helper.py`.
