# Compatibility

What the suite was run on, and what is only expected to work. "Tested" below means a run is recorded in the execution log; everything else is stated as untested.

## Volatility 3

| Version | Status |
|---|---|
| 2.27.0 (stock release) | tested; the version of the main development environment |
| 2.28.2 (contest target; upstream develop at commit fffd844b) | tested; every claim runs on both versions when `MEMDIVER_VOL3_ALT_VOL_PY` is set, and the plugin outputs on 2.27.0 equal those on 2.28.2 for all 77 `msl.*` outputs and for the kernel plugins |
| other 2.x | not tested; `memdiver` requires `volatility3>=2.27,<3` |

All plugins declare `_required_framework_version = (2, 0, 0)`. The plugin directory imports only the standard library and `volatility3` at module level; a test enforces this by AST and by checking that importing every plugin the Volatility way leaves no `memdiver` module loaded.

A cold 2.28.2 run on a kernel image takes about 74 s because of ISF schema validation; warm runs of the same plugins take 7 to 25 s.

## Guest operating systems and kernels

| Target | Status |
|---|---|
| Ubuntu 24.04, kernel 6.8.0-136-generic, x86_64, 4-level paging | tested on a real capture; all kernel plugins and the mount proof |
| Ubuntu 24.04, kernel 6.8.0-136-generic, x86_64, 5-level paging (LA57) | tested on a real capture (`C-LA57`); all kernel plugins give the verdicts of the 4-level twin |
| Ubuntu 24.04, kernel 6.8.0-136-generic, AArch64 | development corpus only, through a third-party Volatility fork (see below) |
| Other kernels | WireGuard: exact built-in layouts for 60 x86_64 kernels (below); dm-crypt: exact entry for 6.8.0-136 only; every other kernel needs trusted in-memory BTF or `--offsets` |

### Layout sources by plugin

| Plugin | Source of module struct offsets |
|---|---|
| `linux.wireguard` | trusted in-memory BTF, then exact table (60 x86_64 entries: Ubuntu 5.15 GA, Ubuntu 6.8 and HWE up to 7.0, Debian 12 6.1 amd64 and cloud, RHEL 9.1 to 9.8 family, Fedora 41 to 45; RHEL 9.0 has no module BTF and no entry), then `--offsets`. In-memory BTF parsing equalled the table on 63 of 63 distribution kernels |
| `linux.dmcrypt` | trusted in-memory BTF, then the exact `("x86_64", "6.8.0-136-generic")` entry (and its AArch64 twin), then `--offsets`. Kernel layouts reviewed against v6.6, v6.7, v6.16 and v6.17; the `used_tag_size` rename (6.11) and `DM_CRYPT_HIGH_PRIORITY` (6.10) are handled |
| `linux.fscrypt` | ISF only (kernel 6.1 or later; older kernels get an explicit error). The 6.16, 6.17 and 6.18 layouts and hardware-wrapped keys are tested with faked structures only |
| `linux.ecryptfs` | in-memory BTF or ISF; guessed offsets demote to `unverified` |
| `linux.keyring` | ISF |

Distribution notes: on an Alma 8 image with stock 2.27 `linux.dmcrypt` exits 0 with clear warnings (no 4.18 offsets exist; 4.18 uses `_name_buckets`). When `dm_mod` is a module (RHEL and Alma ISFs carry no device-mapper types), the core layout comes from the module's symbols and BTF, and a silent miss was turned into a warning. The wireguard `sizeof(net_device)` fallback depends on the kernel (2512 for Ubuntu 6.8.0-31 to -117, 2544 for -136 and -149); the ISF always wins.

## Architectures and paging

| Mode | Status |
|---|---|
| x86_64, 4-level paging | tested, stock Volatility |
| x86_64, 5-level paging (LA57) | tested with this suite's stacker; stock 2.27 shows 0 processes. See [Upstream](UPSTREAM.md) |
| AArch64 | **stock Volatility 3 has no AArch64 Linux layer** (checked on 2.27.0, the development branch and PR #1991). The only one we know is the third-party `volatility3-arm64` fork of eurecom-s3. The AArch64 capture was used for development with that fork and is not part of the judged claims. The page-cache proof `O3` does not apply on AArch64 |
| Windows and macOS guests | not supported; no Windows plugin exists in this suite |

For the process plugins and `msl.*`, the architecture of the captured process is irrelevant to Volatility: they read a `.msl` layer. The samples include arm64 process captures (Docker) of libssh, wolfSSH and wireguard-go.

## Python

| Component | Python |
|---|---|
| `vol3plugins/` and `oracles/` (what a judge runs under bare Volatility) | written for Python 3.8 and later: the import rules (stdlib allow-list that is valid on 3.8) are enforced by test. Actual runs recorded: CPython 3.11.9 |
| `memdiver` (only needed for encrypted or compressed `.msl`, synthesis, the CLI) | 3.11 or later (`requires-python = ">=3.11"`) |
| Documentation build | 3.12 |

## Operating systems of the host

| Host | Status |
|---|---|
| macOS (Apple silicon) | development host; all unit tests, all gate claims, captures (QEMU TCG for x86_64 guests, HVF for AArch64) |
| Ubuntu (x86_64) | see "Fresh-machine runs" below |

## Dependencies

- Required for the kernel and process plugins: Volatility 3 only.
- Optional speed-ups: `cryptography` (AES, X25519), `pycryptodome` (shipped with `volatility3[full]`). A bare Volatility works through pure-Python primitives. Plain `pip install volatility3` brings no `cryptography`.
- `blake3`: needed only to verify BLAKE3 hash chains of `.msl` files (the default chain); installed with MemDiver.
- `pip install memdiver` into a fresh virtual environment takes about 93 s using wheels only (no compiler), and `vol -h` takes 0.35 s with MemDiver and Volatility 2.28.2 side by side (measured on 2026-11-06 with PyPI 1.0.6; the current version was not re-measured). The suite never imports the `oqs` package on its default path, because importing it triggers a git clone and a cmake build of liboqs.

## Fresh-machine runs

TODO (wave D): record here the results of installing from scratch on a clean macOS and a clean Ubuntu machine (Python version, `pip install memdiver` wall time, `vol -p "$(memdiver vol3 plugin-dir)" -h`, the quick start commands, `make validate` without corpus). Nothing in this section is measured yet.
