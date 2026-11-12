# Plugin Synthesis

Synthesis turns a key that is already known in one or more captures into a standalone Volatility 3 plugin that finds and proves the same kind of key in other memory: another capture, another session, a full kernel image. The plugin is one `.py` file. It imports only the standard library and `volatility3`, carries its oracle inside, and needs neither MemDiver nor a crypto library.

## Pipeline

```text
  key known in N captures            (.msl or raw; one key per dump)
        │  locate every occurrence                   engine.key_location
        ▼
  static-mask measurement            which neighbour bytes stay identical across occurrences
        │  wildcard the key bytes, keep the static run     → anchor pattern
        ▼
  recipe v2                          locators + decoder + oracle spec + exporter
        │  render (template v2) + inline the oracle source
        ▼
  <name>.py  +  <name>.recipe.json  (+ <name>.yar when there is an anchor)
        │  self-test, in process, on the reference data
        ▼
  verify on each target              .msl captures (in process) and/or a full image under stock vol
        ▼
  verdict: proven | not proven       from the plugin's own Proven column, never from the recipe
```

The command is `memdiver vol3 synthesize` ([options](USAGE.md#command-memdiver-vol3-synthesize)). The same operation exists as a library call, `synthesize_vol3_plugin`, in `memdiver.app.vol3_synth`.

## The design rule

> The anchor only proposes candidates. The oracle alone decides `Proven`.

A weak anchor therefore costs time (more candidates, capped), never a false proof. This is why the synthesis path can use an entropy fallback that proposes hundreds of thousands of candidates: on the reference run about 200,000 candidates per image were filtered with 0 false proofs.

## Recipe v2

A recipe (`memdiver-vol3-recipe/2`) is a frozen description with five parts.

| Part | Content |
|---|---|
| `locators` | an ordered list. Implemented kinds: `anchor_regex` (a byte pattern with wildcards, alignment, `static_ratio`, hit cap 4,096) and `entropy` (a fallback scan: window threshold 4.5 bits/byte, step 8 or inferred from the observed key alignment up to 8, cap 500,000 candidates) |
| `decoder` | `key_offset`, `key_length`, `candidate_layout` (`single`), optional cipher and fields |
| `oracle` | the format-oracle kind, its parameters, and the evidence sample (inline up to 8 KiB, or a path, with its SHA-256) plus an optional static context |
| `exporter` | `json` |
| `provenance` | generator, per-dump basename and SHA-256, key offsets, key SHA-256, context size, mask windows |

Reserved locator kinds (`yara`, `artifact_window`, `aes_schedule`, `pubkey_adjacency`, `kernel_struct`) are rejected as not implemented rather than silently ignored.

**What the recipe never holds:** the key. Only its SHA-256 is recorded. The CLI reads keys from a file or standard input and echoes none; error messages redact an invalid key.

### Anchor quality guards

- **Degenerate anchors** (fewer than three distinct byte values, or zero bits per byte: filler such as zero padding) are refused.
- **Adjacent-secret rule.** A static anchor byte is copied verbatim into the plugin. A high-entropy static run (at least 16 bytes at 3.5 bits per byte or more) next to the key may be another secret of the same session (an IV, a second key), so the builder refuses it unless `--allow-high-entropy-context` is given. The exception: when the mask was measured across captures that hold at least two *different* keys, a run that stays identical is a program constant (for example the constant gocryptfs keeps in front of its master key), not a secret.
- **Real example.** The gocryptfs recipe from two sessions has a 160-byte anchor, 80 % static, giving 1 to 2 candidates per run.

## The generated plugin

Class `MemDiverSynth<Name>`. Requirements: the layer (`primary`, or the kernel when `--pid` is used), optional `--pid`, `--oracle-sample`, `--oracle-param`, `--exhaustive`, `--show-unverified`, `--oracle-budget`, `--export`. See [Usage](USAGE.md#synthesized-plugins).

- **Where it scans.** On a `.msl` capture, the capture layer. With `--pid` on a kernel image, the process's virtual-address layer (so `--pid` is honoured instead of silently scanning the raw file, a defect fixed during development). Without `--pid` on a LiME image, the physical layer. The `Scope` column states which one ran: `msl:<pid>`, `process:<pid>` or `physical`.
- **Locator order.** Anchor hits first. The entropy fallback runs only when the anchor finds nothing, unless `--exhaustive`. When a vault sample belongs to another vault than the image's own, the plugin warns and runs the anchor first without entropy fallback.
- **Rows.** `KeyOffset`, `KeyHex`, `KeyEntropy`, `KeyLength`, `PatternOffset`, `StaticRatio`, `Proven`, `Scope`, `Detail`.
- **Candidate ordering and budget.** Anchor, then locator order, then entropy; `--oracle-budget` bounds oracle time. See [Oracle cost budget](TECHNICAL_DETAILS.md#oracle-cost-budget).

## Inlined, hash-checked oracles

The oracle's own source (a module of `oracles/formats/`) is copied verbatim into the plugin between two marker lines:

```text
# --- memdiver oracle:<kind> sha256=<hex> begin ---
...
# --- memdiver oracle:<kind> sha256=<hex> end ---
```

At load time a small runtime re-hashes each block and executes it in its own module only if the hash matches. A judge can copy one `.py` file to a machine that has Volatility 3 and nothing else.

The oracle contract is strict: standard-library imports only at module level; no relative imports, no `__file__`; any third-party backend imported lazily with a fallback.

### Crypto backend chain

The generated plugin needs no crypto library. For AES-GCM (12- or 16-byte nonce), XChaCha20-Poly1305 and AES-SIV the chain is:

1. `cryptography`
2. `pycryptodome` (shipped with `volatility3[full]`)
3. pure Python (stdlib primitives `aes` and `chacha`, bound by the loader)

A tier is selected only after it passes a per-cipher, per-nonce-length known-answer self-test (open the correct sealed message, reject a tampered one). Merely importing the library is not enough: a FIPS or LibreSSL build can raise at construction, and the chain then falls through. The template logs the chosen backend once.

On the 95-run gocryptfs sweep (48 AES, 47 XChaCha) the result is 95 of 95 proven, 95 of 95 rejected after a bit flip, and 94 of 94 neighbour keys rejected, on every backend, at oracle level and at plugin level.

## Self-test, verify on `.msl`, verify on a full image

1. **Self-test at emit.** The emitted plugin source is run in process over the reference data (`engine.vol3_verify.run_over_buffer`). The result (`SelfTestHits`) is part of the output.
2. **Verify on `.msl`.** Each dump is scanned in process; the verdict reads the plugin's own `Proven` column. The synthesis verdict is `proven` only if every verify target proved the key.
3. **Verify on a full image.** With `--full-image IMAGE --pid PID` (plus `-s` for the ISF), the new plugin runs under stock `vol` as a subprocess. For an image from another session, give the image's own oracle evidence (`--full-image-sample`) and its expected key (`--full-image-key-hex-file`); the expected key filters every attempt, so a key proven against a different key is not reported as proof. The result states `pid_honoured` (derived from the `Scope` column: `process:<pid>`) and warns when `--pid` was not honoured.

Real result on the x86_64 reference images (4-level, pid 9878, and 5-level, pid 9884; Volatility 2.27.0 and 2.28.2): the plugin synthesized from the `.msl` slices proves the gocryptfs daemon's key in the full image, 2 rows `oracle:gocryptfs-gcm`, key equal to the ground truth, located via the anchor (the entropy fallback was not needed), about 74 s cold and 7 s warm. The vault the plugin needs for proof was recovered from the page cache of the same image with stock `linux.pagecache`. Cancel kills Volatility's process group within 0.05 s.

## The seven format kinds

`memdiver vol3 synthesize --oracle-kind <kind>`. Each kind is a module under `oracles/formats/`.

| Kind | Candidate | Evidence (sample) | Proven when | Cost per wrong candidate |
|---|---|---|---|---|
| `gocryptfs-gcm` | 32- or 64-byte master or content key | one encrypted content file plus `FeatureFlags` of `gocryptfs.conf` (344 to 361 bytes in the samples; no `EncryptedKey` or scrypt parameters, so nothing to crack) | AEAD-opening block 0 (AES-GCM, XChaCha20-Poly1305, AES-SIV; cipher read from the flags) | 16 µs budget value |
| `luks` | 16 to 64-byte volume key | the LUKS1 592-byte header, or a compact LUKS2 JSON of digests, segments, key sizes (never keyslot material) | PBKDF2 of the key equals the header digest | about 200 ms (one PBKDF2) |
| `xts-fsmagic` | 16 to 64-byte dm-crypt key (`key1 ‖ key2` for XTS) | first ciphertext bytes of the data area (default 4 KiB) plus geometry (spec, sector size, IV offset, large IV) and filesystem | decrypted head scores at least 64 bits as ext4, XFS, FAT, NTFS, LVM2, swap, GPT or btrfs | 20 µs |
| `aead-generic` | 16, 24 or 32-byte AEAD key (or HKDF input) | one sealed message: algorithm, nonce, associated data, ciphertext plus tag (at most 8 KiB) | the tag verifies (AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305) | 8 µs |
| `x25519-pubkey` | 32-byte X25519 private key | the public key (public material), or none when it sits next to the candidate | `X25519(candidate, 9)` equals the public key | 1.3 ms |
| `x25519-dh-consistency` | 32-byte X25519 private key | a peer public key plus the precomputed shared secret, or none when both are in memory | `X25519(candidate, remote)` equals the shared secret | 1.3 ms |
| `ssh-kdf-consistency` | an SSH shared secret `K` | none (H, session_id and the found keys come from the same memory) | at least two RFC 4253 keys derived from `(K, H, session_id)` are found in the same memory | 40 µs |

Notes:

- The costs are the `COST_US` budget values the plugin uses to estimate runtime, measured for wrong candidates on the pure-Python path where one exists.
- `xts-fsmagic` is the proof for VeraCrypt (data area, not header). It was validated by decrypting real backing-file pages with the ground-truth keys: LUKS2 reaches ext4 with 108 bits, LUKS1 XFS with 105, VeraCrypt FAT16 with 99.
- AES-192-XTS (48-byte keys) is accepted as a candidate length but cannot be decrypted by the stdlib `aes` primitive.
- Only `gocryptfs-gcm` has a corpus-gated full-image synthesis test. `luks` was run end to end on the 4 GB image (about 2 min 45 s, `oracle:luks` with key equal to the ground truth) but needed `--allow-high-entropy-context` for LUKS1 and a 1,024-byte context for LUKS2. Anchors built that way embed bytes next to the key that might be derived secrets; check them before publishing such a plugin.
- `xts-fsmagic` and `aead-generic` have unit tests and real-data checks by hand; there is no corpus-gated pytest claim for `xts-fsmagic` yet.

## Adding a format

A format module exposes `KIND`, `CANDIDATE_LENGTHS`, `COST_US`, `SAMPLE_KIND`, and `build_oracle(params, sample)` returning an object whose `verify(candidate, ctx)` gives a verdict `proven`, `rejected` or `error`, with the kind, a detail string and any derived data. The contract (imports, paste-safety, optional `cost_us`, `prefilter` and `unique`) is documented in [`oracles/formats/__init__.py`](https://github.com/MemorySlice/MemDiver/blob/main/oracles/formats/__init__.py). A registry-parity test keeps the module list and the known kinds in step.

## Where synthesized plugins are stored

With `--case`, plugins go to `<case>/vol3/plugins` as a `.py` plus `.recipe.json` pair, and older versions go to `<case>/vol3/history`. Only the first directory is handed to `vol -p`, so Volatility lists a plugin once. `memdiver vol3 exec` refuses any directory that holds `vol3/history`.
