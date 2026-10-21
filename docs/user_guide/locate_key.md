---
myst:
  html_meta:
    "description lang=en": "Locate a known secret across N memory dumps with memdiver locate-key."
---

# Locating a known key

`memdiver locate-key` answers one question: **you already hold a secret, so
which of these dumps still contain it, and where?** The secret might come from
an `SSLKEYLOGFILE`, a confirmed brute-force hit or a TLS handshake field. The
command searches every dump for the exact bytes. It reports a per-dump census
and one verdict for the whole set.

It does not discover unknown keys. For that, use `search-reduce` /
`analyze-candidates` (no oracle) or `brute-force` / `auto-floor` (with an
oracle). `locate-key` is what you run *after* one of those has found a key, or
whenever ground truth is already available.

```bash
memdiver locate-key run_dir/ --key-hex "$(cat master_secret.hex)" -o where.json
```

One dump is enough. Unlike the cross-dump comparison commands,
"is this secret in this dump, and where?" is a complete question about a single
dump.

## Supplying the secret

Pass the needle in exactly **one** of three forms. The parser makes them
mutually exclusive, so it refuses a mixture or a missing form before any dump
is opened.

| Flag | Input | Also reported |
|---|---|---|
| `--key-hex HEX` | Bare hex bytes. `'aa bb cc'` and `'0xaabbcc'` are both accepted. | — |
| `--keylog-line LINE` | One NSS key-log row: `'<LABEL> <client_random_hex> <secret_hex>'` | `secret_type` (the label), `client_random` |
| `--pcap-field FIELD_ID` with `--pcap PCAP` | A handshake field read from the capture, e.g. `client_random`, `server_random`, `sni` | `secret_type` (the field id), `client_random` (the session) |

The `--pcap-field` form reads the bytes from the wire instead of having you
paste them, so it cannot drop a nibble. List the field ids of a capture with:

```bash
memdiver inspect-pcap session.pcap --fields
```

Only fields marked `searchable` are accepted. A searchable field is a literal
run of at least 8 bytes. Shorter fields and wire-encoding artifacts match
almost everywhere, so they are refused. If the capture holds several TLS
sessions, also pass `--pcap-session <client_random_hex>`. This flag has no
default, because a field from the wrong session would still look like a valid
needle.

## Dump inputs

- **Positional `dumps`**: one or more files or directories. Each directory is
  expanded to the `*.dump`, `*.msl`, `*.gcore.core`, `*.core`, `*gdb_raw.bin`
  and `*lldb_raw.bin` files in it, de-duplicated and sorted. Only files
  directly inside the directory are considered.
- **A missing path is an error.** If any positional path does not exist, the
  command stops before searching anything and exits `2` with no payload:

  ```text
  memdiver: ERROR — Dump path(s) not found: missing.dump
  ```

  It does not quietly search the remaining dumps, because an `absent` verdict
  would then cover a dump that was never read.
- **Unrecognised files in a directory are noted, not searched.** Files directly
  inside a passed directory that match none of the patterns above are skipped,
  with one note per directory on stderr:

  ```text
  memdiver: note — skipped 2 file(s) in run_dir with unrecognised extensions (e.g. heap.bin, snap.raw); pass a file explicitly to include it
  ```

  Dotfiles and the usual sidecar files (`.json`, `.txt`, `.log`, `.pcap`,
  `.pcapng`, `.yar`, `.yara`, `.npy`, `.md`) are not counted. To search such a
  file, pass it by name. If a directory contains no dumps at all, the command
  fails with `Need at least 1 dump to search, got 0`.
- **`--view VIEW`**: the byte view to search. By default each format uses its
  own view: `raw` for raw dumps and `vas` for `.msl` files.
- **`--max-offsets N`** (default `64`): the maximum number of offsets returned
  per dump. It only shortens the `offsets` list. `hit_count` always gives the
  true number of occurrences, so the verdict and every count stay the same. A
  shortened list sets `offsets_truncated: true`.
- **Encrypted `.msl`**: pass `--key-file` (32-byte raw key), `--passphrase`
  (Argon2id) or `--kem-key-file` (X25519/ML-KEM/hybrid recipient key). When a
  container is still locked, the command raises an error. It does not report a
  confident absence for bytes it never decrypted.

## Output

The JSON payload goes to `-o/--output`, or to stdout if `-o` is not given. One
summary line and one line per diagnostic go to **stderr**, so you still see the
caveats when stdout is piped into another tool:

```text
memdiver: verdict=found present=1/2 searched (of 3 supplied)
memdiver: 1 of 3 dumps were never searched (c.dump: too_small — ...)
```

```{admonition} Read the verdict first
:class: important
`verdict` is `found` (present in at least one searched dump), `absent`
(searched and provably not there) or `not_searched` (nothing could be read).
A `not_searched` verdict claims **nothing**. Never treat it as an absence.
```

### Top-level fields

| Field | Meaning |
|---|---|
| `verdict` | `found` / `absent` / `not_searched` |
| `input_form` | `key_hex`, `keylog_line` or `pcap_field` (`secret` is also possible via MCP/HTTP) |
| `secret_type` | The NSS label, or the field id for `pcap_field`. Empty for `key_hex`. |
| `client_random` | The session the secret belongs to. Empty for `key_hex`. |
| `needle_length`, `needle_sha256` | Size and SHA-256 of the searched bytes. The secret itself is never echoed. |
| `view` | The `--view` you passed (`null` means each format's default) |
| `dumps_total` | Dumps supplied after directory expansion |
| `dumps_searched`, `dumps_present`, `dumps_absent` | Searched dumps, and how many of them did or did not contain the secret |
| `dumps_unreadable`, `dumps_too_small` | Dumps that were never searched |
| `unanimous` | `true` when every searched dump agrees (all present or all absent). `false` when nothing was searched. |
| `first_offset` | Lowest first-hit offset across the present dumps |
| `offsets_agree`, `common_offset` | Whether every present dump has its first hit at the same offset, and that offset (otherwise `null`) |
| `dumps` | One row per dump, in the order supplied |
| `elapsed_s` | Wall time in seconds |
| `diagnostics` | `{code, message, severity, details}` entries, described below |

### Per-dump rows

Each row in `dumps` has `dump_path`, `name`, `format_name`, `size_for_view`,
`status`, `present`, `first_offset`, `hit_count`, `offsets` (ascending),
`offsets_truncated` and `detail`. `status` is one of:

| `status` | Meaning | `present` |
|---|---|---|
| `searched` | The whole view was searched | `true` / `false` |
| `unreadable` | Opening or reading the dump failed. `detail` holds the error. | `null` |
| `too_small` | The view is shorter than the needle. `detail` gives both sizes. | `null` |

### Diagnostics

These are qualifications on the result, not errors. All codes start with
`analysis.locate_key.`:
`not_searched` (warning: some dumps were never read, so every count covers
fewer dumps than were supplied), `absent`, `partial` (present in some searched
dumps and absent from others), `offset_drift` (present dumps disagree on the
offset), `multiple_occurrences` (`hit_count > 1`) and `offsets_truncated`.

```{admonition} Partial survival is normal
:class: tip
A real secret is usually wiped at some points in the process lifecycle and
still present at others. A `found` verdict with a `partial` diagnostic is the
expected result for a lifecycle series, not a failure. Multiple hits within one
dump are real copies, for example in the key schedule and the record-layer
structs.
```

## Exit codes

The payload is written **for all three verdicts**. A non-zero exit code is a
verdict, not a crash. `memdiver locate-key --help` prints the same table.

| Exit | Verdict | Meaning |
|---|---|---|
| `0` | `found` | Present in at least one searched dump |
| `3` | `absent` | Searched and not present. This is the general "not found" code. |
| `2` | `not_searched` | Nothing was readable, so fix the inputs |

Exit code `2` is also used for input errors that produce no payload: a missing
or doubled secret form, a malformed secret, a non-searchable or ambiguous
`--pcap-field`, a dump path that does not exist, no dumps to search, or a
locked encrypted dump. Input errors print `memdiver: ERROR — …` on stderr.

```bash
memdiver locate-key dumps/ --keylog-line "$(grep CLIENT_RANDOM keys.log | head -1)" -o where.json
case $? in
  0) echo "key survives in: $(jq -r '.dumps[] | select(.present) | .name' where.json)" ;;
  3) echo "key wiped from every searched dump" ;;
  *) echo "nothing searched or bad input — see stderr" ;;
esac
```

## Worked examples

Find out which lifecycle phases still hold a TLS 1.2 master secret, and list
every copy:

```bash
memdiver locate-key run_dir/ \
  --keylog-line "CLIENT_RANDOM 52c5…e1 9f0a…7c" --max-offsets 256 -o ms.json
jq '.dumps[] | {name, status, present, hit_count, offsets}' ms.json
```

Check whether the `client_random` from a capture is still in encrypted `.msl`
snapshots:

```bash
memdiver locate-key snapshots/*.msl --passphrase "$MSL_PASS" \
  --pcap session.pcap --pcap-field client_random --pcap-session 52c5…e1
```

## Same producer on every surface

The CLI, the web API and the MCP server all call
`tools_pipeline.locate_key`, so they return the same payload.

| Surface | How |
|---|---|
| **CLI** | `memdiver locate-key …` |
| **Web** | `POST /api/analysis/locate-key` with `dump_paths`, one of `secret_hex` / `keylog_line` / `secret` / `pcap_field` (`{"pcap_path", "field_id", "client_random"?}`, as on the CLI and MCP), plus optional `view` and `max_offsets`. On this route `key_hex` is the *container decryption key*, which is why the needle is called `secret_hex`. Encrypted `.msl` keys go in `key_hex` / `kem_key_hex` (hex) or `passphrase`. An absent key is a `200` with `verdict: "absent"`. Invalid input, such as an unknown `pcap_field` key, is a `400`. |
| **MCP** | `locate_key` tool. It takes `key_hex`, `keylog_line`, `secret` or `pcap_field` (`{"pcap_path", "field_id", "client_random"?}`), plus `key_file` / `passphrase` / `kem_key_file`. See the [MCP reference](mcp_reference.md). |

Nothing is persisted. A key-log-derived location is corroborating evidence, not
an oracle confirmation, so it is never written to the ground-truth table.

See also: [CLI reference](cli_reference.md), [key-log export](keylog_export.md),
and the [pcap oracle](../oracle/pcap_oracle.md).
