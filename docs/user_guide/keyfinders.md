---
myst:
  html_meta:
    "description lang=en": "Find AES, RSA and high-entropy key material in a process capture, restrict it to live heap data and verify it."
---

# Key finders

A key finder reads a capture and reports bytes that *look like* key material.
It does not know whether the bytes are a live key. Every hit is a
**candidate**. This page explains what each finder detects, the traps that
produce wrong answers, the path from a process in a full image to a verified
key, and how to join a hit to its heap chunk and memory mapping.

The finders only read bytes that were captured. A structure that straddles a
capture gap or a failed page is never found in invented zeros, and every result
carries `coverage` and `truncated`. An empty result is not proof of absence.
Read those two fields first.

## The finders

List them, with their parameters, on any surface:

```bash
memdiver keys list
```

| Finder | Detects | Traps |
|---|---|---|
| `aes_schedule` | Expanded AES-128/192/256 round-key schedules, recognised by the schedule's own structure. Confidence is matched derived words over derived words, so a truncated or partly overwritten schedule still scores. | See [AES byte order](#aes-byte-order). Without the right orientation or byte order a real key is missed silently. `key_offset` is reported only when the key itself is stored verbatim next to the schedule. |
| `rsa_der` | DER PKCS#1 and PKCS#8 RSA private keys. A hit is accepted only when `n == p*q`. | Finds serialised keys only. Most TLS servers never hold one in memory. |
| `pem_scan` | PEM private-key blocks, with the RSA or OpenSSH body verified. | Needs the `BEGIN`/`END` armour to be intact. |
| `rsa_factor` | A prime factor of a known RSA modulus stored as raw big-integer bytes (OpenSSL `BIGNUM` limbs). | See [RSA factors](#rsa-factors). It needs a modulus. |
| `entropy_window` | Key-sized windows (16, 24, 32, 48, 64 bytes by default) of near-random bytes. | The least specific finder. Compressed data, hashes and ciphertext are high entropy too. Treat hits as a shortlist for an oracle, not as keys. |

### AES byte order

OpenSSL stores `AES_KEY` as host-endian 32-bit words. On a little-endian host
every word of the schedule is byte-reversed in memory. `aes_schedule` therefore
tries two byte orders, `natural` and `swapped32`, and two orientations,
`forward` and `inverse` (the reversed schedule with InvMixColumns applied to the
middle rounds, used by OpenSSL and AES-NI for decryption). The default
parameters cover all of them. This was checked against real libcrypto
structures for 128, 192 and 256 bits: without `swapped32` all six would be
missed. If you narrow `aes_byte_orders` or `aes_orientations` to speed up a
scan, you give that coverage up.

On a real TLS 1.3 client process (`openssl_run_13_1`, an aarch64 glibc
process), the finder reports nine AES-256 forward/natural schedules. Two of them
are the AES-256-GCM keys derived from `CLIENT_TRAFFIC_SECRET_0` and
`SERVER_TRAFFIC_SECRET_0`. The scan takes well under a second on the process
capture.

### RSA factors

`rsa_factor` finds a prime that divides a public modulus. If you give it no
modulus, it harvests moduli from the same capture: SPKI blobs, certificates,
`RSAPublicKey` structures and `ssh-rsa` blobs. It then slides a window over the
capture looking for a run of bytes that divides one of them. It looks for
little-endian limbs (stride 8 by default) and big-endian bytes (stride 1).

- **Little-endian limbs are the fast, normal case.** OpenSSL stores `BIGNUM`
  limbs little-endian. The big-endian pass at stride 1 is several times slower
  and is mainly for other libraries.
- **No modulus in memory means no result.** If the process holds no public key,
  certificate or `ssh-rsa` blob, the finder has nothing to divide by and reports
  nothing. Supply the modulus yourself with the `rsa_moduli` parameter.
- **Verify the pair.** On a real Cumulus nginx process the finder located both
  2048-bit primes of a 4096-bit key as limbs inside two adjacent heap chunks.
  `p` differs from `q`, both are probable primes, and `p*q` equals the harvested
  modulus. A key rebuilt from them signed and verified. That check is cheap, so
  do it.

### What the other layers add

- **Heap-role restriction.** With `heap_policy="mask"`, a hit survives only when
  its first and last byte lie inside **one allocator chunk's user data**. This
  removes hits in chunk headers, free-list links and allocator metadata. It
  depends on the allocator parser, so check the result of `heap_detect` first.
- **Oracle verification.** A schedule or a factor proves the bytes have the
  right *shape*. Only decrypting something known proves they are *the* key. See
  [Verify the hit](#verify-the-hit).

## Strings, IOCs and YARA

Two other scans work on the same `.msl` and the same hit model. They find
evidence of *where* a key was used, rather than the key itself.

- **Strings table** (`memdiver strings table DUMP`). Extracts ASCII, UTF-8 and
  UTF-16LE strings with their addresses and files them as the `strings` case
  table with IOC columns: URLs, e-mail addresses, IPv4, Unix and Windows paths,
  executables, archives, PEM markers, base64 and hex runs. The IOC patterns are
  heuristics with known noise. IPv4 matches dotted version numbers and 4-part
  OIDs, and base64 matches long identifiers. A string such as
  `SSLKEYLOGFILE=/output/keylog_raw.txt` in a process environment is a lead, not
  a key.
- **YARA** (`memdiver yara check RULE` and `memdiver yara scan RULE DUMP`).
  Scans the captured bytes of one dump with a rule and returns rows with
  `addr`, `space`, `va`, `coverage` and `truncated`. `yara check` reports the
  line and column of a compile error. libyara reports an identifier error at the
  end of the rule, so MemDiver relocates it to the offending token. Rules can be
  stored in a library or in a case and run by name with `--rule-name`.
  The older `scan-yara` command is a census over N dumps without window or VA
  detail. Use `yara scan` when you need the location of every match.

### Detector fixtures

A finder or a YARA rule can be wrong in two ways: it misses a real key, or it
fires on noise. Detector fixtures test that on known samples before you rely on
the scan.

```bash
memdiver fixtures run --kind keyfinder aes_schedule
memdiver fixtures run --kind yara rule.yar
```

The bundled `aes_schedule` fixtures hold four positives (128-bit forward,
inverse, `swapped32`, 256-bit forward) and three decoys (zeros, `0x09` fill, a
schedule with a corrupted `w[Nk]`). The verdict has three states, and
`indeterminate` proves nothing:

| Exit code | Verdict | Meaning |
|---|---|---|
| `0` | pass | Every positive was found and every decoy stayed silent. |
| `1` | fail | A positive was missed, a decoy fired, a rule did not compile or a finder raised. |
| `2` | indeterminate | There are no fixtures, or the sample was padded or too short to judge. Never read it as a pass. |

In the web UI the same verdict appears as a badge on the Key finders panel and
on the YARA panel.

## From a process to a verified key

The route is the same on every surface: image process, `.msl`, heap, finders,
oracle. Use it when you start from a **full memory image** and you do not yet
have a per-process capture. If you already hold a `.msl`, start at step 3.

```{admonition} Sandbox
:class: note
When `MEMDIVER_ALLOWED_ROOTS` is set, every input path must lie in those roots
and output paths in the MemDiver home. A denial returns `path.outside_sandbox`.
Fix the path rather than retrying.
```

1. **Open the process.** Resolve a profile, then open a process view:

   ```bash
   memdiver image open IMAGE --view process --pid PID --case mycase
   ```

   The command prints the view descriptor path (`view_path`). It lands in
   `<case>/views/`.

2. **Extract it to `.msl`.** This takes minutes on a large image:

   ```bash
   memdiver image extract VIEW.mdview --out process.msl
   ```

   The result is a normal capture. It keeps its virtual-address view and every
   page-state fact, so everything below works on it like on any other `.msl`.

3. **Parse the heap.** Start with detection and check the allocator it chose:

   ```bash
   memdiver heap detect process.msl
   ```

   Treat `partial` or `heuristic` allocators (jemalloc, generic) with suspicion.
   The `mask` policy is only as good as this parse. Chunks and the chunk around
   an address come from `memdiver heap chunks` and `memdiver heap at`. See
   [](heap.md).

4. **Run the finders.**

   ```bash
   memdiver keys scan process.msl --finder aes_schedule \
       --heap-policy annotate --case mycase \
       --candidates-out candidates.json
   ```

   `--finder` can be repeated. `--heap-policy` is `off`, `annotate` (the
   default; each hit shows the chunk that holds it) or `mask` (only hits inside
   one chunk's user data). `--view` defaults to `va` for an `.msl`. `--offset`
   and `--length` restrict the scan to a window in those coordinates. With
   `--case`, the hits become the `key_hits` table and `key_hit` annotations;
   `--no-annotate` files the table only. A cut at `--limit` (default 10000)
   sets `truncated`.

5. **Verify** (next section). A key that nothing verified is not a result.

| Step | Web UI | CLI | MCP tool |
|---|---|---|---|
| Open and extract | Image panel | `memdiver image open`, `memdiver image extract` | `image_open_view`, `image_extract_process` |
| Inspect the capture | Hex workspace | `memdiver inspect` | `get_session_info`, `vas_regions`, `get_modules` |
| Heap | Heap tab | `memdiver heap detect/summary/chunks/at` | `heap_detect`, `heap_summary`, `heap_chunks`, `heap_roles` |
| Find | Key finders panel | `memdiver keys list/scan` | `keyfinders_list`, `keyfinders_scan` |
| Verify | Verify button on a hit | `memdiver verify`, `memdiver locate-key`, `memdiver brute-force` | `verify`, `locate_key`, `brute_force` |

In the web UI, the Key finders panel lets you pick finders and a region (the
whole view or the current selection), choose the heap policy, and run. A scan
above 64 MiB of captured bytes runs as a job with progress and Cancel. Each hit
row shows the finder, label, address, length, confidence, the heap role and the
permissions of its mapping. **Copy** copies the key. **Verify** opens the oracle
dialog for that hit. Clicking a row jumps to it in the hex view and highlights
it.

For an agent, the MCP playbook `image_to_process_keys` walks these same steps
with the exact parameters and the traps to check.

## Verify the hit

A hit is a candidate. Verify it before you report it.

- **Known ciphertext.** `memdiver verify DUMP --offset OFFSET --length 32
  --ciphertext-hex HEX --cipher NAME` decrypts known ciphertext with the bytes
  at that offset. For AEAD ciphers add `--nonce-hex`, `--aad-hex` and
  `--tag-hex`. `--offset` is read in the byte view you name with `--view`
  (`vas` by default for an `.msl`), so give the offset in the same coordinates
  as the hit.
- **A TLS capture.** For a key that belongs to a TLS session, `inspect-pcap`
  summarises the sessions in the capture, and a recovered key can be proven by
  decrypting the real capture. See [](keylog_export.md).
- **A known key.** If you already hold the key from a key log,
  `memdiver locate-key` finds it across N dumps and tells you which dumps still
  contain it. See [](locate_key.md).
- **A user oracle.** `candidates.json` from `--candidates-out` is the input to
  `memdiver brute-force`, which runs every candidate through your oracle script.

Report the verification result, never the raw hit count alone. A hit inside a
**freed** chunk (`heap_state`) may be a key that was once live. It is not
evidence of a live key.

## Join a hit to its chunk and mapping

Every hit has an `addr`, a `space` and a `location`. With the heap policy
`annotate` or `mask`, the `key_hits` table already carries the holding chunk
(`heap_chunk_va`, `heap_chunk_size`, `heap_role`, `heap_state`) and the mapping
(`region_start`, `region_end`, `region_perms`, `region_path`). For anything
beyond that, file the capture's tables in the case and join them with one
read-only query:

```bash
memdiver case export process.msl --case mycase --what msl_regions
memdiver case export process.msl --case mycase --what heap_chunks
memdiver case schema --case mycase
```

`case schema` lists the tables, their real column names and which columns are
addresses. Read it before you write SQL, because the query below is a shape and
not a promise. Join on the hit's `va`, which is a virtual address even when
`addr` is a packed-stream offset:

```bash
memdiver case query --case mycase --sql "
  SELECT k.finder, k.label, k.va, c.addr AS chunk, c.size AS chunk_size,
         c.state, r.addr AS vma, r.size AS vma_size, r.protection
  FROM key_hits k
  LEFT JOIN heap_chunks c ON k.va >= c.addr AND k.va < c.addr + c.size
  LEFT JOIN msl_regions r ON k.va >= r.addr AND k.va < r.addr + r.size"
```

Bind values with `--param`, never by string formatting.

On the real TLS capture above, this join places the client key at a heap
address inside a 976-byte `in_use` chunk (user data), and the server key in
another 976-byte chunk. Both lie in one `rw-` mapping of `[heap]`. The RSA
primes on the Cumulus nginx process sit in 272-byte `in_use` chunks of the
`[heap]` mapping: the 2048-bit limbs plus a header.

To ask "what contains this address?" for any address, use `case context-at`:

```bash
memdiver case context-at --case mycase \
    --location '{"space":"msl_va","value":<ADDRESS>,"capture_id":"<id>"}'
```

It lists the table rows and annotations that contain the address, outermost
first. The MCP tools are `case_query`, `case_schema` and `context_at`. Large
address values are exact integers on every surface.

## What to do with the result

A verified key is the start of the next question, not the end. Search for the
same bytes across the other dumps with [](locate_key.md), or learn the object
that holds it across N dumps and ship a plugin that finds it in one image. See
[](object_model.md).
