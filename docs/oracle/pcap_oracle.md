# PCAP verification oracle

The [oracle interface](interface.md) covers *bring-your-own* oracles — untrusted
Python scripts you write. This page covers the **first-party pcap oracle**: a
trusted, built-in oracle that proves a recovered key actually decrypts a **real
captured TLS session**.

Instead of asking "does this candidate equal a known key?", the pcap oracle asks
the stronger question: *does deriving record keys from this candidate and
AEAD-decrypting the captured records succeed?* A candidate that decrypts a real
record on the wire is a key beyond doubt — the headline proof of the Phase-1
"recover a key and prove it decrypts traffic" workflow.

It supports TLS 1.3, TLS 1.2 GCM, and older TLS 1.2 CBC sessions. Because the
oracle is first-party code (not a user script), it runs **without** the
untrusted-oracle sandbox — the capture is only ever parsed as data, never
executed.

:::{note}
The pcap oracle's `dpkt` parser ships in the default `pip install memdiver`, so no
extra is needed. (`memdiver[pcap]` still resolves as a no-op alias.)

If `dpkt` is force-uninstalled, the arm/validate step returns an `INVALID_INPUT`
capability error and pcap runs are unavailable.
:::

## The two steps: arm, then run

### 1. Arm — inspect the capture's TLS sessions

Before running, summarize the capture to see which TLS sessions it contains and
their `client_random` values. This is the "arm" step (analogous to arming a BYO
oracle), and it is a single producer exposed on every surface.

```bash
memdiver inspect-pcap /abs/path/to/traffic.pcap
```

```json
{
  "pcap_path": "/abs/path/to/traffic.pcap",
  "session_count": 1,
  "sessions": [
    {
      "client_random": "3923d14c…26bdd823",
      "server_random": "…",
      "version": "13",
      "cipher_suite": 4867,
      "cipher_name": "TLS_CHACHA20_POLY1305_SHA256",
      "client_app_records": 1,
      "server_app_records": 8,
      "has_app_records": true,
      "app_records_seen": 9,
      "records_returned": 9,
      "challenges_available": 37,
      "challenges_returned": 37
    }
  ],
  "skipped_sessions": [
    {
      "reason": "unsupported_cipher_suite",
      "flow": "10.0.0.5:49812 -> 93.184.216.34:443",
      "cipher_suite": 49199
    }
  ],
  "flow_count": 4,
  "caps": { "max_records_per_direction": 16, "max_challenges": null },
  "records_truncated": false,
  "challenges_available": 37,
  "challenges_returned": 37,
  "challenges_truncated": false
}
```

Only sessions with `has_app_records: true` carry application-data the oracle can
decrypt — a handshake-only session cannot confirm a key.

#### Reading the accounting fields

`session_count` and `sessions` describe what the parser **kept**. The remaining
top-level keys describe what it **dropped**, and they are the reason a
`verified_count: 0` run is interpretable at all:

| Key | Meaning |
|---|---|
| `flow_count` | Directional TCP flows the capture yielded. The denominator for `session_count`: "1 session out of 4 flows" is a very different capture from "1 out of 2". |
| `skipped_sessions` | One entry per session the parser could not use, each with a machine-readable `reason`, the `flow` it was seen on, and reason-specific context. |
| `caps` | The caps actually in force: `max_records_per_direction` (default `16`) **and** `max_challenges` (`null` when uncapped). The key is always present, so "uncapped" cannot be misread as "unreported". |
| `records_truncated` | `true` when *any* session returned fewer records than it saw — whatever the cause. |
| `challenges_available` | Challenges the whole capture would contribute with no challenge cap. Not derivable from the record counts — see *A challenge is not a record*. |
| `challenges_returned` | Challenges that survive `caps.max_challenges`, which is spent across sessions in parse order. |
| `challenges_truncated` | `challenges_returned < challenges_available`: some record got only part of its sequence window, so a no-hit run is a statement about the challenges tried, not about the capture. |

Every kept session additionally carries four accounting numbers:

| Session key | Meaning |
|---|---|
| `app_records_seen` | Application-data records the parser saw across **both** directions. |
| `records_returned` | How many of those the challenge stream actually **covers**. Three things can lower it: `max_records_per_direction` (applied *per direction*), a missing TLS 1.2 ChangeCipherSpec (that direction's data is not decryptable at all), and an exhausted `max_challenges` budget. |
| `challenges_available` | Challenges this session would contribute with no challenge cap. |
| `challenges_returned` | Challenges that survive `max_challenges`. |

In the example above 9 records were seen and 9 returned, so nothing was clipped
— but they produce **37** challenges, not 9, because this is a TLS 1.3 session
(see *A challenge is not a record* below).

:::{note}
The capture-level `challenges_available` / `challenges_returned` /
`challenges_truncated` are reported *per capture* rather than only per session
because that is the level at which `max_challenges` is spent — it truncates the
flat challenge stream **across** sessions, in parse order, so a later session
can legitimately report `challenges_returned: 0` while the capture total is
non-zero. `challenges_truncated` is simply
`challenges_returned < challenges_available`.
:::

:::{important}
`records_truncated` is **not** a statement about `max_records_per_direction`
alone, and `records_returned` is **not** the raw record total. Both are counted
through the very same gate the challenge emitter walks, so the report cannot
claim coverage the oracle never had. The case that forced this: a TLS 1.2
capture with no ChangeCipherSpec (a truncated capture start, a dropped packet, a
one-sided CCS) carries application data that no negotiated key can decrypt. Read
from the raw totals it looked like **full** coverage while the oracle verified
**zero** records; it now reports `records_returned: 0` plus a
`no_change_cipher_spec` entry in `skipped_sessions`. Measured over the whole
corpus (2,598 captures) the numbers are unchanged — every capture there carries
a CCS in both directions — so this changed no result, only what a broken capture
would have told you.
:::

`reason` is one of seven closed values. The first five drop a whole session; the
last two do **not** — the session is kept and reported in `sessions`, with the
entry here explaining why some or all of its records are uncoverable. A session
can therefore legitimately appear in both lists:

| `reason` | What the parser saw |
|---|---|
| `no_client_hello` | Neither direction of the flow carried a ClientHello. |
| `no_server_hello` | A ClientHello, but no ServerHello on the reverse direction. |
| `no_cipher_suite` | *Defensive guard only — see the note below.* A ServerHello whose selected cipher suite could not be read. |
| `short_random` | *Defensive guard only — see the note below.* A handshake whose `client_random`/`server_random` was not 32 bytes (the entry carries `client_random_len` / `server_random_len`). |
| `unsupported_cipher_suite` | A complete handshake negotiating a suite outside MemDiver's KDF/AEAD table (the entry carries the IANA `cipher_suite` code). This one is also logged at `INFO`. |
| `no_change_cipher_spec` | TLS 1.2 only, reported **per direction**: this direction sent application data but no ChangeCipherSpec, so its records are not decryptable under the negotiated keys. The entry carries `direction` (`"client"` / `"server"`) and that direction's own `app_records_seen`, which is why it can be smaller than the session-level figure. The session is kept. |
| `client_random_mismatch` | The session parsed cleanly but this run is pinned to a different one via `--tls-client-random`, so the challenge stream skips it. The entry carries the skipped session's hex `client_random`, so the report says *which* session was passed over. |

:::{note}
`no_cipher_suite` and `short_random` are **defensive guards, not expected
outcomes**. The bundled `dpkt` cannot produce either: `TLSServerHello.unpack`
falls back to `get_unknown_ciphersuite` rather than leaving the suite unreadable,
and a ServerHello with a short random is rejected during unpacking and surfaces
as `no_server_hello`. Both checks stay in place (and both values stay in the
frontend's closed `PcapSkipReason` union) so a different `dpkt` build cannot
produce an unlabelled row — but do not build a UI or a corpus aggregate that
expects to see them.
:::

:::{warning}
Read `records_truncated` and `skipped_sessions` **before** you trust a
zero-confirmation result. The dangerous case is a *partial* loss: on a capture
holding several sessions, the one that carries your key can be dropped as
`unsupported_cipher_suite` while the others parse fine, so the run proceeds
happily against the remaining sessions and reports `verified_count: 0` —
indistinguishable from "the key is not in this dump" unless you look at what was
skipped. `records_truncated: true` is the same hazard one level down: the oracle
only ever saw part of a session's ciphertext, so a no-hit run there is a
statement about the records that were read, not about the capture. (A capture
where *every* session was dropped is at least loud about it: the arm step returns
`session_count: 0`, and a `brute-force` run fails outright with "no complete TLS
handshake found" rather than reporting a clean no-hit.)
:::

### 2. Run — confirm a recovered key against the capture

Point `brute-force` at the same capture with `--pcap`. When a candidate decrypts
a captured record, the hit is recorded with `confirmed_by: "pcap"`.

```bash
memdiver brute-force \
    --candidates candidates.json \
    --dump reference.msl \
    --pcap /abs/path/to/traffic.pcap \
    --key-sizes 32 \
    -o hits.json
```

`--pcap` is **mutually exclusive** with `--oracle` — a run confirms candidates
either through your script or against a capture, never both.

## Choosing `--key-sizes`

The oracle recovers the **traffic/master secret**, then derives record keys from
it via the RFC KDFs — so the candidate length must match the secret, not the
record key:

| Session | Secret recovered | `--key-sizes` |
|---|---|---|
| TLS 1.3 | 32-byte `*_TRAFFIC_SECRET_0` (or handshake secret) | `32` (default) |
| TLS 1.2 | 48-byte master secret | `48` |

A TLS 1.2 run left at the default `32` will never find its 48-byte master secret.

## Choosing `--stride` (the alignment trap)

`--stride` is the offset step of the candidate grid, and the grid is **absolute**:
at `--stride N` only offsets that are multiples of N are ever handed to the
oracle. A secret that does not happen to be N-aligned is therefore never tested,
and the run still ends *successfully* with `verified_count: 0` — which looks
exactly like "the key is not in this dump".

Because a silent false negative is worse than a slow run in a forensic setting,
the default is **`--stride 1` — full coverage**. Every offset inside every
surviving region is tested, so a no-hit means what it says.

Measured on a real corpus dump (25,932 surviving regions, `--key-sizes 32`),
where the true TLS traffic secret sits at offset `585148` (and `585148 % 8 == 4`):

| `--stride` | Candidates tested | Coverage | Secret reachable? |
|---|---|---|---|
| `8` | 110,326 | 15.7 % | **no** — 585148 is not 8-aligned |
| `4` | 194,720 | 27.8 % | yes |
| `1` (default) | 701,084 | 100 % | yes |

Note that `--stride` and `--alignment` are **two different grids**, and only one
of them can cost you the key.

`--stride` is the candidate **enumeration** step: at `--stride N` only offsets
that are multiples of N are handed to the oracle, so any stride > 1 can skip the
key entirely and still report a clean no-hit. Hence the full-coverage default
of `1`.

`--alignment` never discards a byte for being unaligned. It is the scan step of
the block-density gate (`engine/candidate_pipeline._aligned_mask`, defaults
`alignment=8` / `density_threshold=0.5`), which keeps *whole blocks* whose
candidate density reaches the threshold. That is why the secret at offset
`585148` — with `585148 % 8 == 4` — passes the gate fine, and is missed only by
`--stride 8` above.

So `--alignment` coarsens **where** MemDiver looks; `--stride 1` then tests
**every** offset inside what it found. Leaving `--alignment` at `8` costs no
coverage; raising `--stride` does.

Raising the stride is an **opt-in speed tradeoff**: `--stride 8` hands roughly
6× fewer candidates to the oracle on that dump, and finishes correspondingly
faster — but it is exactly the setting that misses the key in the table above.
Raise it only when you can afford that risk, and never conclude "no key" from a
run that was not at full coverage.

Coverage is **not** simply `1 / stride`: regions are short and the grid snaps up
to the first absolute multiple of the stride inside each region, so MemDiver
counts it rather than deriving it. Every run reports the real numbers —
`candidates_tested`, `candidates_possible`, `stride` and `coverage_fraction` are
written into `hits.json` and shown on the web pipeline's brute-force stage. Read
them even on a *successful* run: one hit out of 15.7 % coverage does not mean
exactly one key is present.

When a run confirms nothing **and** coverage is below 100 %, MemDiver emits a
`brute_force.partial_coverage` warning (stderr on the CLI, `warnings[]` in the
producer result) telling you exactly that, with the numbers. At the default
stride `coverage_fraction` is `1.0`, so on defaults the warning correctly never
fires — it appears only when you deliberately raised the stride. The remedy is
to go back to full coverage:

```bash
memdiver brute-force … --pcap traffic.pcap --key-sizes 32 --stride 1 -o hits.json
```

One deliberate exception: the **Replicate gocryptfs IMF** recipe in the web
UI still pins `stride 8`, because the published result was produced at that
setting and the recipe exists to reproduce it.

## Restricting to one session

A capture with several TLS sessions tries every session by default. To confirm
against exactly one, pass its `client_random` (from the arm step):

```bash
memdiver brute-force … --pcap traffic.pcap \
    --tls-client-random 3923d14c…26bdd823 --key-sizes 32 -o hits.json
```

## Sizing the oracle's work: `--pcap-max-records` and `--pcap-max-challenges`

Two caps bound how much of a capture the oracle actually verifies against. Both
default to *no truncation of today's behaviour* and both are silent losses of
coverage when you set them, so set them deliberately.

`--pcap-max-records N` caps how many encrypted application-data records **each
direction of each session** contributes. The default is `16` per direction (so
16 client + 16 server). Lower it for speed on a chatty capture, raise it when
the arm step reports `records_truncated: true` and you want the whole session
verified.

`--pcap-max-challenges N` caps the **total** challenges the oracle keeps, and
defaults to uncapped. `N` must be at least `1` on every surface: `0` and
negative values are **rejected**, not reinterpreted — the shared producer raises
an `INVALID_INPUT` capability error (HTTP 400 on the web surface),
`POST /api/pipeline/run` rejects them in request validation before that, and
`build_oracle` raises `ValueError` for a config that reaches the oracle loader
directly. A cap below 1 verifies nothing, so it could only ever turn a real
recovered key into an unexplained "0 confirmed" — and a `0` used to be read as
*falsy*, i.e. as "uncapped", the exact opposite of the request. When the cap
fires it is logged at `INFO` (`max_challenges=N truncated M challenges to N`).

### A challenge is not a record

The two caps do not convert into each other, and this is the single most
counter-intuitive thing about sizing a pcap run. On a TLS 1.3 session the
handshake→application epoch change is not observable in the capture, so each
application-data record's true record-sequence number is only known to be *at or
below* its position on the wire; MemDiver therefore probes each record over a
sequence-number window (up to 9 candidates — the record's own index plus the 8
before it). One record can thus yield up to nine challenges.

Across the full corpus that averages **~3.9 challenges per record** (48,546
challenges for 12,463 records). Size a cap from that ratio, not from the record
count:

- `--pcap-max-challenges 50` buys roughly **13 records** of verification, not 50.
- To verify *n* records of a TLS 1.3 session, budget on the order of `4 × n`
  challenges — and up to `9 × n` for a long session, where every record's window
  is full.
- TLS 1.2 is one challenge per record, so there the two caps do line up.

This is exactly why the arm step publishes `challenges_available` alongside
`records_returned`: run `inspect-pcap` first and compare your intended cap
against the capture's real challenge count, rather than guessing from the record
totals. `--pcap-max-records` is the cap that maps directly onto
`records_returned`.

:::{warning}
A challenge cap truncates **across** sessions, not per session.
`TlsPcapResource.challenges()` yields every challenge of the first parsed
session, then the second, and so on; `ResourceOracle` materialises that whole
sequence and keeps only the first `max_challenges` entries. So on a capture with
several sessions, a small cap can be consumed entirely by the earliest session
in parse order and leave later sessions with **zero** challenges — a key
belonging to one of those sessions then goes unconfirmed even though the capture
contains its records. Combine `--pcap-max-challenges` with
`--tls-client-random` if you want a bounded run that still targets a specific
session.
:::

```bash
memdiver brute-force … --pcap traffic.pcap \
    --tls-client-random 3923d14c…26bdd823 \
    --pcap-max-records 64 --pcap-max-challenges 128 \
    --key-sizes 32 -o hits.json
```

## Web UI

In the pipeline wizard's **oracle stage**, the pcap panel offers a drop-or-browse
uploader above the manual path field:

1. **Upload** a `.pcap`/`.pcapng`. The capture is streamed to the server (512 MiB
   cap) and its path is filled in for you.
2. It is **armed automatically** — the detected TLS sessions appear as a
   selectable list (version, cipher, record counts). Click a session to pin its
   `client_random`, or leave "match any session".
3. Advance the wizard and **run**; confirmed hits show `confirmed_by = pcap` in
   the results.

Uploaded captures persist under the server's `upload_dir/pcaps/` with an
aggregate quota (default 5 GiB, `MEMDIVER_PCAP_QUOTA_BYTES`); the oldest are
pruned first when the quota is exceeded. You may also type a server-side path
directly instead of uploading.

`upload_dir` has **no default** — there is deliberately no world-writable
`/tmp` fallback, because it is also the containment root every server-side write
path is checked against. The **first** upload therefore asks you where captures
and dumps should live; the choice is stored in your user-local
`~/.memdiver/config.json` (never the git-tracked repo `config.json`) and the
directory is created owner-only (`0o700`). You can review or change it later
under **Settings → Storage**, or pin it for the whole server with
`MEMDIVER_UPLOAD_DIR` — which always wins, and makes the UI control read-only.
An unconfigured server answers `POST /api/pcaps/upload` with **409**
`upload_dir_unconfigured: …`; the UI turns that into the "choose a directory"
prompt and then retries the upload with the same file, so nothing is lost.
If files are still sitting in the old `/tmp/memdiver_uploads`, the prompt offers
a one-time migration.

## All four surfaces

The pcap capability follows the "one producer, four surfaces" rule:

| Surface | Arm (inspect) | Run (confirm) |
|---|---|---|
| **CLI** | `memdiver inspect-pcap <capture>` | `memdiver brute-force --pcap … --tls-client-random … --pcap-max-records … --pcap-max-challenges …` |
| **Web** | `POST /api/pcaps/upload` → `POST /api/pcaps/validate` | `POST /api/pipeline/run` (`pcap_path`, `tls_client_random`, `pcap_max_records`, `pcap_max_challenges`) |
| **MCP** | `inspect_pcap` tool | `brute_force` tool (`pcap_path`, `tls_client_random`, `pcap_max_records`, `pcap_max_challenges`) |
| **Library** | `tools_pipeline.inspect_pcap(pcap_path=…)` | `tools_pipeline.brute_force(pcap_path=…, tls_client_random=…, pcap_max_records=…, pcap_max_challenges=…)` |

Every run-step parameter has the same meaning on all four surfaces; only the
spelling differs (CLI hyphens, everything else snake_case). Leaving a cap unset
(`None` / omitted / `null`) keeps the defaults — 16 records per direction, no
challenge cap. The web API additionally validates both as `>= 1`.

`n-sweep` and `escalate` remain oracle-only; pcap confirmation runs through
`brute-force`.

## Ground truth

Pass `--persist-ground-truth` (CLI/MCP) to record pcap-confirmed hits in the
project's ground-truth ledger, labelled `confirmed_by="pcap"`, mapping the
recovered key to its byte value. This feeds the survival/labelling analytics.

## Producing a loadable key log

Once a key is confirmed, export it as a Wireshark-loadable NSS key log — see
[](../user_guide/keylog_export.md).
