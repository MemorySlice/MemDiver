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
The pcap oracle needs the optional `pcap` extra (the `dpkt` parser):

```bash
pip install "memdiver[pcap]"
```

Without it, the arm/validate step returns an `INVALID_INPUT` capability error and
pcap runs are unavailable.
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
      "has_app_records": true
    }
  ]
}
```

Only sessions with `has_app_records: true` carry application-data the oracle can
decrypt — a handshake-only session cannot confirm a key.

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

## Restricting to one session

A capture with several TLS sessions tries every session by default. To confirm
against exactly one, pass its `client_random` (from the arm step):

```bash
memdiver brute-force … --pcap traffic.pcap \
    --tls-client-random 3923d14c…26bdd823 --key-sizes 32 -o hits.json
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

## All four surfaces

The pcap capability follows the "one producer, four surfaces" rule:

| Surface | Arm (inspect) | Run (confirm) |
|---|---|---|
| **CLI** | `memdiver inspect-pcap <capture>` | `memdiver brute-force --pcap …` |
| **Web** | `POST /api/pcaps/upload` → `POST /api/pcaps/validate` | `POST /api/pipeline/run` (`pcap_path`, `tls_client_random`) |
| **MCP** | `inspect_pcap` tool | `brute_force` tool (`pcap_path`) |
| **Library** | `tools_pipeline.inspect_pcap(pcap_path=…)` | `tools_pipeline.brute_force(pcap_path=…)` |

`n-sweep` and `escalate` remain oracle-only; pcap confirmation runs through
`brute-force`.

## Ground truth

Pass `--persist-ground-truth` (CLI/MCP) to record pcap-confirmed hits in the
project's ground-truth ledger, labelled `confirmed_by="pcap"`, mapping the
recovered key to its byte value. This feeds the survival/labelling analytics.

## Producing a loadable key log

Once a key is confirmed, export it as a Wireshark-loadable NSS key log — see
[](../user_guide/keylog_export.md).
