# Key-log export

Once you have recovered TLS secrets, MemDiver can emit a **Wireshark-loadable NSS
key log** — the `SSLKEYLOGFILE` format — so a capture of the same session
decrypts in Wireshark/tshark. This turns a recovered key into a shareable,
independently-verifiable artifact.

Each key-log line is one secret:

```
<LABEL> <client_random-hex> <secret-hex>
```

## The composer (web UI)

The key-log composer lives in the workspace **Verify key** panel, below the
verification form.

1. Click **Add entry** for each secret you want in the log.
2. Fill the three fields per row:
   - **Secret type** — pick a canonical NSS label from the dropdown (see below).
   - **Client random** — the 64-hex-char TLS `client_random` for the session.
   - **Secret** — the recovered secret, as hex.
3. Click **Export key log** to download `memdiver.keylog`.

Rows that are incomplete or invalid are skipped on export, and the composer tells
you how many were skipped so a missing secret is never silent.

:::{admonition} Where does `client_random` come from?
:class: important

The `client_random` is a TLS **handshake** value — it lives in the capture, not
in the process memory MemDiver scans. Memory forensics recovers the *secret
bytes*; the capture supplies the *client random* that ties them to a session.

The composer bridges this: if you have **armed a pcap** in the pipeline oracle
stage (see [](../oracle/pcap_oracle.md)), each row offers a *prefill from pcap
session* dropdown that fills in a real `client_random` for you. Otherwise, paste
it from the handshake (`inspect-pcap` prints it).
:::

## Canonical NSS labels

The `Secret type` must be a canonical NSS key-log label — the exporter validates
it (a non-canonical label is rejected rather than silently producing a key log
Wireshark refuses to load). The composer dropdown lists the TLS labels:

| TLS version | Labels |
|---|---|
| TLS 1.2 | `CLIENT_RANDOM` (the master secret) |
| TLS 1.3 | `CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `SERVER_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_TRAFFIC_SECRET_0`, `SERVER_TRAFFIC_SECRET_0`, `EXPORTER_SECRET` |

(The backend additionally accepts SSH2 and raw-`AES256_KEY` labels for non-TLS
key logs; the composer focuses on the TLS set.)

## Loading it in Wireshark

- **Wireshark**: *Preferences → Protocols → TLS → (Pre)-Master-Secret log
  filename* → point it at the downloaded `memdiver.keylog`, then reopen the
  capture.
- **tshark**:

  ```bash
  tshark -r traffic.pcap -o tls.keylog_file:memdiver.keylog -Y http
  ```

A TLS 1.3 application-data record decrypts once the matching
`*_TRAFFIC_SECRET_0` line (plus its real `client_random`) is present.

## All four surfaces

Export is a single producer exposed everywhere:

| Surface | How |
|---|---|
| **Web** | Composer → `POST /api/analysis/export-keylog` |
| **CLI** | `memdiver export-keylog --secrets secrets.json -o session.keylog` |
| **MCP** | `export_keylog` tool |
| **Library** | `tools_pipeline.keylog_result(secrets=[…], output_path=…)` |

The CLI reads a JSON file — a list of `{secret_type, client_random, secret}`
dicts (`client_random` and `secret` are hex):

```json
[
  {
    "secret_type": "CLIENT_TRAFFIC_SECRET_0",
    "client_random": "3923d14c…26bdd823",
    "secret": "a05312cb…3382c2c5"
  },
  {
    "secret_type": "SERVER_TRAFFIC_SECRET_0",
    "client_random": "3923d14c…26bdd823",
    "secret": "34733aa5…1521a43e"
  }
]
```

```bash
memdiver export-keylog --secrets secrets.json -o session.keylog
```

Omit `-o` to write the key log to stdout.
