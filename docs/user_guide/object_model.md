---
myst:
  html_meta:
    "description lang=en": "Learn an object layout around a verified key from N memory dumps, export a Volatility 3 plugin and validate it on held-out dumps."
---

# Object model: learn from N dumps, find in one

You hold a few dumps from the same program and you know a secret that is in
each of them, for example from a key log. The question is not "where is this
key?" (that is [](locate_key.md)). It is: **what object holds it, and can I
find the next one in a single image that I know nothing about?**

An **object model** is the answer. MemDiver learns the model from N dumps,
writes it as a Volatility 3 plugin and then **tests the plugin on dumps it never
saw**. You get a plugin that runs on one image with no corpus and no agent,
together with a number that says how far to trust it.

```text
learn on N dumps -> model (JSON) -> exported vol3 plugin -> held-out validation -> verdict
```

## The idea in four steps

1. **Anchor.** Pick a verified value present in every learning dump, normally a
   secret from a key log. Heap objects do not sit at the same address in every
   run, so a flat comparison is wrong around them. MemDiver compares the bytes
   at fixed offsets (deltas) *from the anchor* in each dump instead. This is
   the **anchor consensus**.
2. **Propose a layout.** From the variance at each delta, pointer-likeness of
   the words and, optionally, the bounds of the allocator chunk, MemDiver
   proposes fields: the anchor, other values it can verify (for example the
   client random), pointers, constant bytes, small value sets and variable
   bytes. Alternatives are kept, never silently merged.
3. **Build and export.** You say which fields mean what (or take the key-log
   defaults). The model is written as JSON, then exported as a Volatility 3
   plugin.
4. **Validate on held-out dumps.** The plugin runs on captures that were *not*
   used for learning. Only these numbers count. The learning dumps' own numbers
   are circular.

```{admonition} Requirements
:class: important
- The dumps must be **`.msl` captures with a virtual-address view**. A raw dump
  is refused. See [Limits](#limits).
- The held-out dumps must be **disjoint** from the learning dumps. A leak is
  refused with `semantic.held_out_leak`.
- All dumps must come from **one cohort** (the same library and workload). A mix
  is refused with `cohort.mixed`. Do not set `--mixed-ok` to silence it. Build
  one model per cohort.
- **Validation needs the `volatility3` extra.** Building and exporting do not.
- **Output paths must be NEW files** inside the write roots (the MemDiver home
  and the upload directory). Nothing is overwritten. Use a new path for every
  build.
```

## Worked example: OpenSSL TLS 1.3

The data is a corpus of TLS 1.3 client runs of OpenSSL on aarch64. Each run has
an `.msl` capture and a `keylog.csv` with the real secrets. Runs `13_1` to
`13_16` were used for the walkthrough, with `CLIENT_TRAFFIC_SECRET_0` as the
anchor.

### 1. Anchor consensus

```bash
memdiver consensus-anchor run_13_{1..8}.msl \
    --keylog all_keylogs.txt \
    -o anchor.json
```

Read `keylog_resolution` in the output. Each dump must resolve to its **own**
session, the one whose anchor secret is actually present in that dump. A dump
where no session matches, or several do, is reported as unanchored with a
reason. MemDiver never guesses. For eight dumps, the layout around the anchor
comes out the same in all eight.

### 2. Propose a layout

```bash
memdiver propose-layout run_13_{1..8}.msl \
    --keylog all_keylogs.txt \
    -o layout.json
```

On the real runs, all eight dumps agree on one object:

- An allocator chunk of **0x1510 bytes**. The anchor sits at **user + 0x6fc**.
  This is the OpenSSL connection object.
- The `client_random` is a verified field at **delta -0x5bc** in 8 of 8 dumps.
- `SERVER_TRAFFIC_SECRET_0` is at **delta +0x40** in 8 of 8 dumps.
- 34 pointer words and 4,534 constant bytes in the object.

Review `fields` and their `evidence`. Pass `--no-heap` to skip the
allocator-chunk bounds. `--anchor-length` defaults to the needle length.

### 3. Build the model

```bash
memdiver model-build run_13_{1..8}.msl \
    --keylog all_keylogs.txt \
    --name openssl_tls13 \
    --out-path openssl_tls13.model.json
```

With no spec given, the meanings and relationships come from the key log. Each
secret is labelled with its NSS label and `owned_by` points to the session's
`client_random`. Naming a field that the layout did not propose is refused. In
the gnutls case, the layout has no constant-delta owner and the build stops (see
[Limits](#limits)). The command prints `path` and `sha256`. Read the model's
`warnings` before going on (see [Robustness](#robustness)).

### 4. Export the plugin

```bash
memdiver model-export openssl_tls13.model.json --out-path openssl_tls13_plugin.py
```

The model must pass its own consistency check first. The exported plugin
contains the model as provenance, a scan pattern, the field layout, and one
output row per asserted secret with its owner and status.

### 5. Validate on held-out dumps

```bash
memdiver model-validate openssl_tls13.model.json \
    --keylog all_keylogs.txt \
    --held-out-dumps run_13_{9..16}.msl \
    --out-path openssl_tls13.validated.json
```

`--out-path` writes the model again with the validation recorded in it. Without
`--keylog` use `--held-out-file` for a per-dump list, or `--keylog-run-dir` for
run directories that pair `dumps/msl/*.msl` with `keylog.csv`.

```{admonition} The real result
:class: tip
- **Learn 8, hold out 41** (every other usable run of the corpus): **82/82**
  secrets found, **0 false positives**, 0 false negatives, and the owning
  session correct in **82/82**. Verdict: `pass`. The two asserted secrets per
  capture are `CLIENT_TRAFFIC_SECRET_0` and `SERVER_TRAFFIC_SECRET_0`.
- The same protocol on BoringSSL also gives 82/82 over 41 held-out runs. See
  [Robustness](#robustness) for why that number needs a caveat.
```

## The key-log flow

You do not need to type any hex. A key log is a file in the **NSS key log
format** (`SSLKEYLOGFILE`), as written by friTap and read by Wireshark. Each row
is `<LABEL> <client_random_hex> <secret_hex>`.

- **Per-dump or shared.** Give one key log for all dumps with `--keylog`, or one
  per dump with `--keylog-per-dump` (inline JSON or a JSON file mapping the dump
  to its key log). A shared file may hold the sessions of many runs. Each dump
  is matched to the session whose secret it **contains**, found by exact
  search.
- **Anchor label.** `--anchor-label` names the label whose secret anchors each
  dump. The default is automatic: `CLIENT_TRAFFIC_SECRET_0` if the key log has
  it, otherwise the TLS 1.2 master secret (the `CLIENT_RANDOM` row). The
  result shows which label was used.
- **Related labels.** `--related-labels` names the other secrets of the session
  to locate and put in the model (default: all of them).
- **TLS length rules.** A traffic secret is 32 bytes (SHA-256 suites) or 48 bytes
  (SHA-384). Shorter or longer secrets are not searched. The anchor length
  defaults to the needle length, so a 32-byte-secret library such as BoringSSL
  needs no manual setting.
- **Malformed lines are reported, not hidden.** A truncated secret, for example
  `CLIENT_TRAFFIC_SECRET_0 secret is 2 bytes, expected one of [32, 48]`, is
  dropped with its line number in a malformed-line report. Lines for labels
  that cannot be searched (RSA, `PMS_CLIENT_RANDOM`) are counted as ignored. A
  `#` comment and the corpus header line are accepted.

On the real data, the key-log flow ran with nothing typed. Learning on
`13_1`..`13_8` resolved each dump to its own session with one concatenated
shared key log, and also with per-dump logs. The model that came out passed its
consistency check. Validating on `13_9`..`13_16` with the same shared key log
gave **24/24** secrets (three asserted secrets per capture, 8 captures), no
false positive or negative, and the owner right in 24/24. The default model
also asserts `EXPORTER_SECRET`. With related labels restricted
to `SERVER_TRAFFIC_SECRET_0`, the model asserts two secrets per capture and
scored 16/16, with no false positive and the owner right in 16/16.

```{admonition} A dropped line changes the verdict
:class: warning
If a held-out key log line is malformed, that secret leaves the **ground truth**
for that capture. The plugin's correct recovery of it then counts as
*unexpected*, and the verdict can be `fail`. The validation payload carries the
malformed-line report (`keylog_summary`) next to the verdict so you can tell a
broken key log from a broken model.
```

## Reading the verdict

`model-validate` returns `totals` (expected, tp, fp, fn, relationships) and a
`verdict`. It also gives one row per capture.

- **What is expected.** For each capture, the expected set is the key-log
  sessions whose asserted secrets are actually **present** in that capture,
  found by an exact search that is independent of the plugin. A secret that
  the key log lists but that is not in memory is reported `not_in_memory`. It is
  **never** counted as a false negative.
- **`indeterminate`.** A capture with no such session proves nothing. It is
  marked `indeterminate` and is **not a pass**.
- **`pass`.** A capture passes only when it is exact: all expected secrets
  found, no false positive and every relationship (such as the owner) correct.
  One failing capture fails the set.
- **`fail`.** Look at `fn` first (the pattern is too specific), then `fp` (too
  loose), then the relationships.

Report the held-out numbers only. The learning dumps will score perfectly by
construction.

## Robustness

A plugin has to find an object quickly, so it first matches a short **prefilter
window** (a few literal bytes of the object at a fixed delta) and then checks
the anchor and fields. Pointer words are wildcarded and never matched
literally, since heap addresses differ between runs.

The risk is a prefilter that rests on bytes that are an artifact of *your*
experiment. Held-out dumps from the same experiment cannot reveal that.

- **OpenSSL** is safe in this sense. Its prefilter has 48 informative bytes,
  and they are the TLS 1.3 SHA-384 early-secret constant. The pointer word in
  the window is wildcarded.
- **BoringSSL** is not. Its prefilter has only **5** informative bytes:
  `00 00 00 00 05 00 17 03 03 00 fc`. That is a TLS application-data record
  header whose **payload length `0xfc` is fixed by the test workload**.

The mutation test makes the problem concrete. Changing `fc` to `fd` in
held-out BoringSSL dumps turned **0 of 8** expected secrets found (8/8 found
before; four dumps, two secrets each). The verdict went from `pass` to `fail`,
and every miss was a false negative. A different payload length would hide the
object from the plugin.

**Redundant windows** are the product answer. The builder keeps the primary
prefilter and adds up to two disjoint in-object alternatives of at least four
informative bytes each. The exported plugin matches any of them. A hit is
deduplicated by object base, and a new `Windows` column says which windows
matched. With alternatives, the patched dumps scored **6/6** with no false
positive: the primary window found 0 of them and the alternative window found
all 6. On the unpatched dumps, all 6 of 6 were found by at least two windows.

Two outputs make the residual risk visible:

- **`warnings`** on the model, repeated in the validation payload.
  `prefilter.low_information` means the primary window rests on fewer than 8
  informative bytes. `prefilter.no_alternative` means no alternative window
  could be built.
- **`window_redundancy`** in the validation payload: `tp_by_window`,
  `tps_found_by_multiple_windows` and `tp_total`. If
  `tps_found_by_multiple_windows` is **below** `tp_total`, some hits depend on
  one window, and a different workload or platform may miss them.

Only a cohort that differs in workload or platform is a real proof. No such
cohort was available for BoringSSL on this corpus, so the warning and the
summary are there to say so instead of hiding it. State this in your report.

## Limits

- **gnutls is refused.** In the eight learning runs, the `client_random` is not
  at one constant delta from the secret, so no `owned_by` relationship can be
  learned. The builder refuses (the relationship names a field that was never
  proposed) and writes no model. This is a correct negative, not a bug. 
- **`.msl` with a virtual-address view only.** A raw dump, an ELF core or a
  regioned dump without one is refused with `semantic.no_va_view`. The error
  names the dump and its source type. For a raw dump with a process map, make
  a proper capture first:

  ```bash
  memdiver import dump.raw --maps proc_pid_maps.txt -o dump.msl
  ```

  Without maps the raw dump has no regions, and what depends on them stays
  unavailable. For an ELF core or minidump, `memdiver import dump` keeps the
  virtual-address map.
- **Held-out must be new.** The same run cannot teach and test.
- **The model is exact where it was learned.** It describes the layout of the
  cohort you learned from. A library update that moves fields needs a new model.
  The validation record says on which dumps it was learned and tested.
- **Large addresses.** The web panel sends addresses as JSON numbers, which is
  exact for process addresses. Use the CLI or MCP for kernel-space addresses.

## On the three surfaces

| Step | Web UI (Object model panel) | CLI | MCP tool |
|---|---|---|---|
| Anchor consensus | **Anchor consensus** | `memdiver consensus-anchor` | `anchor_consensus` |
| Layout | **Propose layout** | `memdiver propose-layout` | `propose_layout` |
| Build | **Build model** | `memdiver model-build` | `artifact_model_build` |
| Export | **Export plugin** | `memdiver model-export` | `artifact_model_export` |
| Validate | **Validate on held-out dumps** | `memdiver model-validate` | `artifact_model_validate` |

In the web UI, choose the anchor input first: **Hex needle per dump** or
**Key log**. A key log can be a file chosen in the browser (up to 4 MiB), one
server path for all dumps, or a server path per dump. The label select defaults
to **Automatic (TLS 1.3 traffic secret, else TLS 1.2 master secret)**. The
panel shows the key-log resolution per dump (anchored, absent or ambiguous with
a reason), a malformed-line report, and the proposed layout with each field's
kind, evidence and alternatives. The Build form is pre-filled from the key log.
An output path outside the write roots is answered with a 403 that names the
path and the allowed locations. Validate accepts a path per held-out dump, one
shared file, or one shared server path. An indeterminate capture is labelled
"not a pass".

For an agent, the MCP playbooks `n_image_variance` (cohorts, consensus and
anchor consensus over N dumps) and `object_model_from_keylog` (this page's flow,
with the parameters and the traps) mirror these steps.

## Where next

- [](keyfinders.md) finds the key in a single capture and verifies it.
- [](locate_key.md) searches for a known secret in N dumps.
- [](keylog_export.md) writes the NSS key log from recovered secrets.
