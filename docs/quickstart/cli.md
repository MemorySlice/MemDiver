# CLI quickstart

MemDiver exposes a single console script `memdiver` with 35 subcommands. The most common entry points:

```bash
# One-shot analysis on a library directory
memdiver analyze <library_dirs> --phase post_handshake_end --protocol-version TLS13

# Dataset sweep
memdiver scan --root /path/to/dataset

# Batch of analysis jobs
memdiver batch --config batch.json

# Already know the key? Find where it sits in every dump
memdiver locate-key runs/ --key-hex '<hex>' -o loc.json
```

`locate-key` exits `0` when the secret is found, `3` when it is proven absent
and `2` when nothing could be searched or the input is invalid (for example a
dump path that does not exist). See
[Locating a known key](../user_guide/locate_key.md) for the full workflow.

:::{tip}
Run `memdiver scan --root <dataset>` first to see which phases your dataset
actually contains. Canonical phases are defined in
`core/phase_normalizer.py:CANONICAL_PHASE_ORDER`
(`pre_handshake_end`, `post_handshake_end`, `pre_close`, `post_close`, …).
:::

## Looking at the heap

`heap` finds the allocator that owns a dump's heap (glibc ptmalloc2,
dlmalloc, Scudo, musl mallocng, jemalloc, or a generic fallback) and walks
its chunks:

```bash
# Which allocator, how sure, chunk counts by state and a size histogram
memdiver heap summary dump.msl
# Ranked allocator candidates with their evidence
memdiver heap detect dump.msl
# Free (cached) chunks between 64 and 256 bytes, as JSON
memdiver heap chunks dump.msl --state cached --min-size 64 --max-size 256 --json
# The chunk that holds an address, and its neighbours
memdiver heap at dump.msl --va 0x555555559300
# Walked free lists (tcache, fastbins, ...)
memdiver heap free-lists dump.msl --kind tcache
# Byte roles (header, user data, free link, ...) of the first 4 KiB, as JSON
memdiver heap roles dump.msl --view vas --offset 0 --length 0x1000 --json
```

Every action takes `--allocator` to skip detection, `--base-va` for a flat
raw dump that has no memory map, the same decryption flags as `inspect`, and
`--json` for the machine-readable payload.

The consensus-backed commands also use the heap. `consensus`,
`consensus-window`, `consensus-regions`, `analyze-candidates` and `locate-key`
take `--allocator {auto,ptmalloc2,dlmalloc,scudo,mallocng,jemalloc,generic,off}`
(default `auto`; `off` turns heap analysis off). `analyze-candidates` and
`search-reduce` also take `--heap-policy {annotate,mask,off}`:

```bash
# Default: tag each candidate with its heap chunk, ranking unchanged
memdiver analyze-candidates dumps/ -o cands.json
# Remove allocator metadata from the candidates (count in stages.heap_masked)
memdiver analyze-candidates dumps/ --heap-policy mask -o cands.json
# Which hits of a known key sit in freed (residual) chunks?
memdiver locate-key dumps/ --key-hex '<hex>' --allocator ptmalloc2 -o loc.json
```

The JSON payload carries the heap data as it is. On stderr, `consensus`
prints a `heap status=...` line, and `analyze-candidates` and `locate-key`
print one line per chunk-resident candidate or hit, with hits in freed chunks
marked `residual`. `search-reduce` reads a Welford `--state` session that has
no heap roles, so `annotate` does nothing there and `mask` is refused.

## Importing only some regions

```bash
# What would an import keep? (dry run, nothing written)
memdiver import core.1234 --list-regions --regions heap,stack
# Import only heap + stack (scripts / CI never prompt; without flags they import everything)
memdiver import core.1234 -o capture.msl --regions heap,stack
```

Run `memdiver import core.1234` in a terminal without region flags to pick
categories interactively (heap, stack and unclassified are preselected). See
[Import region selection](../user_guide/cli_reference.md) for every flag,
including `--materialize` for `.msl` input.

## When a consensus is too big for memory

Consensus-building commands (`consensus`, `consensus-window`, `consensus-regions`,
`analyze-candidates`, `analyze`, `batch`, `export --auto`, `experiment`) check
the estimated peak memory first and refuse when it exceeds the budget (70 % of
available RAM, or `MEMDIVER_MEMORY_BUDGET_MB`). Narrow the input
(`--regions heap,stack`, fewer dumps) or override the refusal:

```bash
memdiver consensus dumps/ --force-memory -o consensus.json
```

See [Memory budget](../user_guide/cli_reference.md) for details.

## Complete subcommand list

Detection &amp; analysis
: `analyze`, `scan`, `batch`, `verify`, `inspect`, `inspect-pcap`, `heap`

Consensus (incremental Welford)
: `consensus`, `consensus-begin`, `consensus-add`, `consensus-finalize`, `consensus-window`, `consensus-regions`

Pipeline (Phase-25 orchestration)
: `search-reduce`, `analyze-candidates`, `brute-force`, `n-sweep`, `auto-floor`, `emit-plugin`

Known secret &amp; detectors
: `locate-key`, `locate-field-pairs`, `export-key-pattern`, `scan-yara`, `verify-plugin`, `score-detector`

Format conversion
: `export`, `export-keylog`, `gen-kem-key`, `import`, `import-dir`

Runtime shells
: `web`, `ui`, `mcp`, `experiment`, `capture`

Run `memdiver <subcommand> --help` for flags, or see the full autogenerated [CLI reference](../user_guide/cli_reference.md).
