---
myst:
  html_meta:
    "description lang=en": "Automated, ground-truth-free variance-floor selection for key recovery in MemDiver."
---

# Auto-floor: automated variance-floor selection

`memdiver auto-floor` answers one question about a memory-dump corpus without
any ground truth: **is the key here, and if so where — and was the shipped
variance floor set too high to find it?** It emits exactly one verdict.

The central idea is a reframing. In the classic pipeline the variance floor
`φ` is a *correctness gate*: a candidate below the floor is discarded, so a
floor set too high silently drops the key. Auto-floor demotes the floor to a
*search-ordering cursor*. The decryption oracle you supply (an AEAD tag check,
false-accept ≈ 2⁻¹²⁸) is the only thing that decides whether a candidate is
the key. The floor only decides the **order** in which candidates are handed to
the oracle. Every variance-estimate error therefore costs extra latency, never
a miss.

```{admonition} One sentence
:class: tip
The oracle decides *correctness*; the floor only decides *order*. So the worst
a mis-set floor can do is make the search slower — it can never hide the key.
```

## How it works

```{mermaid}
flowchart LR
    C[Consensus<br/>per-byte variance] --> M[Maximal candidate set<br/>entropy + alignment only<br/>floor disabled]
    M --> R[Rank by window variance<br/>best-first]
    R --> O{Oracle<br/>AEAD tag}
    O -->|accept| V[Verdict]
    O -->|reject all| V
    F[φ = p_min·σ_k²<br/>policy floor] -.orders.-> R
    F -.-> V
```

1. Build the **maximal** candidate set once, with the floor *disabled* — only
   the entropy and alignment gates apply. This is the set the oracle *could*
   ever be asked about.
2. Rank the maximal set by descending window variance.
3. Walk the ranking best-first, handing each distinct candidate to the oracle,
   until one verifies or the set is exhausted.
4. Emit one verdict, recording where the recommended floor `φ` sat relative to
   the hit.

## The four verdicts

::::{grid} 2
:gutter: 3

:::{grid-item-card} ✅ RECOVERED
The key verified **at or above** the shipped default floor. The default would
already have found it — nothing was wrong.
:::

:::{grid-item-card} ⬇️ FLOOR_WAS_TOO_HIGH
The key verified only **below** the default floor. The default would have
missed it; the lowered/best-first search caught it. This automates the manual
"drop the floor" workflow.
:::

:::{grid-item-card} 🚫 ABSENT
The oracle rejected the **entire** maximal set, under stated reachability
preconditions. Qualified by a confidence = coverage × filter-recall.
:::

:::{grid-item-card} ❔ INCONCLUSIVE
A diagnostic gate failed — unhealthy oracle, coverage below `--min-coverage`,
exhausted `--oracle-budget` (reason `cost`), low alignment (`alignment`), or a
managed/moving-GC heap (`regime`). Never a false ABSENT.
:::

::::

```{admonition} Why ABSENT is conditional
:class: note
A negative is only trustworthy if the key *could* have been seen. Auto-floor
returns `ABSENT` only when the maximal set was fully swept under established
preconditions (resident in all captures, contiguous, materialized,
stride-aligned, within coverage, offset correspondence established). If a
budget ran out, alignment was poor, or the target is a managed heap, the
verdict downgrades to `INCONCLUSIVE` with a reason rather than claiming absence.
```

## Quickstart

Auto-floor consumes a finalized Welford **consensus state** and your oracle:

```bash
# 1. Build a consensus over your aligned dumps (Welford, incremental)
memdiver consensus-begin  --out state.json ...
memdiver consensus-add    --state state.json dump_02.raw
memdiver consensus-finalize --state state.json

# 2. Run auto-floor — one verdict, oracle-arbitrated
memdiver auto-floor \
    --state state.json \
    --reference-dump dump_01.raw \
    --oracle ./my_oracle.py \
    --p-min 0.35 \
    --output-dir ./verdict
```

The output directory receives `verdict.json` (machine-readable) and
`report.md` (the sweep curve, the recovered offset, and where `φ` sat). See
[the oracle interface](../oracle/interface.md) for how to write `my_oracle.py`.

## The floor: φ = p_min · σ_k²

A fixed floor conflates two different things — how *often* a key byte is
resident across runs (`p_i`) and the ceiling variance of a full-entropy byte
(`σ_k²`). The level set `{Var = φ}` is a curve in that plane, not a line at a
fixed presence. To *retain* a key that is present in a `p_min` fraction of runs
you set

$$ \varphi = p_{\min}\cdot\sigma_k^2 ,\qquad \sigma_k^2 = \frac{256^2-1}{12}=5461.25 .$$

This turns the floor into a **retention policy** you can state in one number:
"keep any key resident in at least `p_min` of runs." The shipped default
`3000` silently assumes `p_min = 3000/5461 ≈ 0.55`; dropping to `p_min = 0.35`
gives a floor near the hand-tuned value analysts had been using.

`σ_k²` is estimated empirically from the least-diluted interior of candidate
windows (P90, clamped to `[½·σ_k², σ_k²]`). That estimate is only trusted once
there are enough captures: with the defaults (`p_min = 0.35`, presence target
`k = 5`) the gate is `N ≥ ⌈k/p_min⌉ = 15`. Below it, auto-floor falls back to
the conservative ceiling `σ_k² = 5461.25`.

```{image} ../_static/auto_floor_cphi.svg
:alt: Candidate count C(φ) versus variance floor on the gocryptfs corpus, N=100
:width: 90%
:align: center
```

The curve above is measured on the gocryptfs corpus (N = 100). As the floor
descends the candidate count grows smoothly; the key window (mean per-byte
variance ≈ 4310) is retained at *every* floor on the ladder, including the
shipped default 3000. The floor never gates the key out — it only sets how
many candidates precede it in the oracle queue.

## Parameter reference

### Recommended floor

| Flag | Default | Principle |
|---|---|---|
| `--phi0-method` | `pmin` | `pmin` uses the retention-policy floor φ = p_min·σ_k² (recommended). `otsu` is the legacy data-driven valley fit (see [below](#what-does-not-help)). |
| `--p-min` | `0.35` | Retention policy: keep keys resident in ≥ `p_min` of runs. Lower ⇒ deeper floor ⇒ more candidates retained (and oracle-tested). Sets the `N ≥ ⌈5/p_min⌉` gate for trusting the empirical σ_k². |

### Candidate formation

| Flag | Default | Principle |
|---|---|---|
| `--key-sizes` | `32` | Comma-separated key widths to enumerate. |
| `--stride` / `--alignment` | `8` | Candidate grid step / expected key alignment in memory. |
| `--block-size` | `32` | Region-formation block granularity. |
| `--entropy-window` / `--entropy-threshold` | `32` / `4.5` | High-entropy gate: windows below the bits/byte threshold are not key-like and never enter the maximal set. |
| `--density-threshold` | `0.5` | Minimum high-entropy density for a region to survive. |
| `--min-region` | `16` | Smallest region size retained. |

### Oracle & verdict gating

| Flag | Default | Principle |
|---|---|---|
| `--oracle` | *required* | Your `verify(bytes) -> bool`. SHA-256 audited on load; no sandbox — treat like `find -exec`. |
| `--oracle-config` | *none* | Optional TOML passed to `build_oracle` for stateful oracles. |
| `--reference-dump` | *required* | The dump the oracle verifies candidate bytes against. |
| `--self-test-trials` | `8` | Random-negative probes proving the oracle rejects noise and is deterministic. Each costs one call — lower it for rate-limited/one-shot oracles. |
| `--positive-control` | *none* | Hex of a known-good key; adds one self-test call that must *accept*. |
| `--oracle-budget` | *none* | Cap on total oracle calls. Exhausting it yields `INCONCLUSIVE(cost)`, **never** a false `ABSENT` — the safe verdict for expensive oracles. |
| `--coverage` / `--min-coverage` | *none* / `0.80` | Cross-run coverage C∩. Below `--min-coverage` ⇒ `INCONCLUSIVE(coverage)`; otherwise qualifies the `ABSENT` confidence. |
| `--filter-recall` | *none* | Entropy/alignment filter recall; the second factor in `ABSENT` confidence = coverage × recall. |
| `--correspondence` | *none* | Reported offset-correspondence score in [0,1]. |
| `--alignment-quality` / `--min-alignment` | *none* / `0.5` | Per-region alignment quality; below the minimum a no-hit is `INCONCLUSIVE(alignment)`. |
| `--managed-region` | off | Flags a managed runtime / moving-GC heap: a no-hit is `INCONCLUSIVE(regime)`, since off-grid object headers can hide the key. |

## Offline research harness (zero oracle calls)

Two scripts under `scripts/` let you *measure* the floor machinery on a corpus
with a **known** key offset, without ever calling an oracle — useful for
validation and for deciding whether a richer ordering is worth building.

```bash
# Build a flat-VAS consensus (variance.npy + reference.bin + meta.json)
python scripts/build_gocryptfs_consensus.py \
    --dataset /path/to/dataset_gocryptfs --n 100 \
    --emit-halves \
    --out artifacts/consensus_n100

# Score it offline: maximal set, R_var, R_composite, φ-selection (+ A3 if halves)
python scripts/phase_a_experiment.py \
    --consensus-dir artifacts/consensus_n100 \
    --key-offset 0x57a220
```

`R_var` is the number of oracle calls a plain descending-variance sweep would
need to reach the key — computed as a *count*, with zero oracle calls. It is
the offline mirror of the live sweep length. `--emit-halves` additionally
writes the complementary-half variance arrays used by the experimental
subsample-stability instrument ([below](#experimental-subsample-stability)).

### Validated on real data (gocryptfs, N = 100)

Rebuilding the consensus over 100 captures and scoring it offline (zero oracle
calls) reproduces the maximal set exactly and sharpens every floor estimate:

| Quantity | N = 20 | N = 100 |
|---|---|---|
| Maximal candidate set | 115,635 | 115,635 |
| σ_k² (P90 interior) | 4,578 | 3,023 |
| φ_theory(0.35) = 0.35·σ_k² | 1,602 | 1,058 |
| φ_theory(0.55) | ≈ 2,518 | 1,663 |
| φ_knee (descending Kneedle) | 2,500 | **1,500** |
| key retained at φ_knee / default 3000 | — | ✅ / ✅ |

At N = 100 the empirical knee lands **exactly** on the analysts' hand-tuned
floor of 1500, and the policy floor and the knee bracket the manual region
(φ_theory(0.35) = 1058 … φ_knee = 1500 … φ_theory(0.55) = 1663). The key window
is retained at every floor. A principled floor is recoverable as a *policy*,
not a fitted valley.

(what-does-not-help)=
## What does *not* help (and why)

These are honest negatives — measured, and deliberately **not** load-bearing.
They are recorded here rather than in the paper because they argue *against*
building things.

- **A richer ordering statistic barely helps.** Re-scoring the maximal set with
  a single-capture uniformity gate (min-entropy, byte-uniformity χ², low
  autocorrelation) before ranking by variance demotes only *structured*
  clutter. Measured: `R_composite = 6,972` vs the variance baseline
  `R_var = 7,179` — a 2.9 % reduction. The remaining outranking candidates are
  per-run-fresh *uniform* clutter (5,593 at the ceiling) that is statistically
  identical to the key on any single-capture statistic. Only the oracle can
  pass it. Ordering is **not** the lever.
- **Data-driven valley-fitting (`--phi0-method otsu`) is unstable.** On the
  gocryptfs consensus the high-variance component has no clean valley, so the
  Otsu edge estimate lands near 7730 and clamps to the default 3000 — a floor
  that would miss the key. The policy floor (`pmin`) is stable where the valley
  fit is not; `otsu` is kept only as a selectable comparison.
- **The persistence-vs-freshness discriminator does not apply here.** Telling a
  persistent key (recurs across runs) from a fresh nonce works only when the
  *same* secret is captured repeatedly. In this corpus every run uses a
  different password, so the key is fresh-random per run and the discriminator
  is inapplicable. It applies to same-secret corpora.
- **The key is not "low-variance."** The mixture model predicts diluted keys sit
  below fresh clutter; here, because each key is fresh per run, the key window
  is *high* variance (mean ≈ 4310–6060). The "floor too high" effect at N = 20
  was an enumeration/region-formation boundary effect, not a window-mean
  collapse.

(experimental-subsample-stability)=
## Experimental: subsample stability

```{admonition} Experimental — needs further research
:class: warning
The instrument below is not a shipped default and not a validated result. It is
recorded as a direction, measured once at N = 100.
```

The sample-variance relative error over `m` observations is ≈ √(2/(m−1)). At
N = 20 (m ≈ 10 per half) that is ≈ 0.47 and swamps any signal; only at
N ≳ 100 (m ≈ 50, ≈ 0.20) does variance *stability* become informative. The
subsample-stability instrument splits the captures into two complementary
halves (`--emit-halves`), computes per-byte variance on each, and scores every
candidate window by how closely the two halves agree — rewarding windows that
are high-variance *and* stable.

Measured at N = 100: the key window's cross-half agreement (rel-err 0.212)
matches the theoretical scale (0.202) almost exactly — confirming the regime is
finally large enough for the signal to exist. The stability-aware ranking gives
`R_stable = 6,660` vs `R_var = 7,179` (a 7.2 % reduction — more than the
uniformity gate's 2.9 %). It is a real, if modest, gain that grows with N, but
it remains far from oracle-competitive: on a per-run-fresh-clutter target,
stability cannot rank the key first. Whether it becomes useful on same-secret
corpora, or at N ≫ 100, is open.

## See also

- [Oracle interface](../oracle/interface.md) — writing the `verify()` your
  auto-floor run needs.
- [CLI reference](cli_reference.md) — the full `memdiver auto-floor` flag list.
- [Dataset layout](../file_formats/dataset_layout.md) — how captures are
  organized for consensus building.
