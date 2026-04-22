# MemDiver manual UX checklist

Scale: 1 = absent/broken, 3 = present but thin, 5 = clear and polished.

Findings captured programmatically by `specs/ux-audit.spec.ts`
(see `playwright-report/ux-screenshots/findings.json`) plus visual
review of the PNGs in `playwright-report/ux-screenshots/`.

Audit pass: 2026-04-21 (R2-A). Dataset loaded via `Inspect Only`
wizard path so no analysis results are visible; scores reflect the
empty-state experience for a freshly opened MSL.

| Tab            | Clarity | Pill consistency | Loading state | Empty state | Error state | Focus ring |
|----------------|---------|------------------|---------------|-------------|-------------|------------|
| bookmarks      | 4       | N/A              | N/A           | 4           | 3           | 5          |
| dumps          | 4       | 3                | 3             | 3           | 3           | 5          |
| format         | 5       | 5                | 4             | 4           | 3           | 5          |
| structures     | 3       | 2                | 3             | 3           | 2           | 5          |
| sessions       | 3       | N/A              | 3             | 3           | 2           | 5          |
| import         | 4       | N/A              | 3             | 3           | 3           | 5          |
| analysis       | 5       | 4                | 4             | 4           | 4           | 5          |
| results        | 3       | 3                | 3             | 3           | 3           | 5          |
| strings        | 5       | 4                | 4             | 4           | 3           | 5          |
| entropy        | 4       | 3                | 4             | 3           | 3           | 5          |
| consensus      | 3       | 2                | 2             | 3           | 2           | 5          |
| live-consensus | 2       | 2                | 2             | 2           | 2           | 5          |
| architect      | 2       | 1                | 1             | 2           | 1           | 5          |
| experiment     | 2       | 2                | 2             | 2           | 2           | 5          |
| convergence    | 3       | 2                | 2             | 3           | 2           | 5          |
| verify-key     | 4       | 3                | 3             | 4           | 3           | 5          |
| pipeline       | 5       | 4                | 4             | 4           | 4           | 5          |
| (overview)     | 4       | 4                | 3             | 4           | 3           | 5          |

Observations per tab (from `findings.json`):
- Every tab renders a heading or semibold-styled title — `headingVisible: true` for all 17 tabs.
- No `[role=alert]` was surfaced on any tab during the cold tour, so
  the error-state score reflects a code/UX review rather than an
  observed alert.
- The focus ring on the tab buttons themselves (header bar) is
  consistent across all tabs — tailwind focus styles on the tab
  buttons behave the same way everywhere.
- Exploration-mode tabs (`entropy`, `consensus`, `live-consensus`,
  `architect`, `experiment`, `convergence`) only appear after the
  mode-banner toggle, which the audit spec engages automatically.

## Top 3 weakest tabs (action items)

1. **architect** — placeholder stub (`ArchitectPlaceholder`). No
   loading/empty/error affordance beyond static text; no pill; feels
   like a todo rather than a feature. Action: replace with at least an
   "under construction" banner + link to docs.
2. **live-consensus** — Consensus Builder renders an empty canvas
   with no inline copy explaining what to do next; no empty-state
   copy, no obvious error surface. Action: add a header + call-to-
   action or hint text ("Run an analysis first, then live consensus
   will populate here").
3. **experiment** — Panel mounts blank; no visible heading or pill,
   no loading state, no error state. Action: same as above — at
   minimum an empty-state description so users know the tab exists
   on purpose.

Runner-up: `consensus` and `convergence` both surface only a chart
component; when the analysis result is empty, users see a blank
plot with no guidance that they need to run analysis first.

## Strongest tabs

- **analysis**, **strings**, **format**, **pipeline** all have
  explicit empty-state copy ("Load a dump file to...", "Click a
  structure..."), clear headings, and pill/tab badges that make
  state changes obvious.
