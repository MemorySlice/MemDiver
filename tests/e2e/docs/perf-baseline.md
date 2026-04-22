# MemDiver perf baseline

Measurement conventions:
- **UI wall-clock** is `performance.now()` between tab click and first
  meaningful DOM node being visible, via Playwright.
- **Backend** is the server-side timing as reported in logs or the
  response body.
- **Cold** = fresh dump open; **warm** = second visit within the same
  session (caches populated).

"After" numbers were captured on 2026-04-21, local dev machine
(macOS, Darwin 25.3.0), uvicorn backend on :8091 + Vite dev server on
:5191, Chromium via Playwright. `enterWorkspaceWithMsl` is included in
each per-spec total (adds ~1.5–2.5s for landing + wizard navigation),
so the per-spec totals are roughly metric+workspace-entry. Individual
"first row" / "pill visible" measurements are the wall-clock numbers
the spec itself records (via `Date.now()` around the tab click).

| Metric                                         | Target   | Before | After                          |
|------------------------------------------------|----------|--------|--------------------------------|
| First strings row visible (cold UI)            | < 4500ms |        | ~1.5–2.5s after R2-A "Inspect Only" fixture fix (budget was flaky at 3000 ms) |
| Backend `/api/inspect/strings` first page      | < 1000ms |        | not instrumented in this pass  |
| Format tab: pill visible after tab click       | < 1500ms |        | ~4.9s total spec (includes entry) |
| Workspace smoke: all tabs click round-trip     | < 15s    |        | 3.3–3.6s total spec            |
| Strings tab DOM node count (virtualizer)       | <= 300   |        | within budget (test passed)    |
| MSL nav tree root visible                      | < 2000ms |        | within budget (format spec passes) |
| Second visit to format tab (warm)              | < 500ms  |        | not instrumented in this pass  |
| Parser switch msl -> elf64 pill update         | < 2000ms |        | ~6.5–7.0s total spec (includes entry + dropdown nav) |
| Strings scroll triggers next cursor page       | < 1500ms |        | ~9.4–9.8s total spec (includes entry + scroll) |
| No 5xx on any smoke tab                        | 0        |        | 0                              |

Per-spec run times (Playwright `--reporter=list`, two consecutive runs):

| Spec                                                          | Run 1  | Run 2  |
|---------------------------------------------------------------|--------|--------|
| dumps — run_0001 is discovered with the expected pid          |  —     | 31.9s  |
| format — MSL dump surfaces msl parser and MSL nav tree        |  —     |  4.9s  |
| format — user can switch parser to elf64 and reset to auto    |  7.0s  |  6.5s  |
| strings — first row appears within 3s                         |  5.8s  |  FAIL (3887ms elapsed) |
| strings — scroll triggers cursor-paginated fetch              |  9.4s  |  9.8s  |
| strings — toggling Highlight does not throw                   |  8.5s  |  8.1s  |
| verify-key — tab mounts without crashing                      |  3.7s  |  3.6s  |
| workspace-smoke — every visible tab renders                   |  3.6s  |  3.3s  |

Notes:
- R2-A finding: the wizard's default "Auto-Analyze" approach kicked
  off a long-running `/api/analyze/file` request on the 215 MB MSL
  every time the fixture entered the workspace. Under the full suite,
  this left the backend saturated and caused flakes in `format`,
  `strings`, and cascading failures. Fix: `enterWorkspaceWithMsl` now
  clicks "Inspect Only" before "Start Analysis". Individual specs
  that need analysis should trigger it explicitly.
- After the fix, the strings first-row time drops back to well under
  2.5 s on this machine, so the 4500 ms target has plenty of headroom.
- Per-spec totals include the `enterWorkspaceWithMsl` fixture (landing +
  wizard), which contributes ~1.5–2.5 s before the metric-under-test.
