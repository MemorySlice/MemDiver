# frontend/

React + Vite + TypeScript + Tailwind + Zustand SPA. Built bundle ships under `frontend/dist/` and is served by the FastAPI backend at `/`.

## Stack

- React 19, Vite 8, TypeScript 5.9, Tailwind v4 (pure CSS tokens, no shadcn/radix).
- Zustand 5 for state.
- `react-resizable-panels` for the IDA-style dockable layout.
- `react-plotly.js` for charts; `@tanstack/react-virtual` for hex rows.
- `driver.js` for first-time-user tours.

## Top-level views

No URL routing today. `useAppStore.appView` switches between `landing`, `wizard`, and `workspace`.

## Workspace layout

- Sidebar with six tabs (bookmarks, dumps, format, structures, sessions, import).
- Main panel: `HexViewer`, `HexOverlay`, or `HexComparison` depending on `viewMode`.
- Bottom tabs (mode-gated): analysis, results, strings, entropy, consensus, live-consensus, architect, experiment, convergence, verify-key, pipeline.
- Detail panel: neighborhood overlay, structure overlay, or result summary.

## Build

```bash
cd frontend
npm ci
npm run build           # → frontend/dist
npm run dev             # → Vite dev server on :5173 with proxy to :8080
```

## State stores

Thirteen Zustand slices under `frontend/src/stores/`:

`app-store`, `dump-store`, `hex-store`, `analysis-store`, `results-store`, `pipeline-store`, `oracle-store`, `consensus-store`, `consensus-incremental-store`, `strings-store`, `browser-store`, `verification-store`, `settings-store`.

Keyboard shortcuts are wired via `useKeyboardShortcuts` and treat `metaKey` as `ctrlKey`, so the four bindings below also fire on macOS with `⌘`.
