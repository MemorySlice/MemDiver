# frontend/

React + Vite + TypeScript + Tailwind + Zustand SPA. Built bundle ships under `frontend/dist/` and is served by the FastAPI backend at `/`.

## Stack

- React 19, Vite 8, TypeScript 5.9, Tailwind v4 (pure CSS tokens, no shadcn/radix).
- Zustand 5 for state.
- `react-resizable-panels` for the IDA-style dockable layout.
- `react-plotly.js` for charts; `@tanstack/react-virtual` for hex rows.
- `driver.js` for first-time-user tours.
- `i18next` + `react-i18next` for every user-facing string.

## Top-level views

No URL routing today. `useAppStore.appView` switches between `landing`, `wizard`, and `workspace`.

## Workspace layout

- Sidebar with six tabs (bookmarks, dumps, format, structures, sessions, import).
- Main panel: chosen by `dump-store.mainView`, set through `MainViewSwitcher` (**Single** / **Side by side** / **Overlay**; the last two are disabled until two or more dumps are selected). `single` renders `HexViewer`, `sideBySide` renders `MultiHexViewer` (aligned panes), `overlay` renders `HexOverlayPane` (consensus overlay with the dump rail). The older two-dump `viewMode` still renders `HexOverlay` or `HexComparison` when set.
- Bottom tabs (mode-gated): verification mode shows analysis, results, strings, verify-key, pipeline; exploration mode adds entropy, consensus, live-consensus, architect, experiment, convergence, variance, and vas.
- Detail panel: in the overlay main view, a two-tab panel (**Byte** = `OverlayByteInspector`, **Regions** = `VarianceClassBrowser` with `RegionFilterBar`); otherwise neighborhood overlay, structure overlay, or result summary.

## Build

```bash
# From the repo root: frontend/ is an npm workspace, so there is one hoisted
# install and one lockfile at the root.
npm ci
npm run build           # → frontend/dist
npm run dev             # → Vite dev server on :5173 with proxy to :8080
```

## State stores

Eighteen Zustand slices under `frontend/src/stores/`:

`app-store`, `dump-store`, `hex-store`, `analysis-store`, `results-store`, `pipeline-store`, `oracle-store`, `consensus-store`, `consensus-incremental-store`, `strings-store`, `browser-store`, `verification-store`, `settings-store`, `multi-hex-store`, `dump-rail-store`, `overlay-detail-store`, `overlay-render-store`, `variance-regions-store`.

The tour state lives in a separate store, `ftue/store.ts`. Components read stores with per-field selectors; `npm run lint:store-selectors` flags whole-store reads, which re-render forever under Zustand 5.

`settings-store` keeps UI settings in browser `localStorage`. Per-user server-side preferences (upload dir, oracle dir, file-browser favourites, last browsed folder) live in `~/.memdiver/config.json` (or `$XDG_DATA_HOME/memdiver/config.json`) via `api/user_prefs.py` and the `/api/settings/*` endpoints.

Keyboard shortcuts are wired via `useKeyboardShortcuts` and treat `metaKey` as `ctrlKey`, so the four bindings below also fire on macOS with `⌘`:

| Binding | Action |
|---|---|
| `Ctrl+N` | New session (goes through the unsaved-changes guard) |
| `Ctrl+S` | Save the workspace silently as the session `autosave` |
| `Ctrl+G` | Focus the `0x offset` input |
| `Ctrl+B` | Toggle the sidebar |

Hex-grid navigation (arrows, `PageUp`/`PageDown`, `Home`/`End`, `Tab`, `Esc`, `n`/`p`) is a separate hook, `useHexKeyboard`, shared by `HexViewer`, `MultiHexViewer`, and `HexOverlayPane`.

## Guided tours

`frontend/src/ftue/` drives first-time-user tours on top of `driver.js`. `registry.ts` registers three tours, tried in priority order:

| Tour id | Starts when |
|---|---|
| `workspace-layout-101` | the user first reaches the workspace |
| `structure-overlay-101` | in the workspace, after the layout tour was seen |
| `pipeline-101` | the pipeline panel first mounts |

`TourProvider` (mounted in `App.tsx`) re-checks on every `appView` change and starts the first unseen tour whose condition holds. Seen tours are recorded in `localStorage` under `memdiver:ftue:seen` with a version, so bumping a tour's version shows it again. The Settings menu entry **Run onboarding tour** replays a tour by hand. Step text is looked up in the `app` namespace under `tour.<section>.<step>`, falling back to the text in the tour file.

## Internationalisation

`frontend/src/i18n/index.ts` sets up i18next with react-i18next. Every `locales/en/*.json` file is loaded at build time and becomes a namespace named after the file (`analysis`, `app`, `candidates`, `charts`, `common`, `dumps`, `hex`, `investigation`, `landing`, `layout`, `misc`, `msl`, `pipeline`, `results`, `session`, `structures`, `ui`, `wizard`); `common` is the default namespace. English is the only shipped locale (`lng` and `fallbackLng` are both `en`), and there is no language switcher yet. Components call `useTranslation("<namespace>")`; new UI text goes into the matching JSON file rather than into the component. No lint rule enforces this yet.
