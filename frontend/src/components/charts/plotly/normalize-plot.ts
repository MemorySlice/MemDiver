/**
 * Vite 8 + React 19 CJS→ESM interop shim for `react-plotly.js`.
 *
 * The pre-bundled module does `export default require_react_plotly()`
 * without unwrapping `.default`, so the imported symbol is the CJS
 * exports object `{ __esModule: true, default: <Plot component> }`
 * instead of the component. This helper normalizes: if `.default`
 * exists, unwrap it; otherwise the upstream bundler already gets it
 * right and we fall through. Self-healing when a future Vite release
 * fixes the upstream behaviour.
 */
import PlotModule from "react-plotly.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const Plot = ((PlotModule as any).default ?? PlotModule) as typeof PlotModule;
