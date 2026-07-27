/**
 * Single wiring point for the Plotly React component (bundle-shrink + interop).
 *
 * Instead of `react-plotly.js`'s default export — which statically pulls in the
 * full `plotly.js` distribution (~4.5 MB) — we build the component from the
 * `react-plotly.js/factory` entry and hand it the `plotly.js-basic-dist-min`
 * partial bundle (~1 MB). That bundle registers scatter + bar + pie, which
 * covers every trace this app renders (scatter and bar only). All four charts
 * import `{ Plot }` from here, so the swap needs no call-site changes.
 *
 * Both packages are CJS. Under Vite 8 + React 19 ESM interop the pre-bundled
 * module can surface as the CJS exports object `{ __esModule, default: <value> }`
 * instead of the value itself. We unwrap `.default` when present and fall
 * through otherwise — self-healing when a future Vite release fixes the
 * upstream behaviour.
 */
import createPlotlyComponentModule from "react-plotly.js/factory";
import PlotlyModule from "plotly.js-basic-dist-min";

/** Unwrap a CJS module's `.default` when the interop layer leaves it wrapped. */
const cjsDefault = <T>(m: T): T => (m as unknown as { default?: T }).default ?? m;

const createPlotlyComponent = cjsDefault(createPlotlyComponentModule);
const Plotly = cjsDefault(PlotlyModule);

export const Plot = createPlotlyComponent(Plotly);
