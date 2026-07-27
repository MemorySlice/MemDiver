/**
 * Ambient declaration for the `plotly.js-basic-dist-min` partial bundle.
 *
 * The dist package ships no `.d.ts`, so under `moduleResolution: "bundler"`
 * an import of it would raise TS7016. Its runtime shape is the same Plotly
 * object as the full `plotly.js` (scatter + bar + pie traces registered),
 * so we borrow the type from `@types/plotly.js` (already present transitively
 * via `@types/react-plotly.js`). Only `normalize-plot.ts` imports it.
 */
declare module "plotly.js-basic-dist-min" {
  const Plotly: typeof import("plotly.js");
  export default Plotly;
}
