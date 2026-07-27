import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "./src") },
  },
  // Phase 3A Plotly rescue. The Plotly component is built in
  // `charts/plotly/normalize-plot.ts` from `react-plotly.js/factory` + the
  // `plotly.js-basic-dist-min` partial bundle (both CJS). Under Vite 8 +
  // React 19 ESM interop the CJS default-export chain resolves to the module
  // namespace instead of the value. Force pre-bundling of exactly the entries
  // we import at runtime to normalize that chain, and tell Rollup (build-time)
  // to transform the mixed exports.
  optimizeDeps: {
    include: ["react-plotly.js/factory", "plotly.js-basic-dist-min"],
  },
  build: {
    commonjsOptions: {
      transformMixedEsModules: true,
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": `http://127.0.0.1:${process.env.VITE_BACKEND_PORT ?? 8080}`,
      "/ws": {
        target: `ws://127.0.0.1:${process.env.VITE_BACKEND_PORT ?? 8080}`,
        ws: true,
      },
    },
  },
});
