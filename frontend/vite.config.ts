import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "./src") },
  },
  // Phase 3A Plotly rescue. react-plotly.js ships CJS and its default
  // export is the React component; under Vite 8 + React 19 ESM interop
  // `import Plot from "react-plotly.js"` resolves to the module namespace
  // instead. Force pre-bundling to normalize the default-export chain,
  // and tell Rollup (build-time) to transform the mixed exports.
  optimizeDeps: {
    include: ["react-plotly.js", "plotly.js"],
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
