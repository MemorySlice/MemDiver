import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";

// The vitest suite lives OUTSIDE this package now, at <repo>/tests/frontend/,
// so that every test tree in the repo hangs off one root `tests/`. Everything
// below that has to reach it goes through this one constant.
const FRONTEND_TESTS = path.resolve(__dirname, "../tests/frontend");

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
      // Test-only helpers live beside the tests, not in src/.
      "@tests": FRONTEND_TESTS,
    },
    // npm workspaces hoist react/react-dom to <repo>/node_modules. The test
    // files resolve them from <repo>/tests/frontend/ while the components under
    // test resolve them from frontend/src/ -- so a stray `frontend/node_modules/
    // react` would hand the two halves DIFFERENT React instances and every
    // @testing-library/react test would die with "Invalid hook call". Pin both
    // to a single copy. Note this only governs the vite-resolved half; the real
    // guarantee is that there is exactly one hoisted install.
    dedupe: ["react", "react-dom"],
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
  test: {
    environment: "jsdom",
    // Tests live at <repo>/tests/frontend/, mirroring the `src/` tree -- never
    // co-located with the module under test.
    //
    // `dir` is the directory the include globs are scanned from, and it MUST be
    // absolute: vitest hands it straight to the globber as `cwd` and never
    // resolves it against `root`, so a relative value would follow
    // process.cwd() and silently find nothing when run from the repo root.
    //
    // Anchoring here is also what keeps the Playwright suite out. The pattern
    // below accepts `spec` as well as `test`, and <repo>/tests/e2e/specs/ is 34
    // `*.spec.ts` files -- but they are not below `dir`, so they are not merely
    // filtered out, they are unreachable.
    dir: FRONTEND_TESTS,
    include: ["**/*.{test,spec}.{ts,tsx}"],
    // Setting `exclude` REPLACES vitest's defaults (in v4 just node_modules +
    // .git), so they are respelled here. `**/e2e/**` is belt and braces for the
    // watcher: collection is already fenced by `dir`, but the watcher matches a
    // path relative to `dir`, which for an e2e spec is `../e2e/...` -- and `**`
    // happily matches `..`.
    exclude: ["**/node_modules/**", "**/.git/**", "**/e2e/**"],
    setupFiles: [path.resolve(FRONTEND_TESTS, "setup.ts")],
  },
  server: {
    // Adding `workspaces` to the root package.json changes vite's default
    // `fs.allow`: searchForWorkspaceRoot() now finds <repo> instead of
    // frontend/, which would let the dev server serve ANY file under the repo
    // over /@fs/ -- including the memory dumps in tests/fixtures/. Pin it back
    // to what the dev server actually needs.
    fs: {
      allow: [__dirname, path.resolve(__dirname, "../node_modules")],
    },
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
