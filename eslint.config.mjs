// The one ESLint flat config for the whole repo.
//
// It MUST live here, at the root. ESLint 9 sets `basePath` to the directory of
// the config file it finds (config-loader.js: `basePath = dirname(configFilePath)`)
// and then silently reports anything above it as "File ignored because outside
// of base path" -- exit code 0, no findings. So the old frontend/eslint.config.js
// could never see the vitest suite once it moved to <repo>/tests/frontend/.
// ESLint searches UPWARD from cwd, so this config is picked up from the repo
// root and from frontend/ alike -- but there must be exactly ONE of it, because
// find-up stops at the nearest hit and a surviving frontend/eslint.config.js
// would silently restore the old tests-blind behaviour.
//
// `.mjs`, not `.js`: the root package.json deliberately has no `"type"` field
// (it is a bare workspace container governing every stray root-level .js), so a
// root-level `.js` config would be CJS and these imports would throw.
import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import tseslint from "typescript-eslint";
import { defineConfig, globalIgnores } from "eslint/config";

export default defineConfig([
  // Traversal fence. ESLint's own defaults already cover **/node_modules/ and
  // .git/; the rest keeps `eslint .` from crawling a repo that is mostly Python.
  globalIgnores([
    "**/node_modules/",
    "**/dist/",
    "docs/_build/",
    "env/",
    ".venv/",
    "**/playwright-report/",
    "**/test-results/",
    "tests/artifacts/",
    // 34 Playwright specs. They have never been linted; turning them on would
    // be a separate, deliberate change with its own wall of findings.
    "tests/e2e/",
    // 4 hand-rolled .mjs linters. Same story -- never linted, out of scope.
    "scripts/",
  ]),
  {
    // Positive scoping is the real guard; the ignores above are a traversal and
    // performance optimisation. Even if a file slips past them it matches no
    // rule-bearing config here and is therefore linted with zero rules.
    files: [
      "frontend/src/**/*.{ts,tsx}",
      "frontend/*.ts", // vite.config.ts
      "tests/frontend/**/*.{ts,tsx}",
    ],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
    },
  },
]);
