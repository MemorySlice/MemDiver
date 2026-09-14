import { defineConfig, devices } from "@playwright/test";
import path from "node:path";

const BACKEND_PORT = process.env.BACKEND_PORT ?? "8091";
const FRONTEND_PORT = process.env.FRONTEND_PORT ?? "5191";

// tests/e2e/ -> repo root is two levels up.
const REPO_ROOT = path.resolve(__dirname, "..", "..");

/**
 * A MemDiver home of the suite's own.
 *
 * `core.constants.memdiver_home()` honours `XDG_DATA_HOME` (unconditionally —
 * the "on Linux" in its docstring is not what the code does), and that is the
 * only seam there is: `api/upload_dir.user_config_path()` is hardcoded to
 * `memdiver_home()/config.json`. Pointing it here keeps the e2e backend out of
 * the developer's real `~/.memdiver`, and — with the reset below — is what lets
 * `00-first-use-upload-dir.spec.ts` observe the configure-on-first-use 409 for
 * real instead of stubbing one.
 *
 * The directory is STABLE rather than per-run: `memdiver_home()` also backs
 * `project.duckdb` and the session store, and re-creating those every run would
 * be a needless cost for the ~40 specs that do not care. Only the preferences
 * file is reset.
 */
const E2E_HOME = path.join(__dirname, ".memdiver-home");

/** The user preferences file — the one thing reset on every backend spawn. */
const E2E_PREFS = path.join(E2E_HOME, "memdiver", "config.json");

/**
 * The backend's environment.
 *
 * `MEMDIVER_UPLOAD_DIR` is dropped rather than passed through: it pins
 * `Settings.upload_dir` ahead of the user config, so a developer who has one
 * exported would make the first-use state unreachable on their machine and
 * nowhere else. The e2e backend is a throwaway process; it does not inherit
 * that pin.
 */
function backendEnv(): Record<string, string> {
  const env: Record<string, string | undefined> = {
    ...process.env,
    PYTHONUNBUFFERED: "1",
    XDG_DATA_HOME: E2E_HOME,
  };
  delete env.MEMDIVER_UPLOAD_DIR;
  return env as Record<string, string>;
}

/**
 * Deleting the preferences file is part of STARTING the server, deliberately.
 *
 * `get_settings()` is `@lru_cache(maxsize=1)` and the POST handler mutates that
 * instance in place rather than clearing the cache, so a running backend can
 * never be returned to the unconfigured state — only a fresh process re-reads
 * the file. Tying the reset to the spawn makes "a freshly spawned e2e backend
 * has no upload directory" true by construction, and leaves a REUSED server
 * (`reuseExistingServer` below) alone, which is the one case the spec still has
 * to detect for itself.
 *
 * Run through `node -e` rather than `rm -f` because this repo's path contains
 * spaces, and the file name travels in the environment rather than in the
 * command string so no quoting is involved at all.
 */
const RESET_PREFS = `node -e "require('fs').rmSync(process.env.MEMDIVER_E2E_PREFS,{force:true})"`;

export default defineConfig({
  testDir: "./specs",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: process.env.CI ? "list" : [["list"], ["html", { open: "never" }]],
  use: {
    baseURL: `http://127.0.0.1:${FRONTEND_PORT}`,
    trace: "on-first-retry",
    screenshot: "only-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: [
    {
      command: `${RESET_PREFS} && python -m memdiver.cli web --port ${BACKEND_PORT}`,
      cwd: REPO_ROOT,
      url: `http://127.0.0.1:${BACKEND_PORT}/api/notebook/status`,
      timeout: 120_000,
      reuseExistingServer: !process.env.CI,
      stdout: "pipe",
      stderr: "pipe",
      env: { ...backendEnv(), MEMDIVER_E2E_PREFS: E2E_PREFS },
    },
    {
      command: `npm --prefix frontend run dev -- --port ${FRONTEND_PORT} --strictPort --host 127.0.0.1`,
      cwd: REPO_ROOT,
      url: `http://127.0.0.1:${FRONTEND_PORT}`,
      timeout: 120_000,
      reuseExistingServer: !process.env.CI,
      stdout: "pipe",
      stderr: "pipe",
      env: {
        ...process.env,
        VITE_BACKEND_PORT: BACKEND_PORT,
      },
    },
  ],
});
