import { defineConfig, devices } from "@playwright/test";
import path from "node:path";

const BACKEND_PORT = process.env.BACKEND_PORT ?? "8091";
const FRONTEND_PORT = process.env.FRONTEND_PORT ?? "5191";

// tests/e2e/ -> repo root is two levels up.
const REPO_ROOT = path.resolve(__dirname, "..", "..");

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
      command: `python cli.py web --port ${BACKEND_PORT}`,
      cwd: REPO_ROOT,
      url: `http://127.0.0.1:${BACKEND_PORT}/api/notebook/status`,
      timeout: 120_000,
      reuseExistingServer: !process.env.CI,
      stdout: "pipe",
      stderr: "pipe",
      env: {
        ...process.env,
        PYTHONUNBUFFERED: "1",
      },
    },
    {
      command: `npm --prefix frontend run dev -- --port ${FRONTEND_PORT} --strictPort`,
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
