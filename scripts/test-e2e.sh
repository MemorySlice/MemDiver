#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# npm workspaces: every dependency is hoisted into <repo>/node_modules, so
# tests/e2e/node_modules no longer exists and the old `[ ! -d node_modules ]`
# probe would fire on EVERY run -- re-installing and re-downloading Chromium
# each time, and worse, `npm install` from inside the workspace would create a
# nested node_modules with a second copy of every shared package. Probe the
# hoisted package instead, and always install at the ROOT.
if [ ! -d "$REPO_ROOT/node_modules/@playwright/test" ]; then
  npm --prefix "$REPO_ROOT" install
  "$REPO_ROOT/node_modules/.bin/playwright" install chromium
fi

# Playwright discovers playwright.config.ts from cwd, and that config's
# `testDir: "./specs"` and `webServer[].cwd` are resolved relative to itself.
# npx walks up to <repo>/node_modules/.bin for the hoisted binary.
cd "$REPO_ROOT/tests/e2e"
exec npx playwright test "$@"
