#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR/tests/e2e"
if [ ! -d node_modules ]; then
  npm install
  npx playwright install chromium
fi
exec npx playwright test "$@"
