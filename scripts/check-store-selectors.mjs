#!/usr/bin/env node
/**
 * Guards the `useShallow` selector sweep (B3).
 *
 * `const x = useSomeStore()` subscribes a component to EVERY field of that
 * store, so it re-renders on every unrelated `set()`. The hex store alone
 * `set()`s on each chunk fetch, prefetch, cursor move and scroll, so one
 * unscoped read is a per-tick re-render storm.
 *
 * The fix is a selector:
 *   - one field   ->  useSomeStore((s) => s.field)
 *   - many fields ->  useSomeStore(useShallow((s) => ({ ... })))
 *
 * zustand v5 removed the second `equalityFn` argument, so an object-returning
 * selector WITHOUT `useShallow` re-renders infinitely inside
 * `useSyncExternalStore` — this linter does not catch that (see the mount
 * smoke tests in `frontend/src/components/store-selector-mount.test.tsx`), it
 * only catches the unscoped whole-store read.
 */
import { readFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { walk } from "./lib/walk.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..", "frontend", "src");

// `= useFooStore()` with an empty argument list.
const BAD = /=\s*use[A-Za-z0-9_]*Store\(\s*\)/;

// Sites where reading the whole store is the right call. Each entry is a
// repo-relative path; the file must carry an `// intentional: whole-store read`
// comment on the line above so the reason travels with the code.
const ALLOW_PATHS = new Set([
  "frontend/src/components/settings/SettingsMenu.tsx",
]);

// Test files legitimately mount the unscoped shape as a control, to prove the
// render-count harness is measuring something.
const IS_TEST = /\.test\.(ts|tsx)$/;
const INTENT = "intentional: whole-store read";

let failed = 0;
const seenAllowed = new Set();
for (const file of walk(ROOT)) {
  const rel = relative(resolve(__dirname, ".."), file).split("\\").join("/");
  if (IS_TEST.test(file)) continue;
  const allowed = ALLOW_PATHS.has(rel);
  const lines = readFileSync(file, "utf8").split("\n");
  lines.forEach((line, i) => {
    if (!BAD.test(line)) return;
    if (allowed) {
      // An allowlist entry only holds while the reason is written next to the
      // code; otherwise the exemption outlives the argument for it.
      seenAllowed.add(rel);
      const preceding = lines.slice(Math.max(0, i - 4), i).join("\n");
      if (!preceding.includes(INTENT)) {
        console.error(
          `${file}:${i + 1}: allowlisted whole-store read is missing its ` +
            `\`// ${INTENT}\` comment`,
        );
        failed++;
      }
      return;
    }
    {
      console.error(
        `${file}:${i + 1}: whole-store subscription - pass a selector, ` +
          `e.g. useStore((s) => s.field) or useStore(useShallow((s) => ({ ... })))`,
      );
      failed++;
    }
  });
}

// A stale allowlist entry silently exempts nothing; worse, it exempts whatever
// moves into that path later.
for (const rel of ALLOW_PATHS) {
  if (!seenAllowed.has(rel)) {
    console.error(`allowlist entry no longer has a whole-store read: ${rel}`);
    failed++;
  }
}

if (failed > 0) {
  console.error(`${failed} unscoped whole-store subscription(s) found`);
  process.exit(1);
}
console.log("OK: every store read passes a selector");
