#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { walk } from "./lib/walk.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..", "frontend", "src", "components");
// Negative lookbehind for `&` so HTML numeric entities (e.g. `&#9654;` for ▶)
// are not mistaken for hex colour literals; real hex has no `&` before `#`.
const BAD = /(?<!&)#[0-9a-fA-F]{3,8}\b/;
const ALLOW = /design-token-source/;
// charts/tokens.ts is the canonical runtime token resolver: its per-theme hex
// fallbacks (the source of truth for the CSS vars) are legitimate, not literals
// to migrate. Exempt it wholesale, mirroring the colour-literal linter's
// charts/ path exemption.
const ALLOW_PATH = /[/\\]components[/\\]charts[/\\]tokens\.ts$/;

// MOVED to scripts/lib/walk.mjs (P3.2 dedup)
// function walk(dir, out = []) {
//   for (const name of readdirSync(dir)) {
//     const full = join(dir, name);
//     if (statSync(full).isDirectory()) walk(full, out);
//     else if (/\.(ts|tsx)$/.test(name)) out.push(full);
//   }
//   return out;
// }

let failed = 0;
for (const file of walk(ROOT)) {
  if (ALLOW_PATH.test(file)) continue;
  const lines = readFileSync(file, "utf8").split("\n");
  lines.forEach((line, i) => {
    if (BAD.test(line) && !ALLOW.test(line)) {
      console.error(`${file}:${i + 1}: hardcoded hex literal - use a CSS var token instead`);
      failed++;
    }
  });
}
if (failed > 0) {
  console.error(`${failed} hardcoded hex literal(s) found`);
  process.exit(1);
}
console.log("OK: no hardcoded hex literals in components");
