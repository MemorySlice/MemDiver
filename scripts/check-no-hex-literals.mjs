#!/usr/bin/env node
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..", "frontend", "src", "components");
const BAD = /#[0-9a-fA-F]{3,8}\b/;
const ALLOW = /design-token-source/;

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (/\.(ts|tsx)$/.test(name)) out.push(full);
  }
  return out;
}

let failed = 0;
for (const file of walk(ROOT)) {
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
