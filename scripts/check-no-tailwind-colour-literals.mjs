#!/usr/bin/env node
import { readFileSync, readdirSync, statSync, existsSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(__dirname, "..");
const ROOT = resolve(REPO, "frontend", "src", "components");
const BASELINE_PATH = resolve(__dirname, "colour-literal-baseline.txt");

// text-red-400, bg-green-500, border-blue-600, fill-cyan-400, stroke-purple-700.
// Also catches greyscale (zinc/slate/gray/neutral/stone) and pseudo-class variants
// like hover:text-red-400 because word-boundary still holds at ':'.
const BAD = /\b(text|bg|border|fill|stroke)-(red|yellow|green|blue|orange|purple|cyan|pink|rose|amber|lime|emerald|teal|sky|indigo|violet|fuchsia|zinc|slate|gray|neutral|stone)-\d+\b/;

// Chart files render runtime-string colours (Plotly + hand-rolled SVG). Phase C
// migrates these; until then they are exempt.
const ALLOW_PATH = /\/components\/charts\/|\/components\/pipeline\/results\/SurvivorCurve\.tsx|\/components\/pipeline\/run\/FunnelChart\.tsx/;
// Per-line escape hatch.
const ALLOW_COMMENT = /design-token-source/;

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (/\.(ts|tsx)$/.test(name)) out.push(full);
  }
  return out;
}

function collectOffenders() {
  const hits = [];
  for (const file of walk(ROOT)) {
    if (ALLOW_PATH.test(file)) continue;
    const rel = relative(REPO, file);
    const lines = readFileSync(file, "utf8").split("\n");
    lines.forEach((line, i) => {
      if (BAD.test(line) && !ALLOW_COMMENT.test(line)) {
        hits.push(`${rel}:${i + 1}`);
      }
    });
  }
  return hits.sort();
}

function loadBaseline() {
  if (!existsSync(BASELINE_PATH)) return new Set();
  return new Set(readFileSync(BASELINE_PATH, "utf8").split("\n").filter(Boolean));
}

const mode = process.argv[2] ?? "check";
const hits = collectOffenders();

if (mode === "update") {
  const content = hits.join("\n") + (hits.length ? "\n" : "");
  writeFileSync(BASELINE_PATH, content);
  console.log(`Baseline updated: ${hits.length} offender(s) at ${relative(REPO, BASELINE_PATH)}`);
  process.exit(0);
}

const baseline = loadBaseline();
const newHits = hits.filter((h) => !baseline.has(h));
const fixedHits = [...baseline].filter((h) => !hits.includes(h));

if (newHits.length > 0) {
  console.error("NEW colour-literal offenders (not in baseline):");
  for (const h of newHits) console.error(`  ${h}`);
  console.error(`\n${newHits.length} new hit(s). Fix them, or run 'npm run lint:colour-literals:update' to re-baseline.`);
  process.exit(1);
}

if (fixedHits.length > 0) {
  console.log("Nice — offenders removed since last baseline:");
  for (const h of fixedHits) console.log(`  - ${h}`);
  console.log(`\nRun 'npm run lint:colour-literals:update' to shrink the baseline.`);
}

console.log(`OK: ${hits.length} tracked offender(s), 0 new.`);
