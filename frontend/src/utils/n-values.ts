/**
 * The N-sweep "N values" list, shared by the threshold form.
 *
 * Pure helpers, kept out of the component module so the form file exports
 * only components (react-refresh/only-export-components).
 */

/**
 * N ladder for the sweep. Mirrors the CLI's ``--n-values`` default
 * (cli/main.py), clamped to the dumps actually selected: an N past the corpus
 * size would ask the harness to fold more dumps than exist. The corpus size
 * itself is always included so the sweep ends on the full fold.
 */
export function defaultNValues(numDumps: number): number[] {
  if (numDumps < 1) return [1];
  const ladder = [1, 3, 5, 10, 20, 30, 50, 75, 100].filter((n) => n <= numDumps);
  return [...new Set([...ladder, numDumps])].sort((a, b) => a - b);
}

/**
 * Parse the comma-separated N field. Blank entries and anything that is not a
 * positive integer are dropped, so a half-typed value can never reach the
 * store (and the request body) as ``NaN``.
 */
export function parseNValues(raw: string): number[] {
  return raw
    .split(",")
    .map((part) => Number(part.trim()))
    .filter((n) => Number.isInteger(n) && n > 0);
}
