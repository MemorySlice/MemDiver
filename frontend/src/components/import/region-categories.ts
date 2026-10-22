import type { ImportPreview, ImportSelectionCounts, RegionCategory } from "@/api/types";

/** Every selection category, in the order the checklist shows them. */
export const REGION_CATEGORIES: readonly RegionCategory[] = [
  "heap",
  "stack",
  "unclassified",
  "image_data",
  "image_code",
  "mapped_file",
  "shared",
  "runtime",
] as const;

/**
 * The preselection: where runtime secrets normally live. `unclassified` is in
 * it because a raw dump is unclassified throughout — leaving it out would
 * import nothing from one. `runtime` (platform runtime/OS mappings such as
 * Android's boot image and ART metadata) is deliberately left out.
 */
export const DEFAULT_REGION_CATEGORIES: readonly RegionCategory[] = [
  "heap",
  "stack",
  "unclassified",
] as const;

/** Canonical (checklist-ordered) copy of `categories`, duplicates removed. */
export function orderCategories(categories: Iterable<RegionCategory>): RegionCategory[] {
  const chosen = new Set(categories);
  return REGION_CATEGORIES.filter((c) => chosen.has(c));
}

/** True when every category is selected, i.e. the selection filters nothing. */
export function isAllCategories(categories: readonly RegionCategory[]): boolean {
  return orderCategories(categories).length === REGION_CATEGORIES.length;
}

/** True when the selection is exactly the default preselection. */
export function isDefaultCategories(categories: readonly RegionCategory[]): boolean {
  const ordered = orderCategories(categories);
  const defaults = orderCategories(DEFAULT_REGION_CATEGORIES);
  return ordered.length === defaults.length && ordered.every((c, i) => c === defaults[i]);
}

/**
 * Wire spec for `regions` / `region_filter` (`"heap,stack"`), or `null` when
 * every category is selected — "no filter", which keeps the old default.
 */
export function categoriesToSpec(categories: readonly RegionCategory[]): string | null {
  if (isAllCategories(categories)) return null;
  return orderCategories(categories).join(",");
}

/**
 * Inverse of `categoriesToSpec`, also accepting the persisted
 * `"regions=heap,stack;…"` note form. `null` / `"all"` mean every category.
 * Unknown names are dropped.
 */
export function specToCategories(spec: string | null | undefined): RegionCategory[] {
  if (!spec) return [...REGION_CATEGORIES];
  const regionsPart = spec
    .split(";")
    .map((part) => part.trim())
    .map((part) => (part.startsWith("regions=") ? part.slice("regions=".length) : part))[0];
  const names = regionsPart.split(",").map((n) => n.trim());
  if (names.includes("all")) return [...REGION_CATEGORIES];
  const expanded = names.flatMap((n) => (n === "image" ? ["image_code", "image_data"] : [n]));
  return orderCategories(
    expanded.filter((n): n is RegionCategory => (REGION_CATEGORIES as readonly string[]).includes(n)),
  );
}

/** What `categories` keeps and drops of a preview, computed client-side. */
export function selectionCounts(
  totals: ImportPreview["totals"],
  categories: readonly RegionCategory[],
): ImportSelectionCounts {
  const chosen = new Set(categories);
  const counts: ImportSelectionCounts = {
    included_count: 0,
    included_bytes: 0,
    excluded_count: 0,
    excluded_bytes: 0,
  };
  for (const category of REGION_CATEGORIES) {
    const total = totals[category];
    if (!total) continue;
    if (chosen.has(category)) {
      counts.included_count += total.count;
      counts.included_bytes += total.bytes;
    } else {
      counts.excluded_count += total.count;
      counts.excluded_bytes += total.bytes;
    }
  }
  return counts;
}

/** `rwx`-style protection string (bit 1 = read, 2 = write, 4 = execute). */
export function protectionString(protection: number): string {
  return (
    (protection & 1 ? "r" : "-") +
    (protection & 2 ? "w" : "-") +
    (protection & 4 ? "x" : "-")
  );
}

/** True for an `.msl` path (case-insensitive extension check). */
export function isMslPath(path: string): boolean {
  return path.toLowerCase().endsWith(".msl");
}
