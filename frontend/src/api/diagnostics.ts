/**
 * Structured diagnostics (Python `core.service_result.Diagnostic.to_dict`).
 *
 * Carried by consensus, aligned-window and candidates responses, both at the
 * top level and inside the `alignment` report. Every field that carries them
 * is OPTIONAL on the client: older servers omit it, and "no diagnostics" must
 * read the same as "none reported".
 */
export interface Diagnostic {
  code: string;
  /** The backend's English sentence. UI renders its own localized text. */
  message: string;
  severity: "info" | "warning" | string;
  details?: Record<string, unknown>;
}

/**
 * A region-filtered consensus/alignment mixed dumps classified by mapping
 * names with legacy dumps classified by stored region type only.
 */
export const CLASSIFICATION_BASIS_MIXED = "classification_basis_mixed";

/** `details` of a `classification_basis_mixed` diagnostic. */
export interface ClassificationBasisMixedDetails {
  named_dumps: number[];
  stored_type_dumps: number[];
  total_dumps: number;
  remedy?: string;
}

/**
 * Concatenate diagnostic lists, keeping the FIRST of each code.
 *
 * The same diagnostic is hoisted from `alignment.diagnostics` to the top-level
 * `diagnostics`, so a view reading both must not render it twice.
 */
export function mergeDiagnostics(
  ...lists: ReadonlyArray<unknown>
): Diagnostic[] {
  const seen = new Set<string>();
  const merged: Diagnostic[] = [];
  for (const list of lists) {
    // Tolerate a malformed payload (raw `res.json()` is untyped).
    if (!Array.isArray(list)) continue;
    for (const diagnostic of list as readonly Diagnostic[]) {
      if (!diagnostic || typeof diagnostic.code !== "string") continue;
      if (seen.has(diagnostic.code)) continue;
      seen.add(diagnostic.code);
      merged.push(diagnostic);
    }
  }
  return merged;
}

/** The first diagnostic with `code`, or `undefined`. */
export function findDiagnostic(
  diagnostics: readonly Diagnostic[] | null | undefined,
  code: string,
): Diagnostic | undefined {
  return diagnostics?.find((d) => d.code === code);
}

/**
 * The free-text `warnings` NOT already said by a diagnostic.
 *
 * A server may emit a diagnostic's English message into `warnings` too; the
 * localized banner already says it, so the raw sentence is dropped.
 */
export function warningsNotCoveredBy(
  warnings: readonly string[],
  diagnostics: readonly Diagnostic[] | null | undefined,
): string[] {
  const covered = new Set((diagnostics ?? []).map((d) => d.message));
  return warnings.filter((w) => !covered.has(w));
}

function numberList(value: unknown): number[] {
  return Array.isArray(value) ? value.filter((v): v is number => typeof v === "number") : [];
}

/** Read the `details` of a `classification_basis_mixed` diagnostic defensively. */
export function classificationBasisDetails(
  diagnostic: Diagnostic,
): ClassificationBasisMixedDetails {
  const details = diagnostic.details ?? {};
  const named = numberList(details.named_dumps);
  const stored = numberList(details.stored_type_dumps);
  const total =
    typeof details.total_dumps === "number" ? details.total_dumps : named.length + stored.length;
  return {
    named_dumps: named,
    stored_type_dumps: stored,
    total_dumps: total,
    remedy: typeof details.remedy === "string" ? details.remedy : undefined,
  };
}
