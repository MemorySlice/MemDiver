import type { FormatSuggestion } from "@/api/types";

export interface SplitResult {
  suggested: FormatSuggestion[];
  others: string[];
}

/**
 * Split the available parsers into magic-matched suggestions (primary)
 * and the remaining parsers (secondary, flagged with a warning in the UI).
 *
 * A suggestion qualifies as "magic-matched" iff `magic_ok` is true.
 * Non-magic-matched suggestions are folded into `others` so that the
 * primary list stays short and trustworthy.
 */
export function splitSuggested(
  available: string[] | undefined,
  suggested: FormatSuggestion[] | undefined,
): SplitResult {
  const suggestedMatched = (suggested ?? []).filter((s) => s.magic_ok);
  const primaryNames = new Set(suggestedMatched.map((s) => s.format));
  const others = (available ?? []).filter((fmt) => !primaryNames.has(fmt));
  return { suggested: suggestedMatched, others };
}
