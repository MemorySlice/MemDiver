export const HIGHLIGHT_TYPES = [
  "exact-match", "entropy", "change-point", "pattern",
  "structure", "search", "differential", "constraint", "strings",
] as const;

export type HighlightType = (typeof HIGHLIGHT_TYPES)[number];

export const HIGHLIGHT_META: Record<HighlightType, { label: string }> = {
  "exact-match": { label: "Exact Match" },
  "entropy": { label: "Entropy Scan" },
  "change-point": { label: "Change Point" },
  "pattern": { label: "Pattern Match" },
  "structure": { label: "Structure Scan" },
  "search": { label: "User Regex" },
  "differential": { label: "Differential" },
  "constraint": { label: "Constraint" },
  "strings": { label: "Strings" },
};

export function secretTypeToHighlight(secretType: string): HighlightType {
  if (secretType.includes("exact_match")) return "exact-match";
  if (secretType.includes("entropy")) return "entropy";
  if (secretType.includes("change_point")) return "change-point";
  if (secretType.includes("pattern")) return "pattern";
  if (secretType.includes("structure")) return "structure";
  if (secretType.includes("regex") || secretType.includes("search")) return "search";
  if (secretType.includes("differential")) return "differential";
  if (secretType.includes("constraint")) return "constraint";
  if (secretType.includes("string")) return "strings";
  return "exact-match";
}
