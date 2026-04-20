export interface AlgorithmAvailability {
  available: boolean;
  reason: string | null;
}

interface AvailabilityContext {
  inputMode: string | null;
  dumpCount: number;
  hasKeylog: boolean;
  hasCandidateKeys: boolean;
}

export function getAlgorithmAvailability(
  algo: string,
  context: AvailabilityContext
): AlgorithmAvailability {
  switch (algo) {
    case "differential":
      if (context.dumpCount < 2) {
        return { available: false, reason: "Requires 2+ memory dumps for cross-run variance analysis" };
      }
      return { available: true, reason: null };

    case "exact_match":
      if (!context.hasKeylog) {
        return { available: false, reason: "Requires keylog reference data (ground truth)" };
      }
      return { available: true, reason: null };

    case "constraint_validator":
      if (!context.hasCandidateKeys) {
        return { available: false, reason: "Requires candidate keys from prior analysis" };
      }
      return { available: true, reason: null };

    default:
      return { available: true, reason: null };
  }
}

export function getAvailableAlgorithms(
  algorithms: readonly string[],
  context: AvailabilityContext
): Map<string, AlgorithmAvailability> {
  const result = new Map<string, AlgorithmAvailability>();
  for (const algo of algorithms) {
    result.set(algo, getAlgorithmAvailability(algo, context));
  }
  return result;
}
