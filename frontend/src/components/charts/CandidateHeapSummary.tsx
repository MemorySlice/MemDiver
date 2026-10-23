import { useTranslation } from "react-i18next";

import type { HeapPolicy } from "@/api/types";

interface Props {
  /** `thresholds.heap_policy`: the policy the reduction ran under. */
  policy: HeapPolicy | undefined;
  /** `stages.heap_masked`: survivors the `"mask"` gate removed. */
  heapMasked: number | undefined;
}

/**
 * The heap line of a candidate result: which policy ran and, under `"mask"`,
 * how many variance survivors it removed as allocator metadata. Renders
 * nothing for an answer that carries neither (older server, policy off and
 * unreported), so the summary reads exactly as before.
 */
export function CandidateHeapSummary({ policy, heapMasked }: Props) {
  const { t } = useTranslation("heap");
  if (policy === undefined && heapMasked === undefined) return null;

  return (
    <p className="md-text-muted" data-testid="candidate-heap-summary">
      {policy !== undefined && (
        <span data-testid="candidate-heap-policy">
          {t("candidates.policyRan", { policy: t(`candidates.policy.${policy}`) })}
        </span>
      )}
      {policy !== undefined && heapMasked !== undefined && " · "}
      {heapMasked !== undefined && (
        <span data-testid="candidate-heap-masked">
          {t("candidates.masked", { count: heapMasked })}
        </span>
      )}
    </p>
  );
}
