import { useTranslation } from "react-i18next";

import type { CandidateHeapAnnotation } from "@/api/types";
import { formatAddress } from "@/components/heap/heap-format";

const BADGE = "inline-block px-1 rounded border border-[var(--md-border)] text-[10px]";

/** The two heap column headers: chunk (state + residual) and offset in chunk. */
export function CandidateHeapHeaders() {
  const { t } = useTranslation("heap");
  return (
    <>
      <th scope="col" className="py-1 pr-2 font-medium">{t("candidates.chunk")}</th>
      <th scope="col" className="py-1 pr-2 font-medium text-right">
        {t("candidates.offsetInChunk")}
      </th>
    </>
  );
}

/**
 * One row's heap cells.
 *
 * The chunk cell names the state of the chunk holding the region's first byte
 * and flags a RESIDUAL (a freed chunk: the bytes are stale leftovers, not live
 * state), which is the single most decision-relevant heap fact about a
 * candidate. Its hover carries the chunk's slab address, size and how many
 * dumps agree on it; the role agreement over the whole region rides along.
 */
export function CandidateHeapCells({ heap }: { heap: CandidateHeapAnnotation | undefined }) {
  const { t } = useTranslation("heap");
  const chunk = heap?.chunk ?? null;

  if (!chunk) {
    return (
      <>
        <td className="py-0.5 pr-2 md-text-muted" data-testid="candidate-heap-chunk">
          <span title={t("candidates.noChunk")}>{"—"}</span>
        </td>
        <td className="py-0.5 pr-2 text-right font-mono md-text-muted">{"—"}</td>
      </>
    );
  }

  const state = t(`states.${chunk.state}`);
  const titleParts = [
    t("candidates.chunkTitle", {
      start: formatAddress(chunk.start),
      size: chunk.size,
      state,
      agree: chunk.agree,
    }),
  ];
  if (heap?.agreement !== null && heap?.agreement !== undefined) {
    titleParts.push(t("candidates.agreement", { count: heap.agreement }));
  }

  return (
    <>
      <td
        className="py-0.5 pr-2"
        data-testid="candidate-heap-chunk"
        data-chunk-state={chunk.state}
        title={titleParts.join(" · ")}
      >
        <span className="inline-flex items-center gap-1">
          <span className={BADGE}>{state}</span>
          {heap?.residual && (
            <span
              className={`${BADGE} md-bg-warning-subtle`}
              data-testid="candidate-heap-residual"
              title={t("candidates.residualHint")}
            >
              {t("candidates.residual")}
            </span>
          )}
        </span>
      </td>
      <td className="py-0.5 pr-2 text-right font-mono" data-testid="candidate-heap-offset">
        {`+${formatAddress(chunk.offset_in_chunk)}`}
      </td>
    </>
  );
}
