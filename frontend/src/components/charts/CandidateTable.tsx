import { memo } from "react";
import { useTranslation } from "react-i18next";
import {
  dominantClass,
  type ByteClassName,
  type CandidateRegion,
} from "@/api/candidates";
import { offsetToHex } from "@/utils/hex-codec";
import { VARIANCE_META } from "@/utils/variance-classes";

/** Class -> colour, read from the shared variance map so one colour means one
 * class everywhere -- the Consensus tab's histogram, the hex grid and this
 * table. The local copy this replaces was off by one (structural painted blue,
 * pointer cyan), so the table and the hex viewer disagreed about every row. */
const CLASS_COLOR: Record<ByteClassName, string> = {
  invariant: VARIANCE_META.invariant.colorVar,
  structural: VARIANCE_META.structural.colorVar,
  pointer: VARIANCE_META.pointer.colorVar,
  key_candidate: VARIANCE_META.key_candidate.colorVar,
};

interface Props {
  regions: CandidateRegion[];
  /** Called with the region's offset in the comparison coordinate. */
  onJump: (offset: number) => void;
  /** False when offsets are aligned-slab indices; see `offsetsAreDumpOffsets`. */
  jumpable: boolean;
}

/**
 * The ranked candidate list.
 *
 * Rows arrive already ranked by the backend, which also stamps `rank`
 * whichever order the list came back in — so this renders the order it is
 * given rather than re-sorting and risking a second, disagreeing ranking.
 *
 * A row is clickable AND focusable: clicking (or pressing Enter/Space on) it
 * jumps the hex viewer to that offset through the same `scrollToOffset` path
 * the variance minimap uses -- but ONLY when `jumpable`. Under an aligned
 * consensus the offset is a slab index, so the jump is disabled rather than
 * scrolling confidently to the wrong bytes.
 */
export const CandidateTable = memo(function CandidateTable(
  { regions, onJump, jumpable }: Props,
) {
  const { t } = useTranslation("candidates");

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-[11px] border-collapse" data-testid="candidate-table">
        <caption className="sr-only">{t("table.caption")}</caption>
        <thead>
          <tr className="md-text-muted text-left border-b border-[var(--md-border)]">
            <th scope="col" className="py-1 pr-2 font-medium">{t("table.rank")}</th>
            <th scope="col" className="py-1 pr-2 font-medium">{t("table.offset")}</th>
            <th scope="col" className="py-1 pr-2 font-medium text-right">{t("table.length")}</th>
            <th scope="col" className="py-1 pr-2 font-medium">{t("table.class")}</th>
            <th scope="col" className="py-1 pr-2 font-medium text-right">{t("table.score")}</th>
            <th scope="col" className="py-1 pr-2 font-medium text-right">{t("table.variance")}</th>
            <th scope="col" className="py-1 font-medium text-right">{t("table.entropy")}</th>
          </tr>
        </thead>
        <tbody>
          {regions.map((region) => {
            const cls = dominantClass(region.class_counts);
            return (
              <tr
                key={`${region.offset}-${region.length}`}
                data-testid="candidate-row"
                data-offset={region.offset}
                data-length={region.length}
                tabIndex={jumpable ? 0 : undefined}
                title={jumpable ? t("table.jumpTitle") : t("table.jumpUnavailable")}
                onClick={jumpable ? () => onJump(region.offset) : undefined}
                onKeyDown={
                  jumpable
                    ? (e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          onJump(region.offset);
                        }
                      }
                    : undefined
                }
                className={
                  jumpable
                    ? "border-b border-[var(--md-border)] cursor-pointer hover:bg-[var(--md-bg-hover)]"
                    : "border-b border-[var(--md-border)]"
                }
              >
                <td className="py-0.5 pr-2 md-text-muted">{region.rank}</td>
                <td className="py-0.5 pr-2 font-mono">{`0x${offsetToHex(region.offset)}`}</td>
                <td className="py-0.5 pr-2 text-right font-mono">{region.length}</td>
                <td className="py-0.5 pr-2">
                  <span className="flex items-center gap-1">
                    <span
                      aria-hidden="true"
                      className="inline-block w-2 h-2 rounded-sm shrink-0"
                      style={{ background: cls ? CLASS_COLOR[cls] : "var(--md-text-muted)" }}
                    />
                    {cls ? t(`class.${cls}`) : t("class.unclassified")}
                  </span>
                </td>
                <td className="py-0.5 pr-2 text-right font-mono">{region.score.toFixed(3)}</td>
                <td className="py-0.5 pr-2 text-right font-mono">
                  {region.mean_variance.toFixed(1)}
                </td>
                <td className="py-0.5 text-right font-mono">
                  {region.region_entropy.toFixed(2)}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
});
