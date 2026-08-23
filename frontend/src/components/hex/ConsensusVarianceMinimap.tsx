import { memo, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { useConsensusStore } from "@/stores/consensus-store";
import { useHexStore } from "@/stores/hex-store";

// Number of bins requested for the strip. Kept below the backend cap (4096)
// and roughly one bin per few strip pixels so the down-sampled heatmap reads
// cleanly at typical strip heights.
const BINS = 512;

interface Props {
  /** Active .msl dump path — the overview is per-dump. */
  dumpPath: string;
  /** Top-of-view offset in the "va" view (absRow * 16). */
  firstVisibleOffset: number;
  height?: number;
}

/**
 * Pick a strip color for one bin. Stable bins (no changing bytes) paint
 * nothing so the strip background shows through; changing bins are tinted by
 * their peak class (structural → green, pointer → blue, key-candidate → red),
 * with opacity proportional to the fraction of bytes that change. `high`
 * (key-candidate fraction) forces red so likely key material stands out.
 */
function binBackground(changing: number, high: number, level: number): string | undefined {
  if (changing <= 0) return undefined;
  const colorVar =
    high > 0 || level >= 3
      ? "var(--md-accent-red)"
      : level === 2
        ? "var(--md-accent-blue)"
        : "var(--md-accent-green)";
  const fraction = Math.min(1, Math.max(changing, high));
  const pct = Math.max(25, Math.round(fraction * 100));
  return `color-mix(in srgb, ${colorVar} ${pct}%, transparent)`;
}

export const ConsensusVarianceMinimap = memo(function ConsensusVarianceMinimap({
  dumpPath, firstVisibleOffset, height = 300,
}: Props) {
  const { t } = useTranslation("hex");
  const consensusId = useConsensusStore((s) => s.consensusId);
  const overview = useConsensusStore((s) => s.vaOverview);
  const fetchVaOverview = useConsensusStore((s) => s.fetchVaOverview);
  const scrollToOffset = useHexStore((s) => s.scrollToOffset);
  const vaSpanStart = useHexStore((s) => s.vaSpanStart);

  // (Re)fetch the whole-dump overview whenever the consensus build or the
  // active dump changes. fetchVaOverview no-ops without a consensusId.
  useEffect(() => {
    if (!consensusId || !dumpPath) return;
    fetchVaOverview(dumpPath, BINS).catch(() => {
      // Overview is only available for native-MSL consensus; on failure the
      // strip simply does not render (guarded below).
    });
  }, [consensusId, dumpPath, fetchVaOverview]);

  if (!overview || overview.changing.length === 0) return null;
  const { va_start, va_end, bin_size, changing, high, level } = overview;
  const span = va_end - va_start;
  if (span <= 0 || bin_size <= 0) return null;
  const nbins = changing.length;

  const handleClick = (e: React.MouseEvent<HTMLDivElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const pct = (e.clientY - rect.top) / rect.height;
    const bin = Math.min(nbins - 1, Math.max(0, Math.floor(pct * nbins)));
    const va = va_start + bin * bin_size;
    scrollToOffset(va - vaSpanStart);
  };

  // Viewport marker: current top-of-view VA relative to the whole VA span.
  const currentVa = vaSpanStart + firstVisibleOffset;
  const viewPct = ((currentVa - va_start) / span) * 100;

  return (
    <div className="flex flex-col items-center gap-1">
      <span className="text-[9px] md-text-muted uppercase tracking-wide">
        {t("variance.title")}
      </span>
      <div
        className="relative border border-[var(--md-border)] rounded cursor-pointer"
        style={{ width: 20, height, background: "var(--md-bg-tertiary)" }}
        onClick={handleClick}
        title={t("variance.jumpTitle")}
        data-testid="variance-minimap"
      >
        {changing.map((ch, i) => {
          const bg = binBackground(ch, high[i] ?? 0, level[i] ?? 0);
          if (!bg) return null;
          return (
            <div
              key={i}
              className="absolute w-full"
              style={{
                top: `${(i / nbins) * 100}%`,
                height: `${Math.max(1, 100 / nbins)}%`,
                background: bg,
              }}
            />
          );
        })}
        {viewPct >= 0 && viewPct <= 100 && (
          <div
            className="absolute w-full opacity-70"
            style={{
              top: `${viewPct}%`,
              height: 4,
              background: "var(--md-accent-blue)",
            }}
          />
        )}
      </div>
      <div className="flex flex-col gap-0.5 text-[8px] md-text-muted">
        <span>
          <span
            className="inline-block w-2 h-2 rounded-sm mr-1 align-middle"
            style={{ background: "var(--md-accent-green)" }}
          />
          {t("variance.legendChanges")}
        </span>
        <span>
          <span
            className="inline-block w-2 h-2 rounded-sm mr-1 align-middle"
            style={{ background: "var(--md-accent-red)" }}
          />
          {t("variance.legendKey")}
        </span>
      </div>
    </div>
  );
});
