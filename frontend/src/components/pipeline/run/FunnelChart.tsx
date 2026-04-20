/**
 * Animated funnel chart for the Pipeline run dashboard.
 *
 * Renders one horizontal bar per reduction stage (raw → variance →
 * aligned → high_entropy → candidates → verified). Bars are log-scaled
 * against the ``raw`` byte count so a 192 MB → 2 byte reduction is still
 * visually legible. CSS-only transitions — no framer-motion.
 */

import { usePipelineStore } from "@/stores/pipeline-store";
import type { FunnelCounts } from "@/stores/pipeline-store";

interface FunnelRow {
  key: keyof FunnelCounts;
  label: string;
  color: string;
}

const ROWS: FunnelRow[] = [
  { key: "raw", label: "Raw", color: "bg-indigo-600" },
  { key: "variance", label: "Variance", color: "bg-blue-600" },
  { key: "aligned", label: "Aligned", color: "bg-cyan-600" },
  { key: "high_entropy", label: "Entropy", color: "bg-teal-600" },
  { key: "candidates", label: "Candidates", color: "bg-green-600" },
  { key: "verified", label: "Verified", color: "bg-emerald-500" },
];

function logFraction(count: number, raw: number): number {
  if (raw <= 0 || count <= 0) return 0;
  if (count >= raw) return 1;
  const num = Math.log10(Math.max(1, count));
  const den = Math.log10(Math.max(1, raw));
  if (den <= 0) return 0;
  return Math.max(0, Math.min(1, num / den));
}

export function FunnelChart(): JSX.Element {
  const funnel = usePipelineStore((s) => s.funnel);
  const raw = funnel.raw;

  return (
    <div
      className="md-panel p-3 space-y-2 text-xs md-text-secondary"
      data-tour-id="pipeline-funnel"
    >
      <div className="md-text-accent font-semibold">Reduction funnel</div>
      {raw === 0 ? (
        <div className="md-text-muted italic py-2">
          Awaiting consensus…
        </div>
      ) : (
        <div className="space-y-1.5">
          {ROWS.map((row) => {
            const count = funnel[row.key];
            const fraction = logFraction(count, raw);
            return (
              <div key={row.key} className="flex items-center gap-2">
                <div className="w-[100px] shrink-0 capitalize md-text-muted">
                  {row.label}
                </div>
                <div className="flex-1 h-3 rounded bg-[var(--md-bg-hover)] overflow-hidden">
                  <div
                    className={`h-full ${row.color} transition-[width] duration-500 ease-out`}
                    style={{ width: `${fraction * 100}%` }}
                  />
                </div>
                <div className="w-[110px] shrink-0 text-right font-mono md-text-secondary">
                  {count.toLocaleString()}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
