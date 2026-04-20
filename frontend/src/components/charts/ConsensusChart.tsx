import { memo } from "react";
import { useConsensusStore } from "@/stores/consensus-store";

const CLASS_INFO: { key: string; label: string; color: string; desc: string }[] = [
  { key: "invariant", label: "Invariant", color: "var(--md-accent-green, #4ec9b0)", desc: "Identical across all runs" },
  { key: "structural", label: "Structural", color: "var(--md-accent-blue, #569cd6)", desc: "Low variance (< 100)" },
  { key: "pointer", label: "Pointer", color: "var(--md-accent-cyan, #4fc1ff)", desc: "Medium variance (< 3000)" },
  { key: "key_candidate", label: "Key Candidate", color: "var(--md-accent-red, #f44747)", desc: "High variance (key material)" },
];

export const ConsensusChart = memo(function ConsensusChart() {
  const { available, size, numDumps, counts } = useConsensusStore();

  if (!available || !counts || size === 0) {
    return (
      <p className="p-4 text-sm md-text-muted">
        No consensus data. Run consensus with 2+ dumps in Exploration mode.
      </p>
    );
  }

  return (
    <div className="p-3 text-xs space-y-3">
      <h3 className="text-sm font-semibold md-text-accent">Consensus Matrix</h3>
      <div className="flex gap-4 md-text-muted">
        <span>Total bytes: {size.toLocaleString()}</span>
        <span>Dumps analyzed: {numDumps}</span>
      </div>
      <div className="space-y-2">
        {CLASS_INFO.map(({ key, label, color, desc }) => {
          const count = counts[key] ?? 0;
          const pct = size > 0 ? (count / size) * 100 : 0;
          return (
            <div key={key} className="flex items-center gap-2">
              <div
                className="w-3 h-3 rounded-sm shrink-0"
                style={{ background: color }}
                title={desc}
              />
              <span className="min-w-[90px] font-medium">{label}</span>
              <div className="flex-1 h-4 rounded bg-[var(--md-bg-tertiary)] overflow-hidden">
                <div
                  className="h-full rounded transition-all"
                  style={{ background: color, width: `${pct}%` }}
                />
              </div>
              <span className="min-w-[100px] text-right md-text-muted">
                {count.toLocaleString()} ({pct.toFixed(1)}%)
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
});
