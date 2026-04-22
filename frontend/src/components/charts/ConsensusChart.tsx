import { memo } from "react";
import { useConsensusStore } from "@/stores/consensus-store";
import { EmptyState } from "@/components/common/EmptyState";
import { ConsensusIcon } from "@/components/common/Icons";

interface ConsensusChartProps {
  onNavigate?: (tab: "analysis") => void;
}

const CLASS_INFO: { key: string; label: string; color: string; desc: string }[] = [
  { key: "invariant", label: "Invariant", color: "var(--md-accent-green, #4ec9b0)", desc: "Identical across all runs" },
  { key: "structural", label: "Structural", color: "var(--md-accent-blue, #569cd6)", desc: "Low variance (< 100)" },
  { key: "pointer", label: "Pointer", color: "var(--md-accent-cyan, #4fc1ff)", desc: "Medium variance (< 3000)" },
  { key: "key_candidate", label: "Key Candidate", color: "var(--md-accent-red, #f44747)", desc: "High variance (key material)" },
];

export const ConsensusChart = memo(function ConsensusChart({ onNavigate }: ConsensusChartProps = {}) {
  const { available, size, numDumps, counts } = useConsensusStore();

  if (!available || !counts || size === 0) {
    return (
      <EmptyState
        icon={<ConsensusIcon />}
        title="No consensus matrix yet"
        description="Batch-classifies every byte as invariant, structural, pointer, or key-candidate across a fixed set of dumps. Needs 2+ dumps and a completed analysis run."
        primaryCta={onNavigate ? { label: "Run analysis", onClick: () => onNavigate("analysis") } : undefined}
        secondary={{ label: "About consensus", href: "/docs/visualizations/consensus.md" }}
        data-testid="consensus-empty"
      />
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
