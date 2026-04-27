/**
 * Wall-clock stage timings for the Pipeline run dashboard.
 *
 * Displays consensus / reduce / brute_force wall times from the
 * pipeline store's ``timings`` field plus a total row. Values ≥ 1000 ms
 * are shown in seconds; smaller values stay in milliseconds.
 */

import type { JSX } from "react";

import { usePipelineStore } from "@/stores/pipeline-store";
import type { StageTimings } from "@/stores/pipeline-store";

interface TimingRow {
  key: keyof StageTimings;
  label: string;
}

const ROWS: TimingRow[] = [
  { key: "consensus_ms", label: "Consensus" },
  { key: "reduce_ms", label: "Search-reduce" },
  { key: "brute_force_ms", label: "Brute-force" },
];

function formatMs(ms: number): string {
  if (ms >= 1000) {
    return `${(ms / 1000).toFixed(2)} s`;
  }
  return `${ms.toFixed(0)} ms`;
}

export function StageTimingTable(): JSX.Element {
  const timings = usePipelineStore((s) => s.timings);
  const total =
    timings.consensus_ms + timings.reduce_ms + timings.brute_force_ms;

  return (
    <div className="md-panel p-3 space-y-2 text-xs md-text-secondary">
      <div className="md-text-accent font-semibold">Stage timings</div>
      <table className="w-full border-collapse">
        <tbody>
          {ROWS.map((row) => (
            <tr key={row.key} className="border-b border-[var(--md-border)]">
              <td className="py-1 md-text-muted">{row.label}</td>
              <td className="py-1 text-right font-mono">
                {formatMs(timings[row.key])}
              </td>
            </tr>
          ))}
          <tr>
            <td className="pt-1.5 md-text-accent font-semibold">Total</td>
            <td className="pt-1.5 text-right font-mono md-text-accent font-semibold">
              {formatMs(total)}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  );
}
