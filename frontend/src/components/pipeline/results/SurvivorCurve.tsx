import { useMemo } from "react";
import Plot from "react-plotly.js";
import type { Data, Layout } from "plotly.js";

import { usePipelineStore } from "@/stores/pipeline-store";

const TRACE_STYLE = [
  { name: "variance", color: "#60a5fa", dash: undefined },
  { name: "aligned", color: "#34d399", dash: undefined },
  { name: "high_entropy", color: "#fbbf24", dash: undefined },
  { name: "candidates", color: "#f87171", dash: "dot" as const },
];

const LAYOUT: Partial<Layout> = {
  height: 360,
  margin: { l: 60, r: 20, t: 30, b: 50 },
  paper_bgcolor: "rgba(0,0,0,0)",
  plot_bgcolor: "rgba(0,0,0,0)",
  font: { color: "#cbd5e1", size: 11 },
  xaxis: {
    title: { text: "N dumps folded" },
    gridcolor: "rgba(148,163,184,0.15)",
    zerolinecolor: "rgba(148,163,184,0.3)",
  },
  yaxis: {
    type: "log",
    title: { text: "Survivors (log)" },
    gridcolor: "rgba(148,163,184,0.15)",
    zerolinecolor: "rgba(148,163,184,0.3)",
  },
  legend: {
    orientation: "h",
    y: -0.2,
    font: { color: "#cbd5e1" },
  },
};

const PLOT_CONFIG = { displayModeBar: false, responsive: true } as const;

/**
 * Log-y survivor curve for a Phase 25 n-sweep run.
 *
 * Shows one trace per reduce stage (variance / aligned / high_entropy),
 * plus the post-reduce candidate count and a marker at the first N
 * value at which the oracle produced a verified hit.
 */
export function SurvivorCurve() {
  const points = usePipelineStore((s) => s.nsweepPoints);

  const traces = useMemo<Data[]>(() => {
    if (points.length === 0) return [];
    const ns = points.map((p) => p.n);
    const values: Record<string, number[]> = {
      variance: points.map((p) => p.stages.variance ?? 0),
      aligned: points.map((p) => p.stages.aligned ?? 0),
      high_entropy: points.map((p) => p.stages.high_entropy ?? 0),
      candidates: points.map((p) => p.candidates),
    };
    const out: Data[] = TRACE_STYLE.map((t) => ({
      x: ns,
      y: values[t.name],
      type: "scatter",
      mode: "lines+markers",
      name: t.name,
      line: { color: t.color, width: 2, ...(t.dash ? { dash: t.dash } : {}) },
      marker: { size: 6 },
    }));
    const firstHit = points.find((p) => p.hit_offset !== null);
    if (firstHit) {
      out.push({
        x: [firstHit.n],
        y: [1],
        type: "scatter",
        mode: "markers+text",
        name: "oracle_hit",
        marker: { color: "#a855f7", size: 14, symbol: "star" },
        text: ["hit"],
        textposition: "top center",
        textfont: { color: "#a855f7", size: 11 },
      });
    }
    return out;
  }, [points]);

  if (points.length === 0) {
    return (
      <div className="md-panel p-4 text-xs md-text-muted">
        No n-sweep data (pipeline ran without --nsweep).
      </div>
    );
  }

  return (
    <div className="md-panel p-2" data-tour-id="pipeline-survivor-curve">
      <Plot
        data={traces}
        layout={LAYOUT}
        config={PLOT_CONFIG}
        style={{ width: "100%", height: "360px" }}
        useResizeHandler
      />
    </div>
  );
}
