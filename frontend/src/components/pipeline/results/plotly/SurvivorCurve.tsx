/**
 * Plotly-backed SurvivorCurve. Loaded via React.lazy from
 * `../SurvivorCurve.tsx` (the dispatcher) when the user's
 * `settings.display.chartBackend` is "plotly" (default).
 *
 * The SVG alternative lives at `../svg/SurvivorCurve.tsx`.
 */
import { useMemo } from "react";
import { useTranslation } from "react-i18next";
import type { Data, Layout } from "plotly.js";

import { Plot } from "@/components/charts/plotly/normalize-plot";
import { getChartColor } from "@/components/charts/tokens";
import { usePipelineStore } from "@/stores/pipeline-store";
import { SURVIVOR_TRACES } from "../survivor-traces";

const PLOT_CONFIG = { displayModeBar: false, responsive: true } as const;

/**
 * Log-y survivor curve for a Phase 25 n-sweep run.
 *
 * Shows one trace per reduce stage (variance / aligned / high_entropy),
 * plus the post-reduce candidate count and a marker at the first N
 * value at which the oracle produced a verified hit.
 */
export function SurvivorCurve() {
  const { t } = useTranslation("pipeline");
  const points = usePipelineStore((s) => s.nsweepPoints);

  const layout = useMemo<Partial<Layout>>(
    () => ({
      height: 360,
      margin: { l: 60, r: 20, t: 30, b: 50 },
      paper_bgcolor: "rgba(0,0,0,0)",
      plot_bgcolor: "rgba(0,0,0,0)",
      font: { color: getChartColor("--md-chart-text"), size: 11 },
      xaxis: {
        title: { text: t("results.survivor.xAxis") },
        gridcolor: "rgba(148,163,184,0.15)",
        zerolinecolor: "rgba(148,163,184,0.3)",
      },
      yaxis: {
        type: "log",
        title: { text: t("results.survivor.yAxis") },
        gridcolor: "rgba(148,163,184,0.15)",
        zerolinecolor: "rgba(148,163,184,0.3)",
      },
      legend: {
        orientation: "h",
        y: -0.2,
        font: { color: getChartColor("--md-chart-text") },
      },
    }),
    [t],
  );

  const traces = useMemo<Data[]>(() => {
    if (points.length === 0) return [];
    const ns = points.map((p) => p.n);
    const values: Record<string, number[]> = {
      variance: points.map((p) => p.stages.variance ?? 0),
      aligned: points.map((p) => p.stages.aligned ?? 0),
      high_entropy: points.map((p) => p.stages.high_entropy ?? 0),
      candidates: points.map((p) => p.candidates),
    };
    const out: Data[] = SURVIVOR_TRACES.map((t) => ({
      x: ns,
      y: values[t.key],
      type: "scatter",
      mode: "lines+markers",
      name: t.label,
      line: { color: getChartColor(t.token), width: 2, ...(t.dash ? { dash: t.dash } : {}) },
      marker: { size: 6 },
    }));
    const firstHit = points.find((p) => p.hit_offset !== null);
    if (firstHit) {
      out.push({
        x: [firstHit.n],
        y: [1],
        type: "scatter",
        // "markers+text" is a valid Plotly mode but its type union is out
        // of date in @types/plotly.js — cast to loosen the check.
        mode: "markers+text" as unknown as "markers",
        name: "oracle_hit",
        marker: { color: getChartColor("--md-accent-purple"), size: 14, symbol: "star" },
        text: [t("results.survivor.hit")],
        textposition: "top center",
        textfont: { color: getChartColor("--md-accent-purple"), size: 11 },
      });
    }
    return out;
  }, [points, t]);

  if (points.length === 0) {
    return (
      <div className="md-panel p-4 text-xs md-text-muted">
        {t("results.survivor.noData")}
      </div>
    );
  }

  return (
    <div className="md-panel p-2" data-tour-id="pipeline-survivor-curve">
      <Plot
        data={traces}
        layout={layout}
        config={PLOT_CONFIG}
        style={{ width: "100%", height: "360px" }}
        useResizeHandler
      />
    </div>
  );
}

export default SurvivorCurve;
