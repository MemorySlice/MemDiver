/**
 * Plotly-backed EntropyChart. Loaded via React.lazy from
 * `../EntropyChart.tsx` (the dispatcher) when the user's
 * `settings.display.chartBackend` is "plotly" (default).
 *
 * The SVG alternative lives at `../svg/EntropyChart.tsx`. Both derive their
 * geometry from `../entropy-model.ts`: with a server `envelope` this draws
 * the per-bucket min–max band (min trace + max trace filled "tonexty") with
 * the max line on top and a thin mean line; otherwise the `profile_sample`
 * line. Plotly internals are hard to query in e2e, so the wrapper carries
 * the counts as data attributes.
 */
import { memo, useMemo } from "react";
import { useTranslation } from "react-i18next";
import { Plot } from "./normalize-plot";
import { usePlotlyTheme, usePlotlyColors } from "@/hooks/usePlotlyTheme";
import { PLOTLY_CONFIG, PLOTLY_STYLE } from "../chart-config";
import type { EntropyChartProps } from "../types";
import { buildEntropyChartModel, formatBits, type EntropyChartModel } from "../entropy-model";
import { EntropyChartMeta } from "../EntropyChartMeta";

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- Plotly trace types are overly strict
type Trace = any;

function envelopeTraces(
  model: EntropyChartModel,
  color: string,
  names: { band: string; max: string; mean: string },
): Trace[] {
  const env = model.envelope;
  if (!env) return [];
  return [
    {
      x: env.min.x, y: env.min.y, type: "scatter", mode: "lines",
      line: { width: 0, color }, hoverinfo: "skip", showlegend: false, name: names.band,
    },
    {
      x: env.max.x, y: env.max.y, type: "scatter", mode: "lines",
      line: { color, width: 1.5 },
      fill: "tonexty", fillcolor: color + "38",
      name: names.max,
    },
    {
      x: env.mean.x, y: env.mean.y, type: "scatter", mode: "lines",
      line: { color, width: 0.75 }, opacity: 0.6,
      name: names.mean,
    },
  ];
}

/** Minimum region marker width as a fraction of the x range (~3 px at 1500 px). */
const REGION_MIN_FRACTION = 0.002;

export const EntropyChart = memo(function EntropyChart({
  data,
  threshold: thresholdProp,
  title,
}: EntropyChartProps) {
  const { t } = useTranslation("charts");
  const resolvedTitle = title ?? t("entropy.defaultTitle");
  const theme = usePlotlyTheme();
  const colors = usePlotlyColors();
  const model = useMemo(() => buildEntropyChartModel(data, thresholdProp), [data, thresholdProp]);

  if (model.isEmpty) {
    return <p className="p-3 text-sm md-text-muted">{t("entropy.empty")}</p>;
  }

  const traces: Trace[] = model.envelope
    ? envelopeTraces(model, colors.accentBlue, {
        band: t("entropy.series.band"),
        max: t("entropy.series.max"),
        mean: t("entropy.series.mean"),
      })
    : [{
        x: model.profile.x, y: model.profile.y, type: "scatter", mode: "lines",
        line: { color: colors.accentBlue, width: 1 },
        fill: "tozeroy", fillcolor: colors.accentBlue + "20",
        name: t("entropy.seriesName"),
      }];

  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- Plotly shape types are overly strict
  const shapes: any[] = model.regions.flatMap((r) => {
    // A key-sized region is far below one pixel on a multi-MiB dump: widen
    // it to ~3 px (in data units) and add a solid tick along the top.
    const x1 = Math.max(r.end, r.start + (model.xMax - model.xMin) * REGION_MIN_FRACTION);
    return [
      {
        type: "rect", xref: "x", yref: "paper", x0: r.start, x1, y0: 0, y1: 1,
        fillcolor: colors.accentRed, opacity: 0.2, line: { width: 0 },
      },
      {
        type: "rect", xref: "x", yref: "paper", x0: r.start, x1, y0: 0.975, y1: 1,
        fillcolor: colors.accentRed, opacity: 0.9, line: { width: 0 },
      },
    ];
  });

  shapes.push({
    type: "line", xref: "paper", yref: "y",
    x0: 0, x1: 1, y0: model.threshold, y1: model.threshold,
    line: { color: colors.accentRed, width: 1, dash: "dash" },
  });

  shapes.push({
    type: "line", xref: "paper", yref: "y",
    x0: 0, x1: 1, y0: model.maxEntropy, y1: model.maxEntropy,
    line: { color: colors.neutral, width: 1, dash: "dot" }, opacity: 0.6,
  });

  const annotations = [
    {
      xref: "paper", yref: "y", x: 1, y: model.maxEntropy, xanchor: "right", yanchor: "bottom",
      text: t("entropy.maxEntropyLabel", { value: formatBits(model.maxEntropy) }),
      showarrow: false, font: { size: 9, color: colors.neutral },
    },
    {
      xref: "paper", yref: "y", x: 0, y: model.threshold, xanchor: "left", yanchor: "bottom",
      text: t("entropy.thresholdLabel", { value: formatBits(model.threshold) }),
      showarrow: false, font: { size: 9, color: colors.accentRed },
    },
  ];

  return (
    <div
      data-chart-backend="plotly"
      data-testid="entropy-chart"
      data-envelope-buckets={model.envelope?.bucketCount ?? 0}
      data-region-count={model.regions.length}
      data-max-entropy-peak={model.envelope?.peak}
      data-threshold={model.threshold}
      data-max-entropy={model.maxEntropy}
      data-y-top={model.yTop}
      className="w-full"
    >
      <EntropyChartMeta model={model} />
      <Plot
        data={traces}
        layout={{
          ...theme, title: { text: resolvedTitle }, height: 350,
          xaxis: { ...theme.xaxis, title: { text: t("entropy.axis.offset") } },
          yaxis: { ...theme.yaxis, title: { text: t("entropy.axis.entropy") }, range: [0, model.yTop] },
          shapes,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any -- Plotly annotation types are overly strict
          annotations: annotations as any,
          showlegend: false,
        }}
        config={PLOTLY_CONFIG}
        style={PLOTLY_STYLE}
      />
    </div>
  );
});

export default EntropyChart;
