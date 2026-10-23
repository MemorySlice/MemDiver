/**
 * Plotly-backed chunk-size histogram. Loaded lazily by `../HeapSizeHistogram`.
 * Colours come from `useChartTheme` (CSS tokens), never literals.
 */
import { memo, useMemo } from "react";
import { useTranslation } from "react-i18next";

import { Plot } from "@/components/charts/plotly/normalize-plot";
import { PLOTLY_CONFIG, PLOTLY_STYLE } from "@/components/charts/chart-config";
import { useChartTheme } from "@/hooks/useChartTheme";
import { bucketLabel, type HeapSizeHistogramProps } from "../histogram-types";

export const HeapSizeHistogram = memo(function HeapSizeHistogram({ buckets }: HeapSizeHistogramProps) {
  const { t } = useTranslation("heap");
  const { plotly: theme, plotlyColors: colors } = useChartTheme();

  const data = useMemo(
    () => [{
      x: buckets.map(bucketLabel),
      y: buckets.map((b) => b.count),
      type: "bar" as const,
      marker: { color: colors.accentCyan },
      hovertext: buckets.map((b) => t("histogram.bucket", { min: b.min_size, max: b.max_size })),
      name: t("histogram.yAxis"),
    }],
    [buckets, colors.accentCyan, t],
  );

  if (buckets.length === 0) {
    return <p className="p-3 text-sm md-text-muted" data-chart-backend="plotly">{t("histogram.empty")}</p>;
  }

  return (
    <div data-chart-backend="plotly" data-testid="heap-histogram">
      <Plot
        data={data}
        layout={{
          ...theme,
          height: 260,
          margin: { l: 50, r: 20, t: 10, b: 60 },
          xaxis: { ...theme.xaxis, title: { text: t("histogram.xAxis") }, type: "category" },
          yaxis: { ...theme.yaxis, title: { text: t("histogram.yAxis") } },
          showlegend: false,
          bargap: 0.1,
        }}
        config={PLOTLY_CONFIG}
        style={PLOTLY_STYLE}
      />
    </div>
  );
});

export default HeapSizeHistogram;
