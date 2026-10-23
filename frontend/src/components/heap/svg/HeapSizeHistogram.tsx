/**
 * Hand-rolled SVG chunk-size histogram (the `chartBackend === "svg"` twin of
 * `../plotly/HeapSizeHistogram`). One category bar per size bucket.
 */
import { memo, useMemo } from "react";
import { useTranslation } from "react-i18next";

import { niceLinearTicks, scaleLinear } from "@/components/charts/svg/primitives";
import { useChartTheme } from "@/hooks/useChartTheme";
import { useContainerWidth } from "@/hooks/useContainerWidth";
import { bucketLabel, type HeapSizeHistogramProps } from "../histogram-types";

const HEIGHT = 260;
const MARGIN = { top: 10, right: 20, bottom: 50, left: 50 };

export const HeapSizeHistogram = memo(function HeapSizeHistogram({ buckets }: HeapSizeHistogramProps) {
  const { t } = useTranslation("heap");
  const { svg: tokens } = useChartTheme();
  const [containerRef, width] = useContainerWidth();
  const plotW = Math.max(100, width - MARGIN.left - MARGIN.right);
  const plotH = HEIGHT - MARGIN.top - MARGIN.bottom;

  const { yScale, yTicks } = useMemo(() => {
    const max = Math.max(1, ...buckets.map((b) => b.count));
    return {
      yScale: scaleLinear([0, max], [MARGIN.top + plotH, MARGIN.top]),
      yTicks: niceLinearTicks(0, max, 4),
    };
  }, [buckets, plotH]);

  if (buckets.length === 0) {
    return <p className="p-3 text-sm md-text-muted" data-chart-backend="svg">{t("histogram.empty")}</p>;
  }

  const slot = plotW / buckets.length;
  const barW = Math.max(1, slot * 0.85);
  const labelEvery = Math.max(1, Math.ceil(buckets.length / 12));
  const baseline = MARGIN.top + plotH;

  return (
    <div ref={containerRef} data-chart-backend="svg" data-testid="heap-histogram" className="w-full">
      <svg width={width} height={HEIGHT} role="img" aria-label={t("panels.histogram")} style={{ display: "block", background: tokens.chartPaper }}>
        <title>{t("panels.histogram")}</title>
        {yTicks.map((v) => (
          <g key={`y-${v}`}>
            <line x1={MARGIN.left} x2={MARGIN.left + plotW} y1={yScale(v)} y2={yScale(v)} stroke={tokens.chartGrid} />
            <text x={MARGIN.left - 6} y={yScale(v) + 3} textAnchor="end" fontSize={10} fill={tokens.chartText}>{v}</text>
          </g>
        ))}
        {buckets.map((b, i) => {
          const x = MARGIN.left + i * slot + (slot - barW) / 2;
          const y = yScale(b.count);
          return (
            <g key={`${b.min_size}-${b.max_size}`}>
              <rect x={x} y={y} width={barW} height={Math.max(0, baseline - y)} fill={tokens.accentCyan}>
                <title>{`${t("histogram.bucket", { min: b.min_size, max: b.max_size })}: ${b.count}`}</title>
              </rect>
              {i % labelEvery === 0 && (
                <text x={x + barW / 2} y={baseline + 14} textAnchor="middle" fontSize={9} fill={tokens.chartText}>
                  {bucketLabel(b)}
                </text>
              )}
            </g>
          );
        })}
        <text x={MARGIN.left + plotW / 2} y={HEIGHT - 8} textAnchor="middle" fontSize={11} fill={tokens.chartText}>
          {t("histogram.xAxis")}
        </text>
      </svg>
    </div>
  );
});

export default HeapSizeHistogram;
