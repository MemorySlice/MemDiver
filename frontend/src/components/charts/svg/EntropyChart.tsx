/**
 * Hand-rolled SVG EntropyChart.
 *
 * Renders entropy (bits/byte) over byte offset as a filled line plot.
 * Mirrors the Plotly implementation's visual language (blue line +
 * filled area, translucent red overlays for high-entropy regions,
 * dashed red horizontal threshold line) but ships ~80 KB instead of
 * pulling the ~2.3 MB Plotly chunk.
 *
 * Loaded via React.lazy from the dispatcher at `../EntropyChart.tsx`
 * when `settings.display.chartBackend === "svg"`.
 */
import { memo, useMemo } from "react";
import { useChartTheme } from "@/hooks/useChartTheme";
import { useContainerWidth } from "@/hooks/useContainerWidth";
import type { EntropyChartProps } from "../types";
import {
  scaleLinear,
  niceLinearTicks,
  formatHexOffset,
  polylinePath,
} from "./primitives";

const CHART_HEIGHT = 350;
const MARGIN = { top: 40, right: 20, bottom: 40, left: 55 };

export const EntropyChart = memo(function EntropyChart({
  data,
  threshold = 7.5,
  title = "Entropy Profile",
}: EntropyChartProps) {
  const { svg: tokens } = useChartTheme();
  const [containerRef, containerWidth] = useContainerWidth();

  const points = data.profile_sample ?? [];

  const { xScale, yScale, offsetMin, offsetMax, plotW, plotH, lineD, fillD } =
    useMemo(() => {
      const w = containerWidth;
      const plotW = Math.max(100, w - MARGIN.left - MARGIN.right);
      const plotH = CHART_HEIGHT - MARGIN.top - MARGIN.bottom;
      const offsets = points.map((p) => p.offset);
      const offsetMin = offsets.length ? offsets[0] : 0;
      const offsetMax = offsets.length ? offsets[offsets.length - 1] : 1;
      const xScale = scaleLinear([offsetMin, offsetMax], [MARGIN.left, MARGIN.left + plotW]);
      const yScale = scaleLinear([0, 8.5], [MARGIN.top + plotH, MARGIN.top]);

      const lineD = polylinePath(points.map((p) => [xScale(p.offset), yScale(p.entropy)]));
      const baselineY = yScale(0);
      let fillD = "";
      if (points.length > 0) {
        fillD =
          "M " + xScale(points[0].offset).toFixed(2) + " " + baselineY.toFixed(2) +
          lineD.replace(/^M/, "L") +
          " L " + xScale(points[points.length - 1].offset).toFixed(2) + " " + baselineY.toFixed(2) +
          " Z";
      }
      return { xScale, yScale, offsetMin, offsetMax, plotW, plotH, lineD, fillD };
    }, [points, containerWidth]);

  if (points.length === 0) {
    return <p className="p-3 text-sm md-text-muted" data-chart-backend="svg">No entropy profile available.</p>;
  }

  const xTicks = niceLinearTicks(offsetMin, offsetMax, 6);
  const yTicks = niceLinearTicks(0, 8, 5);
  const chartWidth = containerWidth;
  const thresholdY = yScale(threshold);

  return (
    <div ref={containerRef} data-chart-backend="svg" className="w-full" style={{ color: tokens.chartText }}>
      <svg
        width={chartWidth}
        height={CHART_HEIGHT}
        role="img"
        aria-label={title}
        style={{ display: "block", background: tokens.chartPaper }}
      >
        <title>{title}</title>

        {/* Plot area background */}
        <rect
          x={MARGIN.left}
          y={MARGIN.top}
          width={plotW}
          height={plotH}
          fill={tokens.chartPlot}
        />

        {/* Chart title */}
        <text
          x={chartWidth / 2}
          y={MARGIN.top / 2 + 4}
          textAnchor="middle"
          fontSize={13}
          fontWeight={600}
          fill={tokens.chartText}
        >
          {title}
        </text>

        {/* Horizontal grid (at each Y tick) */}
        {yTicks.map((t) => (
          <line
            key={`gy-${t}`}
            x1={MARGIN.left}
            x2={MARGIN.left + plotW}
            y1={yScale(t)}
            y2={yScale(t)}
            stroke={tokens.chartGrid}
            strokeWidth={1}
          />
        ))}

        {/* High-entropy region overlays (translucent red) */}
        {data.high_entropy_regions?.map((r, i) => {
          const x0 = Math.max(MARGIN.left, xScale(Math.max(r.start, offsetMin)));
          const x1 = Math.min(MARGIN.left + plotW, xScale(Math.min(r.end, offsetMax)));
          const width = Math.max(0, x1 - x0);
          if (width === 0) return null;
          return (
            <rect
              key={`hi-${i}`}
              x={x0}
              y={MARGIN.top}
              width={width}
              height={plotH}
              fill={tokens.accentRed}
              opacity={0.15}
            />
          );
        })}

        {/* Filled area under the curve */}
        {fillD && <path d={fillD} fill={tokens.accentBlue} fillOpacity={0.18} />}

        {/* Entropy curve */}
        {lineD && (
          <path
            d={lineD}
            fill="none"
            stroke={tokens.accentBlue}
            strokeWidth={1.5}
            strokeLinejoin="round"
          />
        )}

        {/* Threshold horizontal dashed line */}
        <line
          x1={MARGIN.left}
          x2={MARGIN.left + plotW}
          y1={thresholdY}
          y2={thresholdY}
          stroke={tokens.accentRed}
          strokeWidth={1}
          strokeDasharray="4 3"
        />

        {/* X axis line */}
        <line
          x1={MARGIN.left}
          x2={MARGIN.left + plotW}
          y1={MARGIN.top + plotH}
          y2={MARGIN.top + plotH}
          stroke={tokens.chartGrid}
          strokeWidth={1}
        />

        {/* X axis ticks + labels (hex) */}
        {xTicks.map((t) => (
          <g key={`tx-${t}`}>
            <line
              x1={xScale(t)}
              x2={xScale(t)}
              y1={MARGIN.top + plotH}
              y2={MARGIN.top + plotH + 4}
              stroke={tokens.chartGrid}
            />
            <text
              x={xScale(t)}
              y={MARGIN.top + plotH + 16}
              textAnchor="middle"
              fontSize={10}
              fill={tokens.textMuted}
            >
              {formatHexOffset(t)}
            </text>
          </g>
        ))}

        {/* X axis title */}
        <text
          x={MARGIN.left + plotW / 2}
          y={CHART_HEIGHT - 4}
          textAnchor="middle"
          fontSize={11}
          fill={tokens.textSecondary}
        >
          Offset (bytes)
        </text>

        {/* Y axis ticks + labels */}
        {yTicks.map((t) => (
          <g key={`ty-${t}`}>
            <line
              x1={MARGIN.left - 4}
              x2={MARGIN.left}
              y1={yScale(t)}
              y2={yScale(t)}
              stroke={tokens.chartGrid}
            />
            <text
              x={MARGIN.left - 6}
              y={yScale(t) + 3}
              textAnchor="end"
              fontSize={10}
              fill={tokens.textMuted}
            >
              {t}
            </text>
          </g>
        ))}

        {/* Y axis title (rotated) */}
        <text
          x={14}
          y={MARGIN.top + plotH / 2}
          textAnchor="middle"
          fontSize={11}
          fill={tokens.textSecondary}
          transform={`rotate(-90, 14, ${MARGIN.top + plotH / 2})`}
        >
          Entropy (bits/byte)
        </text>
      </svg>
    </div>
  );
});

export default EntropyChart;
