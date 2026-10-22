/**
 * Hand-rolled SVG EntropyChart.
 *
 * Renders entropy (bits/byte) over byte offset. With a server `envelope`
 * it draws the per-bucket min–max band with the max line on top (so a
 * single-window spike stays visible as a peak) and a thin mean line;
 * without one it falls back to the `profile_sample` filled line plot.
 * Mirrors the Plotly implementation's visual language (translucent red
 * overlays for high-entropy regions, dashed red threshold line, dashed
 * achievable-maximum reference) but ships ~80 KB instead of pulling the
 * ~2.3 MB Plotly chunk. Both backends derive their geometry from
 * `../entropy-model.ts`.
 *
 * Loaded via React.lazy from the dispatcher at `../EntropyChart.tsx`
 * when `settings.display.chartBackend === "svg"`.
 */
import { memo, useMemo } from "react";
import { useTranslation } from "react-i18next";
import { useChartTheme } from "@/hooks/useChartTheme";
import { useContainerWidth } from "@/hooks/useContainerWidth";
import type { EntropyChartProps } from "../types";
import { buildEntropyChartModel, formatBits, type XY } from "../entropy-model";
import { EntropyChartMeta } from "../EntropyChartMeta";
import {
  scaleLinear,
  niceLinearTicks,
  formatHexOffset,
  polylinePath,
} from "./primitives";

const CHART_HEIGHT = 350;
const MARGIN = { top: 40, right: 20, bottom: 40, left: 55 };
/**
 * Narrowest region marker, so every region stays visible (and countable): a
 * 32-byte key is far below one pixel on a multi-MiB dump.
 */
const MIN_REGION_PX = 3;
/** Height of the solid region tick drawn along the top of the plot. */
const REGION_TICK_PX = 6;

type Scale = (v: number) => number;

function seriesPath(series: XY, xScale: Scale, yScale: Scale): string {
  return polylinePath(series.x.map((x, i) => [xScale(x), yScale(series.y[i])]));
}

/** Closed polygon: along the max line, then back along the min line. */
function bandPath(max: XY, min: XY, xScale: Scale, yScale: Scale): string {
  if (max.x.length === 0) return "";
  const upper = max.x.map((x, i) => `${xScale(x).toFixed(2)} ${yScale(max.y[i]).toFixed(2)}`);
  const lower: string[] = [];
  for (let i = min.x.length - 1; i >= 0; i--) {
    lower.push(`${xScale(min.x[i]).toFixed(2)} ${yScale(min.y[i]).toFixed(2)}`);
  }
  return `M ${upper.join(" L ")} L ${lower.join(" L ")} Z`;
}

export const EntropyChart = memo(function EntropyChart({
  data,
  threshold: thresholdProp,
  title,
}: EntropyChartProps) {
  const { t } = useTranslation("charts");
  const resolvedTitle = title ?? t("entropy.defaultTitle");
  const { svg: tokens } = useChartTheme();
  const [containerRef, containerWidth] = useContainerWidth();

  const model = useMemo(() => buildEntropyChartModel(data, thresholdProp), [data, thresholdProp]);
  const points = useMemo(
    () => (model.envelope ? [] : data.profile_sample ?? []),
    [model.envelope, data.profile_sample],
  );

  const { xScale, yScale, offsetMin, offsetMax, plotW, plotH, lineD, fillD, envelopeD } =
    useMemo(() => {
      const w = containerWidth;
      const plotW = Math.max(100, w - MARGIN.left - MARGIN.right);
      const plotH = CHART_HEIGHT - MARGIN.top - MARGIN.bottom;
      const offsetMin = model.xMin;
      const offsetMax = model.xMax;
      const xScale = scaleLinear([offsetMin, offsetMax], [MARGIN.left, MARGIN.left + plotW]);
      const yScale = scaleLinear([0, model.yTop], [MARGIN.top + plotH, MARGIN.top]);

      const env = model.envelope;
      const envelopeD = env
        ? {
            band: bandPath(env.max, env.min, xScale, yScale),
            max: seriesPath(env.max, xScale, yScale),
            mean: seriesPath(env.mean, xScale, yScale),
          }
        : null;
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
      return { xScale, yScale, offsetMin, offsetMax, plotW, plotH, lineD, fillD, envelopeD };
    }, [points, containerWidth, model]);

  if (model.isEmpty) {
    return <p className="p-3 text-sm md-text-muted" data-chart-backend="svg">{t("entropy.empty")}</p>;
  }

  const xTicks = niceLinearTicks(offsetMin, offsetMax, 6);
  const yTicks = niceLinearTicks(0, model.maxEntropy, 5);
  const chartWidth = containerWidth;
  const thresholdY = yScale(model.threshold);
  const maxEntropyY = yScale(model.maxEntropy);

  return (
    <div
      ref={containerRef}
      data-chart-backend="svg"
      data-testid="entropy-chart"
      data-envelope-buckets={model.envelope?.bucketCount ?? 0}
      data-region-count={model.regions.length}
      data-max-entropy-peak={model.envelope?.peak}
      data-threshold={model.threshold}
      data-max-entropy={model.maxEntropy}
      data-y-top={model.yTop}
      className="w-full"
      style={{ color: tokens.chartText }}
    >
      <EntropyChartMeta model={model} />
      <svg
        width={chartWidth}
        height={CHART_HEIGHT}
        role="img"
        aria-label={resolvedTitle}
        style={{ display: "block", background: tokens.chartPaper }}
      >
        <title>{resolvedTitle}</title>

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
          {resolvedTitle}
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
        {model.regions.map((r, i) => {
          if (r.end < offsetMin || r.start > offsetMax) return null;
          const x0 = Math.max(MARGIN.left, xScale(Math.max(r.start, offsetMin)));
          const x1 = Math.min(MARGIN.left + plotW, xScale(Math.min(r.end, offsetMax)));
          const width = Math.max(MIN_REGION_PX, x1 - x0);
          return (
            <g key={`hi-${i}`}>
              <rect
                data-testid="entropy-region"
                x={x0}
                y={MARGIN.top}
                width={width}
                height={plotH}
                fill={tokens.accentRed}
                opacity={0.2}
              />
              {/* Solid tick on top: findable even where the band is a hairline. */}
              <rect
                x={x0}
                y={MARGIN.top}
                width={width}
                height={REGION_TICK_PX}
                fill={tokens.accentRed}
                opacity={0.9}
              />
            </g>
          );
        })}

        {/* Envelope: min–max band, thin mean, max line on top */}
        {envelopeD && (
          <g>
            <path
              data-testid="entropy-envelope-band"
              d={envelopeD.band}
              fill={tokens.accentBlue}
              fillOpacity={0.22}
              stroke="none"
            />
            {envelopeD.mean && (
              <path
                data-testid="entropy-mean-line"
                d={envelopeD.mean}
                fill="none"
                stroke={tokens.accentBlue}
                strokeOpacity={0.6}
                strokeWidth={0.75}
              />
            )}
            <path
              data-testid="entropy-max-line"
              d={envelopeD.max}
              fill="none"
              stroke={tokens.accentBlue}
              strokeWidth={1.5}
              strokeLinejoin="round"
            />
          </g>
        )}

        {/* Filled area under the curve */}
        {fillD && <path d={fillD} fill={tokens.accentBlue} fillOpacity={0.18} />}

        {/* Entropy curve */}
        {lineD && (
          <path
            data-testid="entropy-profile-line"
            d={lineD}
            fill="none"
            stroke={tokens.accentBlue}
            strokeWidth={1.5}
            strokeLinejoin="round"
          />
        )}

        {/* Achievable-maximum reference (subtle) */}
        <line
          data-testid="entropy-max-entropy-line"
          x1={MARGIN.left}
          x2={MARGIN.left + plotW}
          y1={maxEntropyY}
          y2={maxEntropyY}
          stroke={tokens.textMuted}
          strokeOpacity={0.6}
          strokeWidth={1}
          strokeDasharray="2 3"
        />
        <text
          x={MARGIN.left + plotW - 4}
          y={maxEntropyY - 3}
          textAnchor="end"
          fontSize={9}
          fill={tokens.textMuted}
        >
          {t("entropy.maxEntropyLabel", { value: formatBits(model.maxEntropy) })}
        </text>

        {/* Threshold horizontal dashed line */}
        <line
          data-testid="entropy-threshold-line"
          data-threshold={model.threshold}
          x1={MARGIN.left}
          x2={MARGIN.left + plotW}
          y1={thresholdY}
          y2={thresholdY}
          stroke={tokens.accentRed}
          strokeWidth={1}
          strokeDasharray="4 3"
        />
        <text
          x={MARGIN.left + 4}
          y={thresholdY - 3}
          fontSize={9}
          fill={tokens.accentRed}
        >
          {t("entropy.thresholdLabel", { value: formatBits(model.threshold) })}
        </text>

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
          {t("entropy.axis.offset")}
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
          {t("entropy.axis.entropy")}
        </text>
      </svg>
    </div>
  );
});

export default EntropyChart;
