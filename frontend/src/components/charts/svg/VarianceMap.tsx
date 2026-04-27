/**
 * Hand-rolled SVG VarianceMap.
 *
 * Renders cross-dump byte-variance values as a log-scale bar chart with
 * per-bar coloring driven by the optional `classifications` array
 * (0=invariant, 1=structural, 2=pointer, 3=key-candidate). Two dotted
 * horizontal reference lines sit at y=200 (structural cap) and y=3000
 * (pointer cap) — the same thresholds Plotly VarianceMap uses.
 *
 * Loaded via React.lazy from `../VarianceMap.tsx` when
 * `settings.display.chartBackend === "svg"`.
 */
import { memo, useMemo } from "react";
import { useChartTheme } from "@/hooks/useChartTheme";
import { useContainerWidth } from "@/hooks/useContainerWidth";
import type { VarianceMapProps } from "../types";
import {
  scaleLinear,
  scaleLog,
  niceLinearTicks,
  niceLogTicks,
  formatHexOffset,
  formatNumber,
} from "./primitives";

const CHART_HEIGHT = 350;
const MARGIN = { top: 40, right: 20, bottom: 40, left: 55 };

const STRUCTURAL_REF = 200;
const POINTER_REF = 3000;

export const VarianceMap = memo(function VarianceMap({
  variance,
  classifications,
  step = 1,
  title = "Variance Map",
}: VarianceMapProps) {
  const { svg: tokens } = useChartTheme();
  const [containerRef, containerWidth] = useContainerWidth();

  const sampled = useMemo(
    () => (step > 1 ? variance.filter((_, i) => i % step === 0) : variance),
    [variance, step],
  );
  const sampledCls = useMemo(
    () =>
      classifications && step > 1
        ? classifications.filter((_, i) => i % step === 0)
        : classifications,
    [classifications, step],
  );

  const plotW = Math.max(100, containerWidth - MARGIN.left - MARGIN.right);
  const plotH = CHART_HEIGHT - MARGIN.top - MARGIN.bottom;

  const { xScale, yScale, yMax, offsetMax } = useMemo(() => {
    const offsetMax = Math.max(sampled.length - 1, 1) * step;
    const yMaxRaw = sampled.length ? Math.max(...sampled) : 1;
    // Extend top of Y-range so reference lines at 3000 are visible.
    const yMax = Math.max(yMaxRaw, POINTER_REF * 2);
    const xScale = scaleLinear([0, offsetMax], [MARGIN.left, MARGIN.left + plotW]);
    const yScale = scaleLog([1, yMax], [MARGIN.top + plotH, MARGIN.top]);
    return { xScale, yScale, yMax, offsetMax };
  }, [sampled, step, plotW, plotH]);

  if (sampled.length === 0) {
    return (
      <p className="p-3 text-sm md-text-muted" data-chart-backend="svg">
        No variance data.
      </p>
    );
  }

  // Bar width based on the step between samples, collapsed by 1 px so
  // adjacent bars have a faint visual gap.
  const barStep = sampled.length > 1 ? (xScale(step) - xScale(0)) : plotW;
  const barWidth = Math.max(1, barStep - 1);
  const baselineY = yScale(1);

  const classColor = [
    tokens.varianceInvariant,
    tokens.varianceStructural,
    tokens.variancePointer,
    tokens.varianceKeyCandidate,
  ];

  const xTicks = niceLinearTicks(0, offsetMax, 6);
  const yTicks = niceLogTicks(1, yMax);

  return (
    <div ref={containerRef} data-chart-backend="svg" className="w-full" style={{ color: tokens.chartText }}>
      <svg
        width={containerWidth}
        height={CHART_HEIGHT}
        role="img"
        aria-label={title}
        style={{ display: "block", background: tokens.chartPaper }}
      >
        <title>{title}</title>

        <rect x={MARGIN.left} y={MARGIN.top} width={plotW} height={plotH} fill={tokens.chartPlot} />

        <text
          x={containerWidth / 2}
          y={MARGIN.top / 2 + 4}
          textAnchor="middle"
          fontSize={13}
          fontWeight={600}
          fill={tokens.chartText}
        >
          {title}
        </text>

        {/* Log-scale horizontal grid */}
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

        {/* Bars */}
        {sampled.map((v, i) => {
          const x = xScale(i * step);
          const y = yScale(Math.max(v, 1));
          const h = Math.max(0, baselineY - y);
          const cls = sampledCls?.[i] ?? -1;
          const fill = classColor[cls] ?? tokens.accentBlue;
          return <rect key={i} x={x} y={y} width={barWidth} height={h} fill={fill} />;
        })}

        {/* Reference lines at 200 (structural) and 3000 (pointer) */}
        <line
          x1={MARGIN.left}
          x2={MARGIN.left + plotW}
          y1={yScale(STRUCTURAL_REF)}
          y2={yScale(STRUCTURAL_REF)}
          stroke={tokens.varianceStructural}
          strokeWidth={1}
          strokeDasharray="2 3"
        />
        <line
          x1={MARGIN.left}
          x2={MARGIN.left + plotW}
          y1={yScale(POINTER_REF)}
          y2={yScale(POINTER_REF)}
          stroke={tokens.variancePointer}
          strokeWidth={1}
          strokeDasharray="2 3"
        />

        {/* X axis */}
        <line
          x1={MARGIN.left}
          x2={MARGIN.left + plotW}
          y1={MARGIN.top + plotH}
          y2={MARGIN.top + plotH}
          stroke={tokens.chartGrid}
          strokeWidth={1}
        />
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
        <text
          x={MARGIN.left + plotW / 2}
          y={CHART_HEIGHT - 4}
          textAnchor="middle"
          fontSize={11}
          fill={tokens.textSecondary}
        >
          Offset (bytes)
        </text>

        {/* Y axis (log) */}
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
              {formatNumber(t)}
            </text>
          </g>
        ))}
        <text
          x={14}
          y={MARGIN.top + plotH / 2}
          textAnchor="middle"
          fontSize={11}
          fill={tokens.textSecondary}
          transform={`rotate(-90, 14, ${MARGIN.top + plotH / 2})`}
        >
          Variance (log)
        </text>
      </svg>
    </div>
  );
});

export default VarianceMap;
