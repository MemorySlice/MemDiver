/**
 * Hand-rolled SVG SurvivorCurve.
 *
 * Log-y convergence curve for an n-sweep run: three reduce-stage lines
 * (variance / aligned / high_entropy) + the post-reduce candidate count,
 * plus a star marker + "hit" label at the first N for which the oracle
 * produced a verified hit. Matches the Plotly implementation's data
 * shape and color palette.
 *
 * Hover tooltip tracks nearest N-value and shows per-trace counts.
 *
 * Loaded via React.lazy from `../SurvivorCurve.tsx` when
 * `settings.display.chartBackend === "svg"`.
 */
import { useMemo, useState } from "react";
import { usePipelineStore } from "@/stores/pipeline-store";
import { useChartTheme } from "@/hooks/useChartTheme";
import { useContainerWidth } from "@/hooks/useContainerWidth";
import {
  scaleLinear,
  scaleLog,
  niceLinearTicks,
  niceLogTicks,
  formatNumber,
  polylinePath,
} from "@/components/charts/svg/primitives";
import { SURVIVOR_TRACES, type SurvivorTraceKey } from "../survivor-traces";

const CHART_HEIGHT = 360;
const MARGIN = { top: 30, right: 20, bottom: 80, left: 60 };

// SVG renders a dash pattern instead of Plotly's "dot" keyword.
const SVG_DASH: Record<string, string | undefined> = { dot: "3 3" };

export function SurvivorCurve() {
  const points = usePipelineStore((s) => s.nsweepPoints);
  const { svg: tokens } = useChartTheme();
  const [containerRef, containerWidth] = useContainerWidth({
    initialWidth: 720,
    minWidth: 320,
  });
  const [hoverN, setHoverN] = useState<number | null>(null);

  const plotW = Math.max(100, containerWidth - MARGIN.left - MARGIN.right);
  const plotH = CHART_HEIGHT - MARGIN.top - MARGIN.bottom;

  const { xScale, yScale, yMax, xMax, firstHit } = useMemo(() => {
    if (points.length === 0) {
      return {
        xScale: scaleLinear([0, 1], [MARGIN.left, MARGIN.left + plotW]),
        yScale: scaleLog([1, 10], [MARGIN.top + plotH, MARGIN.top]),
        yMax: 10,
        xMax: 1,
        firstHit: null as typeof points[number] | null,
      };
    }
    const ns = points.map((p) => p.n);
    const xMax = Math.max(...ns);
    const xMin = Math.min(...ns);
    let yMax = 0;
    for (const p of points) {
      yMax = Math.max(
        yMax,
        p.stages.variance ?? 0,
        p.stages.aligned ?? 0,
        p.stages.high_entropy ?? 0,
        p.candidates ?? 0,
      );
    }
    yMax = Math.max(yMax, 10);
    const xScale = scaleLinear([xMin, xMax], [MARGIN.left, MARGIN.left + plotW]);
    const yScale = scaleLog([1, yMax], [MARGIN.top + plotH, MARGIN.top]);
    const firstHit = points.find((p) => p.hit_offset !== null) ?? null;
    return { xScale, yScale, yMax, xMax, firstHit };
  }, [points, plotW, plotH]);

  if (points.length === 0) {
    return (
      <div
        data-chart-backend="svg"
        className="md-panel p-4 text-xs md-text-muted"
      >
        No n-sweep data (pipeline ran without --nsweep).
      </div>
    );
  }

  const traceValues = (key: SurvivorTraceKey, p: (typeof points)[number]): number => {
    if (key === "candidates") return p.candidates ?? 0;
    return p.stages[key] ?? 0;
  };

  const xTicks = niceLinearTicks(points[0].n, xMax, Math.min(points.length, 7));
  const yTicks = niceLogTicks(1, yMax);

  const hoverPoint = hoverN === null ? null : points.reduce((best, p) => {
    if (!best) return p;
    return Math.abs(p.n - hoverN) < Math.abs(best.n - hoverN) ? p : best;
  }, points[0]);

  return (
    <div
      ref={containerRef}
      className="md-panel p-2"
      data-chart-backend="svg"
      data-tour-id="pipeline-survivor-curve"
      style={{ position: "relative", color: tokens.chartText }}
    >
      <svg
        width={containerWidth}
        height={CHART_HEIGHT}
        role="img"
        aria-label="Survivor curve"
        style={{ display: "block" }}
        onMouseMove={(e) => {
          const rect = (e.currentTarget as SVGSVGElement).getBoundingClientRect();
          const x = e.clientX - rect.left;
          if (x < MARGIN.left || x > MARGIN.left + plotW) {
            setHoverN(null);
            return;
          }
          const fraction = (x - MARGIN.left) / plotW;
          const xMin = points[0].n;
          setHoverN(xMin + fraction * (xMax - xMin));
        }}
        onMouseLeave={() => setHoverN(null)}
      >
        <title>Survivor curve</title>

        {/* Grid */}
        {yTicks.map((t) => (
          <line
            key={`gy-${t}`}
            x1={MARGIN.left}
            x2={MARGIN.left + plotW}
            y1={yScale(t)}
            y2={yScale(t)}
            stroke={tokens.chartGrid}
            strokeOpacity={0.5}
            strokeWidth={1}
          />
        ))}

        {/* Traces */}
        {SURVIVOR_TRACES.map((trace) => {
          const path = polylinePath(
            points.map((p) => [xScale(p.n), yScale(Math.max(1, traceValues(trace.key, p)))]),
          );
          const dasharray = trace.dash ? SVG_DASH[trace.dash] : undefined;
          return (
            <g key={trace.key}>
              <path
                d={path}
                fill="none"
                stroke={trace.color}
                strokeWidth={2}
                strokeDasharray={dasharray}
                strokeLinejoin="round"
              />
              {points.map((p, i) => (
                <circle
                  key={`m-${trace.key}-${i}`}
                  cx={xScale(p.n)}
                  cy={yScale(Math.max(1, traceValues(trace.key, p)))}
                  r={3}
                  fill={trace.color}
                />
              ))}
            </g>
          );
        })}

        {/* Oracle-hit star + text label */}
        {firstHit && (
          <g>
            <polygon
              points={starPath(xScale(firstHit.n), yScale(1), 8)}
              fill="#a855f7"
              stroke="#a855f7"
              strokeWidth={1}
            />
            <text
              x={xScale(firstHit.n)}
              y={yScale(1) - 14}
              textAnchor="middle"
              fontSize={11}
              fill="#a855f7"
              fontWeight={600}
            >
              hit
            </text>
          </g>
        )}

        {/* Hover line + dots */}
        {hoverPoint && (
          <g>
            <line
              x1={xScale(hoverPoint.n)}
              x2={xScale(hoverPoint.n)}
              y1={MARGIN.top}
              y2={MARGIN.top + plotH}
              stroke={tokens.chartGrid}
              strokeWidth={1}
            />
          </g>
        )}

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
              {Math.round(t)}
            </text>
          </g>
        ))}
        <text
          x={MARGIN.left + plotW / 2}
          y={MARGIN.top + plotH + 34}
          textAnchor="middle"
          fontSize={11}
          fill={tokens.textSecondary}
        >
          N dumps folded
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
          Survivors (log)
        </text>

        {/* Legend (bottom, horizontal) */}
        {SURVIVOR_TRACES.map((trace, i) => {
          const legendY = CHART_HEIGHT - 14;
          const itemW = Math.min(130, plotW / SURVIVOR_TRACES.length);
          const x = MARGIN.left + i * itemW;
          const dasharray = trace.dash ? SVG_DASH[trace.dash] : undefined;
          return (
            <g key={`lg-${trace.key}`}>
              <line
                x1={x}
                x2={x + 14}
                y1={legendY}
                y2={legendY}
                stroke={trace.color}
                strokeWidth={2}
                strokeDasharray={dasharray}
              />
              <text x={x + 18} y={legendY + 3} fontSize={10} fill={tokens.textMuted}>
                {trace.label}
              </text>
            </g>
          );
        })}
      </svg>

      {/* Hover tooltip */}
      {hoverPoint && (
        <div
          style={{
            position: "absolute",
            left: Math.min(
              xScale(hoverPoint.n) + 10,
              containerWidth - 170,
            ),
            top: MARGIN.top + 4,
            padding: "6px 10px",
            borderRadius: 4,
            background: tokens.chartPaper,
            border: `1px solid ${tokens.border}`,
            color: tokens.textPrimary,
            fontSize: 11,
            pointerEvents: "none",
            boxShadow: "0 2px 6px rgba(0,0,0,0.25)",
            fontFamily: "inherit",
          }}
        >
          <div style={{ fontWeight: 600, marginBottom: 3 }}>N = {hoverPoint.n}</div>
          {SURVIVOR_TRACES.map((t) => (
            <div key={t.key} style={{ color: t.color }}>
              {t.label}: {formatNumber(traceValues(t.key, hoverPoint))}
            </div>
          ))}
          {hoverPoint.hit_offset !== null && (
            <div style={{ color: "#a855f7", marginTop: 2 }}>
              oracle hit @ 0x{hoverPoint.hit_offset.toString(16)}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/** Five-pointed star centred at (cx, cy) with outer radius r. */
function starPath(cx: number, cy: number, r: number): string {
  const pts: string[] = [];
  for (let i = 0; i < 10; i++) {
    const angle = (Math.PI / 5) * i - Math.PI / 2;
    const radius = i % 2 === 0 ? r : r / 2.2;
    const x = cx + Math.cos(angle) * radius;
    const y = cy + Math.sin(angle) * radius;
    pts.push(`${x.toFixed(2)},${y.toFixed(2)}`);
  }
  return pts.join(" ");
}

export default SurvivorCurve;
