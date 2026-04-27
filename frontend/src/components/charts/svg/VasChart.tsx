/**
 * Hand-rolled SVG VasChart.
 *
 * Renders a Virtual Address Space projection as horizontal bars, one
 * per VAS entry. Color encodes region type (heap / stack / image /
 * mapped / shared / anonymous). Hovering a row reveals a floating
 * tooltip with base address (hex), type name, RWX protection flags,
 * region size (KB), and mapped path (if present).
 *
 * Dynamic SVG height scales with entry count, same behaviour as the
 * Plotly implementation.
 *
 * Loaded via React.lazy from `../VasChart.tsx` when
 * `settings.display.chartBackend === "svg"`.
 */
import { memo, useMemo, useState } from "react";
import { useChartTheme } from "@/hooks/useChartTheme";
import { useContainerWidth } from "@/hooks/useContainerWidth";
import type { VasChartProps, VasEntry } from "../types";
import { scaleLinear, niceLinearTicks, formatNumber } from "./primitives";

const MARGIN = { top: 40, right: 20, bottom: 36, left: 150 };
const ROW_HEIGHT = 22;

const TYPE_NAMES: Record<number, string> = {
  0x00: "Unknown",
  0x01: "Heap",
  0x02: "Stack",
  0x03: "Image",
  0x04: "Mapped",
  0x05: "Anonymous",
  0x06: "Shared",
};

function protStr(prot: number): string {
  return (
    (prot & 1 ? "R" : "-") + (prot & 2 ? "W" : "-") + (prot & 4 ? "X" : "-")
  );
}

export const VasChart = memo(function VasChart({ entries, title = "Virtual Address Space" }: VasChartProps) {
  const { svg: tokens } = useChartTheme();
  const [containerRef, containerWidth] = useContainerWidth({
    initialWidth: 720,
    minWidth: 360,
  });
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);
  const [mouse, setMouse] = useState<{ x: number; y: number } | null>(null);

  const typeColors: Record<number, string> = useMemo(
    () => ({
      0x00: tokens.textMuted,
      0x01: tokens.accentGreen,
      0x02: tokens.accentRed,
      0x03: tokens.accentBlue,
      0x04: tokens.accentCyan,
      0x05: tokens.textMuted,
      0x06: tokens.accentPurple,
    }),
    [tokens],
  );

  const chartHeight = Math.max(120, entries.length * ROW_HEIGHT + MARGIN.top + MARGIN.bottom);
  const plotW = Math.max(100, containerWidth - MARGIN.left - MARGIN.right);
  const plotH = chartHeight - MARGIN.top - MARGIN.bottom;

  const xMax = useMemo(
    () => (entries.length ? Math.max(...entries.map((e) => e.region_size)) : 1),
    [entries],
  );
  const xScale = useMemo(
    () => scaleLinear([0, xMax], [MARGIN.left, MARGIN.left + plotW]),
    [xMax, plotW],
  );

  if (!entries.length) {
    return (
      <p className="md-text-muted text-sm p-4" data-chart-backend="svg">
        No VAS data.
      </p>
    );
  }

  const xTicks = niceLinearTicks(0, xMax, 5);
  const hovered: VasEntry | null = hoverIdx !== null ? entries[hoverIdx] : null;

  return (
    <div
      ref={containerRef}
      data-chart-backend="svg"
      className="w-full"
      style={{ position: "relative", color: tokens.chartText }}
      onMouseLeave={() => {
        setHoverIdx(null);
        setMouse(null);
      }}
    >
      <svg
        width={containerWidth}
        height={chartHeight}
        role="img"
        aria-label={title}
        style={{ display: "block", background: tokens.chartPaper }}
        onMouseMove={(e) => {
          const rect = (e.currentTarget as SVGSVGElement).getBoundingClientRect();
          setMouse({ x: e.clientX - rect.left, y: e.clientY - rect.top });
        }}
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

        {/* Vertical grid for X ticks */}
        {xTicks.map((t) => (
          <line
            key={`gx-${t}`}
            x1={xScale(t)}
            x2={xScale(t)}
            y1={MARGIN.top}
            y2={MARGIN.top + plotH}
            stroke={tokens.chartGrid}
            strokeWidth={1}
          />
        ))}

        {/* Rows */}
        {entries.map((entry, i) => {
          const y = MARGIN.top + i * ROW_HEIGHT;
          const barWidth = Math.max(1, xScale(entry.region_size) - MARGIN.left);
          const color = typeColors[entry.region_type] ?? tokens.textMuted;
          const isHovered = hoverIdx === i;
          return (
            <g key={i}>
              {/* Transparent full-row hit target so hover works anywhere on the row */}
              <rect
                x={0}
                y={y}
                width={containerWidth}
                height={ROW_HEIGHT}
                fill="transparent"
                onMouseEnter={() => setHoverIdx(i)}
              />
              {/* Row highlight band */}
              {isHovered && (
                <rect
                  x={MARGIN.left}
                  y={y + 1}
                  width={plotW}
                  height={ROW_HEIGHT - 2}
                  fill={color}
                  fillOpacity={0.08}
                />
              )}
              {/* Address label */}
              <text
                x={MARGIN.left - 8}
                y={y + ROW_HEIGHT / 2 + 3}
                textAnchor="end"
                fontSize={10}
                fontFamily="inherit"
                fill={tokens.textMuted}
              >
                0x{entry.base_addr.toString(16)}
              </text>
              {/* Bar */}
              <rect
                x={MARGIN.left}
                y={y + 3}
                width={barWidth}
                height={ROW_HEIGHT - 6}
                fill={color}
                rx={1}
              />
            </g>
          );
        })}

        {/* X axis line */}
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
              {formatNumber(t)}
            </text>
          </g>
        ))}
        <text
          x={MARGIN.left + plotW / 2}
          y={chartHeight - 6}
          textAnchor="middle"
          fontSize={11}
          fill={tokens.textSecondary}
        >
          Size (bytes)
        </text>
      </svg>

      {hovered && mouse && (
        <div
          style={{
            position: "absolute",
            left: Math.min(mouse.x + 12, containerWidth - 230),
            top: Math.max(4, mouse.y - 10),
            padding: "6px 10px",
            borderRadius: 4,
            background: tokens.chartPaper,
            border: `1px solid ${tokens.border}`,
            color: tokens.textPrimary,
            fontSize: 11,
            pointerEvents: "none",
            boxShadow: "0 2px 6px rgba(0,0,0,0.25)",
          }}
        >
          <div style={{ fontWeight: 600 }}>
            {TYPE_NAMES[hovered.region_type] ?? "Unknown"}
          </div>
          <div style={{ color: tokens.textSecondary, marginTop: 2 }}>
            {`addr 0x${hovered.base_addr.toString(16)}`}
          </div>
          <div style={{ color: tokens.textSecondary }}>
            {`${protStr(hovered.protection)} | ${(hovered.region_size / 1024).toFixed(0)} KB`}
          </div>
          {hovered.mapped_path && (
            <div
              style={{
                color: tokens.textMuted,
                marginTop: 2,
                maxWidth: 220,
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
              title={hovered.mapped_path}
            >
              {hovered.mapped_path}
            </div>
          )}
        </div>
      )}
    </div>
  );
});

export default VasChart;
