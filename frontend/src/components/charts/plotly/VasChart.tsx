/**
 * Plotly-backed VasChart. Loaded via React.lazy from
 * `../VasChart.tsx` (the dispatcher) when the user's
 * `settings.display.chartBackend` is "plotly" (default).
 *
 * The SVG alternative lives at `../svg/VasChart.tsx`.
 */
import { memo, useMemo } from "react";
import { useTranslation } from "react-i18next";
import type { Data } from "plotly.js";
import { Plot } from "./normalize-plot";
import { usePlotlyTheme, usePlotlyColors } from "@/hooks/usePlotlyTheme";
import { PLOTLY_CONFIG, PLOTLY_STYLE } from "../chart-config";
import type { VasChartProps, VasEntry } from "../types";

const TYPE_NAME_KEYS: Record<number, string> = {
  0x00: "vas.type.unknown", 0x01: "vas.type.heap", 0x02: "vas.type.stack", 0x03: "vas.type.image",
  0x04: "vas.type.mapped", 0x05: "vas.type.anonymous", 0x06: "vas.type.shared",
};

const NOT_CAPTURED_OPACITY = 0.45;
const NOT_CAPTURED_HATCH = "/" as const;

function protStr(prot: number): string {
  return (prot & 1 ? "R" : "-") + (prot & 2 ? "W" : "-") + (prot & 4 ? "X" : "-");
}

/** `captured === false` marks a layout-only range excluded at import. */
function isNotCaptured(e: VasEntry): boolean {
  return e.captured === false;
}

export const VasChart = memo(function VasChart({ entries, title }: VasChartProps) {
  const { t } = useTranslation("charts");
  const resolvedTitle = title ?? t("vas.defaultTitle");
  const theme = usePlotlyTheme();
  const plotlyColors = usePlotlyColors();

  const typeColors = useMemo(() => ({
    0x00: plotlyColors.neutral,
    0x01: plotlyColors.accentGreen,
    0x02: plotlyColors.accentRed,    // stack uses warm color
    0x03: plotlyColors.accentBlue,
    0x04: plotlyColors.accentCyan,
    0x05: plotlyColors.neutral,
    0x06: plotlyColors.accentPurple,
  } as Record<number, string>), [plotlyColors]);

  if (!entries.length) return <p className="md-text-muted text-sm p-4">{t("vas.empty")}</p>;

  const labels = entries.map((e) => `0x${e.base_addr.toString(16)}`);
  const sizes = entries.map((e) => e.region_size);
  const notCaptured = entries.map(isNotCaptured);
  const hasNotCaptured = notCaptured.some(Boolean);
  const colors = entries.map((e, i) => (notCaptured[i]
    ? plotlyColors.neutral
    : typeColors[e.region_type] || plotlyColors.neutral));
  const hoverText = entries.map((e, i) => {
    const typeName = t(TYPE_NAME_KEYS[e.region_type] ?? "vas.type.unknown");
    const base = `${typeName} | ${protStr(e.protection)} | ${(e.region_size / 1024).toFixed(0)} KB${e.mapped_path ? ` | ${e.mapped_path}` : ""}`;
    return notCaptured[i] ? `${base}<br>${t("vas.notCaptured")}` : base;
  });

  const mainTrace: Data = {
    y: labels, x: sizes, type: "bar" as const, orientation: "h" as const,
    marker: {
      color: colors,
      opacity: notCaptured.map((n) => (n ? NOT_CAPTURED_OPACITY : 1)),
      pattern: { shape: notCaptured.map((n) => (n ? NOT_CAPTURED_HATCH : "" as const)) },
    },
    text: hoverText, hoverinfo: "text" as const,
    showlegend: false,
  };
  // Legend-only swatch. Plotly drops traces with NO points from the legend,
  // so it carries one zero-length bar on an existing category: it draws
  // nothing and adds no category (barmode "overlay" keeps the main bars at
  // full height instead of grouping them with this trace).
  const firstNotCaptured = notCaptured.indexOf(true);
  const notCapturedLegendTrace: Data = {
    y: firstNotCaptured >= 0 ? [labels[firstNotCaptured]] : [],
    x: firstNotCaptured >= 0 ? [0] : [],
    type: "bar" as const, orientation: "h" as const,
    name: t("vas.legend.notCaptured"),
    marker: {
      color: plotlyColors.neutral,
      opacity: NOT_CAPTURED_OPACITY,
      pattern: { shape: NOT_CAPTURED_HATCH },
    },
    hoverinfo: "skip" as const,
    showlegend: true,
  };

  return (
    <Plot
      data={hasNotCaptured ? [mainTrace, notCapturedLegendTrace] : [mainTrace]}
      layout={{
        ...theme, title: { text: resolvedTitle },
        height: Math.max(300, entries.length * 28),
        margin: { ...theme.margin, l: 140 },
        // "0x…" labels would otherwise be auto-typed as numbers (axis "0, 1B").
        yaxis: { ...theme.yaxis, type: "category" as const, autorange: "reversed" as const },
        xaxis: { ...theme.xaxis, title: { text: t("vas.axis.size") } },
        showlegend: hasNotCaptured,
        barmode: "overlay" as const,
        ...(hasNotCaptured && {
          legend: { orientation: "h" as const, x: 1, xanchor: "right" as const, y: 1.02, yanchor: "bottom" as const },
        }),
      }}
      config={PLOTLY_CONFIG}
      style={PLOTLY_STYLE}
    />
  );
});

export default VasChart;
