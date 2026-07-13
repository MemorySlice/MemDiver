/**
 * Plotly-backed VasChart. Loaded via React.lazy from
 * `../VasChart.tsx` (the dispatcher) when the user's
 * `settings.display.chartBackend` is "plotly" (default).
 *
 * The SVG alternative lives at `../svg/VasChart.tsx`.
 */
import { memo, useMemo } from "react";
import { useTranslation } from "react-i18next";
import { Plot } from "./normalize-plot";
import { usePlotlyTheme, usePlotlyColors } from "@/hooks/usePlotlyTheme";
import { PLOTLY_CONFIG, PLOTLY_STYLE } from "../chart-config";
import type { VasChartProps } from "../types";

const TYPE_NAME_KEYS: Record<number, string> = {
  0x00: "vas.type.unknown", 0x01: "vas.type.heap", 0x02: "vas.type.stack", 0x03: "vas.type.image",
  0x04: "vas.type.mapped", 0x05: "vas.type.anonymous", 0x06: "vas.type.shared",
};

function protStr(prot: number): string {
  return (prot & 1 ? "R" : "-") + (prot & 2 ? "W" : "-") + (prot & 4 ? "X" : "-");
}

export const VasChart = memo(function VasChart({ entries, title }: VasChartProps) {
  const { t } = useTranslation("charts");
  const resolvedTitle = title ?? t("vas.defaultTitle");
  const theme = usePlotlyTheme();
  const plotlyColors = usePlotlyColors();

  const typeColors = useMemo(() => ({
    0x00: "#808080",
    0x01: plotlyColors.accentGreen,
    0x02: plotlyColors.accentRed,    // stack uses warm color
    0x03: plotlyColors.accentBlue,
    0x04: plotlyColors.accentCyan,
    0x05: "#808080",
    0x06: plotlyColors.accentPurple,
  } as Record<number, string>), [plotlyColors]);

  if (!entries.length) return <p className="md-text-muted text-sm p-4">{t("vas.empty")}</p>;

  const labels = entries.map((e) => `0x${e.base_addr.toString(16)}`);
  const sizes = entries.map((e) => e.region_size);
  const colors = entries.map((e) => typeColors[e.region_type] || "#808080");
  const hoverText = entries.map((e) => {
    const typeName = t(TYPE_NAME_KEYS[e.region_type] ?? "vas.type.unknown");
    return `${typeName} | ${protStr(e.protection)} | ${(e.region_size / 1024).toFixed(0)} KB${e.mapped_path ? ` | ${e.mapped_path}` : ""}`;
  });

  return (
    <Plot
      data={[{
        y: labels, x: sizes, type: "bar", orientation: "h",
        marker: { color: colors },
        text: hoverText, hoverinfo: "text",
      }]}
      layout={{
        ...theme, title: { text: resolvedTitle },
        height: Math.max(300, entries.length * 28),
        margin: { ...theme.margin, l: 140 },
        yaxis: { ...theme.yaxis, autorange: "reversed" as const },
        xaxis: { ...theme.xaxis, title: { text: t("vas.axis.size") } },
        showlegend: false,
      }}
      config={PLOTLY_CONFIG}
      style={PLOTLY_STYLE}
    />
  );
});

export default VasChart;
