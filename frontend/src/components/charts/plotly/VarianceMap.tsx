/**
 * Plotly-backed VarianceMap. Loaded via React.lazy from
 * `../VarianceMap.tsx` (the dispatcher) when the user's
 * `settings.display.chartBackend` is "plotly" (default).
 *
 * The SVG alternative lives at `../svg/VarianceMap.tsx`.
 */
import { memo } from "react";
import { Plot } from "./normalize-plot";
import { usePlotlyTheme, usePlotlyColors } from "@/hooks/usePlotlyTheme";
import { PLOTLY_CONFIG, PLOTLY_STYLE } from "../chart-config";
import type { VarianceMapProps } from "../types";

export const VarianceMap = memo(function VarianceMap({
  variance,
  classifications,
  step = 1,
  title = "Variance Map",
}: VarianceMapProps) {
  const theme = usePlotlyTheme();
  const colors = usePlotlyColors();

  // Subsample for performance
  const sampled = step > 1 ? variance.filter((_, i) => i % step === 0) : variance;
  const offsets = sampled.map((_, i) => i * step);

  // Map classifications to colors
  let barColors: string[] | undefined;
  if (classifications) {
    const classColorMap = [colors.invariant, colors.structural, colors.pointer, colors.keyCandidate];
    const sampledCls = step > 1 ? classifications.filter((_, i) => i % step === 0) : classifications;
    barColors = sampledCls.map((c) => classColorMap[c] || colors.accentBlue);
  }

  return (
    <Plot
      data={[{
        x: offsets, y: sampled, type: "bar",
        marker: { color: barColors || colors.accentBlue },
        name: "Variance",
      }]}
      layout={{
        ...theme, title: { text: title }, height: 350, bargap: 0,
        xaxis: { ...theme.xaxis, title: { text: "Offset (bytes)" } },
        yaxis: { ...theme.yaxis, title: { text: "Variance" }, type: "log" },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        shapes: [
          { type: "line", xref: "paper", yref: "y", x0: 0, x1: 1, y0: 200, y1: 200, line: { color: colors.structural, width: 1, dash: "dot" } },
          { type: "line", xref: "paper", yref: "y", x0: 0, x1: 1, y0: 3000, y1: 3000, line: { color: colors.pointer, width: 1, dash: "dot" } },
        ] as any,
        showlegend: false,
      }}
      config={PLOTLY_CONFIG}
      style={PLOTLY_STYLE}
    />
  );
});

export default VarianceMap;
