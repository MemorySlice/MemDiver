import { memo } from "react";
import Plot from "react-plotly.js";
import { usePlotlyTheme, usePlotlyColors } from "@/hooks/usePlotlyTheme";
import { PLOTLY_CONFIG, PLOTLY_STYLE } from "./chart-config";
import type { EntropyData } from "@/api/types";

interface Props {
  data: EntropyData;
  threshold?: number;
  title?: string;
}

export const EntropyChart = memo(function EntropyChart({ data, threshold = 7.5, title = "Entropy Profile" }: Props) {
  const theme = usePlotlyTheme();
  const colors = usePlotlyColors();

  if (!data.profile_sample || data.profile_sample.length === 0) {
    return <p className="p-3 text-sm md-text-muted">No entropy profile available.</p>;
  }

  const offsets = data.profile_sample.map((p) => p.offset);
  const values = data.profile_sample.map((p) => p.entropy);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- Plotly shape types are overly strict
  const shapes: any[] = data.high_entropy_regions.map((r) => ({
    type: "rect", xref: "x", yref: "paper",
    x0: r.start, x1: r.end, y0: 0, y1: 1,
    fillcolor: colors.accentRed, opacity: 0.15, line: { width: 0 },
  }));

  shapes.push({
    type: "line", xref: "paper", yref: "y",
    x0: 0, x1: 1, y0: threshold, y1: threshold,
    line: { color: colors.accentRed, width: 1, dash: "dash" },
  });

  return (
    <Plot
      data={[{
        x: offsets, y: values, type: "scatter", mode: "lines",
        line: { color: colors.accentBlue, width: 1 },
        fill: "tozeroy", fillcolor: colors.accentBlue + "20",
        name: "Entropy",
      }]}
      layout={{
        ...theme, title: { text: title }, height: 350,
        xaxis: { ...theme.xaxis, title: { text: "Offset (bytes)" } },
        yaxis: { ...theme.yaxis, title: { text: "Entropy (bits/byte)" }, range: [0, 8.5] },
        shapes,
        showlegend: false,
      }}
      config={PLOTLY_CONFIG}
      style={PLOTLY_STYLE}
    />
  );
});
