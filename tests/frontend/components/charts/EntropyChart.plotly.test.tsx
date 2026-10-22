import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";
import i18n from "@/i18n";
import { ThemeProvider } from "@/providers/ThemeProvider";
import { ENVELOPE_DATA, LEGACY_DATA } from "./entropy-fixtures";

const inTheme = (ui: React.ReactElement) => render(<ThemeProvider>{ui}</ThemeProvider>);
const tr = (key: string, opts?: Record<string, unknown>) => i18n.t(key, { ns: "charts", ...opts });

type Trace = { x: number[]; y: number[]; fill?: string; line: { width: number } };
type Shape = { type: string; yref: string; x0: number; x1: number; y0: number; y1: number; line: { dash?: string } };
type Layout = { yaxis: { range: [number, number] }; shapes: Shape[] };

/** Plotly cannot render under jsdom; record the props the chart hands it. */
const { plotProps } = vi.hoisted(() => ({
  plotProps: [] as Array<{ data: Trace[]; layout: Layout }>,
}));

vi.mock("@/components/charts/plotly/normalize-plot", () => ({
  Plot: (props: { data: Trace[]; layout: Layout }) => {
    plotProps.push(props);
    return <div data-testid="plot-stub" />;
  },
}));

const { EntropyChart } = await import("@/components/charts/plotly/EntropyChart");

const lastProps = () => plotProps[plotProps.length - 1];
// One full-height band per region (each also gets a short solid tick at the top).
const regionShapes = (layout: Layout) =>
  layout.shapes.filter((s) => s.type === "rect" && s.y0 === 0 && s.y1 === 1);
const lineShapes = (layout: Layout) => layout.shapes.filter((s) => s.type === "line");

describe("plotly EntropyChart envelope", () => {
  beforeEach(async () => {
    plotProps.length = 0;
    await i18n.changeLanguage("en");
  });

  it("draws the band as min + max(tonexty) with the max line visible, plus the mean", () => {
    inTheme(<EntropyChart data={ENVELOPE_DATA} />);
    const [minTrace, maxTrace, meanTrace] = lastProps().data;
    expect(minTrace.line.width).toBe(0);
    expect(maxTrace.fill).toBe("tonexty");
    expect(maxTrace.line.width).toBeGreaterThan(1);
    // Step geometry: each bucket spans [start, stop).
    expect(maxTrace.x).toEqual([0, 64, 64, 128, 128, 192, 192, 256]);
    expect(Math.max(...maxTrace.y)).toBe(4.97);
    expect(meanTrace.x).toEqual([32, 96, 160, 224]);

    const chart = screen.getByTestId("entropy-chart");
    expect(chart.dataset.envelopeBuckets).toBe("4");
    expect(chart.dataset.maxEntropyPeak).toBe("4.97");
    expect(chart.dataset.regionCount).toBe("2");
  });

  it("puts the threshold at data.threshold and the y range on max_entropy", () => {
    inTheme(<EntropyChart data={ENVELOPE_DATA} threshold={7.5} />);
    const { layout } = lastProps();
    const [thresholdLine, maxRef] = lineShapes(layout);
    expect(thresholdLine.y0).toBe(4.5);
    expect(maxRef.y0).toBe(5);
    expect(maxRef.line.dash).toBe("dot");
    expect(layout.yaxis.range[0]).toBe(0);
    expect(layout.yaxis.range[1]).toBeGreaterThan(5);
    expect(layout.yaxis.range[1]).toBeLessThan(6);
    expect(screen.getByTestId("entropy-chart").dataset.threshold).toBe("4.5");
  });

  it("marks every region and shows the count and resolution caption", () => {
    inTheme(<EntropyChart data={ENVELOPE_DATA} />);
    const regions = regionShapes(lastProps().layout);
    expect(regions.map((r) => [r.x0, r.x1])).toEqual([[64, 96], [160, 192]]);
    // ...each with a solid tick along the top so a hairline region is findable.
    const ticks = lastProps().layout.shapes.filter((s) => s.type === "rect" && s.y0 > 0.9);
    expect(ticks.map((r) => [r.x0, r.x1])).toEqual([[64, 96], [160, 192]]);
    expect(screen.getByTestId("entropy-region-count")).toHaveTextContent(
      tr("entropy.regions", { count: 2 }),
    );
    expect(screen.getByTestId("entropy-resolution")).toHaveTextContent(tr("entropy.resolution.full"));
  });

  it("warns when the threshold is unreachable for the window", () => {
    inTheme(<EntropyChart data={{ ...ENVELOPE_DATA, threshold: 7.5, threshold_reachable: false }} />);
    expect(screen.getByTestId("entropy-threshold-warning")).toHaveTextContent(
      tr("entropy.thresholdUnreachable", { threshold: "7.50", max: "5" }),
    );
    expect(lastProps().layout.yaxis.range[1]).toBeGreaterThan(7.5);
  });

  it("falls back to the profile_sample line without an envelope", () => {
    inTheme(<EntropyChart data={LEGACY_DATA} />);
    const { data, layout } = lastProps();
    expect(data).toHaveLength(1);
    expect(data[0].fill).toBe("tozeroy");
    expect(data[0].x).toEqual([0, 64, 128]);
    expect(regionShapes(layout)).toHaveLength(1);
    expect(lineShapes(layout)[0].y0).toBe(7.2);
    expect(layout.yaxis.range[1]).toBeGreaterThan(8);
    expect(screen.getByTestId("entropy-chart").dataset.envelopeBuckets).toBe("0");
  });
});
