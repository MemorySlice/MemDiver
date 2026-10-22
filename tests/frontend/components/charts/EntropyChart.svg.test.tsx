import { describe, it, expect, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";
import i18n from "@/i18n";
import { EntropyChart } from "@/components/charts/svg/EntropyChart";
import { ThemeProvider } from "@/providers/ThemeProvider";
import { ENVELOPE_DATA, LEGACY_DATA } from "./entropy-fixtures";

const inTheme = (ui: React.ReactElement) => render(<ThemeProvider>{ui}</ThemeProvider>);
const tr = (key: string, opts?: Record<string, unknown>) => i18n.t(key, { ns: "charts", ...opts });

// Geometry of the SVG chart: 350px tall, 40px top/bottom margins.
const PLOT_TOP = 40;
const PLOT_H = 270;
const yPx = (v: number, yTop: number) => PLOT_TOP + PLOT_H - (v / yTop) * PLOT_H;

describe("svg EntropyChart envelope", () => {
  beforeEach(async () => {
    await i18n.changeLanguage("en");
  });

  it("draws the min–max band with the max line on top and the spike as its peak", () => {
    inTheme(<EntropyChart data={ENVELOPE_DATA} />);
    const band = screen.getByTestId("entropy-envelope-band");
    const maxLine = screen.getByTestId("entropy-max-line");
    expect(band.getAttribute("d")).toMatch(/Z$/);
    // Later siblings paint on top.
    expect(band.compareDocumentPosition(maxLine) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.getByTestId("entropy-mean-line")).toBeInTheDocument();
    expect(screen.queryByTestId("entropy-profile-line")).toBeNull();

    const chart = screen.getByTestId("entropy-chart");
    const yTop = Number(chart.dataset.yTop);
    expect(maxLine.getAttribute("d")).toContain(yPx(4.97, yTop).toFixed(2));
    expect(chart.dataset.envelopeBuckets).toBe("4");
    expect(chart.dataset.maxEntropyPeak).toBe("4.97");
  });

  it("puts the threshold at data.threshold and the y range on max_entropy", () => {
    inTheme(<EntropyChart data={ENVELOPE_DATA} threshold={7.5} />);
    const chart = screen.getByTestId("entropy-chart");
    const yTop = Number(chart.dataset.yTop);
    expect(yTop).toBeGreaterThan(5);
    expect(yTop).toBeLessThan(6);
    expect(chart.dataset.threshold).toBe("4.5");
    const line = screen.getByTestId("entropy-threshold-line");
    expect(Number(line.getAttribute("y1"))).toBeCloseTo(yPx(4.5, yTop), 1);
    const maxRef = screen.getByTestId("entropy-max-entropy-line");
    expect(Number(maxRef.getAttribute("y1"))).toBeCloseTo(yPx(5, yTop), 1);
    expect(screen.getByText(tr("entropy.maxEntropyLabel", { value: "5" }))).toBeInTheDocument();
  });

  it("marks every region and shows the count and resolution caption", () => {
    inTheme(<EntropyChart data={ENVELOPE_DATA} />);
    expect(screen.getAllByTestId("entropy-region")).toHaveLength(2);
    expect(screen.getByTestId("entropy-region-count")).toHaveTextContent(
      tr("entropy.regions", { count: 2 }),
    );
    expect(screen.getByTestId("entropy-resolution")).toHaveTextContent(tr("entropy.resolution.full"));
    expect(screen.queryByTestId("entropy-threshold-warning")).toBeNull();
  });

  it("hints at truncation and names the sampling step", () => {
    inTheme(
      <EntropyChart
        data={{ ...ENVELOPE_DATA, resolution: "sampled", step: 16, region_count: 2500, regions_truncated: true }}
      />,
    );
    expect(screen.getByTestId("entropy-region-count")).toHaveTextContent(
      tr("entropy.regionsTruncated", { shown: 2, total: 2500 }),
    );
    expect(screen.getByTestId("entropy-resolution")).toHaveTextContent(
      tr("entropy.resolution.sampled", { step: 16 }),
    );
  });

  it("warns when the threshold is unreachable for the window", () => {
    inTheme(
      <EntropyChart data={{ ...ENVELOPE_DATA, threshold: 7.5, threshold_reachable: false }} />,
    );
    expect(screen.getByTestId("entropy-threshold-warning")).toHaveTextContent(
      tr("entropy.thresholdUnreachable", { threshold: "7.50", max: "5" }),
    );
    // The y range stretches so the unreachable line stays on the chart.
    expect(Number(screen.getByTestId("entropy-chart").dataset.yTop)).toBeGreaterThan(7.5);
  });

  it("falls back to the profile_sample line without an envelope", () => {
    inTheme(<EntropyChart data={LEGACY_DATA} />);
    expect(screen.getByTestId("entropy-profile-line")).toBeInTheDocument();
    expect(screen.queryByTestId("entropy-envelope-band")).toBeNull();
    expect(screen.queryByTestId("entropy-max-line")).toBeNull();
    expect(screen.getAllByTestId("entropy-region")).toHaveLength(1);
    // No window, no server threshold: 90% of the 8-bit ceiling.
    expect(screen.getByTestId("entropy-chart").dataset.threshold).toBe("7.2");
  });

  it("derives the client fallback threshold from the window (4.5 at 32)", () => {
    inTheme(<EntropyChart data={{ ...LEGACY_DATA, window: 32 }} />);
    const chart = screen.getByTestId("entropy-chart");
    expect(chart.dataset.threshold).toBe("4.5");
    expect(chart.dataset.maxEntropy).toBe("5");
  });

  it("shows the empty state when there is nothing to draw", () => {
    inTheme(<EntropyChart data={{ ...LEGACY_DATA, profile_sample: [] }} />);
    expect(screen.getByText(tr("entropy.empty"))).toBeInTheDocument();
  });
});
