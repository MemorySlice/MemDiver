import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
// See the comment in `ErrorBoundary.test.tsx`.
import "@testing-library/jest-dom/vitest";
import "@/i18n";
import {
  loadChartModule,
  resolvedChartModule,
  type ChartModule,
} from "@/components/charts/chart-module-cache";
import { ChartDispatcher } from "@/components/charts/ChartDispatcher";

interface LabelProps {
  label: string;
}

function makeLoader(text: string) {
  const Impl = ({ label }: LabelProps) => <p>{`${text}:${label}`}</p>;
  const load = vi.fn(async (): Promise<ChartModule<LabelProps>> => ({ default: Impl }));
  return { Impl, load };
}

describe("chart-module-cache", () => {
  it("remembers a loader's component only after its import resolves", async () => {
    const { Impl, load } = makeLoader("x");
    expect(resolvedChartModule(load)).toBeUndefined();
    const pending = loadChartModule(load);
    expect(resolvedChartModule(load)).toBeUndefined();
    await pending;
    expect(resolvedChartModule(load)).toBe(Impl);
  });

  it("does not remember a failed import", async () => {
    const load = vi.fn(async (): Promise<ChartModule<LabelProps>> => {
      throw new Error("chunk failed");
    });
    await expect(loadChartModule(load)).rejects.toThrow("chunk failed");
    expect(resolvedChartModule(load)).toBeUndefined();
  });
});

describe("ChartDispatcher with a preloaded implementation", () => {
  it("renders it synchronously, without a Suspense fallback", async () => {
    const plotly = makeLoader("plotly");
    const svg = makeLoader("svg");
    await loadChartModule(plotly.load);

    render(
      <ChartDispatcher<LabelProps> loadPlotly={plotly.load} loadSvg={svg.load} label="a" />,
    );

    // No await: a lazy() boundary would still be showing the skeleton here.
    expect(screen.getByText("plotly:a")).toBeInTheDocument();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
    expect(plotly.load).toHaveBeenCalledTimes(1);
  });

  it("still lazy-loads (skeleton first) when nothing was preloaded", async () => {
    const plotly = makeLoader("plotly");
    const svg = makeLoader("svg");

    render(
      <ChartDispatcher<LabelProps> loadPlotly={plotly.load} loadSvg={svg.load} label="b" />,
    );

    expect(screen.getByRole("status")).toBeInTheDocument();
    expect(await screen.findByText("plotly:b")).toBeInTheDocument();
    // ...and the next mount is direct.
    expect(resolvedChartModule(plotly.load)).toBe(plotly.Impl);
  });
});
