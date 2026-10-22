import { describe, it, expect, vi, beforeEach } from "vitest";
import { render } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";
import i18n from "@/i18n";
import type { VasEntry } from "@/components/charts/types";
import { ThemeProvider } from "@/providers/ThemeProvider";

const inTheme = (ui: React.ReactElement) => render(<ThemeProvider>{ui}</ThemeProvider>);

/**
 * Plotly cannot render under jsdom, so the Plot component is replaced by a
 * stub that records the props VasChart hands it. Everything else is real.
 */
const { plotProps } = vi.hoisted(() => ({
  plotProps: [] as Array<{ data: Array<Record<string, unknown>>; layout: Record<string, unknown> }>,
}));

vi.mock("@/components/charts/plotly/normalize-plot", () => ({
  Plot: (props: { data: Array<Record<string, unknown>>; layout: Record<string, unknown> }) => {
    plotProps.push(props);
    return <div data-testid="plot-stub" />;
  },
}));

const { VasChart } = await import("@/components/charts/plotly/VasChart");

const CAPTURED: VasEntry = {
  base_addr: 0x400000, region_size: 0x1000, region_type: 0x03, protection: 0x05,
  mapped_path: "/usr/lib/libssl.so", captured: true,
};
const EXCLUDED: VasEntry = {
  base_addr: 0x7fff0000, region_size: 0x2000, region_type: 0x01, protection: 0x03,
  mapped_path: "[heap]", captured: false,
};

type Marker = { color: string[]; opacity: number[]; pattern: { shape: string[] } };

function lastProps() {
  return plotProps[plotProps.length - 1];
}

describe("plotly VasChart captured flag", () => {
  beforeEach(async () => {
    plotProps.length = 0;
    await i18n.changeLanguage("en");
  });

  it("hatches and dims not-captured bars and adds a legend entry", () => {
    inTheme(<VasChart entries={[CAPTURED, EXCLUDED]} />);
    const { data, layout } = lastProps();
    expect(data).toHaveLength(2);
    const marker = data[0].marker as Marker;
    expect(marker.pattern.shape).toEqual(["", "/"]);
    expect(marker.opacity[0]).toBe(1);
    expect(marker.opacity[1]).toBeLessThan(1);
    expect(data[1].name).toBe(i18n.t("vas.legend.notCaptured", { ns: "charts" }));
    expect(data[1].showlegend).toBe(true);
    expect(layout.showlegend).toBe(true);
    // Plotly hides point-less traces from the legend: the swatch carries one
    // zero-length bar on the excluded entry's existing category.
    expect(data[1].x).toEqual([0]);
    expect(data[1].y).toEqual([(data[0].y as string[])[1]]);
    expect(layout.barmode).toBe("overlay");
    const text = data[0].text as string[];
    expect(text[1]).toContain(i18n.t("vas.notCaptured", { ns: "charts" }));
    expect(text[0]).not.toContain(i18n.t("vas.notCaptured", { ns: "charts" }));
  });

  it("omits the legend when every entry is captured or the flag is absent", () => {
    const unknown = { ...CAPTURED, captured: undefined };
    inTheme(<VasChart entries={[CAPTURED, unknown]} />);
    const { data, layout } = lastProps();
    expect(data).toHaveLength(1);
    expect((data[0].marker as Marker).pattern.shape).toEqual(["", ""]);
    expect(layout.showlegend).toBe(false);
  });

  it("keeps hex base labels as categories, not numbers", () => {
    inTheme(<VasChart entries={[CAPTURED, EXCLUDED]} />);
    const { layout } = lastProps();
    expect((layout.yaxis as { type?: string }).type).toBe("category");
  });
});
