import { describe, it, expect, beforeEach } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";
import i18n from "@/i18n";
import { VasChart } from "@/components/charts/svg/VasChart";
import type { VasEntry } from "@/components/charts/types";
import { ThemeProvider } from "@/providers/ThemeProvider";

const inTheme = (ui: React.ReactElement) => render(<ThemeProvider>{ui}</ThemeProvider>);

const CAPTURED: VasEntry = {
  base_addr: 0x400000, region_size: 0x1000, region_type: 0x03, protection: 0x05,
  mapped_path: "/usr/lib/libssl.so", captured: true,
};
const EXCLUDED: VasEntry = {
  base_addr: 0x7fff0000, region_size: 0x2000, region_type: 0x01, protection: 0x03,
  mapped_path: "[heap]", captured: false,
};

const tr = (key: string) => i18n.t(key, { ns: "charts" });

describe("svg VasChart captured flag", () => {
  beforeEach(async () => {
    await i18n.changeLanguage("en");
  });

  it("hatches not-captured bars and shows the legend", () => {
    const { container } = inTheme(<VasChart entries={[CAPTURED, EXCLUDED]} />);
    expect(screen.getByTestId("vas-hatch-pattern")).toBeInTheDocument();
    expect(screen.getAllByTestId("vas-bar-hatch")).toHaveLength(1);
    expect(container.querySelectorAll('[data-captured="false"]')).toHaveLength(1);
    expect(screen.getByTestId("vas-legend-not-captured")).toHaveTextContent(
      tr("vas.legend.notCaptured"),
    );
  });

  it("notes not-captured in the tooltip", () => {
    const { container } = inTheme(<VasChart entries={[CAPTURED, EXCLUDED]} />);
    const svg = container.querySelector("svg")!;
    const hitTargets = container.querySelectorAll('rect[fill="transparent"]');
    fireEvent.mouseMove(svg, { clientX: 10, clientY: 10 });
    fireEvent.mouseEnter(hitTargets[1]);
    expect(screen.getByText(tr("vas.notCaptured"))).toBeInTheDocument();
    fireEvent.mouseEnter(hitTargets[0]);
    expect(screen.queryByText(tr("vas.notCaptured"))).not.toBeInTheDocument();
  });

  it("renders no hatch or legend when nothing is excluded", () => {
    inTheme(<VasChart entries={[CAPTURED, { ...EXCLUDED, captured: undefined }]} />);
    expect(screen.queryByTestId("vas-hatch-pattern")).not.toBeInTheDocument();
    expect(screen.queryByTestId("vas-bar-hatch")).not.toBeInTheDocument();
    expect(screen.queryByTestId("vas-legend-not-captured")).not.toBeInTheDocument();
  });
});
