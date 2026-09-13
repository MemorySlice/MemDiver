/**
 * Tests for `@/components/common/VarianceSwatch`.
 *
 * The chip is decorative: it carries nothing the label does not already carry,
 * so announcing it hands a screen-reader user a bare, nameless element between
 * every two words of a legend. Eleven sites drew this pair by hand and only
 * four remembered `aria-hidden`; the one thing this file exists to pin is that
 * the attribute is no longer any caller's job.
 */

import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";

import { VarianceSwatch } from "@/components/common/VarianceSwatch";

describe("VarianceSwatch", () => {
  it("hides the chip from assistive tech", () => {
    const { container } = render(
      <VarianceSwatch swatchClass="variance-pointer" label="Pointer" />,
    );

    const chip = container.querySelector(".md-variance-swatch")!;
    expect(chip).toHaveAttribute("aria-hidden", "true");
  });

  it("renders the label as real text, so the entry has a name", () => {
    render(<VarianceSwatch swatchClass="variance-pointer" label="Pointer" />);

    expect(screen.getByText("Pointer")).toBeInTheDocument();
  });

  it("carries the caller's modifier class on the chip", () => {
    const { container } = render(
      <VarianceSwatch swatchClass="variance-key-candidate" label="Key Candidate" />,
    );

    const chip = container.querySelector(".md-variance-swatch")!;
    expect(chip.className).toContain("variance-key-candidate");
  });

  it("keeps the shared gap idiom rather than a per-site spelling", () => {
    const { container } = render(
      <VarianceSwatch swatchClass="variance-invariant" label="Invariant" />,
    );

    expect(container.firstElementChild!.className).toContain("inline-flex items-center gap-1");
  });

  it("accepts test ids for the wrapper and for the chip", () => {
    render(
      <VarianceSwatch
        testId="legend-entry"
        swatchTestId="legend-chip"
        swatchClass="absence-gap"
        label="No correspondence"
      />,
    );

    expect(screen.getByTestId("legend-entry")).toBeInTheDocument();
    expect(screen.getByTestId("legend-chip")).toHaveAttribute("aria-hidden", "true");
  });
});
