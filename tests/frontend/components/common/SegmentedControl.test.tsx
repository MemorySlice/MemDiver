/**
 * Tests for `@/components/common/SegmentedControl`.
 *
 * Four segmented groups in the hex area used to own a byte-identical copy of
 * this markup. The contract this file pins is the one the four copies agreed
 * on — `tablist`/`tab`/`aria-selected`, `null` meaning "none of these", a
 * divider on every segment but the first, and a disabled segment that stays in
 * the DOM and says why — plus the two things a caller cannot express twice:
 * naming the group by `aria-label` OR by `aria-labelledby`.
 */

import { describe, it, expect, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";

import { SegmentedControl } from "@/components/common/SegmentedControl";

const OPTIONS = [
  { id: "a", label: "Alpha", testId: "seg-a" },
  { id: "b", label: "Beta", testId: "seg-b" },
  { id: "c", label: "Gamma", testId: "seg-c" },
];

describe("SegmentedControl semantics", () => {
  it("exposes one tablist and one tab per option", () => {
    render(
      <SegmentedControl aria-label="Group" options={OPTIONS} selected="a" onSelect={() => {}} />,
    );

    expect(screen.getByRole("tablist", { name: "Group" })).toBeInTheDocument();
    expect(screen.getAllByRole("tab")).toHaveLength(3);
  });

  it("marks exactly one tab selected", () => {
    render(
      <SegmentedControl aria-label="Group" options={OPTIONS} selected="b" onSelect={() => {}} />,
    );

    expect(screen.getByTestId("seg-b")).toHaveAttribute("aria-selected", "true");
    expect(screen.getByTestId("seg-a")).toHaveAttribute("aria-selected", "false");
    expect(screen.getByTestId("seg-c")).toHaveAttribute("aria-selected", "false");
  });

  /**
   * `null` is a real state, not a missing value: the overlay's `Align` switch
   * reflects the BUILD on screen, and before the first aligned window there is
   * no coordinate to point at.
   */
  it("selects nothing for a null selection", () => {
    render(
      <SegmentedControl aria-label="Group" options={OPTIONS} selected={null} onSelect={() => {}} />,
    );

    for (const id of ["seg-a", "seg-b", "seg-c"]) {
      expect(screen.getByTestId(id)).toHaveAttribute("aria-selected", "false");
    }
  });

  it("can be named by a visible label instead of a string", () => {
    render(
      <>
        <span id="lbl">Align</span>
        <SegmentedControl
          aria-labelledby="lbl"
          options={OPTIONS}
          selected="a"
          onSelect={() => {}}
        />
      </>,
    );

    expect(screen.getByRole("tablist", { name: "Align" })).toBeInTheDocument();
  });

  it("reports the clicked option's id", () => {
    const onSelect = vi.fn();
    render(
      <SegmentedControl aria-label="Group" options={OPTIONS} selected="a" onSelect={onSelect} />,
    );

    fireEvent.click(screen.getByTestId("seg-c"));

    expect(onSelect).toHaveBeenCalledWith("c");
  });
});

describe("SegmentedControl disabled segments", () => {
  it("keeps a disabled segment in the DOM, inert, and explained", () => {
    const onSelect = vi.fn();
    render(
      <SegmentedControl
        aria-label="Group"
        selected="a"
        onSelect={onSelect}
        options={[
          OPTIONS[0],
          { ...OPTIONS[1], disabled: true, title: "needs two dumps" },
        ]}
      />,
    );

    const beta = screen.getByTestId("seg-b");
    expect(beta).toBeInTheDocument();
    expect(beta).toBeDisabled();
    expect(beta).toHaveAttribute("aria-disabled", "true");
    expect(beta).toHaveAttribute("title", "needs two dumps");

    fireEvent.click(beta);
    expect(onSelect).not.toHaveBeenCalled();
  });

  it("leaves aria-disabled off an enabled segment", () => {
    render(
      <SegmentedControl aria-label="Group" options={OPTIONS} selected="a" onSelect={() => {}} />,
    );

    expect(screen.getByTestId("seg-a")).not.toHaveAttribute("aria-disabled");
  });
});

describe("SegmentedControl container", () => {
  it("passes data-* attributes through", () => {
    render(
      <SegmentedControl
        aria-label="Group"
        testId="grp"
        data={{ "data-method": "file_offset" }}
        options={OPTIONS}
        selected="a"
        onSelect={() => {}}
      />,
    );

    expect(screen.getByTestId("grp")).toHaveAttribute("data-method", "file_offset");
  });

  /**
   * The group dim is "this control has nothing to say right now", and it is an
   * inline opacity precisely so it cannot be confused with the
   * `disabled:opacity-50` a segment carries for a transient in-flight state.
   */
  it("dims the whole group without removing it", () => {
    render(
      <SegmentedControl
        aria-label="Group"
        testId="grp"
        dimmed
        options={OPTIONS}
        selected="a"
        onSelect={() => {}}
      />,
    );

    expect(screen.getByTestId("grp")).toHaveStyle({ opacity: "0.45" });
  });

  it("puts a divider on every segment but the first", () => {
    render(
      <SegmentedControl aria-label="Group" options={OPTIONS} selected="a" onSelect={() => {}} />,
    );

    expect(screen.getByTestId("seg-a").className).not.toContain("border-l");
    expect(screen.getByTestId("seg-b").className).toContain("border-l");
    expect(screen.getByTestId("seg-c").className).toContain("border-l");
  });
});
