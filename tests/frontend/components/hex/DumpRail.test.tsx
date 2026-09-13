import { afterEach, describe, expect, it } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { DumpRail } from "@/components/hex/DumpRail";
import type { AlignedWindowAlignment } from "@/api/aligned-window";
import { useDumpRailStore } from "@/stores/dump-rail-store";
import type { DumpEntry } from "@/stores/dump-store";
import { useMultiHexStore } from "@/stores/multi-hex-store";

/**
 * The rail is the only place the analyst can say whose bytes the overlay is
 * reading, so the failures worth guarding are the ones that would leave that
 * question unanswerable: an icon-only control with no accessible name, an
 * excluded dump that still looks included, or a chip whose pressed state does
 * not follow the solo it just set.
 */

const ALIGNED: AlignedWindowAlignment = {
  method: "virtual_address",
  bytes_compared: 8192,
  bytes_discarded: 256,
  sizes_differed: false,
  n_sources: 3,
  warnings: [],
};

function entry(i: number): DumpEntry {
  return {
    id: `d${i}`,
    path: `/dumps/d${i}.msl`,
    name: `d${i}.msl`,
    size: 64 * 1024,
    format: "msl",
    sameProcess: true,
  };
}

const DUMPS = [entry(0), entry(1), entry(2)];

function seedAlignment(alignment: AlignedWindowAlignment | null = ALIGNED) {
  act(() => {
    useMultiHexStore.setState({ alignment });
  });
}

function renderRail(dumps: DumpEntry[] = DUMPS) {
  return render(<DumpRail dumps={dumps} />);
}

afterEach(() => {
  act(() => {
    useDumpRailStore.getState().reset();
    useMultiHexStore.getState().reset();
  });
});

describe("DumpRail chips", () => {
  it("renders one chip per selected dump plus the overlay chip", () => {
    seedAlignment();
    renderRail();

    for (const d of DUMPS) {
      expect(screen.getByTestId(`dump-rail-chip-${d.id}`)).toBeInTheDocument();
    }
    expect(screen.getAllByTestId(/^dump-rail-chip-/)).toHaveLength(3);
    expect(screen.getByTestId("dump-rail-overlay")).toBeInTheDocument();
  });

  it("names the aligned set and its size in the section head", () => {
    seedAlignment();
    renderRail();

    expect(screen.getByTestId("dump-rail-head")).toHaveTextContent(/aligned set/i);
    expect(screen.getByTestId("dump-rail-head")).toHaveTextContent("3");
  });

  /**
   * `aria-pressed` rather than colour alone: the active chip is the answer to
   * "whose bytes am I reading", and that answer has to survive a screen reader.
   */
  it("marks the overlay chip pressed while nothing is soloed", () => {
    seedAlignment();
    renderRail();

    expect(screen.getByTestId("dump-rail-overlay")).toHaveAttribute("aria-pressed", "true");
    for (const d of DUMPS) {
      expect(screen.getByTestId(`dump-rail-solo-${d.id}`)).toHaveAttribute(
        "aria-pressed",
        "false",
      );
    }
  });

  it("moves the pressed state to the chip that was clicked", () => {
    seedAlignment();
    renderRail();

    fireEvent.click(screen.getByTestId("dump-rail-solo-d1"));

    expect(screen.getByTestId("dump-rail-solo-d1")).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByTestId("dump-rail-solo-d0")).toHaveAttribute("aria-pressed", "false");
    expect(screen.getByTestId("dump-rail-overlay")).toHaveAttribute("aria-pressed", "false");
  });
});

describe("DumpRail solo", () => {
  it("solos the dump whose chip was clicked", () => {
    seedAlignment();
    renderRail();

    fireEvent.click(screen.getByTestId("dump-rail-solo-d2"));

    expect(useDumpRailStore.getState().soloPath).toBe(DUMPS[2].path);
    expect(screen.getByTestId("dump-rail-chip-d2")).toHaveAttribute("data-active", "true");
  });

  it("returns to the overlay when the soloed chip is clicked again", () => {
    seedAlignment();
    renderRail();

    fireEvent.click(screen.getByTestId("dump-rail-solo-d2"));
    fireEvent.click(screen.getByTestId("dump-rail-solo-d2"));

    expect(useDumpRailStore.getState().soloPath).toBeNull();
  });

  it("returns to the overlay from the overlay chip", () => {
    seedAlignment();
    renderRail();

    fireEvent.click(screen.getByTestId("dump-rail-solo-d2"));
    fireEvent.click(screen.getByTestId("dump-rail-overlay"));

    expect(useDumpRailStore.getState().soloPath).toBeNull();
  });
});

describe("DumpRail inclusion", () => {
  it("dims a dump that has been left out of the consensus", () => {
    seedAlignment();
    renderRail();

    fireEvent.click(screen.getByTestId("dump-rail-include-d1"));

    const chip = screen.getByTestId("dump-rail-chip-d1");
    expect(chip).toHaveAttribute("data-included", "false");
    expect(chip).toHaveStyle({ opacity: "0.5" });
    expect(screen.getByTestId("dump-rail-chip-d0")).toHaveAttribute("data-included", "true");
  });

  /**
   * An icon-only button with no accessible name is invisible to a screen
   * reader and fails the repo's axe baseline, so the name is asserted on the
   * ROLE query rather than on a test id — that is what a user of assistive tech
   * actually has to find.
   */
  it("gives the eye toggle a name that says what it will do", () => {
    seedAlignment();
    renderRail();

    expect(screen.getByRole("button", { name: /leave d1\.msl out of the consensus/i })).toBe(
      screen.getByTestId("dump-rail-include-d1"),
    );

    fireEvent.click(screen.getByTestId("dump-rail-include-d1"));

    expect(screen.getByRole("button", { name: /count d1\.msl in the consensus/i })).toBe(
      screen.getByTestId("dump-rail-include-d1"),
    );
  });

  /**
   * Emptying the consensus is not a stricter reading, it is a blank grid with
   * no control on screen explaining why — so the last remaining voter cannot be
   * switched off.
   */
  it("refuses to exclude the last included dump", () => {
    seedAlignment();
    renderRail();

    fireEvent.click(screen.getByTestId("dump-rail-include-d1"));
    fireEvent.click(screen.getByTestId("dump-rail-include-d2"));

    const last = screen.getByTestId("dump-rail-include-d0");
    expect(last).toBeDisabled();
    fireEvent.click(last);
    expect(useDumpRailStore.getState().isIncluded(DUMPS[0].path)).toBe(true);
  });
});

describe("DumpRail weights", () => {
  it("cycles the weight through exactly the three legal values", () => {
    seedAlignment();
    renderRail();

    const button = screen.getByTestId("dump-rail-weight-d0");
    expect(button).toHaveTextContent("1.0×");

    fireEvent.click(button);
    expect(screen.getByTestId("dump-rail-weight-d0")).toHaveTextContent("1.5×");

    fireEvent.click(screen.getByTestId("dump-rail-weight-d0"));
    expect(screen.getByTestId("dump-rail-weight-d0")).toHaveTextContent("0.5×");

    fireEvent.click(screen.getByTestId("dump-rail-weight-d0"));
    expect(screen.getByTestId("dump-rail-weight-d0")).toHaveTextContent("1.0×");
  });

  it("gives the weight button a name carrying the dump and the value", () => {
    seedAlignment();
    renderRail();

    expect(
      screen.getByRole("button", { name: /weight for d0\.msl: 1\.0×/i }),
    ).toBe(screen.getByTestId("dump-rail-weight-d0"));
  });

  /** `(weight / 1.5) * 100%` — the design's formula, so 1.5x fills the track. */
  it("fills the track in proportion to the weight", () => {
    seedAlignment();
    renderRail();

    expect(screen.getByTestId("dump-rail-track-fill-d0")).toHaveStyle({
      width: `${(1 / 1.5) * 100}%`,
    });

    fireEvent.click(screen.getByTestId("dump-rail-weight-d0"));

    expect(screen.getByTestId("dump-rail-track-fill-d0")).toHaveStyle({ width: "100%" });
  });

  /**
   * The badge is the only warning that the byte on screen is no longer an
   * equal-weight reading, so it has to follow the weights back to equal too.
   */
  it("says `equal` until a weight is touched, then `weighted`", () => {
    seedAlignment();
    renderRail();

    expect(screen.getByTestId("dump-rail-overlay-mode")).toHaveAttribute(
      "data-weighted",
      "false",
    );

    fireEvent.click(screen.getByTestId("dump-rail-weight-d0"));
    expect(screen.getByTestId("dump-rail-overlay-mode")).toHaveAttribute(
      "data-weighted",
      "true",
    );

    fireEvent.click(screen.getByTestId("dump-rail-weight-d0"));
    fireEvent.click(screen.getByTestId("dump-rail-weight-d0"));
    expect(screen.getByTestId("dump-rail-overlay-mode")).toHaveAttribute(
      "data-weighted",
      "false",
    );
  });
});

describe("DumpRail stats", () => {
  /**
   * The same denominator `HexAlignmentChip` uses, from the same helper:
   * `compared * n_sources + discarded`. Dividing by `compared + discarded`
   * would understate the loss by a factor of the dump count.
   */
  it("reports the alignment coverage the chip already computed", () => {
    seedAlignment();
    renderRail();

    expect(screen.getByTestId("dump-rail-stats-compared")).toHaveTextContent("8192");
    // 256 / (8192 * 3 + 256) = 1.03%
    expect(screen.getByTestId("dump-rail-stats-discarded")).toHaveTextContent("1.0%");
  });

  it("says so when no aligned window has arrived", () => {
    seedAlignment(null);
    renderRail();

    expect(screen.getByTestId("dump-rail-stats-pending")).toBeInTheDocument();
    expect(screen.queryByTestId("dump-rail-stats-compared")).not.toBeInTheDocument();
  });

  /**
   * The plurality can be a byte that exists in no single dump. That has to be
   * said in the UI, not only in a source comment.
   */
  it("warns in words that the overlay byte is computed", () => {
    seedAlignment();
    renderRail();

    expect(screen.getByTestId("dump-rail-plurality-note")).toHaveTextContent(
      /may exist in no single dump/i,
    );
  });
});

describe("DumpRail collapse", () => {
  /**
   * The rail costs the grid horizontal space. Folding it away must leave the
   * control that brings it back in the same place, exactly as
   * `MultiHexViewer`'s collapsed-pane rail does.
   */
  it("folds away to a strip carrying its own restore control", () => {
    seedAlignment();
    renderRail();

    fireEvent.click(screen.getByTestId("dump-rail-collapse"));

    expect(screen.queryByTestId("dump-rail")).not.toBeInTheDocument();
    const restore = screen.getByTestId("dump-rail-restore");
    expect(restore).toHaveAccessibleName(/show the dump rail/i);

    fireEvent.click(restore);
    expect(screen.getByTestId("dump-rail")).toBeInTheDocument();
  });
});
