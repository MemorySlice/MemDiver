/**
 * Tests for `absenceForPageState` in `@/utils/absence-classes`.
 *
 * The ladder existed twice — in `HexViewer` and in `HexOverlayPane` — and the
 * copies disagreed about the fall-through. They were BOTH right for their own
 * caller, which is why this helper answers `undefined` and leaves the
 * fall-through where the context is.
 */

import { describe, it, expect } from "vitest";

import { absenceForPageState } from "@/utils/absence-classes";

describe("absenceForPageState", () => {
  it("maps the two MSL page states that mean something", () => {
    expect(absenceForPageState("FAILED")).toBe("failed");
    expect(absenceForPageState("UNMAPPED")).toBe("unmapped");
  });

  /**
   * `undefined`, never `"loading"`. A CAPTURED page says the byte IS there, and
   * the overlay consults this for every byte the store has already reported as
   * present — answering `"loading"` would hatch a byte the grid is printing.
   */
  it("says nothing about a captured page", () => {
    expect(absenceForPageState("CAPTURED")).toBeUndefined();
  });

  it("says nothing when the page state is not known", () => {
    expect(absenceForPageState(undefined)).toBeUndefined();
    expect(absenceForPageState(null)).toBeUndefined();
    expect(absenceForPageState("")).toBeUndefined();
  });

  /** Unknown states are not guessed at; a new backend value reads as silence. */
  it("says nothing about an unrecognised state", () => {
    expect(absenceForPageState("SOMETHING_NEW")).toBeUndefined();
  });
});
