/**
 * Tests for `absenceForPageState` in `@/utils/absence-classes`.
 *
 * The ladder existed twice — in `HexViewer` and in `HexOverlayPane` — and the
 * copies disagreed about the fall-through. They were BOTH right for their own
 * caller, which is why this helper answers `undefined` and leaves the
 * fall-through where the context is.
 */

import { readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";

import {
  ABSENCE_LEGEND,
  ABSENCE_META,
  PAGE_STATE_ABSENCES,
  absenceForPageState,
  isPageStateAbsence,
  resolveAbsence,
} from "@/utils/absence-classes";
import type { ByteAbsence } from "@/stores/multi-hex-store";

const LOCALES_DIR = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../frontend/src/i18n/locales",
);

/** Resolve a dotted key in one locale's `hex.json`, or `undefined`. */
function hexString(locale: string, key: string): unknown {
  const json = JSON.parse(readFileSync(resolve(LOCALES_DIR, locale, "hex.json"), "utf8"));
  return key.split(".").reduce<unknown>(
    (node, part) => (node && typeof node === "object" ? (node as Record<string, unknown>)[part] : undefined),
    json,
  );
}

describe("absenceForPageState", () => {
  it("maps the two MSL page states that mean something", () => {
    expect(absenceForPageState("FAILED")).toBe("failed");
    expect(absenceForPageState("UNMAPPED")).toBe("unmapped");
  });

  /** MSL 1.1 NotResident: a never-touched page whose content is known zero. */
  it("maps the NOT_RESIDENT page state", () => {
    expect(absenceForPageState("NOT_RESIDENT")).toBe("not-resident");
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

describe("ABSENCE_META page-state entries", () => {
  /**
   * The page states tint a byte the backend did send (zero-filled), so they
   * keep printing it and never void the cell.
   */
  it("describes unmapped as a tint-only page state", () => {
    expect(ABSENCE_META.unmapped).toEqual({
      cellClass: "page-unmapped",
      glyph: null,
      voids: false,
      titleKey: "pageState.unmappedTitle",
      swatchClass: "absence-page-unmapped",
      labelKey: "pageState.unmapped",
    });
  });

  it("describes failed as a tint-only page state", () => {
    expect(ABSENCE_META.failed).toEqual({
      cellClass: "page-failed",
      glyph: null,
      voids: false,
      titleKey: "pageState.failedTitle",
      swatchClass: "absence-page-failed",
      labelKey: "pageState.failed",
    });
  });

  it("describes not-resident as a tint-only page state", () => {
    expect(ABSENCE_META["not-resident"]).toEqual({
      cellClass: "page-not-resident",
      glyph: null,
      voids: false,
      titleKey: "pageState.notResidentTitle",
      swatchClass: "absence-page-not-resident",
      labelKey: "pageState.notResident",
    });
  });

  /** Tinted cells used to appear with no explanation anywhere in the legend. */
  it("lists all three page states in the absence legend", () => {
    expect(ABSENCE_LEGEND).toContain("failed");
    expect(ABSENCE_LEGEND).toContain("unmapped");
    expect(ABSENCE_LEGEND).toContain("not-resident");
    expect([...PAGE_STATE_ABSENCES].sort()).toEqual(["failed", "not-resident", "unmapped"]);
  });

  it("keeps the void causes ahead of the page states and loading out", () => {
    expect(ABSENCE_LEGEND.slice(0, 3)).toEqual(["no-correspondence", "not-in-dump", "error"]);
    expect(ABSENCE_LEGEND).not.toContain("loading");
  });

  it("tells page-state kinds from void causes", () => {
    for (const kind of PAGE_STATE_ABSENCES) expect(isPageStateAbsence(kind)).toBe(true);
    for (const kind of ["loading", "no-correspondence", "not-in-dump", "error"] as const) {
      expect(isPageStateAbsence(kind)).toBe(false);
    }
  });
});

describe("ABSENCE_LEGEND i18n", () => {
  const locales = readdirSync(LOCALES_DIR, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name);

  it("finds at least one locale", () => {
    expect(locales.length).toBeGreaterThan(0);
  });

  /** Every legend entry needs a label and a tooltip in EVERY locale. */
  it.each(locales)("has a label and title for every legend entry in %s", (locale) => {
    for (const kind of ABSENCE_LEGEND) {
      const { labelKey, titleKey, swatchClass } = ABSENCE_META[kind];
      expect(swatchClass, kind).not.toBeNull();
      expect(labelKey, kind).not.toBeNull();
      expect(titleKey, kind).not.toBeNull();
      expect(typeof hexString(locale, labelKey!), `${locale}:${labelKey}`).toBe("string");
      expect(typeof hexString(locale, titleKey!), `${locale}:${titleKey}`).toBe("string");
    }
  });
});

describe("resolveAbsence precedence", () => {
  type Row = [ByteAbsence | null, string | undefined, string | undefined];
  // [byte absence, page state, resolved kind]
  const table: Row[] = [
    // 1. A held byte is never an absence, whatever the page says.
    [null, undefined, undefined],
    [null, "FAILED", undefined],
    [null, "UNMAPPED", undefined],
    // 2. This client's own request state wins over any page state.
    ["loading", undefined, "loading"],
    ["loading", "FAILED", "loading"],
    ["error", "NOT_RESIDENT", "error"],
    ["error", undefined, "error"],
    // 3. A non-captured page state is the more specific reason.
    ["no-correspondence", "FAILED", "failed"],
    ["no-correspondence", "UNMAPPED", "unmapped"],
    ["no-correspondence", "NOT_RESIDENT", "not-resident"],
    ["not-in-dump", "FAILED", "failed"],
    // 4. Otherwise the byte absence as it was.
    ["no-correspondence", undefined, "no-correspondence"],
    ["not-in-dump", undefined, "not-in-dump"],
    ["not-in-dump", "CAPTURED", "not-in-dump"],
    ["no-correspondence", "SOMETHING_NEW", "no-correspondence"],
  ];

  it.each(table)("(%s, %s) -> %s", (byteAbsence, pageState, expected) => {
    expect(resolveAbsence(byteAbsence, pageState)).toBe(expected);
  });
});
