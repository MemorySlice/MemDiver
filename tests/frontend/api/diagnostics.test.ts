import { describe, it, expect } from "vitest";

import {
  CLASSIFICATION_BASIS_MIXED,
  classificationBasisDetails,
  findDiagnostic,
  mergeDiagnostics,
  warningsNotCoveredBy,
  type Diagnostic,
} from "@/api/diagnostics";

const MIXED: Diagnostic = {
  code: CLASSIFICATION_BASIS_MIXED,
  message: "Mixed classification basis.",
  severity: "warning",
  details: { named_dumps: [0, 2], stored_type_dumps: [1], total_dumps: 3, remedy: "re-import" },
};
const OTHER: Diagnostic = { code: "other", message: "Other.", severity: "info", details: {} };

describe("mergeDiagnostics", () => {
  it("dedupes by code, keeping the first occurrence", () => {
    const hoisted = { ...MIXED, message: "hoisted copy" };
    expect(mergeDiagnostics([MIXED], [hoisted, OTHER])).toEqual([MIXED, OTHER]);
  });

  it("tolerates missing and malformed lists", () => {
    expect(mergeDiagnostics(undefined, null, { not: "a list" }, [null, { code: 3 }])).toEqual([]);
  });
});

describe("findDiagnostic", () => {
  it("finds by code and returns undefined when absent", () => {
    expect(findDiagnostic([OTHER, MIXED], CLASSIFICATION_BASIS_MIXED)).toBe(MIXED);
    expect(findDiagnostic([OTHER], CLASSIFICATION_BASIS_MIXED)).toBeUndefined();
    expect(findDiagnostic(undefined, CLASSIFICATION_BASIS_MIXED)).toBeUndefined();
  });
});

describe("warningsNotCoveredBy", () => {
  it("drops warnings a diagnostic already states", () => {
    expect(warningsNotCoveredBy([MIXED.message, "sizes differ"], [MIXED])).toEqual([
      "sizes differ",
    ]);
  });

  it("keeps every warning when there are no diagnostics", () => {
    expect(warningsNotCoveredBy(["a", "b"], undefined)).toEqual(["a", "b"]);
  });
});

describe("classificationBasisDetails", () => {
  it("reads well-formed details", () => {
    expect(classificationBasisDetails(MIXED)).toEqual({
      named_dumps: [0, 2],
      stored_type_dumps: [1],
      total_dumps: 3,
      remedy: "re-import",
    });
  });

  it("falls back defensively on missing or malformed details", () => {
    const bare: Diagnostic = {
      code: CLASSIFICATION_BASIS_MIXED,
      message: "",
      severity: "warning",
      details: { named_dumps: "nope", stored_type_dumps: [4, "x", 5] },
    };
    expect(classificationBasisDetails(bare)).toEqual({
      named_dumps: [],
      stored_type_dumps: [4, 5],
      total_dumps: 2,
      remedy: undefined,
    });
  });
});
