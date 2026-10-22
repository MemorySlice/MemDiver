import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import i18n from "@/i18n";

import { CLASSIFICATION_BASIS_MIXED, type Diagnostic } from "@/api/diagnostics";
import { ClassificationBasisBanner } from "@/components/analysis/ClassificationBasisBanner";

const MIXED_DIAGNOSTIC: Diagnostic = {
  code: CLASSIFICATION_BASIS_MIXED,
  message: "BACKEND ENGLISH SENTENCE",
  severity: "warning",
  details: { named_dumps: [0, 2], stored_type_dumps: [1], total_dumps: 3, remedy: "re-import" },
};

describe("ClassificationBasisBanner", () => {
  it("renders the localized warning, counts and hint when the code is present", () => {
    render(<ClassificationBasisBanner diagnostics={[MIXED_DIAGNOSTIC]} scope="consensus" />);
    const banner = screen.getByTestId("classification-basis-warning");
    expect(banner).toHaveAttribute("data-scope", "consensus");
    expect(banner).toHaveAttribute("role", "alert");
    expect(screen.getByTestId("classification-basis-body")).toHaveTextContent(
      i18n.t("diagnostics:classificationBasisMixed.body", { named: 2, stored: 1, total: 3 }),
    );
    expect(screen.getByTestId("classification-basis-body")).toHaveTextContent(
      "2 of 3 dumps are classified by mapping names, 1 by stored region type only.",
    );
    expect(screen.getByTestId("classification-basis-stored")).toHaveTextContent("1");
    expect(screen.getByTestId("classification-basis-hint")).toHaveTextContent(
      "Re-import older dumps to classify them by mapping names.",
    );
    // Never the backend's English message.
    expect(banner).not.toHaveTextContent("BACKEND ENGLISH SENTENCE");
  });

  it.each([
    ["empty", []],
    ["missing", undefined],
    ["null", null],
  ])("renders nothing when diagnostics are %s", (_label, diagnostics) => {
    render(<ClassificationBasisBanner diagnostics={diagnostics} scope="consensus" />);
    expect(screen.queryByTestId("classification-basis-warning")).not.toBeInTheDocument();
  });

  it("ignores unknown codes", () => {
    render(
      <ClassificationBasisBanner
        diagnostics={[{ code: "something_else", message: "x", severity: "info" }]}
        scope="candidates"
      />,
    );
    expect(screen.queryByTestId("classification-basis-warning")).not.toBeInTheDocument();
  });
});
