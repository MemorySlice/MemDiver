import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import i18n from "@/i18n";

import { ApiErrorHint } from "@/components/common/ApiErrorHint";
import { errorCodeHint } from "@/i18n/error-code-hint";

describe("errorCodeHint", () => {
  it("resolves the localized text of a known code", () => {
    const hint = errorCodeHint("path.outside_sandbox");
    expect(hint).toBe(i18n.t("common:errorCodes.path.outside_sandbox"));
    expect(hint).toContain("MEMDIVER_ALLOWED_ROOTS");
  });

  it("is null for a missing, empty or unknown code", () => {
    expect(errorCodeHint(undefined)).toBeNull();
    expect(errorCodeHint(null)).toBeNull();
    expect(errorCodeHint("")).toBeNull();
    expect(errorCodeHint("no.such_code")).toBeNull();
  });

  it("is null for a code that names a group of codes, not a sentence", () => {
    expect(errorCodeHint("path")).toBeNull();
  });
});

describe("ApiErrorHint", () => {
  it("shows the hint for a known code", () => {
    render(<ApiErrorHint code="path.outside_sandbox" />);
    const note = screen.getByTestId("api-error-hint");
    expect(note).toHaveAttribute("role", "note");
    expect(note).toHaveAttribute("data-error-code", "path.outside_sandbox");
    expect(note).toHaveTextContent(/outside the folders this server is allowed to use/);
    expect(note).toHaveTextContent("MEMDIVER_ALLOWED_ROOTS");
  });

  it("renders nothing for an unknown, empty or absent code", () => {
    const { container, rerender } = render(<ApiErrorHint code="no.such_code" />);
    expect(container).toBeEmptyDOMElement();
    rerender(<ApiErrorHint code={undefined} />);
    expect(container).toBeEmptyDOMElement();
    rerender(<ApiErrorHint code={null} />);
    expect(container).toBeEmptyDOMElement();
  });
});
