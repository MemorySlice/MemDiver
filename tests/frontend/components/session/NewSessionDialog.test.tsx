import { describe, it, expect, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
// See the comment in `ErrorBoundary.test.tsx` -- needed so `tsc -b` sees
// jest-dom's `Assertion` augmentation even though `tests/setup.ts` is
// excluded from that program.
import "@testing-library/jest-dom/vitest";
// Real strings, so every assertion below checks the English the user actually
// sees rather than a key name -- this repo's only guard against a missing key.
import "@/i18n";

import { NewSessionDialog } from "@/components/session/NewSessionDialog";
import type { NewSessionGuard } from "@/hooks/useNewSessionGuard";

/**
 * The dialog is purely presentational: every decision lives in the guard. So
 * the guard is a plain object of spies here, and the assertions are about what
 * is rendered and which spy a click reaches.
 */
function makeGuard(overrides: Partial<NewSessionGuard> = {}): NewSessionGuard {
  return {
    open: true,
    defaultName: "target.raw-2026-09-14-1200",
    summary: { dumps: 2, bookmarks: 1, hasAnalysisResult: true },
    busy: false,
    error: null,
    recoveryFailed: false,
    requestNewSession: vi.fn(),
    saveAndStartNew: vi.fn(async () => {}),
    discardAndStartNew: vi.fn(async () => {}),
    forceDiscardAndStartNew: vi.fn(),
    cancel: vi.fn(),
    ...overrides,
  };
}

function renderDialog(
  overrides: Partial<NewSessionGuard> = {},
  existingNames: readonly string[] = [],
) {
  const guard = makeGuard(overrides);
  render(<NewSessionDialog guard={guard} existingNames={existingNames} />);
  return guard;
}

const nameInput = () => screen.getByTestId("new-session-name") as HTMLInputElement;

describe("NewSessionDialog", () => {
  it("offers all three ways out, named in English", () => {
    renderDialog();

    expect(screen.getByTestId("new-session-dialog")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Start a new session?" })).toBeInTheDocument();
    expect(screen.getByTestId("new-session-save")).toHaveTextContent("Save and start new");
    expect(screen.getByTestId("new-session-discard")).toHaveTextContent("Discard and start new");
    expect(screen.getByTestId("new-session-cancel")).toHaveTextContent("Cancel");
  });

  it("spells out what would be lost", () => {
    renderDialog();

    expect(screen.getByText("2 dumps loaded")).toBeInTheDocument();
    expect(screen.getByText("analysis results")).toBeInTheDocument();
    // Singular form -- the guard against a missing `_one` plural key.
    expect(screen.getByText("1 bookmark")).toBeInTheDocument();
  });

  it("omits stakes the workspace does not hold", () => {
    renderDialog({ summary: { dumps: 0, bookmarks: 0, hasAnalysisResult: false } });

    expect(screen.queryByText("analysis results")).not.toBeInTheDocument();
    expect(screen.queryByText(/dumps? loaded/)).not.toBeInTheDocument();
  });

  it("pre-fills the name with the guard's suggestion and lets it be edited", () => {
    renderDialog();
    expect(nameInput()).toHaveValue("target.raw-2026-09-14-1200");

    fireEvent.change(nameInput(), { target: { value: "boringssl-run-3" } });

    expect(nameInput()).toHaveValue("boringssl-run-3");
  });

  it("saves under the name the user typed, not the suggestion", () => {
    const guard = renderDialog();
    fireEvent.change(nameInput(), { target: { value: "boringssl-run-3" } });

    fireEvent.click(screen.getByTestId("new-session-save"));

    expect(guard.saveAndStartNew).toHaveBeenCalledWith("boringssl-run-3");
  });

  it("warns before an accidental overwrite, because the server does not", () => {
    renderDialog({}, ["boringssl-run-3"]);
    expect(
      screen.queryByText(/already exists and will be overwritten/),
    ).not.toBeInTheDocument();

    fireEvent.change(nameInput(), { target: { value: "  boringssl-run-3  " } });

    // Matched on the TRIMMED name, since that is what would reach the server.
    expect(
      screen.getByText(
        "A session named “boringssl-run-3” already exists and will be overwritten.",
      ),
    ).toBeInTheDocument();
  });

  it("discards through the guard's normal path by default", () => {
    const guard = renderDialog();

    fireEvent.click(screen.getByTestId("new-session-discard"));

    expect(guard.discardAndStartNew).toHaveBeenCalledTimes(1);
    expect(guard.forceDiscardAndStartNew).not.toHaveBeenCalled();
  });

  it("cancels through the guard", () => {
    const guard = renderDialog();

    fireEvent.click(screen.getByTestId("new-session-cancel"));

    expect(guard.cancel).toHaveBeenCalledTimes(1);
  });

  it("reports a failed save without closing", () => {
    renderDialog({ error: "disk full" });

    expect(screen.getByTestId("new-session-error")).toHaveTextContent(
      "Could not save the session. Your workspace has not been changed. disk full",
    );
    expect(screen.getByTestId("new-session-dialog")).toBeInTheDocument();
  });

  /**
   * After a failed recovery write the discard is no longer safe, so the button
   * has to stop promising the safety net and route to the escape hatch instead.
   */
  it("swaps the discard button to 'Discard anyway' once recovery has failed", () => {
    const guard = renderDialog({ recoveryFailed: true, error: "no space" });

    expect(screen.getByTestId("new-session-discard")).toHaveTextContent("Discard anyway");
    expect(screen.getByTestId("new-session-error")).toHaveTextContent(
      "Could not write the recovery copy. Discarding now would lose this work. no space",
    );

    fireEvent.click(screen.getByTestId("new-session-discard"));

    expect(guard.forceDiscardAndStartNew).toHaveBeenCalledTimes(1);
    expect(guard.discardAndStartNew).not.toHaveBeenCalled();
  });

  it("disables every action and says so while a save is in flight", () => {
    renderDialog({ busy: true });

    expect(screen.getByTestId("new-session-save")).toHaveTextContent("Saving");
    expect(screen.getByTestId("new-session-save")).toBeDisabled();
    expect(screen.getByTestId("new-session-discard")).toBeDisabled();
    expect(screen.getByTestId("new-session-cancel")).toBeDisabled();
  });

  it("focuses the name field, and ignores a backdrop click", () => {
    const guard = renderDialog();

    expect(nameInput()).toHaveFocus();
    // A three-way choice about losing work must be made deliberately.
    fireEvent.click(screen.getByTestId("new-session-dialog-overlay"));
    expect(guard.cancel).not.toHaveBeenCalled();
  });
});
