import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import type { DetectorFixtureRun } from "@/api/detectors";

const api = vi.hoisted(() => ({ runDetectorFixtures: vi.fn() }));
vi.mock("@/api/detectors", async (orig) => ({ ...(await orig<typeof import("@/api/detectors")>()), ...api }));

const { DetectorFixtureBadge } = await import("@/components/detectors/DetectorFixtureBadge");

const RULE = "rule r { condition: true }";
const run = (over: Partial<DetectorFixtureRun>): DetectorFixtureRun => ({
  artifact_kind: "yara", verdict: "pass", reason: null, reason_code: null,
  counts: { pass: 2, fail: 0, indeterminate: 0, total: 2 }, results: [], recorded: false, ...over,
});

describe("DetectorFixtureBadge", () => {
  beforeEach(() => api.runDetectorFixtures.mockReset());

  it("shows nothing proven until run, and disables the button for an empty rule", () => {
    const { rerender } = render(<DetectorFixtureBadge artifactKind="yara" artifact="  " />);
    expect(screen.getByTestId("detector-fixtures-run")).toBeDisabled();
    rerender(<DetectorFixtureBadge artifactKind="yara" artifact={RULE} />);
    expect(screen.getByTestId("detector-fixtures-run")).toBeEnabled();
    expect(screen.queryByTestId("verdict-badge")).toBeNull();
    expect(screen.getByTestId("detector-fixtures-not-run")).toBeInTheDocument();
  });

  it("renders a passing verdict with its summary and passes the case dir", async () => {
    api.runDetectorFixtures.mockResolvedValue(run({}));
    render(<DetectorFixtureBadge artifactKind="yara" artifact={RULE} caseDir="/case" />);
    fireEvent.click(screen.getByTestId("detector-fixtures-run"));
    const badge = await screen.findByTestId("verdict-badge");
    expect(badge).toHaveAttribute("data-verdict", "pass");
    expect(screen.getByTestId("detector-fixtures-summary")).toHaveTextContent("2 of 2");
    expect(api.runDetectorFixtures).toHaveBeenCalledWith("yara", RULE, { caseDir: "/case", params: undefined });
  });

  it("renders a failure with its reason", async () => {
    api.runDetectorFixtures.mockResolvedValue(run({
      verdict: "fail", reason: "1 fixture(s) failed", counts: { pass: 1, fail: 1, indeterminate: 0, total: 2 } }));
    render(<DetectorFixtureBadge artifactKind="yara" artifact={RULE} />);
    fireEvent.click(screen.getByTestId("detector-fixtures-run"));
    expect((await screen.findByTestId("verdict-badge"))).toHaveAttribute("data-verdict", "fail");
    expect(screen.getByTestId("detector-fixtures-reason")).toHaveTextContent("1 fixture(s) failed");
  });

  it("shows no-fixtures as indeterminate, never as a pass", async () => {
    api.runDetectorFixtures.mockResolvedValue(run({
      verdict: "indeterminate", reason_code: "no_fixtures", counts: { pass: 0, fail: 0, indeterminate: 0, total: 0 } }));
    render(<DetectorFixtureBadge artifactKind="yara" artifact={RULE} />);
    fireEvent.click(screen.getByTestId("detector-fixtures-run"));
    expect((await screen.findByTestId("verdict-badge"))).toHaveAttribute("data-verdict", "indeterminate");
    expect(screen.getByTestId("detector-fixtures-none")).toBeInTheDocument();
    expect(screen.queryByTestId("detector-fixtures-summary")).toBeNull();
  });

  it("clears a stale verdict when the rule changes and reports request errors", async () => {
    api.runDetectorFixtures.mockResolvedValueOnce(run({}));
    const { rerender } = render(<DetectorFixtureBadge artifactKind="yara" artifact={RULE} />);
    fireEvent.click(screen.getByTestId("detector-fixtures-run"));
    await screen.findByTestId("verdict-badge");
    rerender(<DetectorFixtureBadge artifactKind="yara" artifact={RULE + " "} />);
    expect(screen.queryByTestId("verdict-badge")).toBeNull();
    api.runDetectorFixtures.mockRejectedValueOnce(new Error("boom"));
    fireEvent.click(screen.getByTestId("detector-fixtures-run"));
    await waitFor(() => expect(screen.getByTestId("detector-fixtures-error")).toHaveTextContent("boom"));
  });
});
