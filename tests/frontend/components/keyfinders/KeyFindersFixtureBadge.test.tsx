import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import type { DetectorFixtureRun } from "@/api/detectors";
import { useImageStore } from "@/stores/image-store";

const kf = vi.hoisted(() => ({ listKeyFinders: vi.fn() }));
vi.mock("@/api/keyfinders", async (orig) => ({ ...(await orig<typeof import("@/api/keyfinders")>()), ...kf }));
const det = vi.hoisted(() => ({ runDetectorFixtures: vi.fn() }));
vi.mock("@/api/detectors", async (orig) => ({ ...(await orig<typeof import("@/api/detectors")>()), ...det }));

const { KeyFindersPanel } = await import("@/components/keyfinders/KeyFindersPanel");

const NAMES = ["aes_schedule", "rsa_der"];
const passRun: DetectorFixtureRun = {
  artifact_kind: "keyfinder", verdict: "pass", reason: null, reason_code: null,
  counts: { pass: 3, fail: 0, indeterminate: 0, total: 3 }, results: [], recorded: false,
};

describe("KeyFindersPanel fixture badges", () => {
  beforeEach(() => {
    det.runDetectorFixtures.mockReset();
    kf.listKeyFinders.mockReset();
    kf.listKeyFinders.mockResolvedValue({
      finders: NAMES.map((name) => ({ name, description: name, mode: "window", module: "m", parameters: [] })),
      default_finders: NAMES,
    });
    useImageStore.setState({ caseDir: "" });
  });

  it("mounts one badge per finder without fetching, and runs only the clicked finder", async () => {
    render(<KeyFindersPanel />);
    const item = await screen.findByTestId("keyfinders-item-aes_schedule");
    expect(screen.getAllByTestId("detector-fixture-badge")).toHaveLength(NAMES.length);
    expect(det.runDetectorFixtures).not.toHaveBeenCalled();

    det.runDetectorFixtures.mockResolvedValue(passRun);
    fireEvent.click(item.querySelector("[data-testid='detector-fixtures-run']")!);
    expect(await screen.findByTestId("verdict-badge")).toHaveAttribute("data-verdict", "pass");
    expect(det.runDetectorFixtures).toHaveBeenCalledTimes(1);
    expect(det.runDetectorFixtures).toHaveBeenCalledWith(
      "keyfinder", "aes_schedule", { caseDir: undefined, params: undefined });
  });

  it("passes the active case dir", async () => {
    useImageStore.setState({ caseDir: " /case " });
    det.runDetectorFixtures.mockResolvedValue(passRun);
    render(<KeyFindersPanel />);
    const item = await screen.findByTestId("keyfinders-item-rsa_der");
    fireEvent.click(item.querySelector("[data-testid='detector-fixtures-run']")!);
    await screen.findByTestId("verdict-badge");
    expect(det.runDetectorFixtures).toHaveBeenCalledWith("keyfinder", "rsa_der", { caseDir: "/case", params: undefined });
  });
});
