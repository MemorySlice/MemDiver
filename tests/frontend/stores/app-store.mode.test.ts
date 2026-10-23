import { beforeEach, describe, expect, it, vi } from "vitest";

import type { SessionSnapshot } from "@/api/types";

vi.mock("@/api/client", () => ({
  getPathInfo: vi.fn(() => new Promise(() => {})),
  getTagStatus: vi.fn(() => new Promise(() => {})),
  probeTagStatusWithKey: vi.fn(() => new Promise(() => {})),
  getPageStates: vi.fn(() => new Promise(() => {})),
  extractStrings: vi.fn(() => new Promise(() => {})),
}));

const {
  APP_MODES,
  EXPLORATION_ALGORITHMS,
  VERIFICATION_ALGORITHMS,
  parseAppMode,
  useAppStore,
} = await import("@/stores/app-store");
const { buildSessionSnapshot } = await import("@/utils/buildSessionSnapshot");

function snapshot(mode: string): SessionSnapshot {
  return {
    schema_version: 1,
    memdiver_version: "0.0.0",
    created_at: "2026-01-01T00:00:00Z",
    session_name: "s",
    input_mode: "dataset",
    input_path: "",
    dataset_root: "",
    keylog_filename: "keylog.csv",
    template_name: "Auto-detect",
    protocol_name: "TLS",
    protocol_version: "1.3",
    scenario: "",
    selected_libraries: [],
    selected_phase: "",
    algorithm: "",
    mode,
    max_runs: 10,
    normalize_phases: false,
    selected_algorithms: [],
    single_file_format: "",
    ground_truth_mode: "auto",
    analysis_result: null,
    bookmarks: [],
    investigation_offset: null,
  } as SessionSnapshot;
}

beforeEach(() => {
  useAppStore.getState().resetWizard();
});

describe("app mode", () => {
  it("offers heap as a third mode", () => {
    expect(APP_MODES).toEqual(["verification", "exploration", "heap"]);
  });

  it("heap mode selects the exploration algorithm set", () => {
    useAppStore.getState().setMode("heap");
    expect(useAppStore.getState().mode).toBe("heap");
    expect(useAppStore.getState().selectedAlgorithms).toEqual([...EXPLORATION_ALGORITHMS]);
    useAppStore.getState().setMode("verification");
    expect(useAppStore.getState().selectedAlgorithms).toEqual([...VERIFICATION_ALGORITHMS]);
  });

  it.each(["verification", "exploration", "heap"])("round-trips %s through a saved session", async (mode) => {
    useAppStore.getState().setMode(mode as "heap");
    const saved = buildSessionSnapshot("s");
    expect(saved.mode).toBe(mode);

    useAppStore.getState().resetWizard();
    await useAppStore.getState().restoreSession(snapshot(saved.mode as string));
    expect(useAppStore.getState().mode).toBe(mode);
  });

  it.each(["", "testing", "HEAP", "future-mode"])(
    "falls back to verification for an unknown persisted mode %j",
    async (mode) => {
      await useAppStore.getState().restoreSession(snapshot(mode));
      expect(useAppStore.getState().mode).toBe("verification");
    },
  );

  it("parseAppMode rejects non-strings", () => {
    expect(parseAppMode(undefined)).toBe("verification");
    expect(parseAppMode(42)).toBe("verification");
    expect(parseAppMode("heap")).toBe("heap");
  });
});
