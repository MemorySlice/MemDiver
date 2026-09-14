import { describe, it, expect, beforeEach, vi } from "vitest";

import { useAppStore } from "@/stores/app-store";
import { useAnalysisStore } from "@/stores/analysis-store";
import { useResultsStore } from "@/stores/results-store";
import { useDumpStore } from "@/stores/dump-store";
import { useDumpRailStore } from "@/stores/dump-rail-store";
import { useHexStore } from "@/stores/hex-store";
import { useStringsStore } from "@/stores/strings-store";
import { useMultiHexStore } from "@/stores/multi-hex-store";
import { useConsensusStore } from "@/stores/consensus-store";
import { useConsensusIncrementalStore } from "@/stores/consensus-incremental-store";
import { useVarianceRegionsStore } from "@/stores/variance-regions-store";
import { useVerificationStore } from "@/stores/verification-store";
import { useOverlayRenderStore } from "@/stores/overlay-render-store";
import { useOverlayDetailStore } from "@/stores/overlay-detail-store";

/**
 * The regression guard for the bug where starting a new session inherited the
 * PREVIOUS session's consensus, panes, variance regions, rail weights and --
 * worst of the set -- whatever ciphertext and key bytes had been typed into the
 * key verification form.
 *
 * Every store below is seeded with a value FIRST, so each assertion is a real
 * before/after and not a tautology about a store that was already empty.
 */
function seedEveryStore(): void {
  useAppStore.setState({
    inputPath: "/dumps/target.raw",
    datasetRoot: "/data/runs",
    mode: "exploration",
    hasCandidateKeys: true,
    hexFocus: { offset: 64, length: 16 },
    fullWidthHex: true,
    wizardStep: 2,
    wizardComplete: true,
    lastSavedDigest: "DIGEST",
    lastLoadedSnapshot: { session_name: "prev" } as never,
  });

  useAnalysisStore.setState({ progress: 55, message: "scanning", error: "boom" });
  useResultsStore.setState({ filterAlgorithm: "entropy_scan" });

  useDumpStore.getState().addDump({
    path: "/dumps/target.raw",
    name: "target.raw",
    size: 4096,
    format: "raw",
  });

  useDumpRailStore.setState({
    collapsed: true,
    soloPath: "/dumps/target.raw",
    excludedPaths: new Set(["/dumps/other.raw"]),
  });

  useHexStore.setState({
    bookmarks: [{ offset: 16, length: 4, label: "key?" }],
    cursorOffset: 128,
  });

  useStringsStore.setState({ filterText: "BEGIN", totalCount: 7, truncated: true });

  useMultiHexStore.setState({ truncated: true, pending: new Set(["/dumps/target.raw:0"]) });

  useConsensusStore.setState({
    available: true,
    size: 4096,
    numDumps: 3,
    overlayEnabled: true,
    consensusId: "c-1",
    builtFrom: ["/dumps/target.raw"],
  });

  useConsensusIncrementalStore.setState({
    sessionId: "inc-1",
    numDumps: 3,
    size: 4096,
    error: "stalled",
  });

  useVarianceRegionsStore.setState({ total: 42, activeIndex: 3, windowScoped: true });

  // The one that matters most: plaintext key material typed by the analyst.
  useVerificationStore.setState({
    ciphertextHex: "deadbeef",
    ivHex: "00112233445566778899aabb",
    tagHex: "ffeeddccbbaa99887766554433221100",
    cipher: "AES-256-GCM",
  });

  useOverlayRenderStore.getState().setRenderMode("glyph");
  useOverlayDetailStore.getState().setTab("regions");
}

beforeEach(() => {
  useAppStore.getState().resetWizard();
});

describe("app-store resetWizard", () => {
  it("returns its own slice to the landing defaults", () => {
    seedEveryStore();

    useAppStore.getState().resetWizard();

    const state = useAppStore.getState();
    expect(state.appView).toBe("landing");
    expect(state.wizardStep).toBe(0);
    expect(state.wizardComplete).toBe(false);
    expect(state.inputPath).toBe("");
    expect(state.datasetRoot).toBe("");
    expect(state.mode).toBe("verification");
    expect(state.hasCandidateKeys).toBe(false);
    expect(state.hexFocus).toBeNull();
    expect(state.fullWidthHex).toBe(false);
  });

  /**
   * Leaving the previous session's digest here would make the next dirty-check
   * compare against work that is no longer loaded -- so a fresh workspace would
   * read as CLEAN and the guard would never fire.
   */
  it("clears lastSavedDigest and lastLoadedSnapshot", () => {
    seedEveryStore();

    useAppStore.getState().resetWizard();

    expect(useAppStore.getState().lastSavedDigest).toBeNull();
    expect(useAppStore.getState().lastLoadedSnapshot).toBeNull();
  });

  it("clears the analysis and results stores", () => {
    seedEveryStore();

    useAppStore.getState().resetWizard();

    expect(useAnalysisStore.getState()).toMatchObject({
      progress: 0,
      message: "",
      error: null,
      result: null,
      isRunning: false,
    });
    expect(useResultsStore.getState().algorithmResults).toEqual({});
    expect(useResultsStore.getState().filterAlgorithm).toBeNull();
  });

  it("clears the dump list and the dump rail", () => {
    seedEveryStore();
    expect(useDumpStore.getState().dumps).toHaveLength(1);

    useAppStore.getState().resetWizard();

    expect(useDumpStore.getState().dumps).toEqual([]);
    expect(useDumpStore.getState().activeDumpId).toBeNull();
    expect(useDumpStore.getState().originDumpId).toBeNull();
    expect(useDumpRailStore.getState().collapsed).toBe(false);
    expect(useDumpRailStore.getState().soloPath).toBeNull();
    expect(useDumpRailStore.getState().excludedPaths.size).toBe(0);
    expect(useDumpRailStore.getState().weightByPath.size).toBe(0);
  });

  it("clears the hex viewer and the strings panel", () => {
    seedEveryStore();

    useAppStore.getState().resetWizard();

    expect(useHexStore.getState().bookmarks).toEqual([]);
    expect(useHexStore.getState().cursorOffset).toBeNull();
    expect(useStringsStore.getState().rows).toEqual([]);
    expect(useStringsStore.getState().filterText).toBe("");
    expect(useStringsStore.getState().totalCount).toBe(0);
    expect(useStringsStore.getState().truncated).toBe(false);
  });

  /**
   * The overlay/consensus family. These were omitted when the sibling-reset
   * list was first written, which is exactly how a new session used to open
   * holding the previous one's consensus and panes.
   */
  it("clears the multi-dump pane cache and bumps its window generation", () => {
    seedEveryStore();
    const before = useMultiHexStore.getState().windowVersion;

    useAppStore.getState().resetWizard();

    const multi = useMultiHexStore.getState();
    expect(multi.byPath.size).toBe(0);
    expect(multi.pending.size).toBe(0);
    expect(multi.truncated).toBe(false);
    expect(multi.alignment).toBeNull();
    // Monotonic, never zeroed: a window-derived consumer holding the previous
    // value has to see the reset as a CHANGE.
    expect(multi.windowVersion).toBeGreaterThan(before);
  });

  it("clears both consensus stores", () => {
    seedEveryStore();

    useAppStore.getState().resetWizard();

    expect(useConsensusStore.getState()).toMatchObject({
      available: false,
      size: 0,
      numDumps: 0,
      overlayEnabled: false,
      consensusId: null,
      builtFrom: [],
    });
    expect(useConsensusIncrementalStore.getState()).toMatchObject({
      sessionId: null,
      size: 0,
      numDumps: 0,
      status: "idle",
      error: null,
    });
  });

  it("clears the variance-region browser", () => {
    seedEveryStore();

    useAppStore.getState().resetWizard();

    expect(useVarianceRegionsStore.getState()).toMatchObject({
      category: null,
      regions: [],
      total: 0,
      activeIndex: -1,
      loading: false,
      windowScoped: false,
    });
  });

  /**
   * The worst of the set: `verification-store` holds plaintext secrets the
   * analyst typed. A new session inheriting them is a data-leak between
   * investigations, not merely stale UI.
   */
  it("clears the typed key material", () => {
    seedEveryStore();

    useAppStore.getState().resetWizard();

    expect(useVerificationStore.getState()).toMatchObject({
      ciphertextHex: "",
      ivHex: "",
      nonceHex: "",
      aadHex: "",
      tagHex: "",
      cipher: "AES-256-CBC",
      result: null,
      error: null,
    });
  });

  it("clears both overlay view preferences", () => {
    seedEveryStore();

    useAppStore.getState().resetWizard();

    expect(useOverlayRenderStore.getState().renderMode).toBe("class");
    expect(useOverlayDetailStore.getState().tab).toBe("byte");
  });

  /**
   * `multi-hex-store.reset()` cancels retry timers and `variance-regions-store
   * .reset()` invalidates the generation of anything in flight. Neither may
   * surface as an unhandled rejection -- tests elsewhere call `resetWizard()`
   * purely as a between-test reset helper and would start failing at random.
   */
  it("resets cleanly and repeatedly without an unhandled rejection", async () => {
    const onUnhandled = vi.fn();
    process.on("unhandledRejection", onUnhandled);
    try {
      for (let i = 0; i < 3; i += 1) {
        seedEveryStore();
        useAppStore.getState().resetWizard();
      }
      // Give any orphaned promise a turn to reject.
      await new Promise((resolve) => setTimeout(resolve, 10));
      expect(onUnhandled).not.toHaveBeenCalled();
    } finally {
      process.off("unhandledRejection", onUnhandled);
    }
  });
});
