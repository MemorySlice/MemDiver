import { describe, it, expect, afterEach, vi } from "vitest";

import { CLASSIFICATION_BASIS_MIXED, type Diagnostic } from "@/api/diagnostics";
import { useConsensusStore } from "@/stores/consensus-store";

const MIXED: Diagnostic = {
  code: CLASSIFICATION_BASIS_MIXED,
  message: "mixed",
  severity: "warning",
  details: { named_dumps: [0], stored_type_dumps: [1], total_dumps: 2, remedy: "" },
};

function okResponse(body: unknown): Response {
  return { ok: true, status: 200, json: async () => body, text: async () => "" } as Response;
}

function stubConsensus(body: unknown): void {
  vi.stubGlobal("fetch", vi.fn(async () => okResponse(body)));
}

afterEach(() => {
  vi.unstubAllGlobals();
  useConsensusStore.getState().reset();
});

describe("consensus-store diagnostics", () => {
  it("records top-level diagnostics merged with alignment.diagnostics, deduped", async () => {
    const other: Diagnostic = { code: "other", message: "o", severity: "info", details: {} };
    stubConsensus({
      consensus_id: "c1",
      diagnostics: [MIXED],
      alignment: { method: "virtual_address", warnings: [], diagnostics: [MIXED, other] },
    });
    await useConsensusStore.getState().runConsensus(["/a", "/b"], true);
    expect(useConsensusStore.getState().diagnostics).toEqual([MIXED, other]);
  });

  it("reads alignment.diagnostics when the top level omits them", async () => {
    stubConsensus({ consensus_id: "c1", alignment: { diagnostics: [MIXED] } });
    await useConsensusStore.getState().runConsensus(["/a", "/b"], true);
    expect(useConsensusStore.getState().diagnostics).toEqual([MIXED]);
  });

  it("is empty for an older server that sends neither", async () => {
    stubConsensus({ consensus_id: "c1" });
    await useConsensusStore.getState().runConsensus(["/a", "/b"], false);
    expect(useConsensusStore.getState().diagnostics).toEqual([]);
  });

  it("is cleared by reset and by adopting an incremental fold", async () => {
    stubConsensus({ consensus_id: "c1", diagnostics: [MIXED] });
    await useConsensusStore.getState().runConsensus(["/a", "/b"], true);
    useConsensusStore.getState().adoptIncremental({
      consensusId: "s1",
      size: 1,
      numDumps: 2,
      counts: null,
    });
    expect(useConsensusStore.getState().diagnostics).toEqual([]);

    await useConsensusStore.getState().runConsensus(["/a", "/b"], true);
    useConsensusStore.getState().reset();
    expect(useConsensusStore.getState().diagnostics).toEqual([]);
  });

  it("keeps the previous build's diagnostics when a rebuild fails", async () => {
    stubConsensus({ consensus_id: "c1", diagnostics: [MIXED] });
    await useConsensusStore.getState().runConsensus(["/a", "/b"], true);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({ ok: false, status: 500, text: async () => "boom" }) as Response),
    );
    await useConsensusStore.getState().runConsensus(["/a", "/b"], true);
    expect(useConsensusStore.getState().error).not.toBeNull();
    expect(useConsensusStore.getState().diagnostics).toEqual([MIXED]);
  });
});
