import { beforeEach, describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import type { AnalysisCandidatesResponse, AlignmentReport } from "@/api/candidates";
import { CLASSIFICATION_BASIS_MIXED, type Diagnostic } from "@/api/diagnostics";
import { useDumpStore } from "@/stores/dump-store";
import { useConsensusStore } from "@/stores/consensus-store";

const { analyzeCandidatesMock } = vi.hoisted(() => ({ analyzeCandidatesMock: vi.fn() }));

vi.mock("@/api/candidates", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/api/candidates")>()),
  analyzeCandidates: analyzeCandidatesMock,
}));

const { CandidatePanel } = await import("@/components/charts/CandidatePanel");

const MIXED: Diagnostic = {
  code: CLASSIFICATION_BASIS_MIXED,
  message: "BACKEND ENGLISH",
  severity: "warning",
  details: { named_dumps: [0], stored_type_dumps: [1], total_dumps: 2, remedy: "" },
};

const ALIGNMENT: AlignmentReport = {
  method: "module_offset",
  bytes_compared: 100,
  bytes_discarded: 0,
  sizes_differed: false,
  n_sources: 2,
  warnings: [],
};

function response(over: Partial<AnalysisCandidatesResponse>): AnalysisCandidatesResponse {
  return {
    num_dumps: 2,
    size: 100,
    class_counts: {},
    alignment: ALIGNMENT,
    thresholds: {},
    stages: { total_bytes: 100, variance: 0, byte_class: 0, aligned: 0, high_entropy: 0 },
    fallback_entropy_only: false,
    num_regions: 0,
    regions: [],
    regions_returned: 0,
    regions_truncated: false,
    max_returned: 200,
    order: "rank",
    consensus_id: "c1",
    persisted: true,
    warnings: [],
    diagnostics: [],
    ...over,
  };
}

beforeEach(() => {
  analyzeCandidatesMock.mockReset();
  useDumpStore.setState({
    dumps: [
      { id: "a", path: "/dumps/a.bin", name: "a.bin", size: 10, format: "raw", sameProcess: true },
      { id: "b", path: "/dumps/b.bin", name: "b.bin", size: 10, format: "raw", sameProcess: true },
    ],
    aslrNormalize: false,
  });
  useConsensusStore.setState({ available: true });
});

describe("CandidatePanel classification-basis warning", () => {
  it("renders ONE localized banner when both top-level and alignment carry the code", async () => {
    analyzeCandidatesMock.mockResolvedValue(
      response({
        diagnostics: [MIXED],
        warnings: [MIXED.message],
        alignment: { ...ALIGNMENT, warnings: [MIXED.message], diagnostics: [MIXED] },
      }),
    );
    render(<CandidatePanel />);
    const banners = await screen.findAllByTestId("classification-basis-warning");
    expect(banners).toHaveLength(1);
    expect(banners[0]).toHaveAttribute("data-scope", "candidates");
    // The raw English sentence is not repeated anywhere in the panel.
    expect(screen.queryByText("BACKEND ENGLISH")).not.toBeInTheDocument();
    expect(screen.queryByTestId("candidate-alignment-warnings")).not.toBeInTheDocument();
  });

  it("renders no banner when diagnostics are empty", async () => {
    analyzeCandidatesMock.mockResolvedValue(response({}));
    render(<CandidatePanel />);
    await screen.findByTestId("candidate-alignment-banner");
    expect(screen.queryByTestId("classification-basis-warning")).not.toBeInTheDocument();
  });
});
