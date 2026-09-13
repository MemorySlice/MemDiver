import { afterEach, beforeEach, describe, it, expect, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import type {
  AnalysisCandidatesRequest,
  AnalysisCandidatesResponse,
  AlignmentReport,
  CandidateRegion,
} from "@/api/candidates";
import { useDumpStore } from "@/stores/dump-store";
import { useConsensusStore } from "@/stores/consensus-store";
import { useHexStore } from "@/stores/hex-store";

/**
 * Only the network call is mocked. `buildCandidatesRequest`,
 * `DEFAULT_CANDIDATE_FILTERS` and `dominantClass` stay REAL, so the
 * default-class rule and the min_variance omission are exercised through the
 * component exactly as they ship — a mock of the whole module would let the
 * panel default to key-candidate-only and still pass.
 */
const { analyzeCandidatesMock } = vi.hoisted(() => ({
  analyzeCandidatesMock: vi.fn(),
}));

vi.mock("@/api/candidates", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/api/candidates")>()),
  analyzeCandidates: analyzeCandidatesMock,
}));

const { CandidatePanel } = await import("@/components/charts/CandidatePanel");

const QUIET_ALIGNMENT: AlignmentReport = {
  method: "file_offset",
  bytes_compared: 11_223_040,
  bytes_discarded: 0,
  sizes_differed: false,
  n_sources: 8,
  warnings: [],
};

function region(over: Partial<CandidateRegion> = {}): CandidateRegion {
  return {
    offset: 370_672,
    length: 48,
    rank: 10,
    score: 0.732,
    score_components: { byte_class: 0.8, variance: 0.7, entropy: 0.9, length: 1 },
    class_counts: { structural: 8, pointer: 18, key_candidate: 22 },
    mean_variance: 4123.5,
    mean_entropy: 3.9,
    region_entropy: 5.61,
    ...over,
  };
}

function response(over: Partial<AnalysisCandidatesResponse> = {}): AnalysisCandidatesResponse {
  const regions = over.regions ?? [region()];
  return {
    num_dumps: 8,
    size: 11_223_040,
    class_counts: { invariant: 11_216_911, structural: 1652, pointer: 2566, key_candidate: 1911 },
    alignment: QUIET_ALIGNMENT,
    thresholds: {},
    stages: {
      total_bytes: 11_223_040,
      variance: 6129,
      byte_class: 6129,
      aligned: 900,
      high_entropy: 420,
    },
    fallback_entropy_only: false,
    num_regions: regions.length,
    regions,
    regions_returned: regions.length,
    regions_truncated: false,
    max_returned: 200,
    order: "rank",
    consensus_id: "consensus-1",
    persisted: true,
    warnings: [],
    diagnostics: [],
    ...over,
  };
}

/** Two dumps loaded + a finished consensus — the state A6 fires in. */
function seedWorkspace(): void {
  useDumpStore.setState({
    dumps: [
      { id: "a", path: "/dumps/pre.bin", name: "pre.bin", size: 10, format: "raw", sameProcess: true },
      { id: "b", path: "/dumps/post.bin", name: "post.bin", size: 10, format: "raw", sameProcess: true },
    ],
    aslrNormalize: false,
  });
  useConsensusStore.setState({ available: true });
}

function lastRequest(): AnalysisCandidatesRequest {
  const calls = analyzeCandidatesMock.mock.calls;
  return calls[calls.length - 1][0] as AnalysisCandidatesRequest;
}

beforeEach(() => {
  analyzeCandidatesMock.mockReset();
  analyzeCandidatesMock.mockResolvedValue(response());
  useDumpStore.setState({ dumps: [], aslrNormalize: false });
  useConsensusStore.setState({ available: false });
  useHexStore.setState({ cursorOffset: 0, scrollTarget: null });
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("CandidatePanel gating", () => {
  it("asks for a second dump rather than querying with one", () => {
    useDumpStore.setState({
      dumps: [
        { id: "a", path: "/dumps/only.bin", name: "only.bin", size: 10, format: "raw", sameProcess: true },
      ],
    });
    render(<CandidatePanel />);
    expect(screen.getByTestId("candidate-need-dumps")).toBeInTheDocument();
    expect(analyzeCandidatesMock).not.toHaveBeenCalled();
  });

  it("queries automatically once a consensus is available", async () => {
    seedWorkspace();
    render(<CandidatePanel />);
    await waitFor(() => expect(analyzeCandidatesMock).toHaveBeenCalledTimes(1));
    expect(lastRequest().dump_paths).toEqual(["/dumps/pre.bin", "/dumps/post.bin"]);
  });
});

describe("CandidatePanel default class selection", () => {
  it("checks structural, pointer and key_candidate — never invariant", async () => {
    seedWorkspace();
    render(<CandidatePanel />);
    await screen.findByTestId("candidate-table");

    expect(screen.getByTestId("candidate-class-structural")).toBeChecked();
    expect(screen.getByTestId("candidate-class-pointer")).toBeChecked();
    expect(screen.getByTestId("candidate-class-key_candidate")).toBeChecked();
    expect(screen.getByTestId("candidate-class-invariant")).not.toBeChecked();
  });

  /**
   * The regression guard. A key-candidate-only default loses the real
   * 48-byte TLS secret entirely (measured), so this must fail if anyone
   * narrows it.
   */
  it("FAILS if the default ever becomes key_candidate-only", async () => {
    seedWorkspace();
    render(<CandidatePanel />);
    await waitFor(() => expect(analyzeCandidatesMock).toHaveBeenCalled());

    const sent = lastRequest().classes ?? [];
    expect(
      sent,
      "a key_candidate-only default returns fragments from INSIDE a mixed-class key",
    ).not.toEqual(["key_candidate"]);
    expect([...sent].sort()).toEqual(["key_candidate", "pointer", "structural"]);
  });

  it("never sends min_variance, so the class filter is not re-narrowed to 3000", async () => {
    seedWorkspace();
    render(<CandidatePanel />);
    await waitFor(() => expect(analyzeCandidatesMock).toHaveBeenCalled());

    const sent = lastRequest();
    expect(sent.min_variance).toBeUndefined();
    expect(JSON.stringify(sent)).not.toContain("min_variance");
  });
});

describe("CandidatePanel filters", () => {
  it("composes an edited filter into the next request body", async () => {
    seedWorkspace();
    render(<CandidatePanel />);
    await screen.findByTestId("candidate-table");

    // Drop key_candidate, raise the minimum length, change the alignment.
    fireEvent.click(screen.getByTestId("candidate-class-key_candidate"));
    fireEvent.change(screen.getByLabelText(/Min length/i), { target: { value: "48" } });
    fireEvent.change(screen.getByTestId("candidate-alignment-select"), { target: { value: "16" } });
    fireEvent.click(screen.getByTestId("candidate-apply"));

    await waitFor(() => expect(analyzeCandidatesMock.mock.calls.length).toBeGreaterThan(1));
    const sent = lastRequest();
    expect(sent.classes).toEqual(["structural", "pointer"]);
    expect(sent.min_region).toBe(48);
    expect(sent.alignment).toBe(16);
    expect(sent.min_variance).toBeUndefined();
  });
});

describe("CandidateTable rendering", () => {
  it("renders one row per region and formats the offset as hex", async () => {
    seedWorkspace();
    render(<CandidatePanel />);
    const table = await screen.findByTestId("candidate-table");

    const rows = screen.getAllByTestId("candidate-row");
    expect(rows).toHaveLength(1);
    // 370672 === 0x0005a7f0, the measured offset of the real TLS 1.2 secret.
    expect(within(table).getByText("0x0005a7f0")).toBeInTheDocument();
    expect(within(rows[0]).getByText("48")).toBeInTheDocument();
    expect(within(rows[0]).getByText("10")).toBeInTheDocument();
  });

  it("labels a row by its dominant class, not by whether it contains key bytes", async () => {
    seedWorkspace();
    render(<CandidatePanel />);
    const rows = await screen.findAllByTestId("candidate-row");
    // 22 key_candidate > 18 pointer > 8 structural.
    expect(within(rows[0]).getByText("Key Candidate")).toBeInTheDocument();
  });

  it("jumps the hex viewer to the clicked row's offset", async () => {
    seedWorkspace();
    render(<CandidatePanel />);
    const rows = await screen.findAllByTestId("candidate-row");

    fireEvent.click(rows[0]);
    expect(useHexStore.getState().cursorOffset).toBe(370_672);
    // scrollToOffset stores a ROW target (offset / 16), same as the minimap.
    expect(useHexStore.getState().scrollTarget).toBe(Math.floor(370_672 / 16));
  });

  it.each(["module_offset", "virtual_address"] as const)(
    "refuses the jump under %s alignment rather than scrolling to the wrong bytes",
    async (method) => {
      // Under an aligned consensus the offset indexes a concatenated slab of
      // the regions the dumps share, NOT any one dump's byte stream. Scrolling
      // to it would land on real bytes at the wrong address -- the same class
      // of bug as the consensus overlay once painting slab-coordinate classes
      // at raw-container offsets. Refusing is the honest option until a
      // slab->VA mapping exists.
      analyzeCandidatesMock.mockResolvedValue(
        response({ alignment: { ...QUIET_ALIGNMENT, method } }),
      );
      seedWorkspace();
      render(<CandidatePanel />);
      const rows = await screen.findAllByTestId("candidate-row");

      fireEvent.click(rows[0]);
      expect(useHexStore.getState().cursorOffset).toBe(0);
      expect(useHexStore.getState().scrollTarget).toBeNull();

      // ...and it says why, rather than looking merely broken.
      expect(rows[0]).not.toHaveAttribute("tabindex");
      expect(rows[0].getAttribute("title")).toMatch(/aligned/i);
    },
  );
});

describe("CandidatePanel alignment banner", () => {
  it("always names the alignment method", async () => {
    seedWorkspace();
    render(<CandidatePanel />);
    await screen.findByTestId("candidate-alignment-banner");
    expect(screen.getByTestId("candidate-alignment-method")).toHaveTextContent(
      /flat file offset/i,
    );
  });

  it("stays quiet on equal-sized dumps (no warnings block, no alert role)", async () => {
    seedWorkspace();
    render(<CandidatePanel />);
    const banner = await screen.findByTestId("candidate-alignment-banner");
    expect(screen.queryByTestId("candidate-alignment-warnings")).not.toBeInTheDocument();
    expect(banner).not.toHaveAttribute("role", "alert");
  });

  it("surfaces warnings prominently when the comparison is questionable", async () => {
    const warning =
      "Flat file-offset alignment on 2 dumps of differing size: only the first 10 bytes of each were compared.";
    analyzeCandidatesMock.mockResolvedValue(
      response({
        alignment: {
          ...QUIET_ALIGNMENT,
          sizes_differed: true,
          bytes_discarded: 4096,
          warnings: [warning],
        },
        warnings: [warning],
      }),
    );
    seedWorkspace();
    render(<CandidatePanel />);

    const banner = await screen.findByTestId("candidate-alignment-banner");
    expect(banner).toHaveAttribute("role", "alert");
    expect(screen.getByTestId("candidate-alignment-warnings")).toHaveTextContent(
      /differing size/i,
    );
  });
});

describe("CandidatePanel empty + honesty", () => {
  it("renders the backend diagnostic instead of a blank table", async () => {
    analyzeCandidatesMock.mockResolvedValue(
      response({
        regions: [],
        num_regions: 0,
        regions_returned: 0,
        diagnostics: [
          {
            code: "candidates.empty",
            message: "The entropy gate emptied the result: 6129 bytes survived variance, 0 survived entropy.",
            severity: "warning",
          },
        ],
      }),
    );
    seedWorkspace();
    render(<CandidatePanel />);

    await screen.findByTestId("candidate-empty");
    expect(screen.queryByTestId("candidate-table")).not.toBeInTheDocument();
    expect(screen.getByTestId("candidate-diagnostic")).toHaveTextContent(
      /entropy gate emptied the result/i,
    );
  });

  it("says a candidate is a changed region, not a proven key", async () => {
    seedWorkspace();
    render(<CandidatePanel />);
    const legend = await screen.findByTestId("candidate-legend");
    expect(legend).toHaveTextContent(/not a proven key/i);
  });

  it("shows the failure instead of an empty table when the query errors", async () => {
    analyzeCandidatesMock.mockRejectedValue(new Error("Need at least 2 dumps to compare"));
    seedWorkspace();
    render(<CandidatePanel />);
    const error = await screen.findByTestId("candidate-error");
    expect(error).toHaveTextContent(/Need at least 2 dumps/i);
    expect(screen.queryByTestId("candidate-table")).not.toBeInTheDocument();
  });
});
