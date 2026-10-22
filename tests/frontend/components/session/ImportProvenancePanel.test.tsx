import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";

import "@/i18n";
import { ImportProvenancePanel } from "@/components/session/ImportProvenancePanel";
import type { ImportProvenanceRecord } from "@/api/types";

const MATERIALIZED: ImportProvenanceRecord = {
  source_format: 4,
  source_format_name: "MSL",
  tool_name: "memdiver",
  import_time_ns: 0,
  orig_file_size: 8192,
  source_hash: "00".repeat(32),
  note: "source_format=msl;materialized=1;orig_eoc_hash=abcd; regions=heap;excluded_regions=1;excluded_bytes=8192",
  base_note: "source_format=msl;materialized=1;orig_eoc_hash=abcd",
  selected_categories: ["heap"],
  selection_all: false,
  writable_only: false,
  module_globs: [],
  excluded_regions: 1,
  excluded_bytes: 8192,
  fallback_all: false,
  materialized: true,
  orig_eoc_hash: "abcd",
  dropped_key_hints: 2,
};

function stubFetch(body: unknown, status = 200) {
  const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(body), { status }));
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("ImportProvenancePanel", () => {
  it("shows kept categories, exclusions and the materialized origin", async () => {
    const fetchMock = stubFetch({ provenance: [MATERIALIZED] });
    render(<ImportProvenancePanel mslPath="/x/copy.msl" />);
    expect(await screen.findByText("Import provenance")).toBeInTheDocument();
    expect(String(fetchMock.mock.calls[0][0])).toContain("/api/inspect/import-provenance?msl_path=%2Fx%2Fcopy.msl");
    expect(screen.getByTestId("import-provenance-source-format")).toHaveTextContent("MSL");
    expect(screen.getByTestId("import-provenance-kept")).toHaveTextContent("Heap");
    expect(screen.getByTestId("import-provenance-excluded")).toHaveTextContent("1 region, 8.0 KiB");
    expect(screen.getByTestId("import-provenance-materialized")).toBeInTheDocument();
    expect(screen.getByTestId("import-provenance-orig-hash")).toHaveTextContent("abcd");
  });

  it("pluralises exclusions and describes an all / module selection", async () => {
    stubFetch({
      provenance: [{
        ...MATERIALIZED,
        materialized: false,
        orig_eoc_hash: null,
        selection_all: true,
        writable_only: true,
        module_globs: ["libssl*"],
        excluded_regions: 3,
        excluded_bytes: 3 * 4096,
      }],
    });
    render(<ImportProvenancePanel mslPath="/x/a.msl" />);
    const excluded = await screen.findByTestId("import-provenance-excluded");
    expect(excluded).toHaveTextContent("3 regions, 12.0 KiB");
    expect(screen.getByTestId("import-provenance-kept")).toHaveTextContent(
      "All regions (writable only) + modules libssl*",
    );
    expect(screen.queryByTestId("import-provenance-materialized")).not.toBeInTheDocument();
  });

  it("says when no selection was recorded", async () => {
    stubFetch({
      provenance: [{ ...MATERIALIZED, selected_categories: null, excluded_regions: null, materialized: false }],
    });
    render(<ImportProvenancePanel mslPath="/x/a.msl" />);
    expect(await screen.findByTestId("import-provenance-kept")).toHaveTextContent(
      "No region selection recorded",
    );
    expect(screen.queryByTestId("import-provenance-excluded")).not.toBeInTheDocument();
  });

  it("shows the mapping-name classification row only when region_names is set", async () => {
    stubFetch({ provenance: [{ ...MATERIALIZED, region_names: true }] });
    render(<ImportProvenancePanel mslPath="/x/android.msl" />);
    const row = await screen.findByTestId("import-provenance-region-names");
    expect(row).toHaveTextContent("Classified by mapping names");
    expect(row).toHaveTextContent("Yes");
  });

  it.each([[false], [undefined]] as const)("omits the mapping-name row when region_names is %s", async (flag) => {
    stubFetch({ provenance: [{ ...MATERIALIZED, region_names: flag }] });
    render(<ImportProvenancePanel mslPath="/x/old.msl" />);
    await screen.findByTestId("import-provenance-kept");
    expect(screen.queryByTestId("import-provenance-region-names")).not.toBeInTheDocument();
  });

  it("labels a kept runtime category", async () => {
    stubFetch({ provenance: [{ ...MATERIALIZED, selected_categories: ["heap", "runtime"] }] });
    render(<ImportProvenancePanel mslPath="/x/a.msl" />);
    expect(await screen.findByTestId("import-provenance-kept")).toHaveTextContent("Heap, Runtime");
  });

  it("renders nothing when the dump has no provenance", async () => {
    const fetchMock = stubFetch({ provenance: [] });
    const { container } = render(<ImportProvenancePanel mslPath="/x/live.msl" />);
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });

  it("shows a localized error when the request fails", async () => {
    stubFetch({ detail: "boom" }, 500);
    render(<ImportProvenancePanel mslPath="/x/a.msl" />);
    expect(await screen.findByTestId("import-provenance-error")).toHaveTextContent(
      "Could not load import provenance",
    );
  });
});
