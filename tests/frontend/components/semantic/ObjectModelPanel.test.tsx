import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import type { AnchorConsensusResult, ProposedLayoutResult } from "@/api/semantic";
import i18n from "@/i18n";
import { useDumpStore } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";
import enObjectModel from "@/i18n/locales/en/objectModel.json";

const api = vi.hoisted(() => ({ getAnchorConsensus: vi.fn(), proposeLayout: vi.fn() }));
vi.mock("@/api/semantic", async (orig) => ({ ...(await orig<typeof import("@/api/semantic")>()), ...api }));

const { ObjectModelPanel } = await import("@/components/semantic/ObjectModelPanel");

const A = "/dumps/a.raw";
const B = "/dumps/b.raw";
const common = {
  cohort: null, delta_start: -16, length: 64, occurrence: 0,
  instances: [
    { dump_path: A, va: 0x7f000000, offset: 0x1000, view: "va", basis: "needle", captured_bytes: 64 },
  ],
  unanchored: [{ dump_path: B, occurrences: 0, reason: "occurrence 0 not present" }],
  alternatives: { [A]: 1, [B]: 0 }, class_counts: {},
  warnings: ["only one instance anchored"],
};
const ANCHOR: AnchorConsensusResult = {
  ...common, min_instances: 1,
  regions: [
    { delta_start: -16, delta_end: 0, length: 16, class: "structural", min_captured: 1, max_distinct: 3 },
    { delta_start: 0, delta_end: 32, length: 32, class: "key_candidate", min_captured: 1, max_distinct: 9 },
  ],
};
const LAYOUT: ProposedLayoutResult = {
  ...common, anchor_length: 8, base_delta: -16, total_size: 96,
  bounds_evidence: ["malloc chunk header"],
  fields: [
    { delta: 0, length: 8, kind: "anchor", name: "anchor", evidence: ["verified artifact"], alternatives: [] },
    { delta: 8, length: 8, kind: "pointer", name: "pointer_+0x8", evidence: ["quorum"], alternatives: [{}] },
  ],
};

const origScroll = useHexStore.getState().scrollToOffset;

beforeEach(() => {
  useDumpStore.getState().hydrateDumps({
    dumps: [{ path: A, name: "a.raw", size: 1, format: "raw" }, { path: B, name: "b.raw", size: 1, format: "raw" }],
  });
});
afterEach(() => {
  vi.clearAllMocks();
  useHexStore.setState({ scrollToOffset: origScroll });
});

describe("ObjectModelPanel", () => {
  it("sends per-dump needles and renders regions, unanchored dumps and warnings", async () => {
    api.getAnchorConsensus.mockResolvedValue(ANCHOR);
    render(<ObjectModelPanel />);
    fireEvent.change(screen.getByLabelText("Needle for a.raw"), { target: { value: "AA bb" } });
    fireEvent.click(screen.getByText("Anchor consensus"));
    await screen.findByTestId("anchor-results");
    expect(api.getAnchorConsensus.mock.calls[0][0]).toMatchObject({
      dump_paths: [A, B], needles: { [A]: "aabb" }, delta_start: -2048, length: 6144, occurrence: 0,
    });
    expect(screen.getAllByTestId("region-row")).toHaveLength(2);
    expect(screen.getAllByTestId("class-badge").map((b) => b.textContent)).toEqual(["structural", "key_candidate"]);
    const un = screen.getByTestId("unanchored");
    expect(within(un).getByText(/b\.raw/)).toBeInTheDocument();
    expect(screen.getByTestId("warnings")).toHaveTextContent("only one instance anchored");
  });

  it("uses one needle for every dump when the toggle is on", async () => {
    api.getAnchorConsensus.mockResolvedValue(ANCHOR);
    render(<ObjectModelPanel />);
    fireEvent.click(screen.getByLabelText("Same needle for all dumps"));
    fireEvent.change(screen.getByLabelText("Needle (hex)"), { target: { value: "0xdead" } });
    fireEvent.click(screen.getByText("Anchor consensus"));
    await waitFor(() => expect(api.getAnchorConsensus).toHaveBeenCalled());
    expect(api.getAnchorConsensus.mock.calls[0][0].needles).toEqual({ [A]: "dead", [B]: "dead" });
  });

  it("rejects a malformed needle without calling the API", () => {
    render(<ObjectModelPanel />);
    fireEvent.change(screen.getByLabelText("Needle for a.raw"), { target: { value: "xyz" } });
    fireEvent.click(screen.getByText("Anchor consensus"));
    expect(screen.getByRole("alert")).toHaveTextContent("a.raw");
    expect(api.getAnchorConsensus).not.toHaveBeenCalled();
  });

  it("proposes a layout with related values, filters by kind and navigates on click", async () => {
    api.proposeLayout.mockResolvedValue(LAYOUT);
    const scroll = vi.fn();
    useHexStore.setState({ scrollToOffset: scroll });
    render(<ObjectModelPanel />);
    fireEvent.change(screen.getByLabelText("Needle for a.raw"), { target: { value: "aabbccdd" } });
    fireEvent.click(screen.getByText("Add related value"));
    fireEvent.change(screen.getByLabelText("Related value name"), { target: { value: "sid" } });
    fireEvent.change(screen.getByLabelText("sid hex for a.raw"), { target: { value: "0102" } });
    fireEvent.click(screen.getByText("Propose layout"));
    await screen.findByTestId("layout-results");
    expect(api.proposeLayout.mock.calls[0][0].related).toEqual({ sid: { [A]: "0102" } });
    expect(screen.getByTestId("bounds")).toHaveTextContent("-0x10");
    expect(screen.getAllByTestId("field-row")).toHaveLength(2);
    expect(screen.getByTestId("unanchored")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Filter by kind"), { target: { value: "pointer" } });
    expect(screen.getAllByTestId("field-row")).toHaveLength(1);
    fireEvent.click(screen.getByTestId("field-row"));
    // The hex view scrolls in VIEW coordinates: the instance's span-relative
    // `offset` (0x1000), never its absolute VA (live-browser bug, 2026-10-26).
    expect(scroll).toHaveBeenCalledWith(0x1000 + 8);
    expect(scroll).not.toHaveBeenCalledWith(0x7f000000 + 8);
  });

  it("shows the server's message when the request fails", async () => {
    api.getAnchorConsensus.mockRejectedValue(new Error("boom"));
    render(<ObjectModelPanel />);
    fireEvent.change(screen.getByLabelText("Needle for a.raw"), { target: { value: "aa" } });
    fireEvent.click(screen.getByText("Anchor consensus"));
    expect(await screen.findByRole("alert")).toHaveTextContent("boom");
  });
});

describe("objectModel i18n", () => {
  it("every key used by the panel exists in the registered namespace", () => {
    const flat = (o: Record<string, unknown>, p = ""): string[] =>
      Object.entries(o).flatMap(([k, v]) =>
        typeof v === "object" && v !== null ? flat(v as Record<string, unknown>, `${p}${k}.`) : [`${p}${k}`]);
    const keys = flat(enObjectModel as Record<string, unknown>);
    expect(keys.length).toBeGreaterThan(30);
    for (const k of keys) expect(i18n.exists(k, { ns: "objectModel" })).toBe(true);
    expect(i18n.exists("tabs.object", { ns: "layout" })).toBe(true);
  });
});
