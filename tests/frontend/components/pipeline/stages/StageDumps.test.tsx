import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
// Real i18n bundle on purpose: these tests assert the rendered ENGLISH strings,
// which is the only guard in this repo against a missing or typo'd key.
import "@/i18n";

import type { DiscoverDumpsResult } from "@/api/types";

/**
 * "Add dumps by directory" — the second way into stage 2.
 *
 * The complaint that produced this feature was that a corpus had to be entered
 * path by path. The manual textarea stays (an analyst naming exactly N dumps
 * needs it), so every assertion here is about the NEW route not disturbing the
 * old one: discovery fills a preview, the kind filter re-asks the server
 * (because `counts_by_kind` is computed before the filter, so the counts of
 * the unticked kinds only stay real if the server keeps answering), the merge
 * dedupes against what is already in the form, and a capped result says so
 * rather than passing a partial list off as the whole corpus.
 */

const client = vi.hoisted(() => ({ discoverDumps: vi.fn() }));
// PARTIAL: only the discovery call is under test; `client.ts` also exports
// `request`/`ApiError`/`readableFailure`, which the modules below use for real.
vi.mock("@/api/client", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/api/client")>()),
  discoverDumps: client.discoverDumps,
}));

// The browse dialog has its own test; here it stands in for "the user picked a
// directory", which is all `StageDumps` consumes from it.
const CORPUS = "/data/corpus";
vi.mock("@/components/wizard/FileBrowser", () => ({
  FileBrowser: ({ onSelect }: { onSelect: (p: string) => void }) => (
    <button type="button" onClick={() => onSelect(CORPUS)}>
      pick-directory
    </button>
  ),
}));

const { StageDumps } = await import("@/components/pipeline/stages/StageDumps");
const { usePipelineStore } = await import("@/stores/pipeline-store");

const MSL_A = "/data/corpus/run_0001/dump.msl";
const MSL_B = "/data/corpus/run_0002/dump.msl";
const GCORE = "/data/corpus/run_0003/core.1234";

function discovery(
  dumps: Array<{ path: string; kind: string }>,
  extra: Partial<DiscoverDumpsResult> = {},
): DiscoverDumpsResult {
  return {
    dumps: dumps.map((d) => ({ ...d, size: 1024, run: "run" })),
    total: dumps.length,
    truncated: false,
    counts_by_kind: { msl: 2, gcore: 1 },
    ...extra,
  };
}

/** Render the stage and walk the browse -> discover flow to the preview. */
async function browseToPreview(): Promise<void> {
  render(<StageDumps onAdvance={vi.fn()} />);
  fireEvent.click(screen.getByRole("button", { name: "Browse folder…" }));
  fireEvent.click(screen.getByRole("button", { name: "pick-directory" }));
  await waitFor(() => expect(client.discoverDumps).toHaveBeenCalled());
}

/** The paths currently ticked in the discovery preview. */
function checkedDumpPaths(): string[] {
  return screen
    .getAllByRole("checkbox")
    .filter((el) => (el as HTMLInputElement).checked)
    .map((el) => el.getAttribute("aria-label") ?? "")
    .filter((label) => label.startsWith("select /"))
    .map((label) => label.replace("select ", ""));
}

const PRISTINE = usePipelineStore.getState();

beforeEach(() => {
  client.discoverDumps.mockReset();
  client.discoverDumps.mockResolvedValue(
    discovery([{ path: MSL_A, kind: "msl" }, { path: MSL_B, kind: "msl" }]),
  );
  usePipelineStore.setState({
    ...PRISTINE,
    stage: "dumps",
    form: { ...PRISTINE.form, sourcePaths: [] },
  });
});

afterEach(() => {
  usePipelineStore.setState(PRISTINE, true);
});

describe("StageDumps directory discovery", () => {
  it("scans the chosen directory for .msl by default and preselects every hit", async () => {
    await browseToPreview();

    expect(client.discoverDumps).toHaveBeenCalledWith(CORPUS, ["msl"]);
    expect(await screen.findByText(MSL_A)).toBeInTheDocument();
    expect(screen.getByText(MSL_B)).toBeInTheDocument();
    expect(checkedDumpPaths()).toEqual([MSL_A, MSL_B]);
  });

  it("labels each kind with a count taken over everything discovered", async () => {
    await browseToPreview();

    // gcore is UNTICKED yet still reports 1 -- that is the whole point of the
    // backend counting before it filters.
    expect(await screen.findByLabelText(/msl \(2\)/)).toBeChecked();
    expect(screen.getByLabelText(/gcore \(1\)/)).not.toBeChecked();
  });

  it("re-asks the server when a kind is switched on, and re-selects the new list", async () => {
    await browseToPreview();
    await screen.findByText(MSL_A);

    client.discoverDumps.mockResolvedValue(
      discovery([
        { path: MSL_A, kind: "msl" },
        { path: MSL_B, kind: "msl" },
        { path: GCORE, kind: "gcore" },
      ]),
    );
    fireEvent.click(screen.getByLabelText(/gcore \(1\)/));

    await waitFor(() =>
      expect(client.discoverDumps).toHaveBeenLastCalledWith(CORPUS, ["msl", "gcore"]),
    );
    expect(await screen.findByText(GCORE)).toBeInTheDocument();
    expect(checkedDumpPaths()).toEqual([MSL_A, MSL_B, GCORE]);
  });

  it("adds only the ticked dumps, in the server's order", async () => {
    await browseToPreview();
    await screen.findByText(MSL_A);

    fireEvent.click(screen.getByLabelText(`select ${MSL_A}`));
    fireEvent.click(screen.getByRole("button", { name: "Add 1 selected" }));

    expect(usePipelineStore.getState().form.sourcePaths).toEqual([MSL_B]);
  });

  it("merges into the paths already typed by hand, without duplicating them", async () => {
    const TYPED = "/typed/by/hand.msl";
    usePipelineStore.setState({
      form: { ...usePipelineStore.getState().form, sourcePaths: [TYPED, MSL_A] },
    });

    await browseToPreview();
    // By label, not by text: MSL_A is on screen TWICE here -- once in the
    // preview and once in the already-selected list, which is the situation
    // under test.
    await screen.findByLabelText(`select ${MSL_A}`);
    fireEvent.click(screen.getByRole("button", { name: "Add 2 selected" }));

    // MSL_A was already there and stays in its original position; only MSL_B
    // is appended, and the server's ordering of the new paths is preserved.
    expect(usePipelineStore.getState().form.sourcePaths).toEqual([
      TYPED,
      MSL_A,
      MSL_B,
    ]);
  });

  it("says out loud when the server capped the result", async () => {
    client.discoverDumps.mockResolvedValue(
      discovery([{ path: MSL_A, kind: "msl" }], { truncated: true, total: 900 }),
    );

    await browseToPreview();

    expect(
      await screen.findByText(/not the complete set/i),
    ).toBeInTheDocument();
  });

  it("surfaces the endpoint's error key instead of an empty panel", async () => {
    client.discoverDumps.mockResolvedValue(
      discovery([], { error: "Path does not exist", counts_by_kind: {} }),
    );

    await browseToPreview();

    expect(
      await screen.findByText(/Path does not exist/),
    ).toBeInTheDocument();
  });

  it("keeps the manual textarea working alongside the browse route", async () => {
    render(<StageDumps onAdvance={vi.fn()} />);

    const box = screen.getByPlaceholderText(/run_0001/);
    fireEvent.change(box, { target: { value: `${MSL_A}\n${MSL_B}` } });
    fireEvent.click(screen.getByRole("button", { name: "Add paths" }));

    expect(usePipelineStore.getState().form.sourcePaths).toEqual([MSL_A, MSL_B]);
  });
});
