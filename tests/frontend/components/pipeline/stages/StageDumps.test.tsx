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

/**
 * The endpoint answers 200-with-an-`error` for a path that is not a directory,
 * which is exactly how the paste route tells a dump apart from a typo.
 */
function notADirectory(): DiscoverDumpsResult {
  return {
    dumps: [],
    total: 0,
    truncated: false,
    counts_by_kind: {},
    error: "Path is not a directory",
  };
}

function missingPath(): DiscoverDumpsResult {
  return { ...notADirectory(), error: "Path does not exist" };
}

/** Classify `dirs` as scannable directories and every other path as a file. */
function serverSees(dirs: Record<string, DiscoverDumpsResult>): void {
  client.discoverDumps.mockImplementation((path: string) =>
    Promise.resolve(dirs[path] ?? notADirectory()),
  );
}

/** Type into the textarea and press Add paths. */
function paste(lines: string[]): void {
  fireEvent.change(screen.getByPlaceholderText(/run_0001/), {
    target: { value: lines.join("\n") },
  });
  fireEvent.click(screen.getByRole("button", { name: "Add paths" }));
}

const selectedPaths = (): string[] =>
  usePipelineStore.getState().form.sourcePaths;

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

  // Confirming ends the scan. While the panel stayed up after the merge, the
  // same corpus rendered twice on one screen -- 95 live tick-rows above 95
  // selected rows -- and the analyst had to re-read both to tell them apart.
  it("closes the discovery panel once the ticked dumps are merged", async () => {
    await browseToPreview();
    await screen.findByText(MSL_A);

    fireEvent.click(screen.getByRole("button", { name: "Add 2 selected" }));

    expect(screen.queryByText(/Dumps found in/)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(`select ${MSL_A}`)).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Add \d+ selected/ }),
    ).not.toBeInTheDocument();
    // The merge itself still happened -- closing is a display decision only.
    expect(usePipelineStore.getState().form.sourcePaths).toEqual([
      MSL_A,
      MSL_B,
    ]);
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
    serverSees({});
    render(<StageDumps onAdvance={vi.fn()} />);

    paste([MSL_A, MSL_B]);

    await waitFor(() => expect(selectedPaths()).toEqual([MSL_A, MSL_B]));
  });
});

/**
 * Pasted lines are classified before they can become "dumps".
 *
 * The bug this covers: a user pasted their dataset DIRECTORY, and the UI
 * reported "1 dump selected" whose one entry was the directory. A typo behaved
 * the same way — it became a phantom dump that only failed inside the run. So
 * a folder must land in the scan panel (where the kind filter and the
 * pre-filter counts are visible) and a bad path must be refused out loud,
 * while a plain file path keeps working exactly as before.
 */
describe("StageDumps paste classification", () => {
  it("routes a pasted directory into the scan panel instead of adding it", async () => {
    serverSees({
      [CORPUS]: discovery([
        { path: MSL_A, kind: "msl" },
        { path: MSL_B, kind: "msl" },
      ]),
    });
    render(<StageDumps onAdvance={vi.fn()} />);

    paste([CORPUS]);

    expect(await screen.findByText(`Dumps found in ${CORPUS}`)).toBeInTheDocument();
    expect(checkedDumpPaths()).toEqual([MSL_A, MSL_B]);
    // The directory itself never becomes a dump.
    expect(selectedPaths()).toEqual([]);
  });

  it("still lands in the panel when the ticked kinds match nothing, so the other counts are visible", async () => {
    serverSees({
      [CORPUS]: discovery([], { counts_by_kind: { msl: 0, gcore: 95 } }),
    });
    render(<StageDumps onAdvance={vi.fn()} />);

    paste([CORPUS]);

    expect(await screen.findByText(`Dumps found in ${CORPUS}`)).toBeInTheDocument();
    // gcore is unticked but its real count is on screen to be ticked.
    expect(screen.getByLabelText(/gcore \(95\)/)).not.toBeChecked();
    expect(selectedPaths()).toEqual([]);
  });

  it("adds a pasted file verbatim", async () => {
    serverSees({});
    render(<StageDumps onAdvance={vi.fn()} />);

    paste([MSL_A]);

    await waitFor(() => expect(selectedPaths()).toEqual([MSL_A]));
  });

  it("refuses a path that does not exist and says why", async () => {
    client.discoverDumps.mockResolvedValue(missingPath());
    render(<StageDumps onAdvance={vi.fn()} />);

    paste(["/typo/nope.msl"]);

    expect(
      await screen.findByText(/Not added — \/typo\/nope\.msl: Path does not exist\./),
    ).toBeInTheDocument();
    expect(selectedPaths()).toEqual([]);
    // Left in the box: that is the repair path.
    expect(screen.getByPlaceholderText(/run_0001/)).toHaveValue("/typo/nope.msl");
  });

  it("handles a mixed paste: files added, first directory scanned", async () => {
    serverSees({ [CORPUS]: discovery([{ path: MSL_B, kind: "msl" }]) });
    render(<StageDumps onAdvance={vi.fn()} />);

    paste([MSL_A, CORPUS]);

    await waitFor(() => expect(selectedPaths()).toEqual([MSL_A]));
    expect(await screen.findByText(`Dumps found in ${CORPUS}`)).toBeInTheDocument();
  });

  it("scans one folder at a time and says so, keeping the rest in the box", async () => {
    const OTHER = "/data/other-corpus";
    serverSees({
      [CORPUS]: discovery([{ path: MSL_A, kind: "msl" }]),
      [OTHER]: discovery([{ path: MSL_B, kind: "msl" }]),
    });
    render(<StageDumps onAdvance={vi.fn()} />);

    paste([CORPUS, OTHER]);

    expect(await screen.findByText(new RegExp(`${OTHER} is a folder too`))).toBeInTheDocument();
    expect(screen.getByText(`Dumps found in ${CORPUS}`)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/run_0001/)).toHaveValue(OTHER);
  });

  it("appends in the pasted order and does not duplicate what is already there", async () => {
    usePipelineStore.setState({
      form: { ...usePipelineStore.getState().form, sourcePaths: [MSL_B] },
    });
    serverSees({});
    render(<StageDumps onAdvance={vi.fn()} />);

    paste([MSL_A, MSL_B, GCORE]);

    // MSL_B keeps its original position -- the consensus alignment downstream
    // pairs dumps positionally, so the order must not shuffle.
    await waitFor(() => expect(selectedPaths()).toEqual([MSL_B, MSL_A, GCORE]));
  });

  it("shows a busy state and cannot double-fire while classifying", async () => {
    let release: (value: DiscoverDumpsResult) => void = () => {};
    client.discoverDumps.mockReturnValue(
      new Promise<DiscoverDumpsResult>((resolve) => {
        release = resolve;
      }),
    );
    render(<StageDumps onAdvance={vi.fn()} />);

    paste([MSL_A]);

    const busy = await screen.findByRole("button", { name: "Checking paths…" });
    expect(busy).toBeDisabled();
    fireEvent.click(busy);
    expect(client.discoverDumps).toHaveBeenCalledTimes(1);

    release(notADirectory());
    await waitFor(() => expect(selectedPaths()).toEqual([MSL_A]));
  });
});

/**
 * The first dump is the reference, and that is mechanical, not cosmetic: the
 * sweep binds its reference bytes from `sources[0]` once and verifies only
 * those, so a first dump from the wrong run returns zero hits silently.
 */
describe("StageDumps reference dump", () => {
  it("marks only the first selected dump as the reference", () => {
    usePipelineStore.setState({
      form: {
        ...usePipelineStore.getState().form,
        sourcePaths: [MSL_A, MSL_B, GCORE],
      },
    });
    render(<StageDumps onAdvance={vi.fn()} />);

    expect(screen.getAllByText("reference")).toHaveLength(1);
    const rows = screen.getAllByRole("listitem");
    expect(rows[0]).toHaveTextContent("reference");
    expect(rows[1]).not.toHaveTextContent("reference");
    expect(
      screen.getByText(/only its bytes are verified against the oracle/i),
    ).toBeInTheDocument();
  });

  // Placement, not presence: the badge is on row 1 and the list scrolls, so a
  // note rendered after the list is ~N rows away from the thing it explains.
  it("puts the reference note above the list, not after it", () => {
    usePipelineStore.setState({
      form: {
        ...usePipelineStore.getState().form,
        sourcePaths: [MSL_A, MSL_B, GCORE],
      },
    });
    render(<StageDumps onAdvance={vi.fn()} />);

    const note = screen.getByText(
      /only its bytes are verified against the oracle/i,
    );
    const list = screen.getAllByRole("list")[0];
    expect(list).toBeDefined();
    expect(list).not.toContainElement(note);
    expect(
      note.compareDocumentPosition(list as Node) &
        Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
  });
});
