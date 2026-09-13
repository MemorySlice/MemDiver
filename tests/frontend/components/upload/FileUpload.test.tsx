import { afterEach, beforeEach, describe, it, expect, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { useDumpStore, type DumpEntry } from "@/stores/dump-store";
import { useAppStore } from "@/stores/app-store";

vi.mock("@/api/client", () => ({
  getPathInfo: vi.fn(() => new Promise(() => {})),
  getTagStatus: vi.fn(() => new Promise(() => {})),
  probeTagStatusWithKey: vi.fn(() => new Promise(() => {})),
}));

const { FileUpload } = await import("@/components/upload/FileUpload");

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason?: unknown) => void;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function uploadResponse(output: string) {
  return {
    ok: true,
    json: () =>
      Promise.resolve({
        source: "/tmp/source.bin",
        output,
        regions_written: 3,
        total_bytes: 2048,
      }),
  };
}

function file(name: string): File {
  return new File([new Uint8Array([1, 2, 3, 4])], name, { type: "application/octet-stream" });
}

/** Drops `files` on the dropzone, which is the multi-file path under test. */
function drop(files: File[]) {
  fireEvent.drop(screen.getByTestId("upload-dropzone"), {
    dataTransfer: { files },
  });
}

function existingDump(): DumpEntry {
  return {
    id: "already-open",
    path: "/dumps/already-open.msl",
    name: "already-open.msl",
    size: 8192,
    format: "msl",
    sameProcess: true,
  };
}

beforeEach(() => {
  useDumpStore.getState().clearAll();
  useAppStore.setState({ inputMode: "file" });
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

describe("FileUpload sequential queue", () => {
  it("starts the second upload only after the first has resolved", async () => {
    const first = deferred<ReturnType<typeof uploadResponse>>();
    const second = deferred<ReturnType<typeof uploadResponse>>();
    const fetchMock = vi
      .fn()
      .mockReturnValueOnce(first.promise)
      .mockReturnValueOnce(second.promise);
    vi.stubGlobal("fetch", fetchMock);

    render(<FileUpload />);
    drop([file("a.bin"), file("b.bin")]);

    // Both files are queued immediately...
    await waitFor(() => expect(screen.getAllByTestId("upload-queue-item")).toHaveLength(2));
    // ...but only ONE request is in flight. `/api/dumps/upload` converts raw
    // captures server-side; firing the whole batch at once degrades every
    // response instead of finishing any of them sooner.
    expect(fetchMock).toHaveBeenCalledTimes(1);

    first.resolve(uploadResponse("/tmp/a.msl"));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));

    second.resolve(uploadResponse("/tmp/b.msl"));
    await waitFor(() => expect(useDumpStore.getState().dumps).toHaveLength(2));
  });

  it("reports per-item status and a batch summary", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(uploadResponse("/tmp/a.msl"))
      .mockResolvedValueOnce({ ok: false, status: 500 });
    vi.stubGlobal("fetch", fetchMock);

    render(<FileUpload />);
    drop([file("a.bin"), file("b.bin")]);

    await waitFor(() => {
      const items = screen.getAllByTestId("upload-queue-item");
      expect(items[0]).toHaveAttribute("data-status", "done");
      expect(items[1]).toHaveAttribute("data-status", "failed");
    });
    // A failure inside the batch must not abort the rest of it.
    expect(useDumpStore.getState().dumps).toHaveLength(1);
    expect(screen.getByTestId("upload-batch-summary")).toHaveTextContent("1 file imported.");
    expect(screen.getByTestId("upload-batch-summary")).toHaveTextContent("1 file failed.");
  });

  it("keeps the converted path wrappable and reachable on hover", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(uploadResponse("/var/folders/xy/tmpABC.msl")));

    render(<FileUpload />);
    drop([file("a.bin")]);

    const output = await screen.findByTitle("/var/folders/xy/tmpABC.msl");
    expect(output).toHaveClass("break-all");
    expect(output).toHaveClass("font-mono");
  });
});

describe("FileUpload focus handling", () => {
  it("does not steal focus from a dump the analyst is already reading", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(uploadResponse("/tmp/new.msl")));
    useDumpStore.setState({
      dumps: [existingDump()],
      selectedDumpIds: ["already-open"],
      activeDumpId: "already-open",
      originDumpId: "already-open",
    });

    render(<FileUpload />);
    drop([file("new.bin")]);

    await waitFor(() => expect(useDumpStore.getState().dumps).toHaveLength(2));
    expect(useDumpStore.getState().activeDumpId).toBe("already-open");
    // ...and the import still joins the analysis, so it shows up as a pane.
    expect(useDumpStore.getState().selectedDumpIds).toHaveLength(2);
    // The ORIGIN never moves to a later import either.
    expect(useDumpStore.getState().originDumpId).toBe("already-open");
  });

  it("focuses the first import when there was nothing focused before", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(uploadResponse("/tmp/first.msl")));

    render(<FileUpload />);
    drop([file("first.bin"), file("second.bin")]);

    await waitFor(() => expect(useDumpStore.getState().dumps).toHaveLength(2));
    const state = useDumpStore.getState();
    expect(state.activeDumpId).toBe(state.dumps[0].id);
    expect(state.originDumpId).toBe(state.dumps[0].id);
  });
});

describe("FileUpload reaches the multi-dump workflow", () => {
  it("hides the compare affordances while only one dump is loaded", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(uploadResponse("/tmp/only.msl")));

    render(<FileUpload />);
    drop([file("only.bin")]);

    await waitFor(() => expect(useDumpStore.getState().dumps).toHaveLength(1));
    expect(screen.queryByTestId("upload-multi-dump")).not.toBeInTheDocument();
  });

  it("offers the strip and the layout switcher once a second dump lands", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(uploadResponse("/tmp/x.msl")));

    render(<FileUpload />);
    drop([file("a.bin"), file("b.bin")]);

    await waitFor(() => expect(screen.getByTestId("upload-multi-dump")).toBeInTheDocument());
    expect(screen.getByTestId("dump-selection-strip")).toBeInTheDocument();
    expect(screen.getByTestId("main-view-sideBySide")).toBeEnabled();
  });
});
