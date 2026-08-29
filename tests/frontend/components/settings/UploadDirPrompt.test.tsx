import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { act } from "react";
// See the comment in `ErrorBoundary.test.tsx` -- needed so `tsc -b` sees
// jest-dom's `Assertion` augmentation even though `tests/setup.ts` is
// excluded from that program.
import "@testing-library/jest-dom/vitest";
// Real strings, so every assertion below checks the English the user actually
// sees rather than a key name -- this repo's only guard against a missing key.
import "@/i18n";

// The directory picker is the real ``wizard/FileBrowser`` in production; here it
// is stubbed to a single button so the test exercises the prompt, not
// ``/api/path/browse``.
vi.mock("@/components/wizard/FileBrowser", () => ({
  FileBrowser: ({ onSelect }: { onSelect: (p: string) => void; onClose: () => void }) => (
    <button type="button" data-testid="stub-file-browser" onClick={() => onSelect("/srv/chosen")}>
      pick /srv/chosen
    </button>
  ),
}));

import { UploadDirPrompt } from "@/components/settings/UploadDirPrompt";
import type { UploadDirStatus } from "@/api/settings";

function jsonResponse(body: unknown, ok = true, status = 200): Response {
  return {
    ok,
    status,
    json: async () => body,
    text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
  } as unknown as Response;
}

const UNCONFIGURED: UploadDirStatus = {
  configured: false,
  path: null,
  source: null,
  env_pinned: false,
  quota_bytes: 5368709120,
};

const WITH_LEGACY: UploadDirStatus = {
  ...UNCONFIGURED,
  legacy: {
    path: "/tmp/memdiver_uploads",
    file_count: 3,
    total_bytes: 1234,
    owned_by_us: true,
  },
};

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/** Mount the prompt with `status` as the initial GET, and pick a directory. */
async function mountAndChoose(status: UploadDirStatus) {
  fetchMock.mockResolvedValueOnce(jsonResponse(status));
  const onSaved = vi.fn();
  const onClose = vi.fn();
  render(<UploadDirPrompt onSaved={onSaved} onClose={onClose} />);
  await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));

  await act(async () => {
    screen.getByTestId("upload-dir-choose").click();
  });
  await act(async () => {
    screen.getByTestId("stub-file-browser").click();
  });
  return { onSaved, onClose };
}

describe("UploadDirPrompt", () => {
  it("renders the English prompt title and body", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(UNCONFIGURED));
    render(<UploadDirPrompt onSaved={vi.fn()} onClose={vi.fn()} />);

    expect(await screen.findByText("Choose an Upload Directory")).toBeInTheDocument();
    expect(
      screen.getByText(/MemDiver has no upload directory yet/),
    ).toBeInTheDocument();
  });

  it("shows no legacy summary when the backend omits the legacy key", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(UNCONFIGURED));
    render(<UploadDirPrompt onSaved={vi.fn()} onClose={vi.fn()} />);
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));

    expect(screen.queryByTestId("upload-dir-legacy")).not.toBeInTheDocument();
    expect(screen.queryByTestId("upload-dir-migrate")).not.toBeInTheDocument();
  });

  it("shows the legacy summary -- path, file count, total bytes -- when legacy is present", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(WITH_LEGACY));
    render(<UploadDirPrompt onSaved={vi.fn()} onClose={vi.fn()} />);

    expect(await screen.findByTestId("upload-dir-legacy")).toBeInTheDocument();
    expect(screen.getByText("/tmp/memdiver_uploads")).toBeInTheDocument();
    // "Move 3 existing file(s) (1.2 KB) from the old temporary directory"
    expect(
      screen.getByText("Move 3 existing file(s) (1.2 KB) from the old temporary directory"),
    ).toBeInTheDocument();
  });

  it("posts the chosen path with migrate_legacy false by default", async () => {
    const { onSaved } = await mountAndChoose(UNCONFIGURED);
    expect(screen.getByTestId("upload-dir-chosen-path")).toHaveTextContent("/srv/chosen");

    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        configured: true,
        path: "/srv/chosen",
        source: "user_config",
        migrated: 0,
        skipped: 0,
      }),
    );
    await act(async () => {
      screen.getByTestId("upload-dir-save").click();
    });

    const [url, init] = fetchMock.mock.calls[1];
    expect(url).toBe("/api/settings/upload-dir");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({
      path: "/srv/chosen",
      migrate_legacy: false,
    });
    expect(onSaved).toHaveBeenCalledTimes(1);
    expect(onSaved.mock.calls[0][0]).toMatchObject({ path: "/srv/chosen" });
  });

  it("posts migrate_legacy true once the migrate checkbox is ticked", async () => {
    await mountAndChoose(WITH_LEGACY);

    await act(async () => {
      screen.getByTestId("upload-dir-migrate").click();
    });
    expect(screen.getByTestId("upload-dir-migrate")).toBeChecked();

    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        configured: true,
        path: "/srv/chosen",
        source: "user_config",
        migrated: 3,
        skipped: 0,
      }),
    );
    await act(async () => {
      screen.getByTestId("upload-dir-save").click();
    });

    expect(JSON.parse(fetchMock.mock.calls[1][1].body as string)).toEqual({
      path: "/srv/chosen",
      migrate_legacy: true,
    });
  });

  it("renders a 400 reason inline and stays open", async () => {
    const { onSaved, onClose } = await mountAndChoose(UNCONFIGURED);

    fetchMock.mockResolvedValueOnce(
      jsonResponse({ detail: "/srv/chosen is not writable by this user" }, false, 400),
    );
    await act(async () => {
      screen.getByTestId("upload-dir-save").click();
    });

    expect(screen.getByTestId("upload-dir-error")).toHaveTextContent(
      "/srv/chosen is not writable by this user",
    );
    // Still open, and neither callback fired -- the user gets to correct it.
    expect(screen.getByTestId("upload-dir-prompt")).toBeInTheDocument();
    expect(screen.getByText("Choose an Upload Directory")).toBeInTheDocument();
    expect(onSaved).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
  });

  it("keeps Save disabled until a path has been chosen", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(UNCONFIGURED));
    render(<UploadDirPrompt onSaved={vi.fn()} onClose={vi.fn()} />);
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));

    expect(screen.getByTestId("upload-dir-save")).toBeDisabled();
    expect(screen.getByTestId("upload-dir-chosen-path")).toHaveTextContent("Not configured");
  });
});
