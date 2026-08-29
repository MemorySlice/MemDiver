import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { act } from "react";
import "@testing-library/jest-dom/vitest";
// Real strings: the assertions below check the English the user actually sees.
import "@/i18n";

import { ApiError } from "@/api/client";
import type { PcapSession, PcapValidateResult } from "@/api/pipeline";

// The two network calls the component makes through the pipeline client.
const uploadPcap = vi.fn();
const validatePcap = vi.fn();
vi.mock("@/api/pipeline", () => ({
  uploadPcap: (...a: unknown[]) => uploadPcap(...a),
  validatePcap: (...a: unknown[]) => validatePcap(...a),
}));

// Stubbed so the test drives the prompt rather than ``/api/path/browse``.
vi.mock("@/components/wizard/FileBrowser", () => ({
  FileBrowser: ({ onSelect }: { onSelect: (p: string) => void; onClose: () => void }) => (
    <button type="button" data-testid="stub-file-browser" onClick={() => onSelect("/srv/uploads")}>
      pick /srv/uploads
    </button>
  ),
}));

import { PcapUpload } from "@/components/pipeline/oracle/PcapUpload";
import { usePipelineStore } from "@/stores/pipeline-store";

/** The exact 409 the backend sends when no upload directory is configured. */
const UNCONFIGURED_DETAIL =
  "upload_dir_unconfigured: no upload directory configured; choose one in Settings -> Storage";

function jsonResponse(body: unknown, ok = true, status = 200): Response {
  return {
    ok,
    status,
    json: async () => body,
    text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
  } as unknown as Response;
}

function makeSession(): PcapSession {
  return {
    client_random: "a".repeat(64),
    server_random: "b".repeat(64),
    version: "13",
    cipher_suite: 0x1301,
    cipher_name: "TLS_AES_128_GCM_SHA256",
    client_app_records: 3,
    server_app_records: 5,
    has_app_records: true,
  };
}

function makeValidateResult(): PcapValidateResult {
  const sessions = [makeSession()];
  return { pcap_path: "/srv/uploads/capture.pcap", session_count: sessions.length, sessions };
}

/** Fresh store slice per test so one drop cannot leak into the next. */
function resetStore(): void {
  usePipelineStore.setState((s) => ({
    pcapSessions: [],
    form: { ...s.form, pcapPath: null, tlsClientRandom: null },
  }));
}

const fetchMock = vi.fn();

beforeEach(() => {
  uploadPcap.mockReset();
  validatePcap.mockReset();
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  resetStore();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/** Drop `file` onto the dropzone and let the async handler settle. */
async function drop(file: File): Promise<void> {
  await act(async () => {
    fireEvent.drop(screen.getByTestId("pcap-upload-dropzone"), {
      dataTransfer: { files: [file] },
    });
  });
}

describe("PcapUpload", () => {
  it("uploads and arms a dropped capture on the happy path", async () => {
    uploadPcap.mockResolvedValue({ pcap_path: "/srv/uploads/capture.pcap" });
    validatePcap.mockResolvedValue(makeValidateResult());
    render(<PcapUpload />);

    const file = new File(["\xd4\xc3\xb2\xa1"], "capture.pcap");
    await drop(file);

    expect(uploadPcap).toHaveBeenCalledTimes(1);
    expect(uploadPcap).toHaveBeenCalledWith(file);
    expect(validatePcap).toHaveBeenCalledWith("/srv/uploads/capture.pcap");
    expect(screen.getByTestId("pcap-uploaded-path")).toHaveTextContent(
      "/srv/uploads/capture.pcap",
    );
    expect(screen.queryByTestId("upload-dir-prompt")).not.toBeInTheDocument();
  });

  it("still reports an unrelated upload failure as an error, not as the prompt", async () => {
    uploadPcap.mockRejectedValue(new ApiError(400, "not a pcap file"));
    render(<PcapUpload />);

    await drop(new File(["nope"], "notes.txt"));

    expect(screen.getByTestId("pcap-upload-error")).toHaveTextContent("not a pcap file");
    expect(screen.queryByTestId("upload-dir-prompt")).not.toBeInTheDocument();
    expect(usePipelineStore.getState().form.pcapPath).toBeNull();
  });

  it("does NOT open the prompt for a 409 that is not the upload-dir token", async () => {
    uploadPcap.mockRejectedValue(new ApiError(409, "an upload is already in progress"));
    render(<PcapUpload />);

    await drop(new File(["x"], "capture.pcap"));

    expect(screen.queryByTestId("upload-dir-prompt")).not.toBeInTheDocument();
    expect(screen.getByTestId("pcap-upload-error")).toHaveTextContent(
      "an upload is already in progress",
    );
  });

  it("does NOT open the prompt for a 400 that merely carries the token", async () => {
    // The status half of the guard is load-bearing.
    uploadPcap.mockRejectedValue(new ApiError(400, UNCONFIGURED_DETAIL));
    render(<PcapUpload />);

    await drop(new File(["x"], "capture.pcap"));

    expect(screen.queryByTestId("upload-dir-prompt")).not.toBeInTheDocument();
    expect(screen.getByTestId("pcap-upload-error")).toBeInTheDocument();
  });

  it("opens the prompt on the token 409 and replays the SAME file after a save", async () => {
    // Call 1: no upload directory yet. Call 2 (the replay): success.
    uploadPcap
      .mockRejectedValueOnce(new ApiError(409, UNCONFIGURED_DETAIL))
      .mockResolvedValueOnce({ pcap_path: "/srv/uploads/capture.pcap" });
    validatePcap.mockResolvedValue(makeValidateResult());
    // The prompt's own status GET.
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        configured: false,
        path: null,
        source: null,
        env_pinned: false,
        quota_bytes: 5368709120,
      }),
    );

    render(<PcapUpload />);
    const file = new File(["\xd4\xc3\xb2\xa1"], "capture.pcap");
    await drop(file);

    // The rejection became a prompt, not a dead-end error.
    expect(uploadPcap).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId("upload-dir-prompt")).toBeInTheDocument();
    expect(screen.getByText("Choose an Upload Directory")).toBeInTheDocument();
    expect(screen.queryByTestId("pcap-upload-error")).not.toBeInTheDocument();
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));

    // Pick a directory...
    await act(async () => {
      screen.getByTestId("upload-dir-choose").click();
    });
    await act(async () => {
      screen.getByTestId("stub-file-browser").click();
    });

    // ...and save it.
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        configured: true,
        path: "/srv/uploads",
        source: "user_config",
        migrated: 0,
        skipped: 0,
      }),
    );
    await act(async () => {
      screen.getByTestId("upload-dir-save").click();
    });

    // THE ASSERTION THIS TEST EXISTS FOR: the user does not have to drop the
    // file again -- the upload is replayed with the identical File object.
    await waitFor(() => expect(uploadPcap).toHaveBeenCalledTimes(2));
    expect(uploadPcap.mock.calls[1][0]).toBe(file);
    expect(uploadPcap.mock.calls[1][0]).toBe(uploadPcap.mock.calls[0][0]);

    // And the replay completed the original flow.
    await waitFor(() =>
      expect(screen.queryByTestId("upload-dir-prompt")).not.toBeInTheDocument(),
    );
    expect(validatePcap).toHaveBeenCalledWith("/srv/uploads/capture.pcap");
    expect(usePipelineStore.getState().form.pcapPath).toBe("/srv/uploads/capture.pcap");
  });

  it("forgets the pending file when the prompt is dismissed", async () => {
    uploadPcap.mockRejectedValueOnce(new ApiError(409, UNCONFIGURED_DETAIL));
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        configured: false,
        path: null,
        source: null,
        env_pinned: false,
        quota_bytes: 5368709120,
      }),
    );
    render(<PcapUpload />);

    await drop(new File(["x"], "capture.pcap"));
    expect(screen.getByTestId("upload-dir-prompt")).toBeInTheDocument();

    await act(async () => {
      screen.getByText("Cancel").click();
    });

    expect(screen.queryByTestId("upload-dir-prompt")).not.toBeInTheDocument();
    // No replay: dismissing is not a save.
    expect(uploadPcap).toHaveBeenCalledTimes(1);
  });
});
