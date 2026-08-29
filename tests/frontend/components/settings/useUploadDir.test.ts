import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { act, renderHook, waitFor } from "@testing-library/react";

import { useUploadDir } from "@/components/settings/useUploadDir";
import type { UploadDirStatus } from "@/api/settings";

/** Build a minimal Response-like stub for the mocked fetch. */
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

const CONFIGURED: UploadDirStatus = {
  configured: true,
  path: "/Users/x/MemDiverUploads",
  source: "user_config",
  env_pinned: false,
  quota_bytes: 5368709120,
};

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("useUploadDir", () => {
  it("fetches the status on mount", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(UNCONFIGURED));
    const { result } = renderHook(() => useUploadDir());

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.status).toEqual(UNCONFIGURED);
    expect(result.current.error).toBeNull();
    expect(fetchMock.mock.calls[0][0]).toBe("/api/settings/upload-dir");
  });

  it("exposes the optional legacy block when the backend offers a migration", async () => {
    const withLegacy: UploadDirStatus = {
      ...UNCONFIGURED,
      legacy: {
        path: "/tmp/memdiver_uploads",
        file_count: 3,
        total_bytes: 1234,
        owned_by_us: true,
      },
    };
    fetchMock.mockResolvedValueOnce(jsonResponse(withLegacy));
    const { result } = renderHook(() => useUploadDir());

    await waitFor(() => expect(result.current.status).not.toBeNull());
    expect(result.current.status?.legacy?.file_count).toBe(3);
  });

  it("POSTs the path and the migrate flag, and folds the result into status", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(UNCONFIGURED));
    const { result } = renderHook(() => useUploadDir());
    await waitFor(() => expect(result.current.loading).toBe(false));

    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        configured: true,
        path: "/srv/uploads",
        source: "user_config",
        migrated: 2,
        skipped: 1,
      }),
    );

    let saved: unknown;
    await act(async () => {
      saved = await result.current.save("/srv/uploads", true);
    });

    const [url, init] = fetchMock.mock.calls[1];
    expect(url).toBe("/api/settings/upload-dir");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({
      path: "/srv/uploads",
      migrate_legacy: true,
    });
    expect(saved).toMatchObject({ migrated: 2, skipped: 1 });
    expect(result.current.status?.path).toBe("/srv/uploads");
    expect(result.current.error).toBeNull();
  });

  it("defaults migrate_legacy to false", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(UNCONFIGURED));
    const { result } = renderHook(() => useUploadDir());
    await waitFor(() => expect(result.current.loading).toBe(false));

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
      await result.current.save("/srv/uploads");
    });

    expect(JSON.parse(fetchMock.mock.calls[1][1].body as string)).toEqual({
      path: "/srv/uploads",
      migrate_legacy: false,
    });
  });

  it("resolves null and surfaces the unwrapped 400 detail instead of throwing", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(UNCONFIGURED));
    const { result } = renderHook(() => useUploadDir());
    await waitFor(() => expect(result.current.loading).toBe(false));

    fetchMock.mockResolvedValueOnce(
      jsonResponse({ detail: "/etc is not writable" }, false, 400),
    );

    let saved: unknown = "unset";
    await act(async () => {
      saved = await result.current.save("/etc");
    });

    expect(saved).toBeNull();
    // The reason, not the raw {"detail": ...} envelope.
    expect(result.current.error).toBe("/etc is not writable");
    // The stale status is left intact so the UI keeps showing the truth.
    expect(result.current.status).toEqual(UNCONFIGURED);
  });

  it("surfaces the 409 env-pin reason", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ ...CONFIGURED, source: "env", env_pinned: true }));
    const { result } = renderHook(() => useUploadDir());
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.status?.env_pinned).toBe(true);

    const detail =
      "upload_dir is pinned by MEMDIVER_UPLOAD_DIR; unset it to configure the directory from the UI";
    fetchMock.mockResolvedValueOnce(jsonResponse({ detail }, false, 409));
    await act(async () => {
      await result.current.save("/srv/uploads");
    });
    expect(result.current.error).toBe(detail);
  });

  it("re-reads the backend on refresh", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(UNCONFIGURED));
    const { result } = renderHook(() => useUploadDir());
    await waitFor(() => expect(result.current.loading).toBe(false));

    fetchMock.mockResolvedValueOnce(jsonResponse(CONFIGURED));
    await act(async () => {
      await result.current.refresh();
    });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(result.current.status).toEqual(CONFIGURED);
  });

  it("reports a failed fetch without leaving loading stuck on", async () => {
    fetchMock.mockRejectedValueOnce(new Error("backend down"));
    const { result } = renderHook(() => useUploadDir());

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.error).toBe("backend down");
    expect(result.current.status).toBeNull();
  });
});
