import { describe, it, expect, vi, afterEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";

import { mslInspectUrl, useFetchJson } from "@/hooks/useFetchJson";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("mslInspectUrl", () => {
  it("builds an encoded inspect url", () => {
    expect(mslInspectUrl("handles", "/a b.msl")).toBe(
      "/api/inspect/handles?msl_path=%2Fa%20b.msl",
    );
  });

  it("returns null without an MSL path", () => {
    expect(mslInspectUrl("handles", "")).toBeNull();
  });
});

describe("useFetchJson", () => {
  it("does not fetch for a null url", () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const { result } = renderHook(() => useFetchJson<number[]>(null));
    expect(fetchMock).not.toHaveBeenCalled();
    expect(result.current).toEqual({ data: null, error: null });
  });

  it("returns the parsed body", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse([1, 2])));
    const { result } = renderHook(() => useFetchJson<number[]>("/x"));
    await waitFor(() => expect(result.current.data).toEqual([1, 2]));
    expect(result.current.error).toBeNull();
  });

  it("reports HTTP failures as an error string", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({}, 500)));
    const { result } = renderHook(() => useFetchJson<number[]>("/x"));
    await waitFor(() => expect(result.current.error).toBe("Error: HTTP 500"));
  });

  it("clears the error immediately on url change and keeps stale data", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse([1]))
      .mockResolvedValueOnce(jsonResponse({}, 500))
      .mockReturnValueOnce(new Promise(() => {}));
    vi.stubGlobal("fetch", fetchMock);
    const { result, rerender } = renderHook(
      ({ url }) => useFetchJson<number[]>(url),
      { initialProps: { url: "/a" } },
    );
    await waitFor(() => expect(result.current.data).toEqual([1]));
    rerender({ url: "/b" });
    await waitFor(() => expect(result.current.error).toBe("Error: HTTP 500"));
    rerender({ url: "/c" });
    expect(result.current).toEqual({ data: [1], error: null });
  });

  it("drops stale data on url change when asked to", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse([1]))
      .mockReturnValueOnce(new Promise(() => {}));
    vi.stubGlobal("fetch", fetchMock);
    const { result, rerender } = renderHook(
      ({ url }) => useFetchJson<number[]>(url, { resetDataOnChange: true }),
      { initialProps: { url: "/a" } },
    );
    await waitFor(() => expect(result.current.data).toEqual([1]));
    rerender({ url: "/b" });
    expect(result.current.data).toBeNull();
  });
});
