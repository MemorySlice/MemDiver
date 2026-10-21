import { describe, it, expect, vi, afterEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";

import { useFetchText } from "@/hooks/useFetchText";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("useFetchText", () => {
  it("starts loading, then returns the text", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("hello")));
    const { result } = renderHook(() => useFetchText("/a"));
    expect(result.current).toEqual({ text: null, error: null, loading: true });
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current).toEqual({ text: "hello", error: null, loading: false });
  });

  it("reports HTTP failures by message", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("", { status: 404 })));
    const { result } = renderHook(() => useFetchText("/a"));
    await waitFor(() => expect(result.current.error).toBe("HTTP 404"));
    expect(result.current.text).toBeNull();
    expect(result.current.loading).toBe(false);
  });

  it("goes back to loading as soon as the url changes", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response("first"))
      .mockReturnValueOnce(new Promise(() => {}));
    vi.stubGlobal("fetch", fetchMock);
    const { result, rerender } = renderHook(({ url }) => useFetchText(url), {
      initialProps: { url: "/a" },
    });
    await waitFor(() => expect(result.current.text).toBe("first"));
    rerender({ url: "/b" });
    expect(result.current).toEqual({ text: null, error: null, loading: true });
  });

  it("ignores a response for a url that is no longer current", async () => {
    let resolveFirst: (r: Response) => void = () => {};
    const fetchMock = vi
      .fn()
      .mockReturnValueOnce(new Promise<Response>((r) => { resolveFirst = r; }))
      .mockResolvedValueOnce(new Response("second"));
    vi.stubGlobal("fetch", fetchMock);
    const { result, rerender } = renderHook(({ url }) => useFetchText(url), {
      initialProps: { url: "/a" },
    });
    rerender({ url: "/b" });
    await waitFor(() => expect(result.current.text).toBe("second"));
    resolveFirst(new Response("first"));
    await new Promise((r) => setTimeout(r, 0));
    expect(result.current.text).toBe("second");
  });
});
