import { afterEach, describe, expect, it, vi } from "vitest";
import { act, renderHook } from "@testing-library/react";

import { useDebounced } from "@/hooks/useDebounced";

afterEach(() => vi.useRealTimers());

describe("useDebounced", () => {
  it("settles the initial value at once and later values after the delay", () => {
    vi.useFakeTimers();
    const { result, rerender } = renderHook(({ v }) => useDebounced(v, 300), { initialProps: { v: "a" } });
    expect(result.current).toBe("a");
    rerender({ v: "ab" });
    act(() => { vi.advanceTimersByTime(299); });
    expect(result.current).toBe("a");
    rerender({ v: "abc" });
    act(() => { vi.advanceTimersByTime(299); });
    expect(result.current).toBe("a");
    act(() => { vi.advanceTimersByTime(1); });
    expect(result.current).toBe("abc");
  });
});
