import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, renderHook, waitFor } from "@testing-library/react";

const api = vi.hoisted(() => ({ listAnnotations: vi.fn(), addAnnotation: vi.fn(), retractAnnotation: vi.fn() }));
vi.mock("@/api/annotations", () => api);
const { useTableRules } = await import("@/components/vol3/useTableRules");
const { DEFAULT_RULES, rulePayload } = await import("@/components/vol3/highlight-rules");

const stored = { id: "e1", kind: "table_rule", locations: [],
  payload: rulePayload({ id: "u1", table: "pslist", column: "COMM", op: "eq", value: "evil", style: "danger" }) };

beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  api.listAnnotations.mockResolvedValue({ entries: [stored], count: 1 });
  api.addAnnotation.mockResolvedValue({});
  api.retractAnnotation.mockResolvedValue({});
});

describe("useTableRules", () => {
  it("loads the capture's table_rule entries on open and appends them to the defaults", async () => {
    const { result } = renderHook(() => useTableRules(" /case ", "cap1"));
    await waitFor(() => expect(result.current.stored).toHaveLength(1));
    expect(api.listAnnotations).toHaveBeenCalledWith("/case", "cap1", "table_rule");
    expect(result.current.rules).toHaveLength(DEFAULT_RULES.length + 1);
    expect(result.current.stored[0].entryId).toBe("e1");
  });

  it("does nothing until a case and a capture are known", () => {
    const { result } = renderHook(() => useTableRules("", "cap1"));
    expect(result.current.ready).toBe(false);
    expect(api.listAnnotations).not.toHaveBeenCalled();
    expect(result.current.rules).toEqual(DEFAULT_RULES);
  });

  it("add posts a table_rule entry with the rule as payload and NO locations, then reloads", async () => {
    const { result } = renderHook(() => useTableRules("/case", "cap1"));
    await waitFor(() => expect(api.listAnnotations).toHaveBeenCalledTimes(1));
    await act(async () => { await result.current.add({ table: "lsof", column: "Path", op: "contains", value: "/tmp", style: "warn" }); });
    const body = api.addAnnotation.mock.calls[0][0];
    expect(body).toMatchObject({ case_dir: "/case", capture_id: "cap1", kind: "table_rule",
      payload: { table: "lsof", column: "Path", op: "contains", value: "/tmp", style: "warn" } });
    expect(body.payload.id).toMatch(/^rule:/);
    expect(body.locations).toBeUndefined();
    await waitFor(() => expect(api.listAnnotations).toHaveBeenCalledTimes(2));
  });

  it("disable retracts the stored entry (the log is never edited) and reloads", async () => {
    const { result } = renderHook(() => useTableRules("/case", "cap1"));
    await waitFor(() => expect(result.current.stored).toHaveLength(1));
    api.listAnnotations.mockResolvedValue({ entries: [], count: 0 });
    await act(async () => { await result.current.disable(result.current.stored[0]); });
    expect(api.retractAnnotation).toHaveBeenCalledWith(expect.objectContaining({
      case_dir: "/case", capture_id: "cap1", entry_id: "e1" }));
    await waitFor(() => expect(result.current.stored).toHaveLength(0));
  });

  it("surfaces a write failure instead of swallowing it", async () => {
    api.addAnnotation.mockRejectedValue(new Error("403"));
    const { result } = renderHook(() => useTableRules("/case", "cap1"));
    await waitFor(() => expect(result.current.stored).toHaveLength(1));
    await act(async () => { await result.current.add({ table: "t", column: "c", op: "eq", value: "1", style: "ok" }); });
    expect(result.current.error).toBeTruthy();
  });
});
