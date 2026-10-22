import { describe, it, expect, vi, beforeEach } from "vitest";

import { ApiError } from "@/api/client";
import {
  isMemoryBudgetError,
  withMemoryBudgetOverride,
  withForceMemory,
} from "@/api/memory-budget";
import { useMemoryBudgetStore } from "@/stores/memory-budget-store";

const ENVELOPE = {
  error: "estimate 2.0 GiB exceeds budget 1.0 GiB",
  code: "memory_budget_exceeded",
  category: "PRECONDITION",
  message: "estimate 2.0 GiB exceeds budget 1.0 GiB",
  estimate_bytes: 2 * 1024 ** 3,
  budget_bytes: 1024 ** 3,
  details: { operation: "consensus" },
};
const budgetError = () => new ApiError(507, JSON.stringify(ENVELOPE));

beforeEach(() => {
  useMemoryBudgetStore.setState({ pending: null });
});

describe("isMemoryBudgetError", () => {
  it("parses the 507 envelope", () => {
    expect(isMemoryBudgetError(budgetError())).toEqual({
      message: ENVELOPE.message,
      estimateBytes: ENVELOPE.estimate_bytes,
      budgetBytes: ENVELOPE.budget_bytes,
    });
  });

  it("reads the body, not the message, of a prefixed ApiError", () => {
    const err = new ApiError(507, "Consensus failed: 507 ...", JSON.stringify(ENVELOPE));
    expect(isMemoryBudgetError(err)?.budgetBytes).toBe(ENVELOPE.budget_bytes);
  });

  it("accepts a FastAPI detail-wrapped envelope", () => {
    const err = new ApiError(507, JSON.stringify({ detail: ENVELOPE }));
    expect(isMemoryBudgetError(err)?.estimateBytes).toBe(ENVELOPE.estimate_bytes);
  });

  it("returns null for other failures", () => {
    expect(isMemoryBudgetError(new ApiError(400, '{"error":"bad","code":"invalid"}'))).toBeNull();
    expect(isMemoryBudgetError(new ApiError(500, "boom"))).toBeNull();
    expect(isMemoryBudgetError(new Error("memory_budget_exceeded"))).toBeNull();
    expect(isMemoryBudgetError("nope")).toBeNull();
  });
});

describe("withMemoryBudgetOverride", () => {
  it("returns the first result without asking when nothing is refused", async () => {
    const send = vi.fn(async () => "ok");
    const confirm = vi.fn();
    await expect(withMemoryBudgetOverride(send, confirm)).resolves.toBe("ok");
    expect(send).toHaveBeenCalledTimes(1);
    expect(send).toHaveBeenCalledWith(false);
    expect(confirm).not.toHaveBeenCalled();
  });

  it("re-sends with force on confirm", async () => {
    const send = vi.fn(async (force: boolean) => {
      if (!force) throw budgetError();
      return "forced";
    });
    const confirm = vi.fn(async () => true);
    await expect(withMemoryBudgetOverride(send, confirm)).resolves.toBe("forced");
    expect(send.mock.calls).toEqual([[false], [true]]);
    expect(confirm).toHaveBeenCalledWith(
      expect.objectContaining({ budgetBytes: ENVELOPE.budget_bytes }),
    );
  });

  it("rethrows the refusal without retrying on cancel", async () => {
    const refusal = budgetError();
    const send = vi.fn(async () => {
      throw refusal;
    });
    await expect(withMemoryBudgetOverride(send, async () => false)).rejects.toBe(refusal);
    expect(send).toHaveBeenCalledTimes(1);
  });

  it("passes other errors through without asking", async () => {
    const other = new ApiError(500, "boom");
    const confirm = vi.fn();
    await expect(
      withMemoryBudgetOverride(async () => {
        throw other;
      }, confirm),
    ).rejects.toBe(other);
    expect(confirm).not.toHaveBeenCalled();
  });

  it("asks through the dialog store by default, sharing one prompt", async () => {
    const send = vi.fn(async (force: boolean) => {
      if (!force) throw budgetError();
      return force;
    });
    const a = withMemoryBudgetOverride(send);
    const b = withMemoryBudgetOverride(send);
    await vi.waitFor(() => expect(useMemoryBudgetStore.getState().pending).not.toBeNull());
    useMemoryBudgetStore.getState().answer(true);
    await expect(Promise.all([a, b])).resolves.toEqual([true, true]);
    expect(useMemoryBudgetStore.getState().pending).toBeNull();
  });
});

describe("withForceMemory", () => {
  it("adds the flag only when forcing", () => {
    expect(withForceMemory({ a: 1 }, false)).toEqual({ a: 1 });
    expect(withForceMemory({ a: 1 }, true)).toEqual({ a: 1, force_memory: true });
  });
});

// ---- background-task failures (terminal error event / task record) ----

import {
  memoryBudgetInfoFromTask,
  offerForcedResubmit,
  MemoryBudgetTaskError,
} from "@/api/memory-budget";

const TASK_ERROR_INFO = {
  code: "memory_budget_exceeded",
  estimate_bytes: 3 * 1024 ** 3,
  budget_bytes: 1024 ** 3,
  details: { operation: "consensus" },
};

describe("memoryBudgetInfoFromTask", () => {
  it("reads the terminal error event's extra", () => {
    expect(
      memoryBudgetInfoFromTask({ error: "over budget", extra: TASK_ERROR_INFO }),
    ).toEqual({ message: "over budget", estimateBytes: 3 * 1024 ** 3, budgetBytes: 1024 ** 3 });
  });

  it("reads the task record's error_info", () => {
    expect(
      memoryBudgetInfoFromTask({ error: "over budget", error_info: TASK_ERROR_INFO })?.budgetBytes,
    ).toBe(1024 ** 3);
  });

  it("returns null for other failures", () => {
    expect(memoryBudgetInfoFromTask({ error: "boom" })).toBeNull();
    expect(memoryBudgetInfoFromTask({ error: "boom", extra: { code: "other" } })).toBeNull();
  });

  it("is recognised by isMemoryBudgetError when wrapped", () => {
    const info = memoryBudgetInfoFromTask({ error: "x", extra: TASK_ERROR_INFO })!;
    expect(isMemoryBudgetError(new MemoryBudgetTaskError(info))).toBe(info);
  });
});

describe("offerForcedResubmit", () => {
  const failure = { error: "over budget", extra: TASK_ERROR_INFO };

  it("re-submits on confirm, and only offers once per task", async () => {
    const resubmit = vi.fn(async () => "new-task");
    const confirm = vi.fn(async () => true);
    await expect(offerForcedResubmit("t-confirm", failure, resubmit, confirm)).resolves.toBe("new-task");
    await expect(offerForcedResubmit("t-confirm", failure, resubmit, confirm)).resolves.toBeNull();
    expect(resubmit).toHaveBeenCalledTimes(1);
    expect(confirm).toHaveBeenCalledTimes(1);
  });

  it("does not re-submit on cancel", async () => {
    const resubmit = vi.fn(async () => "new-task");
    await expect(
      offerForcedResubmit("t-cancel", failure, resubmit, async () => false),
    ).resolves.toBeNull();
    expect(resubmit).not.toHaveBeenCalled();
  });

  it("ignores non-budget failures without asking", async () => {
    const confirm = vi.fn();
    await offerForcedResubmit("t-other", { error: "boom" }, vi.fn(), confirm);
    expect(confirm).not.toHaveBeenCalled();
  });
});
