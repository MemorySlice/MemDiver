import { afterEach, describe, expect, it, vi } from "vitest";
import { act, renderHook } from "@testing-library/react";

import { ApiError, readableFailure } from "@/api/client";
import { hasKey, isObject } from "@/api/guards";
import { isKeyFindersTicket, scanKeyFinders } from "@/api/keyfinders";
import { getStringsTable, isJobTicket as isStringsTicket } from "@/api/strings";
import { isJobTicket as isVol3Ticket, runVol3Plugin } from "@/api/vol3";
import { cancelYaraJob, getYaraJobPayload, isYaraTicket, scanYara } from "@/api/yara";
import { useJobRun } from "@/hooks/useJobRun";
import i18n from "@/i18n";

vi.mock("@/hooks/useTaskProgress", () => ({ useTaskProgress: () => undefined }));

afterEach(() => vi.unstubAllGlobals());

const answerEmpty = () =>
  vi.stubGlobal("fetch", vi.fn(async () => new Response("", { status: 200 })));

const NON_OBJECTS: unknown[] = [undefined, null, "task_id", "", 0, 42, true, Symbol("s")];

const GUARDS = {
  isKeyFindersTicket, isStringsTicket, isVol3Ticket, isYaraTicket,
} as Record<string, (r: unknown) => boolean>;

describe("isObject / hasKey", () => {
  it("reject every non-object without throwing", () => {
    for (const v of NON_OBJECTS) {
      expect(isObject(v)).toBe(false);
      expect(hasKey(v, "task_id")).toBe(false);
    }
  });

  it("accept objects, and hasKey needs the key", () => {
    expect(isObject({})).toBe(true);
    expect(isObject([])).toBe(true);
    expect(hasKey({ task_id: "t" }, "task_id")).toBe(true);
    expect(hasKey({ rows: [] }, "task_id")).toBe(false);
  });
});

describe.each(Object.entries(GUARDS))("%s", (_name, guard) => {
  it("is false for undefined, null and primitives", () => {
    for (const v of NON_OBJECTS) expect(guard(v)).toBe(false);
  });

  it("is true only for an object with task_id", () => {
    expect(guard({ task_id: "t1", status: "queued" })).toBe(true);
    expect(guard({ rows: [] })).toBe(false);
  });
});

describe("an empty 200 body on a scan submit", () => {
  const SUBMITS: [string, () => Promise<unknown>][] = [
    ["POST /api/keyfinders/scan", () => scanKeyFinders({ dump_path: "/d", finders: [], heap_policy: "off" })],
    ["POST /api/yara/scan", () => scanYara({ dump_path: "/d", rules: [] } as unknown as Parameters<typeof scanYara>[0])],
    ["POST /api/strings/table", () => getStringsTable({ dump_path: "/d" })],
    ["POST /api/vol3/run", () => runVol3Plugin({ dump_path: "/d", plugin: "p" } as unknown as Parameters<typeof runVol3Plugin>[0])],
  ];

  it.each(SUBMITS)("%s rejects with the readable empty-response ApiError", async (_name, submit) => {
    answerEmpty();
    const err = await submit().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(readableFailure(err)).toBe(i18n.t("common:emptyResponse"));
  });

  it("surfaces through useJobRun as that message, not a TypeError", async () => {
    answerEmpty();
    const hook = renderHook(() => useJobRun({
      submit: scanYara, isTicket: isYaraTicket, getPayload: getYaraJobPayload,
      cancelJob: cancelYaraJob, noPayloadKey: "yara:run.noPayload",
    }));
    await act(async () => {
      await hook.result.current.run({ dump_path: "/d" } as unknown as Parameters<typeof scanYara>[0]);
    });
    expect(hook.result.current.state.status).toBe("error");
    expect(hook.result.current.state.error).toBe(i18n.t("common:emptyResponse"));
    expect(hook.result.current.state.error).not.toMatch(/in' operator|TypeError/);
  });
});
