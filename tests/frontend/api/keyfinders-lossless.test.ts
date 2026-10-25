import { afterEach, describe, expect, it, vi } from "vitest";

import { getKeyFindersJobPayload, scanKeyFinders } from "@/api/keyfinders";
import { getStringsTable } from "@/api/strings";

const KERNEL = 0xffffffff81000041n;
const RESULT = `{"rows":[{"addr":${KERNEL},"va":${KERNEL},"vas_offset":65}]}`;

afterEach(() => vi.unstubAllGlobals());

const answer = (body: string) =>
  vi.stubGlobal("fetch", vi.fn(async () => new Response(body, { status: 200 })));

type Rows = { rows: { addr: string; va: string; vas_offset: number }[] };

describe("key-finder and strings clients keep kernel VAs exact", () => {
  it("POST /api/keyfinders/scan", async () => {
    answer(RESULT);
    const res = (await scanKeyFinders({ dump_path: "/d", finders: [], heap_policy: "off" })) as unknown as Rows;
    expect(BigInt(res.rows[0].addr)).toBe(KERNEL);
    expect(BigInt(res.rows[0].va)).toBe(KERNEL);
    expect(res.rows[0].vas_offset).toBe(65);
  });

  it("GET /api/tasks/{id}/result", async () => {
    answer(`{"payload":${RESULT}}`);
    const res = (await getKeyFindersJobPayload("t")) as unknown as Rows;
    expect(BigInt(res.rows[0].addr)).toBe(KERNEL);
  });

  it("POST /api/strings/table", async () => {
    answer(RESULT);
    const res = (await getStringsTable({ dump_path: "/d" })) as unknown as Rows;
    expect(BigInt(res.rows[0].addr)).toBe(KERNEL);
  });
});
