import { describe, expect, it } from "vitest";
import type { Vol3Column, Vol3Row } from "@/api/vol3";
import {
  DEFAULT_RULES, cellMatches, matchRow, ruleFromEntry, rulesFromEntries, rulePayload, tableMatches,
  type HighlightRule,
} from "@/components/vol3/highlight-rules";

const col = (name: string): Vol3Column => ({ name, type: "str", space: null });
const row = (...values: unknown[]): Vol3Row => ({ depth: 0, values, absent: {} });

describe("cellMatches", () => {
  it("eq / ne compare numbers numerically and everything else as text", () => {
    expect(cellMatches(5, "eq", "5")).toBe(true);
    expect(cellMatches("0x5", "eq", 5)).toBe(false);
    expect(cellMatches("EXIT_DEAD", "eq", "EXIT_DEAD")).toBe(true);
    expect(cellMatches("a", "ne", "b")).toBe(true);
    expect(cellMatches(5, "ne", 5)).toBe(false);
  });

  it("an absent cell reads as the empty string", () => {
    expect(cellMatches(null, "eq", "")).toBe(true);
    expect(cellMatches(undefined, "eq", "")).toBe(true);
    expect(cellMatches(0, "eq", "")).toBe(false);
  });

  it("lt / gt are numeric only", () => {
    expect(cellMatches(3, "lt", 5)).toBe(true);
    expect(cellMatches("10", "gt", "9")).toBe(true);
    expect(cellMatches("abc", "gt", 1)).toBe(false);
    expect(cellMatches(null, "lt", 1)).toBe(false);
  });

  it("contains, regex and in", () => {
    expect(cellMatches("rwxp", "contains", "x")).toBe(true);
    expect(cellMatches("rw-p", "contains", "x")).toBe(false);
    expect(cellMatches("sshd", "regex", "^ss")).toBe(true);
    expect(cellMatches("sshd", "in", ["bash", "sshd"])).toBe(true);
    expect(cellMatches("sshd", "in", "bash, sshd")).toBe(true);
    expect(cellMatches("cron", "in", "bash, sshd")).toBe(false);
  });

  it("an invalid regex never matches (and never throws)", () => {
    expect(cellMatches("x", "regex", "(")).toBe(false);
  });
});

describe("tableMatches", () => {
  it("matches whole dotted segments of the plugin name, case-insensitively", () => {
    expect(tableMatches("pslist", "linux.pslist.PsList")).toBe(true);
    expect(tableMatches("proc.Maps", "linux.proc.Maps")).toBe(true);
    expect(tableMatches("list", "linux.pslist.PsList")).toBe(false);
    expect(tableMatches("*", "anything")).toBe(true);
    expect(tableMatches("PSSCAN", "linux.psscan.PsScan")).toBe(true);
  });
});

describe("default rules", () => {
  const maps = [col("Start"), col("Flags"), col("File Path")];
  const hit = (plugin: string, columns: Vol3Column[], r: Vol3Row) => matchRow(DEFAULT_RULES, plugin, columns, r);

  it("a mapping with both w and x is danger", () => {
    expect(hit("linux.proc.Maps", maps, row(1, "rwxp", "/lib/x.so"))?.style).toBe("danger");
    expect(hit("linux.proc.Maps", maps, row(1, "rw-p", "/lib/x.so"))).toBeNull();
    expect(hit("linux.proc.Maps", maps, row(1, "r-xp", "/lib/x.so"))).toBeNull();
  });

  it("an anonymous executable mapping is warn, a named or non-executable one is not", () => {
    expect(hit("linux.proc.Maps", maps, row(1, "r-xp", ""))?.style).toBe("warn");
    expect(hit("linux.proc.Maps", maps, row(1, "r-xp", null))?.style).toBe("warn");
    expect(hit("linux.proc.Maps", maps, row(1, "rw-p", ""))).toBeNull();
    expect(hit("linux.proc.Maps", maps, row(1, "r-xp", "/bin/ls"))).toBeNull();
  });

  it("the most severe rule wins and lists the columns that tripped", () => {
    const m = hit("linux.proc.Maps", maps, row(1, "rwxp", ""));
    expect(m?.style).toBe("danger");
    expect(m?.columns).toEqual(["Flags"]);
  });

  it("EXIT_DEAD is info on pslist and psscan, and only there", () => {
    const cols = [col("PID"), col("EXIT_STATE")];
    expect(hit("linux.pslist.PsList", cols, row(1, "EXIT_DEAD"))?.style).toBe("info");
    expect(hit("linux.psscan.PsScan", cols, row(1, "EXIT_DEAD"))?.style).toBe("info");
    expect(hit("linux.lsof.Lsof", cols, row(1, "EXIT_DEAD"))).toBeNull();
    expect(hit("linux.pslist.PsList", cols, row(1, "TASK_RUNNING"))).toBeNull();
  });

  it("column names match case-insensitively and a missing column never matches", () => {
    expect(hit("linux.proc.Maps", [col("flags")], row("rwx"))?.style).toBe("danger");
    expect(hit("linux.proc.Maps", [col("Other")], row("rwx"))).toBeNull();
  });
});

describe("persistence mapping", () => {
  const rule: HighlightRule = { id: "r1", table: "pslist", column: "COMM", op: "in", value: ["a", "b"], style: "warn",
    also: [{ column: "PID", op: "gt", value: 10 }] };

  it("round-trips a rule through a table_rule entry payload", () => {
    const entry = { id: "e9", kind: "table_rule", locations: [], payload: rulePayload(rule) };
    expect(ruleFromEntry(entry)).toEqual({ ...rule, entryId: "e9" });
  });

  it("drops malformed payloads and other kinds", () => {
    const bad = [{ id: "1", kind: "table_rule", locations: [], payload: { table: "t", column: "c", op: "nope", value: 1, style: "warn" } },
      { id: "2", kind: "table_rule", locations: [], payload: { table: "t", column: "c", op: "eq", value: 1, style: "loud" } },
      { id: "3", kind: "table_rule", locations: [], payload: null },
      { id: "4", kind: "annotation", locations: [], payload: rulePayload(rule) }];
    expect(rulesFromEntries(bad)).toEqual([]);
  });
});
