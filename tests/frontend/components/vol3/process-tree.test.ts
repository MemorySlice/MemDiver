import { describe, expect, it } from "vitest";
import type { Vol3Column, Vol3Row } from "@/api/vol3";
import { buildProcessTree, canBuildTree, visibleRows, type TreeNode } from "@/components/vol3/process-tree";

const col = (name: string): Vol3Column => ({ name, type: "str", space: null });
const COLS = [col("PID"), col("PPID"), col("COMM")];
const row = (...values: unknown[]): Vol3Row => ({ depth: 0, values, absent: {} });
const names = (n: TreeNode[]): number[] => n.flatMap((x) => [x.pid, ...names(x.children)]);

describe("buildProcessTree", () => {
  it("nests children under ppid and sorts by pid", () => {
    const roots = buildProcessTree(COLS, [row(3, 1, "c"), row(1, 0, "init"), row(2, 1, "b"), row(4, 3, "d")]);
    expect(roots.map((r) => r.pid)).toEqual([1]);
    expect(roots[0].children.map((c) => c.pid)).toEqual([2, 3]);
    expect(roots[0].children[1].children[0].comm).toBe("d");
    expect(roots[0].orphan).toBe(false);
  });

  it("makes a process with a missing parent an orphan root, but ppid 0 a plain root", () => {
    const roots = buildProcessTree(COLS, [row(10, 99, "lost"), row(2, 0, "kthreadd")]);
    expect(roots.map((r) => [r.pid, r.orphan])).toEqual([[2, false], [10, true]]);
  });

  it("is safe on self-parents, 2-cycles, duplicates and bad pids; each pid appears once", () => {
    const roots = buildProcessTree(COLS, [
      row(5, 5, "self"), row(6, 7, "a"), row(7, 6, "b"), row(8, 7, "kid"),
      row(8, 7, "kid-dup"), row("x", 1, "bad"), row(null, 1, "none"),
    ]);
    const all = names(roots);
    expect([...all].sort()).toEqual([5, 6, 7, 8]);
    expect(new Set(all).size).toBe(all.length);
    expect(roots.find((r) => r.pid === 6)?.cycle).toBe(true);
    expect(roots.find((r) => r.pid === 8)).toBeUndefined();
    expect(buildProcessTree(COLS, [row(8, 7, "first"), row(8, 7, "second"), row(7, 0, "p")])[0].children[0].comm).toBe("first");
  });

  it("counts distinct TIDs per pid only when a TID column exists", () => {
    const withTid = [col("PID"), col("TID"), col("PPID"), col("COMM")];
    const roots = buildProcessTree(withTid, [row(1, 1, 0, "init"), row(1, 9, 0, "init"), row(1, 9, 0, "init")]);
    expect(roots[0].threads).toBe(2);
    expect(buildProcessTree(COLS, [row(1, 0, "init")])[0].threads).toBeNull();
  });

  it("needs PID and PPID columns; accepts exact decimal-string pids and psscan's ImageFileName", () => {
    expect(canBuildTree([col("PID"), col("COMM")])).toBe(false);
    expect(buildProcessTree([col("PID"), col("COMM")], [row(1, "x")])).toEqual([]);
    const roots = buildProcessTree([col("PID"), col("PPID"), col("ImageFileName")], [row("1", "0", "sshd")]);
    expect(roots[0]).toMatchObject({ pid: 1, comm: "sshd" });
  });
});

describe("visibleRows", () => {
  const roots = buildProcessTree(COLS, [row(1, 0, "init"), row(2, 1, "sshd"), row(3, 2, "bash"), row(4, 1, "cron")]);

  it("walks depth-first and skips collapsed subtrees", () => {
    expect(visibleRows(roots, new Set(), "").map((r) => [r.node.pid, r.depth])).toEqual([[1, 0], [2, 1], [3, 2], [4, 1]]);
    const folded = visibleRows(roots, new Set([2]), "");
    expect(folded.map((r) => r.node.pid)).toEqual([1, 2, 4]);
    expect(folded[1]).toMatchObject({ hasChildren: true, expanded: false });
  });

  it("search keeps matches and their ancestors, expanding collapsed ones", () => {
    expect(visibleRows(roots, new Set([2]), "bash").map((r) => r.node.pid)).toEqual([1, 2, 3]);
    expect(visibleRows(roots, new Set(), "4").map((r) => r.node.pid)).toEqual([1, 4]);
    expect(visibleRows(roots, new Set(), "zzz")).toEqual([]);
  });
});
