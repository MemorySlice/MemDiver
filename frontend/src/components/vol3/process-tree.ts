/**
 * Process tree from pslist / pstree / psscan rows (PID + PPID columns).
 * Total on any input: duplicate pids, self-parents, cycles and missing parents
 * all yield a forest in which every process appears exactly once.
 */
import type { Vol3Column, Vol3Row } from "@/api/vol3";

export interface TreeNode {
  pid: number;
  ppid: number | null;
  comm: string;
  /** Distinct TIDs seen for this pid, or `null` when the table has no TID column. */
  threads: number | null;
  children: TreeNode[];
  /** Parent pid is not in the table (and is not 0 / itself): shown as a root. */
  orphan: boolean;
  /** Re-rooted to break a parent cycle. */
  cycle: boolean;
}

export interface TreeRow {
  node: TreeNode;
  depth: number;
  hasChildren: boolean;
  expanded: boolean;
}

const find = (columns: readonly Vol3Column[], ...names: string[]) =>
  columns.findIndex((c) => names.includes(c.name.trim().toLowerCase()));

const asPid = (v: unknown): number | null =>
  typeof v === "number" && Number.isSafeInteger(v) ? v
    : typeof v === "string" && /^\d+$/.test(v) && Number.isSafeInteger(Number(v)) ? Number(v) : null;

/** Does this table carry the PID and PPID columns a tree needs? */
export const canBuildTree = (columns: readonly Vol3Column[]) =>
  find(columns, "pid") >= 0 && find(columns, "ppid") >= 0;

export function buildProcessTree(columns: readonly Vol3Column[], rows: readonly Vol3Row[]): TreeNode[] {
  const pidAt = find(columns, "pid"), ppidAt = find(columns, "ppid");
  const commAt = find(columns, "comm", "imagefilename", "name");
  const tidAt = find(columns, "tid");
  if (pidAt < 0 || ppidAt < 0) return [];

  const nodes = new Map<number, TreeNode>();
  const tids = new Map<number, Set<unknown>>();
  for (const row of rows) {
    const pid = asPid(row.values[pidAt]);
    if (pid === null) continue;
    if (tidAt >= 0) tids.set(pid, (tids.get(pid) ?? new Set()).add(row.values[tidAt]));
    if (nodes.has(pid)) continue;
    const comm = commAt >= 0 ? row.values[commAt] : null;
    nodes.set(pid, {
      pid, ppid: asPid(row.values[ppidAt]), comm: comm === null || comm === undefined ? "" : String(comm),
      threads: null, children: [], orphan: false, cycle: false,
    });
  }
  for (const [pid, set] of tids) nodes.get(pid)!.threads = set.size;

  const parentOf = (n: TreeNode) =>
    n.ppid !== null && n.ppid !== n.pid ? nodes.get(n.ppid) ?? null : null;
  const roots: TreeNode[] = [];
  const attach = (n: TreeNode, parent: TreeNode | null) => {
    if (parent) { parent.children.push(n); return; }
    n.orphan = n.ppid !== null && n.ppid !== 0 && n.ppid !== n.pid && !nodes.has(n.ppid);
    roots.push(n);
  };
  const sorted = [...nodes.values()].sort((a, b) => a.pid - b.pid);
  for (const n of sorted) attach(n, parentOf(n));

  // Anything not reachable from a root sits on a parent cycle: re-root its lowest pid.
  const seen = new Set<number>();
  const mark = (n: TreeNode) => { const stack = [n]; while (stack.length) { const c = stack.pop()!; if (!seen.has(c.pid)) { seen.add(c.pid); stack.push(...c.children); } } };
  roots.forEach(mark);
  for (const n of sorted) {
    if (seen.has(n.pid)) continue;
    const parent = parentOf(n);
    parent?.children.splice(parent.children.indexOf(n), 1);
    n.cycle = true;
    roots.push(n);
    mark(n);
  }
  return roots;
}

const matches = (n: TreeNode, query: string) =>
  String(n.pid).includes(query) || n.comm.toLowerCase().includes(query);

/**
 * The rows to draw: depth-first, skipping collapsed subtrees. A non-empty `query`
 * keeps only matching nodes plus their ancestors and expands everything.
 */
export function visibleRows(
  roots: readonly TreeNode[], collapsed: ReadonlySet<number>, query: string,
): TreeRow[] {
  const q = query.trim().toLowerCase();
  const keep = new Map<TreeNode, boolean>();
  const wanted = (n: TreeNode): boolean => {
    if (!q) return true;
    if (!keep.has(n)) keep.set(n, matches(n, q) || n.children.map(wanted).some(Boolean));
    return keep.get(n)!;
  };
  const out: TreeRow[] = [];
  const stack: { node: TreeNode; depth: number }[] =
    [...roots].reverse().map((node) => ({ node, depth: 0 }));
  while (stack.length) {
    const { node, depth } = stack.pop()!;
    if (!wanted(node)) continue;
    const shownKids = node.children.filter(wanted);
    const expanded = q !== "" || !collapsed.has(node.pid);
    out.push({ node, depth, hasChildren: shownKids.length > 0, expanded });
    if (expanded) for (let i = shownKids.length - 1; i >= 0; i -= 1) stack.push({ node: shownKids[i], depth: depth + 1 });
  }
  return out;
}
