import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import type { Vol3RunResult } from "@/api/vol3";
import { useSelectionStore } from "@/stores/selection-store";
import { buildProcessTree, canBuildTree, visibleRows } from "./process-tree";

const buttonClass =
  "px-2 py-1 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40";
const INDENT_PX = 14;

/**
 * Collapsible process tree of a pslist / pstree / psscan result. Clicking a row
 * selects its pid (D14); the Image panel's table and the results table follow.
 */
export function ProcessTree({ result, loading, onLoad }: {
  /** The latest process-listing result of the panel, if any. */
  result: Vol3RunResult | null;
  loading: boolean;
  onLoad: () => void;
}) {
  const { t } = useTranslation("vol3");
  const selectedPid = useSelectionStore((s) => s.pid);
  const [query, setQuery] = useState("");
  const [collapsed, setCollapsed] = useState<ReadonlySet<number>>(new Set());
  const roots = useMemo(
    () => (result && canBuildTree(result.columns) ? buildProcessTree(result.columns, result.rows) : []),
    [result]);
  const rows = useMemo(() => visibleRows(roots, collapsed, query), [roots, collapsed, query]);

  const toggle = (pid: number) => setCollapsed((c) => {
    const next = new Set(c);
    if (next.has(pid)) next.delete(pid); else next.add(pid);
    return next;
  });

  return (
    <div className="space-y-2" data-testid="process-tree">
      <div className="flex items-center gap-2">
        <button type="button" className={buttonClass} disabled={loading} onClick={onLoad}
          data-testid="load-process-tree">{t("tree.load")}</button>
        {loading && <span role="status" className="md-text-muted">{t("run.running")}</span>}
      </div>
      {roots.length === 0 ? (
        <p className="md-text-muted" data-testid="tree-empty">{t("tree.empty")}</p>
      ) : (
        <>
          <input type="text" value={query} onChange={(e) => setQuery(e.target.value)}
            aria-label={t("tree.search")} placeholder={t("tree.search")} data-testid="tree-search"
            className="w-full px-2 py-1 text-xs rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)]" />
          <ul role="tree" aria-label={t("tree.label")} className="max-h-96 overflow-auto font-mono">
            {rows.map(({ node, depth, hasChildren, expanded }) => (
              <li key={node.pid} role="treeitem" aria-level={depth + 1} data-testid="tree-node"
                aria-selected={selectedPid === node.pid}
                aria-expanded={hasChildren ? expanded : undefined}
                className={`flex items-center gap-1 px-1 ${selectedPid === node.pid ? "bg-[var(--md-bg-selected)]" : "hover:bg-[var(--md-bg-hover)]"}`}
                style={{ paddingLeft: depth * INDENT_PX + 4 }}>
                {hasChildren ? (
                  <button type="button" onClick={() => toggle(node.pid)} data-testid="tree-toggle"
                    aria-label={t(expanded ? "tree.collapse" : "tree.expand", { pid: node.pid })}
                    className="w-4 text-center">{expanded ? "▾" : "▸"}</button>
                ) : <span className="w-4" aria-hidden="true" />}
                <button type="button" onClick={() => useSelectionStore.getState().setPid(node.pid)}
                  data-testid="tree-select" className="flex flex-1 items-center gap-2 text-left"
                  aria-label={t("tree.select", { pid: node.pid, comm: node.comm })}>
                  <span className="font-semibold">{node.comm || t("tree.noName")}</span>
                  <span className="md-text-secondary">{node.pid}</span>
                  {node.threads !== null && (
                    <span className="md-text-muted" data-testid="tree-threads">
                      {t("tree.threads", { count: node.threads })}</span>
                  )}
                  {node.orphan && <span className="md-text-muted" data-testid="tree-orphan"
                    title={t("tree.orphanHint", { ppid: node.ppid })}>{t("tree.orphan")}</span>}
                  {node.cycle && <span className="md-text-muted" data-testid="tree-cycle">{t("tree.cycle")}</span>}
                </button>
              </li>
            ))}
          </ul>
          {rows.length === 0 && <p className="md-text-muted">{t("tree.noMatch")}</p>}
        </>
      )}
    </div>
  );
}
