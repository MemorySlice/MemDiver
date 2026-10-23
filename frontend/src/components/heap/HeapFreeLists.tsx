/**
 * The allocator's free lists as a two-level tree: kind → list, each list
 * expanding to its chain. Cycle / corrupt lists are flagged; any address in a
 * chain jumps the hex viewer there (via `/api/heap/chunk-at` translation).
 */

import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useShallow } from "zustand/react/shallow";

import type { HeapFreeList } from "@/api/types";
import { useHeapFreeListData } from "@/hooks/useHeapData";
import { selectHeapDump, useHeapStore } from "@/stores/heap-store";
import { formatAddress } from "./heap-format";
import { jumpHexToVa } from "./heap-navigation";

/** Chain entries rendered per list before collapsing the rest into a count. */
const FREE_LIST_CHAIN_LIMIT = 256;

interface Props {
  dumpPath: string;
}

export function HeapFreeLists({ dumpPath }: Props) {
  const { t } = useTranslation("heap");
  useHeapFreeListData(dumpPath);
  const { freeLists, status, error } = useHeapStore(
    useShallow((s) => {
      const e = selectHeapDump(dumpPath)(s);
      return { freeLists: e.freeLists, status: e.freeListsStatus, error: e.freeListsError };
    }),
  );
  const [unmapped, setUnmapped] = useState(false);

  const jump = (va: number) => {
    setUnmapped(false);
    jumpHexToVa(dumpPath, va)
      .then((ok) => setUnmapped(!ok))
      .catch(() => setUnmapped(true));
  };

  if (status === "loading" || (status === "idle" && !freeLists)) {
    return <p role="status" className="p-2 text-xs md-text-muted">{t("freeLists.loading")}</p>;
  }
  if (error) {
    return (
      <div role="alert" className="m-2 p-2 text-xs rounded md-bg-error-subtle md-text-error flex gap-2">
        <span className="flex-1">{error}</span>
        <button
          type="button"
          className="px-1.5 rounded border border-[var(--md-border)]"
          onClick={() => void useHeapStore.getState().loadFreeLists(dumpPath)}
        >
          {t("overview.retry")}
        </button>
      </div>
    );
  }
  if (!freeLists || freeLists.lists.length === 0) {
    return <p className="p-2 text-xs md-text-muted">{t("freeLists.empty")}</p>;
  }

  const kinds = Array.from(new Set(freeLists.lists.map((l) => l.kind)));
  return (
    <div className="p-2 text-xs space-y-1" data-testid="heap-free-lists">
      <p className="md-text-muted">
        {t("freeLists.summary", {
          lists: freeLists.list_count,
          cycles: freeLists.cycle_count,
          corrupt: freeLists.corrupt_count,
        })}
      </p>
      {unmapped && <p role="status" className="md-text-warning">{t("overview.regionUnmapped")}</p>}
      <ul role="tree" className="space-y-1">
        {kinds.map((kind) => (
          <li key={kind} role="treeitem" aria-expanded>
            <details open>
              <summary className="cursor-pointer font-semibold">{kind}</summary>
              <ul role="group" className="pl-3 space-y-0.5">
                {freeLists.lists
                  .filter((l) => l.kind === kind)
                  .map((list) => (
                    <FreeListNode key={`${list.kind}-${list.index}`} list={list} onJump={jump} />
                  ))}
              </ul>
            </details>
          </li>
        ))}
      </ul>
    </div>
  );
}

function FreeListNode({ list, onJump }: { list: HeapFreeList; onJump: (va: number) => void }) {
  const { t } = useTranslation("heap");
  const shown = list.chunk_vas.slice(0, FREE_LIST_CHAIN_LIMIT);
  const hidden = list.chunk_vas.length - shown.length;
  const badge = "px-1 rounded";
  return (
    <li role="treeitem" data-testid="heap-free-list" data-kind={list.kind} data-index={list.index}>
      <details>
        <summary className="cursor-pointer flex flex-wrap items-center gap-2">
          <span className="font-mono">[{list.index}]</span>
          <button
            type="button"
            className="font-mono hover:underline"
            title={t("freeLists.head")}
            onClick={(e) => {
              e.preventDefault();
              onJump(list.head_va);
            }}
          >
            {formatAddress(list.head_va)}
          </button>
          <span className="md-text-muted">{t("freeLists.lengthValue", { count: list.length })}</span>
          {list.cycle && <span className={`${badge} md-bg-warning-subtle`} data-testid="heap-free-list-cycle">{t("freeLists.cycle")}</span>}
          {list.corrupt && <span className={`${badge} md-bg-error-subtle md-text-error`} data-testid="heap-free-list-corrupt">{t("freeLists.corrupt")}</span>}
          {list.decoded && <span className={`${badge} md-bg-info-subtle`}>{t("freeLists.decoded")}</span>}
          {list.unresolved_vas.length > 0 && (
            <span className="md-text-warning">{t("freeLists.unresolved", { count: list.unresolved_vas.length })}</span>
          )}
        </summary>
        <ol className="pl-4 font-mono">
          {shown.map((va, i) => (
            <li key={`${i}-${va}`}>
              <button type="button" className="hover:underline" onClick={() => onJump(va)} data-testid="heap-free-list-entry">
                {formatAddress(va)}
              </button>
            </li>
          ))}
          {hidden > 0 && <li className="font-sans md-text-muted">{t("freeLists.more", { count: hidden })}</li>}
        </ol>
      </details>
    </li>
  );
}
