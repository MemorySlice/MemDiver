/**
 * Details of the chunk selected in the heap panel: the common header fields,
 * then the allocator's own (`extra`) fields — ptmalloc prev_size/flags,
 * scudo class_id/state/checksum, mallocng slot_idx/meta_va, …, with any other
 * key listed generically.
 */

import { useTranslation } from "react-i18next";
import { useShallow } from "zustand/react/shallow";

import { selectHeapDump, useHeapStore } from "@/stores/heap-store";
import { decodeChunkFlags, orderedExtraFields } from "./chunk-fields";
import { confidencePercent, formatAddress, formatFieldValue, formatFlags } from "./heap-format";
import { jumpHexToViewOffset } from "./heap-navigation";

interface Props {
  dumpPath: string;
}

export function HeapChunkInspector({ dumpPath }: Props) {
  const { t } = useTranslation("heap");
  const { chunk, allocator } = useHeapStore(
    useShallow((s) => {
      const e = selectHeapDump(dumpPath)(s);
      return { chunk: e.selectedChunk, allocator: e.summary?.allocator ?? e.detection?.best ?? null };
    }),
  );

  if (!chunk) {
    return <p className="p-2 text-xs md-text-muted" data-testid="heap-inspector-empty">{t("inspector.empty")}</p>;
  }

  const flags = formatFlags(decodeChunkFlags(allocator, chunk.flags));
  const extra = orderedExtraFields(allocator, chunk);
  const row = (label: string, value: string, testId?: string) => (
    <>
      <dt className="md-text-muted">{label}</dt>
      <dd className="font-mono break-all" data-testid={testId}>{value}</dd>
    </>
  );

  return (
    <div className="p-2 text-xs space-y-2" data-testid="heap-inspector">
      <h4 className="font-semibold md-text-secondary">{t("panels.inspector")}</h4>
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5">
        {row(t("chunks.columns.va"), formatAddress(chunk.va), "heap-inspector-va")}
        {row(t("chunks.columns.offset"), formatAddress(chunk.view_offset))}
        {row(t("chunks.columns.size"), chunk.size.toLocaleString())}
        {row(t("chunks.columns.state"), t(`states.${chunk.state}`))}
        {row(t("inspector.headerLength"), String(chunk.header_len))}
        {row(
          t("inspector.userRange"),
          `${formatAddress(chunk.user_va)} +${chunk.user_len.toLocaleString()}`,
        )}
        {flags && row(t("inspector.flags"), flags, "heap-inspector-flags")}
        {chunk.bin !== null && chunk.bin !== "" && row(t("inspector.bin"), String(chunk.bin))}
        {row(t("chunks.columns.confidence"), `${confidencePercent(chunk.confidence)}%`)}
      </dl>
      {extra.length > 0 && (
        <section>
          <h5 className="font-semibold md-text-muted mb-0.5">{t("inspector.extra")}</h5>
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5" data-testid="heap-inspector-extra">
            {extra.map(([key, value]) => (
              <div key={key} className="contents" data-field={key}>
                <dt className="font-mono md-text-muted">{key}</dt>
                <dd className="font-mono break-all">{formatFieldValue(key, value)}</dd>
              </div>
            ))}
          </dl>
        </section>
      )}
      {chunk.view_offset !== null && (
        <button
          type="button"
          onClick={() => jumpHexToViewOffset(chunk.view_offset)}
          className="px-1.5 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]"
        >
          {t("chunks.jumpTo")}
        </button>
      )}
    </div>
  );
}
