import { useTranslation } from "react-i18next";

import type { KeyHitRow } from "@/api/keyfinders";
import { wireIntHex as hex } from "@/api/lossless-json";

const KEY_PREVIEW_CHARS = 16;
const smallButton =
  "px-1.5 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40";

async function copyText(text: string) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // Clipboard unavailable (insecure context / denied): the full key stays in the tooltip.
  }
}

function heapText(row: KeyHitRow, t: (k: string, o?: Record<string, unknown>) => string): string {
  if (!row.heap) return "—";
  const role = t(`heap.role.${row.heap.role}`, { defaultValue: row.heap.role });
  const span = row.heap.spans_chunks ? ` ${t("heap.spans")}` : "";
  return `${role} · ${hex(row.heap.chunk_va)} (${row.heap.chunk_size} B)${span}`;
}

/** The finder-hit table: one row per hit, click to navigate, button to verify. */
export function KeyHitsTable({ rows, active, onRowClick, onVerify }: {
  rows: readonly KeyHitRow[];
  active: number | null;
  onRowClick: (index: number) => void;
  onVerify: (index: number) => void;
}) {
  const { t } = useTranslation("keyfinders");
  return (
    <div className="overflow-auto">
      <table className="w-full text-left" data-testid="keyfinders-table">
        <thead className="md-text-secondary">
          <tr>
            {["finder", "label", "address", "length", "confidence", "key", "heap", "region", "actions"].map((c) => (
              <th key={c} scope="col" className="px-1 py-0.5 font-normal">{t(`col.${c}`)}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => {
            const keyHex = typeof row.metadata.key_hex === "string" ? row.metadata.key_hex : null;
            return (
              <tr key={`${row.finder}:${String(row.addr)}:${i}`} data-testid="keyfinders-row"
                aria-selected={active === i} onClick={() => onRowClick(i)}
                className={`cursor-pointer hover:bg-[var(--md-bg-hover)] ${active === i ? "bg-[var(--md-bg-hover)]" : ""}`}>
                <td className="px-1 py-0.5">{t(`finders.${row.finder}.label`, { defaultValue: row.finder })}</td>
                <td className="px-1 py-0.5">{row.label}</td>
                <td className="px-1 py-0.5 font-mono" title={row.space}>{hex(row.addr)}</td>
                <td className="px-1 py-0.5">{row.length}</td>
                <td className="px-1 py-0.5">{row.confidence.toFixed(2)}</td>
                <td className="px-1 py-0.5 font-mono" data-testid="keyfinders-key">
                  {keyHex ? (
                    <span className="inline-flex items-center gap-1">
                      <span title={keyHex}>
                        {keyHex.length > KEY_PREVIEW_CHARS ? `${keyHex.slice(0, KEY_PREVIEW_CHARS)}…` : keyHex}
                      </span>
                      <button type="button" className={smallButton} data-testid="keyfinders-copy"
                        aria-label={t("row.copyAria", { addr: hex(row.addr) })}
                        onClick={(e) => { e.stopPropagation(); void copyText(keyHex); }}>{t("row.copy")}</button>
                    </span>
                  ) : "—"}
                </td>
                <td className="px-1 py-0.5" data-testid="keyfinders-heap">{heapText(row, t)}</td>
                <td className="px-1 py-0.5 font-mono" data-testid="keyfinders-region">{row.region?.perms ?? "—"}</td>
                <td className="px-1 py-0.5">
                  <button type="button" className={smallButton} data-testid="keyfinders-verify"
                    aria-label={t("row.verifyAria", { addr: hex(row.addr) })}
                    onClick={(e) => { e.stopPropagation(); onVerify(i); }}>{t("row.verify")}</button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
