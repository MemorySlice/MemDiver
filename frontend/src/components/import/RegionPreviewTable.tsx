import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import type { RegionCategory, RegionInfo } from "@/api/types";
import { formatBytes } from "@/utils/format-bytes";
import { protectionString } from "./region-categories";

/** Rows rendered at most; a full process can carry tens of thousands. */
export const MAX_PREVIEW_ROWS = 500;

export interface RegionPreviewTableProps {
  regions: RegionInfo[];
  selected: readonly RegionCategory[];
}

/** Collapsible per-region table of a preview; rows outside the selection are dimmed. */
export function RegionPreviewTable({ regions, selected }: RegionPreviewTableProps) {
  const { t } = useTranslation("import");
  const [open, setOpen] = useState(false);
  const tableId = useId();
  const chosen = new Set(selected);
  const shown = regions.slice(0, MAX_PREVIEW_ROWS);

  return (
    <div className="space-y-1">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-controls={tableId}
        data-testid="region-table-toggle"
        className="text-sm md-text-secondary hover:md-text-primary transition-colors"
      >
        {open ? "▾" : "▸"}{" "}
        {open ? t("table.toggleHide") : t("table.toggleShow", { count: regions.length })}
      </button>
      {open && (
        <div id={tableId} className="max-h-64 overflow-auto border border-[var(--md-border)] rounded">
          <table className="w-full text-xs" data-testid="region-table">
            <caption className="sr-only">{t("table.caption")}</caption>
            <thead className="sticky top-0 bg-[var(--md-bg-secondary)]">
              <tr className="text-left">
                <th scope="col" className="px-2 py-1">{t("table.base")}</th>
                <th scope="col" className="px-2 py-1">{t("table.size")}</th>
                <th scope="col" className="px-2 py-1">{t("table.protection")}</th>
                <th scope="col" className="px-2 py-1">{t("table.category")}</th>
                <th scope="col" className="px-2 py-1">{t("table.name")}</th>
                <th scope="col" className="px-2 py-1">{t("table.module")}</th>
                <th scope="col" className="px-2 py-1">{t("table.included")}</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((r) => {
                const included = chosen.has(r.category);
                return (
                  <tr
                    key={`${r.base_addr}-${r.size}`}
                    data-included={included}
                    className={`border-t border-[var(--md-border)] ${included ? "" : "opacity-50"}`}
                  >
                    <td className="px-2 py-0.5 font-mono">0x{r.base_addr.toString(16)}</td>
                    <td className="px-2 py-0.5 whitespace-nowrap">{formatBytes(r.size)}</td>
                    <td className="px-2 py-0.5 font-mono">{protectionString(r.protection)}</td>
                    <td className="px-2 py-0.5">{t(`category.${r.category}.label`)}</td>
                    <td
                      className="px-2 py-0.5 font-mono"
                      title={r.name ?? undefined}
                      data-testid="region-table-name"
                    >
                      <span className="block max-w-[10rem] truncate whitespace-nowrap">
                        {r.name ?? t("table.nameUnknown")}
                      </span>
                    </td>
                    <td className="px-2 py-0.5 font-mono" title={r.module_path ?? undefined}>
                      <span className="block max-w-[8rem] truncate whitespace-nowrap">{r.module_path ?? ""}</span>
                    </td>
                    <td className="px-2 py-0.5">{included ? t("table.yes") : t("table.no")}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {regions.length > shown.length && (
            <p className="px-2 py-1 text-xs md-text-muted">
              {t("table.truncated", { shown: shown.length, count: regions.length })}
            </p>
          )}
        </div>
      )}
    </div>
  );
}
