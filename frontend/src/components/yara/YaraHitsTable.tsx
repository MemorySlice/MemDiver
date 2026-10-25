import { useTranslation } from "react-i18next";

import type { YaraHitRow } from "@/api/yara";
import { wireIntHex as hex } from "@/api/lossless-json";

/** The rule-hit table: one row per matched string instance, click to navigate. */
export function YaraHitsTable({ rows, active, onRowClick }: {
  rows: readonly YaraHitRow[];
  active: number | null;
  onRowClick: (index: number) => void;
}) {
  const { t } = useTranslation("yara");
  return (
    <div className="overflow-auto">
      <table className="w-full text-left" data-testid="yara-table">
        <thead className="md-text-secondary">
          <tr>
            {["rule", "string", "address", "length", "bytes"].map((c) => (
              <th key={c} scope="col" className="px-1 py-0.5 font-normal">{t(`col.${c}`)}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={`${row.rule}:${row.string_id}:${String(row.addr)}:${i}`} data-testid="yara-row"
              aria-selected={active === i} onClick={() => onRowClick(i)}
              className={`cursor-pointer hover:bg-[var(--md-bg-hover)] ${active === i ? "bg-[var(--md-bg-hover)]" : ""}`}>
              <td className="px-1 py-0.5">{row.rule}</td>
              <td className="px-1 py-0.5 font-mono">{row.string_id}</td>
              <td className="px-1 py-0.5 font-mono" title={row.space}>{hex(row.addr)}</td>
              <td className="px-1 py-0.5">{row.length}</td>
              <td className="px-1 py-0.5 font-mono" title={row.matched_hex}>
                {row.matched_hex.length > 16 ? `${row.matched_hex.slice(0, 16)}…` : row.matched_hex}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
