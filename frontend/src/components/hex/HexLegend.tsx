import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { useHexStore } from "@/stores/hex-store";
import { HIGHLIGHT_META } from "@/utils/highlight-types";
import type { HighlightType } from "@/utils/highlight-types";
import { selectHeapLayerEnabled, useHeapStore } from "@/stores/heap-store";
import { PAGE_STATE_ABSENCES } from "@/utils/absence-classes";
import { usePageStateTintsActive } from "@/hooks/usePageStateTintsActive";
import { kindSlot } from "./highlight-utils";
import { QUERY_HIGHLIGHT_PLUGIN } from "@/components/vol3/vol3-highlights";
import { HeapLegend } from "./HeapLegend";
import { AbsenceLegend } from "./AbsenceLegend";

const VOL3_PREFIX = "vol3:";
const isVol3Kind = (kind: string | undefined) => kind?.startsWith(VOL3_PREFIX) ?? false;
const KEY_HIT_KIND = "key_hit";
const YARA_HIT_KIND = "yara_hit";

export function HexLegend() {
  const { t } = useTranslation("hex");
  const regions = useHexStore((s) => s.highlightedRegions);
  const dumpPath = useHexStore((s) => s.dumpPath);
  const heapLayerOn = useHeapStore(selectHeapLayerEnabled(dumpPath));
  const [collapsed, setCollapsed] = useState(false);
  // The single-dump grid tints FAILED / UNMAPPED / NOT_RESIDENT bytes in the
  // "va" view; without these entries those tints were a private notation.
  const pageStateTintsActive = usePageStateTintsActive();

  const activeTypes = useMemo(() => {
    const counts = new Map<string, number>();
    for (const r of regions) {
      if (isVol3Kind(r.kind) || r.kind === KEY_HIT_KIND || r.kind === YARA_HIT_KIND) continue;
      counts.set(r.type, (counts.get(r.type) ?? 0) + 1);
    }
    return counts;
  }, [regions]);

  // Vol3 rows paint their own palette slot, so they get their own entries
  // (one per plugin) instead of being counted as "Pattern Match".
  const vol3Kinds = useMemo(() => {
    const counts = new Map<string, number>();
    for (const r of regions) {
      if (r.kind && isVol3Kind(r.kind)) counts.set(r.kind, (counts.get(r.kind) ?? 0) + 1);
    }
    return counts;
  }, [regions]);

  const keyHitCount = useMemo(() => regions.filter((r) => r.kind === KEY_HIT_KIND).length, [regions]);
  const yaraHitCount = useMemo(() => regions.filter((r) => r.kind === YARA_HIT_KIND).length, [regions]);

  if (activeTypes.size === 0 && vol3Kinds.size === 0 && keyHitCount === 0 && yaraHitCount === 0 && !heapLayerOn && !pageStateTintsActive) return null;

  return (
    <div className="flex items-center gap-1 px-2 py-0.5 border-b border-[var(--md-border)] text-[10px] md-text-secondary">
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="hover:bg-[var(--md-bg-hover)] rounded px-0.5"
        title={collapsed ? t("legend.show") : t("legend.hide")}
      >
        {collapsed ? "\u25B6" : "\u25BC"}
      </button>
      {!collapsed && (
        <div className="flex items-center gap-2 flex-wrap">
          {Array.from(activeTypes.entries()).map(([type, count]) => {
            const meta = HIGHLIGHT_META[type as HighlightType];
            if (!meta) return null;
            return (
              <span key={type} className="flex items-center gap-1">
                <span
                  className={`inline-block w-3 h-3 rounded-sm highlight-${type}`}
                  style={{ background: `var(--md-hl-${type})` }}
                />
                <span>{meta.label}</span>
                <span className="md-text-muted">({count})</span>
              </span>
            );
          })}
          {Array.from(vol3Kinds.entries()).map(([kind, count]) => {
            const plugin = kind.slice(VOL3_PREFIX.length);
            return (
              <span key={kind} data-testid="hex-legend-vol3" className="flex items-center gap-1">
                <span
                  className={`inline-block w-3 h-3 rounded-sm highlight-kind-${kindSlot(kind)}`}
                  style={{ background: `var(--md-hl-kind-${kindSlot(kind)})` }}
                />
                <span>
                  {plugin === QUERY_HIGHLIGHT_PLUGIN
                    ? t("legend.vol3Query")
                    : t("legend.vol3Rows", { plugin })}
                </span>
                <span className="md-text-muted">({count})</span>
              </span>
            );
          })}
          {keyHitCount > 0 && (
            <span data-testid="hex-legend-key-hit" className="flex items-center gap-1">
              <span
                className={`inline-block w-3 h-3 rounded-sm highlight-kind-${kindSlot(KEY_HIT_KIND)}`}
                style={{ background: `var(--md-hl-kind-${kindSlot(KEY_HIT_KIND)})` }}
              />
              <span>{t("legend.keyHit")}</span>
              <span className="md-text-muted">({keyHitCount})</span>
            </span>
          )}
          {yaraHitCount > 0 && (
            <span data-testid="hex-legend-yara-hit" className="flex items-center gap-1">
              <span
                className={`inline-block w-3 h-3 rounded-sm highlight-kind-${kindSlot(YARA_HIT_KIND)}`}
                style={{ background: `var(--md-hl-kind-${kindSlot(YARA_HIT_KIND)})` }}
              />
              <span>{t("legend.yaraHit")}</span>
              <span className="md-text-muted">({yaraHitCount})</span>
            </span>
          )}
          {heapLayerOn && dumpPath && <HeapLegend dumpPath={dumpPath} />}
          {pageStateTintsActive && (
            <span data-testid="hex-page-state-legend" className="flex items-center gap-2">
              <AbsenceLegend pageStates kinds={PAGE_STATE_ABSENCES} />
            </span>
          )}
        </div>
      )}
    </div>
  );
}
