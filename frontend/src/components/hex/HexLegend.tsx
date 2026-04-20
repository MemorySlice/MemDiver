import { useMemo, useState } from "react";
import { useHexStore } from "@/stores/hex-store";
import { HIGHLIGHT_META } from "@/utils/highlight-types";
import type { HighlightType } from "@/utils/highlight-types";

export function HexLegend() {
  const regions = useHexStore((s) => s.highlightedRegions);
  const [collapsed, setCollapsed] = useState(false);

  const activeTypes = useMemo(() => {
    const counts = new Map<string, number>();
    for (const r of regions) {
      counts.set(r.type, (counts.get(r.type) ?? 0) + 1);
    }
    return counts;
  }, [regions]);

  if (activeTypes.size === 0) return null;

  return (
    <div className="flex items-center gap-1 px-2 py-0.5 border-b border-[var(--md-border)] text-[10px] md-text-secondary">
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="hover:bg-[var(--md-bg-hover)] rounded px-0.5"
        title={collapsed ? "Show legend" : "Hide legend"}
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
        </div>
      )}
    </div>
  );
}
