import { useHexStore } from "@/stores/hex-store";

const TYPE_BADGE: Record<string, string> = {
  static: "bg-teal-600/20 text-teal-400 border-teal-600/40",
  key_material: "bg-red-600/20 text-red-400 border-red-600/40",
  dynamic: "bg-amber-600/20 text-amber-400 border-amber-600/40",
};

export function NeighborhoodOverlayPanel() {
  const overlay = useHexStore((s) => s.activeNeighborhoodOverlay);
  const clearOverlay = useHexStore((s) => s.setActiveNeighborhoodOverlay);
  const scrollToOffset = useHexStore((s) => s.scrollToOffset);

  if (!overlay) return null;

  const { hitOffset, hitSize, neighborhoodStart, variance, fields } = overlay;
  const windowEnd = neighborhoodStart + variance.length;

  const minVar = Math.min(...variance);
  const maxVar = Math.max(...variance);
  const meanVar = variance.reduce((a, b) => a + b, 0) / variance.length;

  const handleRowClick = (fieldOffset: number) => {
    scrollToOffset(neighborhoodStart + fieldOffset);
  };

  return (
    <div className="h-full flex flex-col md-bg-secondary">
      <div className="p-3 border-b border-[var(--md-border)] space-y-1">
        {/* Header */}
        <div className="flex items-center justify-between gap-2">
          <h4 className="font-semibold md-text-accent truncate font-mono">
            Neighborhood: 0x{hitOffset.toString(16)}
          </h4>
          <button
            onClick={() => clearOverlay(null)}
            className="px-1.5 py-0.5 text-[10px] rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] shrink-0"
          >
            Clear
          </button>
        </div>

        {/* Metadata */}
        <div className="flex gap-3 text-[10px] md-text-muted flex-wrap">
          <span>
            Window: 0x{neighborhoodStart.toString(16)}&ndash;0x
            {windowEnd.toString(16)} ({variance.length}B)
          </span>
          <span>Key: {hitSize}B</span>
        </div>
      </div>

      {/* Field table */}
      <div className="flex-1 overflow-auto px-3 pb-2">
        <table className="w-full text-[10px]">
          <thead>
            <tr className="md-text-muted sticky top-0 md-bg-secondary">
              <th className="text-left p-0.5">Label</th>
              <th className="text-left p-0.5">Offset</th>
              <th className="text-left p-0.5">Len</th>
              <th className="text-left p-0.5">Type</th>
              <th className="text-right p-0.5">Var</th>
            </tr>
          </thead>
          <tbody>
            {fields.map((f) => (
              <tr
                key={`${f.offset}-${f.label}`}
                className="cursor-pointer hover:bg-[var(--md-bg-hover)] transition-colors"
                onClick={() => handleRowClick(f.offset)}
              >
                <td className="p-0.5 font-medium truncate max-w-[100px]">
                  {f.label}
                </td>
                <td className="p-0.5 font-mono">0x{f.offset.toString(16)}</td>
                <td className="p-0.5">{f.length}</td>
                <td className="p-0.5">
                  <span
                    className={`inline-block px-1 py-px rounded border text-[9px] leading-tight ${TYPE_BADGE[f.type] ?? ""}`}
                  >
                    {f.type.replace("_", " ")}
                  </span>
                </td>
                <td className="p-0.5 font-mono text-right">
                  {f.mean_variance.toFixed(1)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {/* Variance summary */}
        <div className="mt-2 pt-1 border-t border-[var(--md-border)] text-[10px] md-text-muted flex gap-3">
          <span>min {minVar.toFixed(1)}</span>
          <span>max {maxVar.toFixed(1)}</span>
          <span>mean {meanVar.toFixed(1)}</span>
        </div>
      </div>
    </div>
  );
}
