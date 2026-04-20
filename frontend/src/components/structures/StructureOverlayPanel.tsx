import { useEffect, useRef } from "react";
import { useHexStore } from "@/stores/hex-store";

type Variant = "sidebar" | "detail";

interface Props {
  variant?: Variant;
}

export function StructureOverlayPanel({ variant = "detail" }: Props) {
  const overlay = useHexStore((s) => s.activeStructureOverlay);
  const clearOverlay = useHexStore((s) => s.setActiveStructureOverlay);
  const scrollToOffset = useHexStore((s) => s.scrollToOffset);
  const setActiveFieldOffset = useHexStore((s) => s.setActiveFieldOffset);
  const activeFieldOffset = useHexStore((s) => s.activeFieldOffset);
  const rowRefs = useRef<Map<number, HTMLTableRowElement>>(new Map());

  useEffect(() => {
    if (activeFieldOffset === null) return;
    const row = rowRefs.current.get(activeFieldOffset);
    if (row) {
      row.scrollIntoView({ block: "nearest", behavior: "smooth" });
    }
  }, [activeFieldOffset]);

  if (!overlay) return null;

  const handleRowClick = (offset: number) => {
    scrollToOffset(offset);
    setActiveFieldOffset(offset);
  };

  const header = (
    <div className="flex items-center justify-between gap-2">
      <div className="flex items-center gap-2 min-w-0">
        <h4 className="font-semibold md-text-accent truncate">
          {overlay.structureName}
        </h4>
        <span className="px-1.5 py-0.5 rounded bg-[var(--md-bg-hover)] font-mono text-[10px] md-text-secondary shrink-0">
          {overlay.fields.length} fields
        </span>
      </div>
      <button
        onClick={() => {
          clearOverlay(null);
          setActiveFieldOffset(null);
        }}
        className="px-1.5 py-0.5 text-[10px] rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] shrink-0"
      >
        Clear
      </button>
    </div>
  );

  const meta = (
    <div className="flex gap-3 text-[10px] md-text-muted">
      <span>Offset: 0x{overlay.baseOffset.toString(16)}</span>
      <span>Size: {overlay.totalSize}B</span>
    </div>
  );

  const table = (
    <table className="w-full text-[10px]">
      <thead>
        <tr className="md-text-muted sticky top-0 md-bg-secondary">
          <th className="text-left p-0.5">Field</th>
          <th className="text-left p-0.5">Offset</th>
          <th className="text-left p-0.5">Len</th>
          <th className="text-left p-0.5">Value</th>
          <th className="text-left p-0.5"></th>
        </tr>
      </thead>
      <tbody>
        {overlay.fields.map((f) => {
          const isActive = activeFieldOffset === f.offset;
          return (
            <tr
              key={`${f.offset}-${f.name}`}
              ref={(el) => {
                if (el) rowRefs.current.set(f.offset, el);
                else rowRefs.current.delete(f.offset);
              }}
              className={`cursor-pointer transition-colors ${
                isActive
                  ? "bg-[var(--md-accent-blue)] text-white"
                  : "hover:bg-[var(--md-bg-hover)]"
              }`}
              onClick={() => handleRowClick(f.offset)}
            >
              <td className="p-0.5 font-medium">{f.name}</td>
              <td className="p-0.5 font-mono">0x{f.offset.toString(16)}</td>
              <td className="p-0.5">{f.length}</td>
              <td
                className="p-0.5 font-mono truncate max-w-[160px]"
                title={f.display}
              >
                {f.display}
              </td>
              <td className="p-0.5">
                {f.valid ? (
                  <span
                    className={
                      isActive ? "text-white" : "text-[var(--md-accent-green)]"
                    }
                    title="Constraint passed"
                  >
                    ok
                  </span>
                ) : (
                  <span className="md-text-muted">--</span>
                )}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );

  if (variant === "sidebar") {
    return (
      <div
        data-tour-id="structure-overlay-panel"
        className="border-t border-[var(--md-border)] mt-2 pt-2 px-3 text-xs space-y-2"
      >
        {header}
        {meta}
        {table}
      </div>
    );
  }

  return (
    <div
      data-tour-id="structure-overlay-panel"
      className="h-full flex flex-col md-bg-secondary"
    >
      <div className="p-3 border-b border-[var(--md-border)] space-y-1">
        {header}
        {meta}
      </div>
      <div className="flex-1 overflow-auto px-3 pb-3">{table}</div>
    </div>
  );
}
