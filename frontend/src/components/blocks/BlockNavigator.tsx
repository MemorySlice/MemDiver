import { useEffect, useState } from "react";

interface BlockEntry {
  label: string;
  block_type: number;
  offset: number;
  size: number;
  detail: string;
}

interface BlockGroup {
  category: string;
  blocks: BlockEntry[];
}

interface Props {
  mslPath: string;
  onBlockClick?: (offset: number) => void;
}

export function BlockNavigator({ mslPath, onBlockClick }: Props) {
  const [groups, setGroups] = useState<BlockGroup[]>([]);
  const [totalBlocks, setTotalBlocks] = useState(0);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!mslPath) return;
    setError(null);
    fetch(`/api/inspect/blocks?msl_path=${encodeURIComponent(mslPath)}`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((data: BlockGroup[]) => {
        setGroups(data);
        setTotalBlocks(data.reduce((s, g) => s + g.blocks.length, 0));
      })
      .catch((e) => setError(String(e)));
  }, [mslPath]);

  const toggle = (cat: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(cat) ? next.delete(cat) : next.add(cat);
      return next;
    });
  };

  if (error) return <p className="p-3 text-xs text-red-500">{error}</p>;

  return (
    <div className="p-3 text-xs space-y-2">
      <h3 className="text-sm font-semibold md-text-accent">MSL Blocks</h3>
      <p className="md-text-muted">{totalBlocks} blocks total</p>
      {groups.map((g) => (
        <div key={g.category}>
          <button
            onClick={() => toggle(g.category)}
            className="flex items-center gap-1 w-full text-left py-1 hover:bg-[var(--md-bg-hover)] rounded px-1"
          >
            <span className="md-text-secondary">
              {expanded.has(g.category) ? "\u25BC" : "\u25B6"}
            </span>
            <span className="font-medium">{g.category}</span>
            <span className="ml-auto text-[10px] md-text-muted">
              {g.blocks.length}
            </span>
          </button>
          {expanded.has(g.category) && (
            <div className="ml-4 border-l border-[var(--md-border)] pl-2 space-y-0.5">
              {g.blocks.map((b, i) => (
                <button
                  key={i}
                  onClick={() => onBlockClick?.(b.offset)}
                  className="block w-full text-left py-0.5 md-text-secondary hover:bg-[var(--md-bg-hover)] rounded px-1 cursor-pointer"
                >
                  <span className="font-mono">{b.label}</span>
                  <span className="ml-2 md-text-muted">
                    0x{b.offset.toString(16)} ({b.size}B)
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
