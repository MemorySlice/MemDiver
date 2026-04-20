import { useCallback, useEffect, useRef, useState } from "react";
import { readHex } from "@/api/client";
import type { HexData } from "@/api/types";

interface Props {
  pathA: string;
  pathB: string;
  labelA?: string;
  labelB?: string;
}

const PAGE_SIZE = 1024;

export function HexComparison({ pathA, pathB, labelA = "Dump A", labelB = "Dump B" }: Props) {
  const [dataA, setDataA] = useState<HexData | null>(null);
  const [dataB, setDataB] = useState<HexData | null>(null);
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const scrollRefA = useRef<HTMLDivElement>(null);
  const scrollRefB = useRef<HTMLDivElement>(null);
  const isScrolling = useRef(false);

  const fetchBoth = useCallback(async (off: number) => {
    try {
      setError(null);
      const [a, b] = await Promise.all([readHex(pathA, off, PAGE_SIZE), readHex(pathB, off, PAGE_SIZE)]);
      setDataA(a);
      setDataB(b);
      setOffset(off);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load comparison data");
    }
  }, [pathA, pathB]);

  useEffect(() => { fetchBoth(0); }, [fetchBoth]);

  const syncScroll = (source: "a" | "b") => {
    if (isScrolling.current) return;
    isScrolling.current = true;
    const from = source === "a" ? scrollRefA.current : scrollRefB.current;
    const to = source === "a" ? scrollRefB.current : scrollRefA.current;
    if (from && to) to.scrollTop = from.scrollTop;
    requestAnimationFrame(() => { isScrolling.current = false; });
  };

  if (error) return <p className="p-4 text-sm" style={{ color: "var(--md-accent-red)" }}>{error}</p>;
  if (!dataA || !dataB) return <p className="md-text-muted p-4 text-sm">Loading comparison...</p>;

  const maxSize = Math.min(dataA.file_size, dataB.file_size);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-2 px-2 py-1 border-b border-[var(--md-border)] text-xs">
        <button onClick={() => fetchBoth(Math.max(0, offset - PAGE_SIZE))} disabled={offset === 0}
          className="px-2 py-0.5 rounded border border-[var(--md-border)] disabled:opacity-30 hover:bg-[var(--md-bg-hover)]">Prev</button>
        <span className="md-text-secondary">Offset: 0x{offset.toString(16)}</span>
        <button onClick={() => fetchBoth(Math.min(maxSize - PAGE_SIZE, offset + PAGE_SIZE))}
          className="px-2 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]">Next</button>
      </div>
      <div className="flex flex-1 min-h-0">
        <div className="flex-1 flex flex-col border-r border-[var(--md-border)]">
          <div className="px-2 py-1 text-xs font-medium md-text-accent border-b border-[var(--md-border)]">{labelA}</div>
          <div ref={scrollRefA} onScroll={() => syncScroll("a")} className="flex-1 overflow-auto font-mono text-xs leading-5 p-1">
            {dataA.hex_lines.map((line, i) => <div key={i} className="whitespace-pre px-1">{line}</div>)}
          </div>
        </div>
        <div className="flex-1 flex flex-col">
          <div className="px-2 py-1 text-xs font-medium md-text-accent border-b border-[var(--md-border)]">{labelB}</div>
          <div ref={scrollRefB} onScroll={() => syncScroll("b")} className="flex-1 overflow-auto font-mono text-xs leading-5 p-1">
            {dataB.hex_lines.map((line, i) => <div key={i} className="whitespace-pre px-1">{line}</div>)}
          </div>
        </div>
      </div>
    </div>
  );
}
