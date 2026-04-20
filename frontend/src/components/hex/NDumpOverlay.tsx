/**
 * N-dump overlay hex viewer -- shows bytes from multiple dumps
 * with consensus classification coloring.
 */
import { useState, useMemo } from 'react';
import { byteToHex, offsetToHex } from '@/utils/hex-codec';

interface NDumpOverlayProps {
  dumpPaths: string[];
  dumpData: Map<string, Uint8Array>;
  classifications?: number[]; // 0=invariant, 1=structural, 2=pointer, 3=key_candidate
  pageSize?: number;
}

const CLASS_COLORS: Record<number, string> = {
  0: 'text-green-400',    // invariant
  1: 'text-blue-400',     // structural
  2: 'text-cyan-400',     // pointer
  3: 'text-red-400',      // key_candidate
};

const CLASS_BG: Record<number, string> = {
  0: 'bg-green-500/10',
  1: 'bg-blue-500/10',
  2: 'bg-cyan-500/10',
  3: 'bg-red-500/20',
};

export function NDumpOverlay({
  dumpPaths,
  dumpData,
  classifications,
  pageSize = 256,
}: NDumpOverlayProps) {
  const [page, setPage] = useState(0);
  const [visibleDumps, setVisibleDumps] = useState<Set<string>>(
    () => new Set(dumpPaths)
  );
  const [nSlider, setNSlider] = useState(dumpPaths.length);

  const activePaths = useMemo(
    () => dumpPaths.filter(p => visibleDumps.has(p)).slice(0, nSlider),
    [dumpPaths, visibleDumps, nSlider]
  );

  const offset = page * pageSize;
  const totalPages = useMemo(() => {
    const maxLen = Math.max(
      ...Array.from(dumpData.values()).map(d => d.length),
      0
    );
    return Math.ceil(maxLen / pageSize);
  }, [dumpData, pageSize]);

  const toggleDump = (path: string) => {
    setVisibleDumps(prev => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });
  };

  // Compute per-byte variance indicator across visible dumps
  const byteInfo = useMemo(() => {
    const info: Array<{ hex: string; cls: number; differs: boolean }> = [];
    for (let i = 0; i < pageSize; i++) {
      const byteOffset = offset + i;
      const values = activePaths
        .map(p => dumpData.get(p)?.[byteOffset])
        .filter((v): v is number => v !== undefined);

      const hex = values.length > 0 ? byteToHex(values[0]) : '--';
      const cls = classifications?.[byteOffset] ?? -1;
      const differs = new Set(values).size > 1;
      info.push({ hex, cls, differs });
    }
    return info;
  }, [activePaths, dumpData, offset, pageSize, classifications]);

  return (
    <div className="flex flex-col h-full">
      {/* Controls */}
      <div className="flex items-center gap-4 p-2 border-b border-zinc-700 text-xs">
        <span className="text-zinc-400">Dumps ({activePaths.length}/{dumpPaths.length}):</span>
        {dumpPaths.map(p => {
          const name = p.split('/').pop() ?? p;
          return (
            <label key={p} className="flex items-center gap-1 cursor-pointer">
              <input
                type="checkbox"
                checked={visibleDumps.has(p)}
                onChange={() => toggleDump(p)}
                className="w-3 h-3"
              />
              <span className={visibleDumps.has(p) ? 'text-zinc-300' : 'text-zinc-600'}>
                {name.length > 20 ? '...' + name.slice(-17) : name}
              </span>
            </label>
          );
        })}
        <div className="ml-auto flex items-center gap-2">
          <span className="text-zinc-400">N:</span>
          <input
            type="range"
            min={1}
            max={dumpPaths.length}
            value={nSlider}
            onChange={e => setNSlider(Number(e.target.value))}
            className="w-24"
          />
          <span className="text-zinc-300 w-6">{nSlider}</span>
        </div>
      </div>

      {/* Legend */}
      <div className="flex gap-3 px-2 py-1 text-xs border-b border-zinc-800">
        <span className="text-green-400">Invariant</span>
        <span className="text-blue-400">Structural</span>
        <span className="text-cyan-400">Pointer</span>
        <span className="text-red-400">Key Candidate</span>
        <span className="text-yellow-400">Differs</span>
      </div>

      {/* Hex grid */}
      <div className="flex-1 overflow-auto font-mono text-xs p-2">
        {Array.from({ length: Math.ceil(pageSize / 16) }, (_, row) => {
          const rowOffset = offset + row * 16;
          return (
            <div key={row} className="flex items-center gap-2 leading-5">
              <span className="text-zinc-500 w-16 text-right select-none">
                {offsetToHex(rowOffset)}
              </span>
              <div className="flex gap-0.5">
                {Array.from({ length: 16 }, (_, col) => {
                  const idx = row * 16 + col;
                  if (idx >= pageSize) return null;
                  const { hex, cls, differs } = byteInfo[idx];
                  const colorCls = cls >= 0 ? CLASS_COLORS[cls] : 'text-zinc-500';
                  const bgCls = cls >= 0 ? CLASS_BG[cls] : '';
                  return (
                    <span
                      key={col}
                      className={`w-5 text-center rounded-sm ${colorCls} ${bgCls} ${
                        differs ? 'ring-1 ring-yellow-500/50' : ''
                      }`}
                      title={`Offset 0x${(rowOffset + col).toString(16)} ${
                        differs ? '(varies across dumps)' : ''
                      }`}
                    >
                      {hex}
                    </span>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between p-2 border-t border-zinc-700 text-xs">
        <button
          onClick={() => setPage(p => Math.max(0, p - 1))}
          disabled={page === 0}
          className="px-2 py-1 bg-zinc-800 rounded disabled:opacity-30"
        >
          Prev
        </button>
        <span className="text-zinc-400">
          Page {page + 1} / {totalPages} (offset 0x{offset.toString(16)})
        </span>
        <button
          onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
          disabled={page >= totalPages - 1}
          className="px-2 py-1 bg-zinc-800 rounded disabled:opacity-30"
        >
          Next
        </button>
      </div>
    </div>
  );
}
