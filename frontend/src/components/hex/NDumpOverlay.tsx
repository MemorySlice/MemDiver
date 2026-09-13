/**
 * N-dump overlay hex viewer -- shows bytes from multiple dumps
 * with consensus classification coloring.
 */
import { useState, useMemo, type CSSProperties } from 'react';
import { useTranslation } from 'react-i18next';
import { VarianceSwatch } from '@/components/common/VarianceSwatch';
import { byteToHex, offsetToHex } from '@/utils/hex-codec';
import {
  VARIANCE_CATEGORIES,
  VARIANCE_META,
  varianceCategoryForCode,
} from '@/utils/variance-classes';

interface NDumpOverlayProps {
  dumpPaths: string[];
  dumpData: Map<string, Uint8Array>;
  classifications?: number[]; // 0=invariant, 1=structural, 2=pointer, 3=key_candidate
  pageSize?: number;
}

/**
 * Per-byte colouring, read from the shared `VARIANCE_META` map.
 *
 * This pane used to carry its own palette, and it was WRONG: it painted
 * invariant green and pointer cyan, while the hex grid paints STRUCTURAL green
 * -- so green meant two different things depending on which pane you were
 * looking at. Going through the map is what makes that class of drift
 * impossible.
 */
function byteStyle(code: number): CSSProperties {
  const category = varianceCategoryForCode(code);
  if (!category) return {};
  const { colorVar } = VARIANCE_META[category];
  // Invariant gets the same treatment `hex.css` gives it -- muted text over a
  // 35% tint of a token that is background-shaped and unreadable as text.
  const invariant = category === "invariant";
  return {
    color: invariant ? "var(--md-text-muted)" : colorVar,
    background: `color-mix(in srgb, ${colorVar} ${invariant ? 35 : 18}%, transparent)`,
  };
}

export function NDumpOverlay({
  dumpPaths,
  dumpData,
  classifications,
  pageSize = 256,
}: NDumpOverlayProps) {
  const { t } = useTranslation('hex');
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
      <div className="flex items-center gap-4 p-2 border-b border-[var(--md-border)] text-xs">
        <span className="md-text-secondary">{t("ndump.dumpsLabel", { active: activePaths.length, total: dumpPaths.length })}</span>
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
              <span className={visibleDumps.has(p) ? 'text-[var(--md-text-primary)]' : 'md-text-muted'}>
                {name.length > 20 ? '...' + name.slice(-17) : name}
              </span>
            </label>
          );
        })}
        <div className="ml-auto flex items-center gap-2">
          <span className="md-text-secondary">{t("ndump.nLabel")}</span>
          <input
            type="range"
            min={1}
            max={dumpPaths.length}
            value={nSlider}
            onChange={e => setNSlider(Number(e.target.value))}
            className="w-24"
          />
          <span className="text-[var(--md-text-primary)] w-6">{nSlider}</span>
        </div>
      </div>

      {/* Legend */}
      <div className="flex gap-3 px-2 py-1 text-xs border-b border-[var(--md-border)]">
        {/* In code order; `differs` is a ring rather than a class. */}
        {VARIANCE_CATEGORIES.map((category) => (
          <VarianceSwatch
            key={category}
            className="md-text-secondary"
            swatchClass={VARIANCE_META[category].swatchClass}
            label={t(VARIANCE_META[category].labelKey)}
          />
        ))}
      </div>

      {/* Hex grid */}
      <div className="flex-1 overflow-auto font-mono text-xs p-2">
        {Array.from({ length: Math.ceil(pageSize / 16) }, (_, row) => {
          const rowOffset = offset + row * 16;
          return (
            <div key={row} className="flex items-center gap-2 leading-5">
              <span className="md-text-muted w-16 text-right select-none">
                {offsetToHex(rowOffset)}
              </span>
              <div className="flex gap-0.5">
                {Array.from({ length: 16 }, (_, col) => {
                  const idx = row * 16 + col;
                  if (idx >= pageSize) return null;
                  const { hex, cls, differs } = byteInfo[idx];
                  const classified = varianceCategoryForCode(cls) !== null;
                  return (
                    <span
                      key={col}
                      className={`w-5 text-center rounded-sm ${
                        classified ? '' : 'md-text-muted'
                      } ${differs ? 'md-ring-differs' : ''}`}
                      style={byteStyle(cls)}
                      title={t("ndump.byteTitle", {
                        offset: (rowOffset + col).toString(16),
                        note: differs ? t("ndump.variesNote") : '',
                      })}
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
      <div className="flex items-center justify-between p-2 border-t border-[var(--md-border)] text-xs">
        <button
          onClick={() => setPage(p => Math.max(0, p - 1))}
          disabled={page === 0}
          className="px-2 py-1 bg-[var(--md-bg-tertiary)] rounded disabled:opacity-30"
        >
          {t("ndump.prev")}
        </button>
        <span className="md-text-secondary">
          {t("ndump.page", { current: page + 1, total: totalPages, offset: offset.toString(16) })}
        </span>
        <button
          onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
          disabled={page >= totalPages - 1}
          className="px-2 py-1 bg-[var(--md-bg-tertiary)] rounded disabled:opacity-30"
        >
          {t("ndump.next")}
        </button>
      </div>
    </div>
  );
}
