import { memo, useMemo } from "react";

const MAX_MARKERS = 500;

interface Props {
  fileSize: number;
  offsets: number[];
  currentOffset: number;
  height?: number;
  onClickOffset: (offset: number) => void;
}

export const SearchMinimap = memo(function SearchMinimap({
  fileSize, offsets, currentOffset, height = 300, onClickOffset,
}: Props) {
  if (!offsets.length || !fileSize) return null;

  const displayOffsets = useMemo(() => {
    if (offsets.length <= MAX_MARKERS) return offsets;
    const step = offsets.length / MAX_MARKERS;
    const sampled: number[] = [];
    for (let i = 0; i < MAX_MARKERS; i++) {
      sampled.push(offsets[Math.floor(i * step)]);
    }
    return sampled;
  }, [offsets]);

  const handleClick = (e: React.MouseEvent<HTMLDivElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const pct = (e.clientY - rect.top) / rect.height;
    const targetOffset = Math.floor(pct * fileSize);
    onClickOffset(targetOffset);
  };

  const viewPct = (currentOffset / fileSize) * 100;

  return (
    <div
      className="relative border border-[var(--md-border)] rounded cursor-pointer"
      style={{ width: 20, height, background: "var(--md-bg-tertiary)" }}
      onClick={handleClick}
      title={`${offsets.length} results${offsets.length > MAX_MARKERS ? ` (showing ${MAX_MARKERS})` : ""}`}
    >
      {displayOffsets.map((off) => (
        <div
          key={off}
          className="absolute w-full"
          style={{
            top: `${(off / fileSize) * 100}%`,
            height: 2,
            background: "var(--md-search-hit)",
          }}
        />
      ))}
      <div
        className="absolute w-full opacity-50"
        style={{
          top: `${viewPct}%`,
          height: 4,
          background: "var(--md-accent-blue)",
        }}
      />
    </div>
  );
});
