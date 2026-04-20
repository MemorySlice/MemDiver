import { memo, useMemo } from "react";
import { byteToHex, offsetToHex } from "@/utils/hex-codec";

interface LibraryPanel {
  name: string;
  data: Uint8Array;
}

interface Props {
  libraries: LibraryPanel[];
  secretType: string;
  /** Offset of the key region within each dump */
  keyOffset: number;
  /** Length of the key region */
  keyLength: number;
  /** Context bytes before/after key region */
  context?: number;
  bytesPerRow?: number;
}

function hexLine(
  data: Uint8Array,
  rowStart: number,
  rowEnd: number,
  baseOffset: number,
  keyStart: number,
  keyEnd: number,
  _bytesPerRow: number,
): string {
  const parts: string[] = [];
  const absStart = baseOffset + rowStart;
  parts.push(`<span class="md-text-muted">${offsetToHex(absStart)}</span>  `);

  for (let i = rowStart; i < rowEnd; i++) {
    const abs = baseOffset + i;
    const isKey = abs >= keyStart && abs < keyEnd;
    const b = data[i];
    const color = isKey
      ? "var(--md-accent-green, #4ec9b0)"
      : b === 0
        ? "var(--md-text-muted, #666)"
        : "inherit";
    parts.push(`<span style="color:${color};${isKey ? "font-weight:600;" : ""}">${byteToHex(b)}</span> `);
    if ((i - rowStart) === 7) parts.push(" ");
  }

  return parts.join("");
}

export const CrossLibraryHex = memo(function CrossLibraryHex({
  libraries,
  secretType,
  keyOffset,
  keyLength,
  context = 64,
  bytesPerRow = 16,
}: Props) {
  const panels = useMemo(() => {
    return libraries.map((lib) => {
      const start = Math.max(0, keyOffset - context);
      const end = Math.min(lib.data.length, keyOffset + keyLength + context);
      const region = lib.data.slice(start, end);
      const maxRows = 16;
      const lines: string[] = [];

      for (let row = 0; row < Math.min(region.length, maxRows * bytesPerRow); row += bytesPerRow) {
        const rowEnd = Math.min(row + bytesPerRow, region.length);
        lines.push(hexLine(region, row, rowEnd, start, keyOffset, keyOffset + keyLength, bytesPerRow));
      }

      return { name: lib.name, html: lines.join("\n") };
    });
  }, [libraries, keyOffset, keyLength, context, bytesPerRow]);

  if (!libraries.length) {
    return <p className="p-4 text-sm md-text-muted">No library data for comparison.</p>;
  }

  return (
    <div className="p-3 text-xs space-y-2">
      <h3 className="text-sm font-semibold md-text-accent">
        Cross-Library Comparison: {secretType}
      </h3>
      <div className="flex gap-3 overflow-x-auto">
        {panels.map((panel) => (
          <div key={panel.name} className="flex-1 min-w-[320px]">
            <div className="font-semibold mb-1" style={{ color: "var(--md-accent-blue)" }}>
              {panel.name}
            </div>
            <pre
              className="font-mono text-xs leading-relaxed rounded p-2 overflow-x-auto"
              style={{ background: "var(--md-bg-primary)" }}
              dangerouslySetInnerHTML={{ __html: panel.html }}
            />
          </div>
        ))}
      </div>
    </div>
  );
});
