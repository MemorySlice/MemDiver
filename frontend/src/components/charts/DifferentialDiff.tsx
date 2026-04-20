import { memo, useMemo } from "react";
import { byteToHex, offsetToHex } from "@/utils/hex-codec";

interface Props {
  dumpA: Uint8Array;
  dumpB: Uint8Array;
  labelA?: string;
  labelB?: string;
  maxRows?: number;
  bytesPerRow?: number;
}

function byteColor(a: number, b: number, isDumpB: boolean): string {
  if (a !== b) return isDumpB ? "var(--md-accent-green, #4ec9b0)" : "var(--md-accent-red, #f44747)";
  if (a === 0) return "var(--md-text-muted, #666)";
  return "inherit";
}

export const DifferentialDiff = memo(function DifferentialDiff({
  dumpA,
  dumpB,
  labelA = "Dump A",
  labelB = "Dump B",
  maxRows = 64,
  bytesPerRow = 16,
}: Props) {
  const { lines, diffCount, compareLen } = useMemo(() => {
    const len = Math.min(dumpA.length, dumpB.length);
    const maxBytes = maxRows * bytesPerRow;
    let diffs = 0;
    const result: string[] = [];

    for (let row = 0; row < Math.min(len, maxBytes); row += bytesPerRow) {
      const end = Math.min(row + bytesPerRow, len);
      const parts: string[] = [];

      // Offset
      parts.push(`<span class="md-text-muted">${offsetToHex(row)}</span>  `);

      // Dump A bytes
      for (let i = row; i < end; i++) {
        const a = dumpA[i], b = dumpB[i];
        if (a !== b) diffs++;
        const c = byteColor(a, b, false);
        parts.push(`<span style="color:${c}">${byteToHex(a)}</span> `);
        if (i - row === 7) parts.push(" ");
      }

      parts.push(" | ");

      // Dump B bytes
      for (let i = row; i < end; i++) {
        const a = dumpA[i], b = dumpB[i];
        const c = byteColor(a, b, true);
        parts.push(`<span style="color:${c}">${byteToHex(b)}</span> `);
        if (i - row === 7) parts.push(" ");
      }

      result.push(parts.join(""));
    }

    return { lines: result, diffCount: diffs, compareLen: len };
  }, [dumpA, dumpB, maxRows, bytesPerRow]);

  if (!dumpA.length || !dumpB.length) {
    return <p className="p-4 text-sm md-text-muted">Need two dumps for differential comparison.</p>;
  }

  const pct = compareLen > 0 ? ((diffCount / compareLen) * 100).toFixed(1) : "0";

  return (
    <div className="p-3 text-xs space-y-2">
      <h3 className="text-sm font-semibold md-text-accent">Differential Diff</h3>
      <p className="md-text-muted text-[10px]">
        {labelA} vs {labelB} | {diffCount} bytes differ ({pct}%) | {compareLen} bytes compared
      </p>
      <pre
        className="font-mono text-xs leading-relaxed rounded p-3 overflow-x-auto"
        style={{ background: "var(--md-bg-primary)" }}
        dangerouslySetInnerHTML={{ __html: lines.join("\n") }}
      />
    </div>
  );
});
