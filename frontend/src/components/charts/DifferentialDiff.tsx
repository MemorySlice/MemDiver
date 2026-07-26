import { memo, useMemo } from "react";
import { useTranslation } from "react-i18next";
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
  if (a !== b) return isDumpB ? "var(--md-accent-green)" : "var(--md-accent-red)";
  if (a === 0) return "var(--md-text-muted)";
  return "inherit";
}

export const DifferentialDiff = memo(function DifferentialDiff({
  dumpA,
  dumpB,
  labelA,
  labelB,
  maxRows = 64,
  bytesPerRow = 16,
}: Props) {
  const { t } = useTranslation("charts");
  const resolvedLabelA = labelA ?? t("differential.labelA");
  const resolvedLabelB = labelB ?? t("differential.labelB");
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
    return <p className="p-4 text-sm md-text-muted">{t("differential.empty")}</p>;
  }

  const pct = compareLen > 0 ? ((diffCount / compareLen) * 100).toFixed(1) : "0";

  return (
    <div className="p-3 text-xs space-y-2">
      <h3 className="text-sm font-semibold md-text-accent">{t("differential.title")}</h3>
      <p className="md-text-muted text-[10px]">
        {t("differential.summary", { labelA: resolvedLabelA, labelB: resolvedLabelB, diffCount, pct, compareLen })}
      </p>
      <pre
        className="font-mono text-xs leading-relaxed rounded p-3 overflow-x-auto"
        style={{ background: "var(--md-bg-primary)" }}
        dangerouslySetInnerHTML={{ __html: lines.join("\n") }}
      />
    </div>
  );
});
