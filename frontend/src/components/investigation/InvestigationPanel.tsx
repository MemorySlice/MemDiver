import { useEffect, useState } from "react";
import { readHex, getEntropy } from "@/api/client";

interface Props {
  dumpPath: string;
  offset: number;
}

export function InvestigationPanel({ dumpPath, offset }: Props) {
  const [byteVal, setByteVal] = useState<number | null>(null);
  const [entropy, setEntropy] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setError(null);
    setByteVal(null);
    setEntropy(null);

    readHex(dumpPath, offset, 1).then((d) => {
      if (d.hex_lines.length > 0) {
        const hex = d.hex_lines[0].split(/\s+/)[1];
        if (hex) setByteVal(parseInt(hex, 16));
      }
    }).catch((e) => setError(e instanceof Error ? e.message : "Failed to read byte"));

    getEntropy(dumpPath, Math.max(0, offset - 128), 256).then((d) => {
      setEntropy(d.overall_entropy);
    }).catch((e) => setError(e instanceof Error ? e.message : "Failed to get entropy"));
  }, [dumpPath, offset]);

  const entropyPct = entropy !== null ? (entropy / 8) * 100 : 0;
  const entropyColor = entropyPct > 90 ? "var(--md-accent-red)" : entropyPct > 70 ? "var(--md-accent-orange)" : "var(--md-accent-green)";

  return (
    <div className="p-3 space-y-3 text-xs">
      <h3 className="text-sm font-semibold md-text-accent">
        Offset 0x{offset.toString(16).padStart(8, "0")}
      </h3>

      {error && <p className="text-xs" style={{ color: "var(--md-accent-red)" }}>{error}</p>}

      {byteVal !== null && (
        <div className="md-panel p-2 space-y-1">
          <div className="md-text-secondary">Byte Value</div>
          <div>Hex: <span className="hb-key">0x{byteVal.toString(16).padStart(2, "0")}</span></div>
          <div>Dec: {byteVal}</div>
          <div>ASCII: {byteVal >= 32 && byteVal < 127 ? String.fromCharCode(byteVal) : "."}</div>
        </div>
      )}

      {entropy !== null && (
        <div className="md-panel p-2 space-y-1">
          <div className="md-text-secondary">Local Entropy</div>
          <div className="flex items-center gap-2">
            <div className="flex-1 h-2 rounded-full bg-[var(--md-bg-tertiary)]">
              <div className="h-full rounded-full" style={{ width: `${entropyPct}%`, background: entropyColor }} />
            </div>
            <span>{entropy.toFixed(2)} bits</span>
          </div>
        </div>
      )}
    </div>
  );
}
