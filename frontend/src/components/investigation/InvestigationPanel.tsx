import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { readHex, getEntropy } from "@/api/client";
import { useDumpStore } from "@/stores/dump-store";

interface Props {
  dumpPath: string;
  offset: number;
}

export function InvestigationPanel({ dumpPath, offset }: Props) {
  const { t } = useTranslation("investigation");
  const [byteVal, setByteVal] = useState<number | null>(null);
  const [entropy, setEntropy] = useState<number | null>(null);
  const [byteError, setByteError] = useState<string | null>(null);
  const [entropyError, setEntropyError] = useState<string | null>(null);
  const keyMaterial = useDumpStore((s) => s.getKeyMaterialByPath(dumpPath));

  useEffect(() => {
    setByteError(null);
    setEntropyError(null);
    setByteVal(null);
    setEntropy(null);

    readHex(dumpPath, offset, 1, keyMaterial).then((d) => {
      if (d.hex_lines.length > 0) {
        const hex = d.hex_lines[0].split(/\s+/)[1];
        if (hex) setByteVal(parseInt(hex, 16));
      }
    }).catch((e) => setByteError(e instanceof Error ? e.message : t("panel.readByteError")));

    getEntropy(dumpPath, Math.max(0, offset - 128), 256, keyMaterial).then((d) => {
      // Near EOF (or a locked keyed view) the 256-byte window can fall outside
      // the entropy-readable size, in which case the backend returns an error
      // envelope with no `overall_entropy`. Coerce to null so the panel hides
      // the entropy bar rather than rendering (undefined).toFixed() — which
      // throws and unmounts the whole hex viewer via the ErrorBoundary.
      setEntropy(typeof d.overall_entropy === "number" ? d.overall_entropy : null);
    }).catch((e) => setEntropyError(e instanceof Error ? e.message : t("panel.getEntropyError")));
  }, [dumpPath, offset, t, keyMaterial]);

  const entropyPct = entropy !== null ? (entropy / 8) * 100 : 0;
  const entropyColor = entropyPct > 90 ? "var(--md-accent-red)" : entropyPct > 70 ? "var(--md-accent-orange)" : "var(--md-accent-green)";

  return (
    <div className="p-3 space-y-3 text-xs">
      <h3 className="text-sm font-semibold md-text-accent">
        {t("panel.offsetTitle", { offset: offset.toString(16).padStart(8, "0") })}
      </h3>

      {byteError && <p className="text-xs" style={{ color: "var(--md-accent-red)" }}>{t("panel.bytePrefix", { message: byteError })}</p>}
      {entropyError && <p className="text-xs" style={{ color: "var(--md-accent-red)" }}>{t("panel.entropyPrefix", { message: entropyError })}</p>}

      {byteVal !== null && (
        <div className="md-panel p-2 space-y-1">
          <div className="md-text-secondary">{t("panel.byteValue")}</div>
          <div>{t("panel.hex")} <span className="hb-key">0x{byteVal.toString(16).padStart(2, "0")}</span></div>
          <div>{t("panel.dec")} {byteVal}</div>
          <div>{t("panel.ascii")} {byteVal >= 32 && byteVal < 127 ? String.fromCharCode(byteVal) : "."}</div>
        </div>
      )}

      {entropy !== null && (
        <div className="md-panel p-2 space-y-1">
          <div className="md-text-secondary">{t("panel.localEntropy")}</div>
          <div className="flex items-center gap-2">
            <div className="flex-1 h-2 rounded-full bg-[var(--md-bg-tertiary)]">
              <div className="h-full rounded-full" style={{ width: `${entropyPct}%`, background: entropyColor }} />
            </div>
            <span>{t("panel.bits", { value: entropy.toFixed(2) })}</span>
          </div>
        </div>
      )}
    </div>
  );
}
