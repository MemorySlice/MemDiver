import { useTranslation } from "react-i18next";
import { useCursorInspection } from "@/hooks/useCursorInspection";
import { useHexStore } from "@/stores/hex-store";

interface Props {
  dumpPath: string;
  offset: number;
}

export function InvestigationPanel({ dumpPath, offset }: Props) {
  const { t } = useTranslation("investigation");
  const { view, byteVal, entropy, byteError, entropyError } = useCursorInspection(dumpPath, offset);
  const format = useHexStore((s) => s.format);
  const availableViews = useHexStore((s) => s.availableViews);
  const vaSpanStart = useHexStore((s) => s.vaSpanStart);
  const pageStatesLoaded = useHexStore((s) => s.pageStatesLoaded);
  // Same rule as HexStatusBar: name the view whenever the dump has several.
  const multiView = format === "msl" || availableViews.length > 1;
  const offsetHex = offset.toString(16).padStart(8, "0");
  // "va"-view offsets are relative to the VA span start; show the absolute
  // virtual address too once the span is known.
  const virtualAddress = view === "va" && pageStatesLoaded ? vaSpanStart + offset : null;

  const entropyPct = entropy !== null ? (entropy / 8) * 100 : 0;
  const entropyColor = entropyPct > 90 ? "var(--md-accent-red)" : entropyPct > 70 ? "var(--md-accent-orange)" : "var(--md-accent-green)";

  return (
    <div className="p-3 space-y-3 text-xs" data-testid="investigation-panel" data-view={view}>
      <h3 className="text-sm font-semibold md-text-accent">
        {multiView
          ? t("panel.viewOffsetTitle", { view: t(`panel.viewNames.${view}`), offset: offsetHex })
          : t("panel.offsetTitle", { offset: offsetHex })}
      </h3>
      {virtualAddress !== null && (
        <div className="md-text-secondary font-mono" data-testid="investigation-va">
          {t("panel.virtualAddress", { va: virtualAddress.toString(16) })}
        </div>
      )}

      {byteError && <p className="text-xs" style={{ color: "var(--md-accent-red)" }}>{t("panel.bytePrefix", { message: byteError })}</p>}
      {entropyError && <p className="text-xs" style={{ color: "var(--md-accent-red)" }}>{t("panel.entropyPrefix", { message: entropyError })}</p>}

      {byteVal !== null && (
        <div className="md-panel p-2 space-y-1">
          <div className="md-text-secondary">{t("panel.byteValue")}</div>
          <div>{t("panel.hex")} <span className="hb-key" data-testid="investigation-byte-hex">0x{byteVal.toString(16).padStart(2, "0")}</span></div>
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
