import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { useHexStore } from "@/stores/hex-store";
import { useDumpStore } from "@/stores/dump-store";
import {
  checkStatic,
  generatePattern,
  exportPattern,
  autoExport,
  type CheckStaticResult,
  type PatternGenResult,
} from "@/api/client";
import type { AutoExportResult } from "@/api/types";
import { EmptyState } from "@/components/common/EmptyState";
import { ArchitectIcon } from "@/components/common/Icons";

const BTN = "px-2 py-1 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] text-xs";
const BTN_ACCENT = "px-2 py-1 rounded text-xs bg-[var(--md-accent-blue)] md-text-on-accent";
const INPUT = "w-full px-1.5 py-1 rounded border border-[var(--md-border)] bg-[var(--md-bg-primary)] text-[10px] font-mono";

type ArchitectMode = "manual" | "auto";
type ExportFormat = "yara" | "json" | "volatility3";

export function ArchitectPlaceholder() {
  const { t } = useTranslation("misc");
  const selection = useHexStore((s) => s.selection);
  const dumps = useDumpStore((s) => s.dumps);
  const dumpPaths = useMemo(() => dumps.map((d) => d.path), [dumps]);

  const [mode, setMode] = useState<ArchitectMode>("manual");
  const [step, setStep] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [staticResult, setStaticResult] = useState<CheckStaticResult | null>(null);
  const [patternResult, setPatternResult] = useState<PatternGenResult | null>(null);
  const [patternName, setPatternName] = useState("memdiver_pattern");
  const [exportFormat, setExportFormat] = useState<ExportFormat>("yara");
  const [exportOutput, setExportOutput] = useState<string | null>(null);

  const [autoAlign, setAutoAlign] = useState(true);
  const [autoContext, setAutoContext] = useState(32);
  const [autoResult, setAutoResult] = useState<AutoExportResult | null>(null);

  const selStart = selection ? Math.min(selection.anchor, selection.active) : 0;
  const selLen = selection ? Math.abs(selection.active - selection.anchor) + 1 : 0;
  const hasSelection = selection !== null && selLen > 0;
  const hasDumps = dumpPaths.length >= 2;

  async function runStaticCheck() {
    if (!hasSelection) return;
    setLoading(true);
    setError(null);
    // Clear stale downstream results so Step 2/3 don't show the previous
    // region's pattern/exported signature (which the user could copy/download).
    setPatternResult(null);
    setExportOutput(null);
    try {
      const data = await checkStatic({
        dump_paths: dumpPaths,
        offset: selStart,
        length: selLen,
        // Dumps in a set share one key; carry the first available one.
        ...useDumpStore.getState().getKeyMaterialByPath(dumpPaths[0]),
      });
      setStaticResult(data);
      setStep(2);
      if (data.static_mask && data.static_mask.length > 0) {
        const store = useHexStore.getState();
        type HLType = "pattern" | "differential";
        const regions = data.static_mask.map((isStatic: boolean, i: number) => ({
          offset: selStart + i,
          length: 1,
          type: (isStatic ? "pattern" : "differential") as HLType,
          label: isStatic ? t("research.staticByte") : t("research.volatileByte"),
        }));
        store.setHighlightedRegions([
          ...store.highlightedRegions.filter((r) => r.type !== "pattern" && r.type !== "differential"),
          ...regions,
        ]);
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : t("research.staticCheckFailed"));
    } finally {
      setLoading(false);
    }
  }

  async function handleGeneratePattern() {
    if (!staticResult) return;
    setLoading(true);
    setError(null);
    try {
      const data = await generatePattern({
        reference_hex: staticResult.reference_hex,
        static_mask: staticResult.static_mask,
        name: patternName,
      });
      setPatternResult(data);
      setStep(3);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : t("research.patternGenFailed"));
    } finally {
      setLoading(false);
    }
  }

  async function runExport() {
    if (!patternResult) return;
    setLoading(true);
    setError(null);
    try {
      const data = await exportPattern({
        pattern: patternResult as unknown as Record<string, unknown>,
        format: exportFormat,
      });
      setExportOutput(data.content);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : t("research.exportFailed"));
    } finally {
      setLoading(false);
    }
  }

  async function runAutoExport() {
    if (!hasDumps) return;
    setLoading(true);
    setError(null);
    setAutoResult(null);
    try {
      const data = await autoExport({
        dump_paths: dumpPaths,
        format: exportFormat,
        name: patternName,
        align: autoAlign,
        context: autoContext,
        // Dumps in a set share one key; carry the first available one.
        ...useDumpStore.getState().getKeyMaterialByPath(dumpPaths[0]),
      });
      setAutoResult(data);
      const store = useHexStore.getState();
      store.setHighlightedRegions([
        ...store.highlightedRegions.filter((r) => r.type !== "pattern"),
        {
          offset: data.region.offset,
          length: data.region.length,
          type: "pattern",
          label: t("research.autoRegionLabel", { format: data.format }),
        },
      ]);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : t("research.autoExportFailed"));
    } finally {
      setLoading(false);
    }
  }

  const copyToClipboard = (text: string | null | undefined) =>
    text && navigator.clipboard.writeText(text).catch(() => {});

  const downloadVol3 = (content: string) => {
    const blob = new Blob([content], { type: "text/x-python" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${patternName}_vol3_plugin.py`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (!hasDumps) {
    return (
      <EmptyState
        icon={<ArchitectIcon />}
        title={t("research.emptyTitle")}
        description={t("research.emptyDescription")}
        secondary={{ label: t("research.emptySecondaryLabel"), doc: "visualizations/architect.md" }}
        data-testid="architect-empty"
      />
    );
  }

  return (
    <div className="md-panel p-2 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-xs font-semibold md-text-accent">{t("research.heading")}</h3>
        <div className="flex gap-1">
          <button
            className={mode === "manual" ? BTN_ACCENT : BTN}
            onClick={() => setMode("manual")}
          >
            {t("research.modeManual")}
          </button>
          <button
            className={mode === "auto" ? BTN_ACCENT : BTN}
            onClick={() => setMode("auto")}
          >
            {t("research.modeAuto")}
          </button>
        </div>
      </div>
      {error && <p className="text-[10px] md-text-error">{error}</p>}

      {mode === "manual" && (
        <>
          {/* Step 1 */}
          <div className="space-y-1">
            <p className="text-[10px] md-text-muted font-semibold">
              {t("research.step1Title")}
            </p>
            {!hasSelection ? (
              <p className="text-[10px] md-text-muted">{t("research.selectRegionFirst")}</p>
            ) : (
              <p className="text-[10px] font-mono">
                {t("research.offsetBytes", {
                  offset: selStart.toString(16).toUpperCase(),
                  bytes: selLen,
                })}
              </p>
            )}
            <p className="text-[10px] md-text-muted">{t("research.dumpsLoaded", { total: dumpPaths.length })}</p>
            {!hasDumps && (
              <p className="text-[10px] md-text-warning">{t("research.need2DumpsCompare")}</p>
            )}
            <button
              className={BTN}
              disabled={!hasSelection || !hasDumps || loading}
              onClick={runStaticCheck}
            >
              {loading && step === 1 ? t("research.checking") : t("research.checkStatic")}
            </button>
            {staticResult && (
              <div className="text-[10px] space-y-0.5">
                <p>{t("research.staticRatio")} <span className="md-text-accent font-semibold">
                  {(staticResult.static_ratio * 100).toFixed(1)}%
                </span></p>
                <p>{t("research.anchorRegions", { total: staticResult.anchors.length })}</p>
              </div>
            )}
          </div>

          {/* Step 2 */}
          <div className={`space-y-1 ${step < 2 ? "opacity-40 pointer-events-none" : ""}`}>
            <p className="text-[10px] md-text-muted font-semibold">{t("research.step2Title")}</p>
            <input
              className={INPUT}
              value={patternName}
              onChange={(e) => setPatternName(e.target.value)}
              placeholder={t("research.patternNamePlaceholder")}
            />
            <button className={BTN} disabled={!staticResult || loading} onClick={handleGeneratePattern}>
              {loading && step === 2 ? t("research.generating") : t("research.generatePattern")}
            </button>
            {patternResult && (
              <div className="text-[10px] space-y-0.5">
                <pre className="font-mono p-1 rounded bg-[var(--md-bg)] border border-[var(--md-border)] overflow-x-auto max-h-20 text-[9px]">
                  {patternResult.wildcard_pattern}
                </pre>
                <p>
                  {t("research.staticVolatileBytes", {
                    static: patternResult.static_count,
                    volatile: patternResult.volatile_count,
                    length: patternResult.length,
                  })}
                </p>
              </div>
            )}
          </div>

          {/* Step 3 */}
          <div className={`space-y-1 ${step < 3 ? "opacity-40 pointer-events-none" : ""}`}>
            <p className="text-[10px] md-text-muted font-semibold">{t("research.step3Title")}</p>
            <div className="flex gap-1">
              <button
                className={exportFormat === "yara" ? BTN_ACCENT : BTN}
                onClick={() => { setExportFormat("yara"); setExportOutput(null); }}
              >{t("research.formatYara")}</button>
              <button
                className={exportFormat === "json" ? BTN_ACCENT : BTN}
                onClick={() => { setExportFormat("json"); setExportOutput(null); }}
              >{t("research.formatJson")}</button>
              <button
                className={exportFormat === "volatility3" ? BTN_ACCENT : BTN}
                onClick={() => { setExportFormat("volatility3"); setExportOutput(null); }}
              >{t("research.formatVol3")}</button>
            </div>
            <button className={BTN} disabled={!patternResult || loading} onClick={runExport}>
              {loading && step === 3 ? t("research.exporting") : t("research.export")}
            </button>
            {exportOutput && (
              <div className="space-y-1">
                <pre className="font-mono p-1 rounded bg-[var(--md-bg)] border border-[var(--md-border)] overflow-x-auto max-h-40 text-[9px]">
                  {exportOutput}
                </pre>
                <div className="flex gap-1">
                  <button className={BTN} onClick={() => copyToClipboard(exportOutput)}>{t("research.copyToClipboard")}</button>
                  {exportFormat === "volatility3" && (
                    <button className={BTN} onClick={() => downloadVol3(exportOutput!)}>{t("research.downloadPy")}</button>
                  )}
                </div>
              </div>
            )}
          </div>
        </>
      )}

      {mode === "auto" && (
        <div className="space-y-2">
          <p className="text-[10px] md-text-muted">
            {t("research.autoDescription")}
          </p>

          <div className="text-[10px] space-y-0.5">
            <p>{t("research.dumpsLoaded", { total: dumpPaths.length })}</p>
            {!hasDumps && (
              <p className="md-text-warning">{t("research.need2DumpsAuto")}</p>
            )}
          </div>

          <div className="flex gap-1">
            <button
              className={exportFormat === "yara" ? BTN_ACCENT : BTN}
              onClick={() => setExportFormat("yara")}
            >{t("research.formatYara")}</button>
            <button
              className={exportFormat === "json" ? BTN_ACCENT : BTN}
              onClick={() => setExportFormat("json")}
            >{t("research.formatJson")}</button>
            <button
              className={exportFormat === "volatility3" ? BTN_ACCENT : BTN}
              onClick={() => setExportFormat("volatility3")}
            >{t("research.formatVol3")}</button>
          </div>

          <input
            className={INPUT}
            value={patternName}
            onChange={(e) => setPatternName(e.target.value)}
            placeholder={t("research.patternNamePlaceholder")}
          />

          <label className="flex items-center gap-1.5 text-[10px]">
            <input
              type="checkbox"
              checked={autoAlign}
              onChange={(e) => setAutoAlign(e.target.checked)}
              className="accent-[var(--md-accent-blue)]"
            />
            {t("research.alignCandidates")}
          </label>

          <label className="block text-[10px]">
            <span className="md-text-muted">{t("research.contextPadding", { bytes: autoContext })}</span>
            <input
              type="range"
              min={4}
              max={64}
              step={4}
              value={autoContext}
              onChange={(e) => setAutoContext(parseInt(e.target.value, 10))}
              className="w-full"
            />
          </label>

          <button
            className={BTN}
            disabled={!hasDumps || loading}
            onClick={runAutoExport}
          >
            {loading ? t("research.autoDetecting") : t("research.autoDetectExport")}
          </button>

          {autoResult && (
            <div className="space-y-1">
              <p className="text-[10px]">
                <span className="md-text-accent font-semibold">{t("research.detectedRegion")}</span>{" "}
                {t("research.detectedRegionDetail", {
                  offset: autoResult.region.offset.toString(16).toUpperCase(),
                  bytes: autoResult.region.length,
                  keyStart: autoResult.region.key_start.toString(16).toUpperCase(),
                  keyEnd: autoResult.region.key_end.toString(16).toUpperCase(),
                })}
              </p>
              <pre className="font-mono p-1 rounded bg-[var(--md-bg)] border border-[var(--md-border)] overflow-x-auto max-h-40 text-[9px]">
                {autoResult.content}
              </pre>
              <div className="flex gap-1">
                <button className={BTN} onClick={() => copyToClipboard(autoResult.content)}>
                  {t("research.copyToClipboard")}
                </button>
                {autoResult.format === "volatility3" && (
                  <button className={BTN} onClick={() => downloadVol3(autoResult.content)}>
                    {t("research.downloadPy")}
                  </button>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
