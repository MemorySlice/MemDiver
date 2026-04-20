import { useMemo, useState } from "react";
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

const BTN = "px-2 py-1 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] text-xs";
const BTN_ACCENT = "px-2 py-1 rounded text-xs bg-[var(--md-accent-blue)] text-white";
const INPUT = "w-full px-1.5 py-1 rounded border border-[var(--md-border)] bg-[var(--md-bg-primary)] text-[10px] font-mono";

type ArchitectMode = "manual" | "auto";
type ExportFormat = "yara" | "json" | "volatility3";

export function ArchitectPlaceholder() {
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
    try {
      const data = await checkStatic({ dump_paths: dumpPaths, offset: selStart, length: selLen });
      setStaticResult(data);
      setStep(2);
      if (data.static_mask && data.static_mask.length > 0) {
        const store = useHexStore.getState();
        type HLType = "pattern" | "differential";
        const regions = data.static_mask.map((isStatic: boolean, i: number) => ({
          offset: selStart + i,
          length: 1,
          type: (isStatic ? "pattern" : "differential") as HLType,
          label: isStatic ? "static byte" : "volatile byte",
        }));
        store.setHighlightedRegions([
          ...store.highlightedRegions.filter((r) => r.type !== "pattern" && r.type !== "differential"),
          ...regions,
        ]);
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Static check failed");
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
      setError(e instanceof Error ? e.message : "Pattern generation failed");
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
      setError(e instanceof Error ? e.message : "Export failed");
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
      });
      setAutoResult(data);
      const store = useHexStore.getState();
      store.setHighlightedRegions([
        ...store.highlightedRegions.filter((r) => r.type !== "pattern"),
        {
          offset: data.region.offset,
          length: data.region.length,
          type: "pattern",
          label: `auto-detected ${data.format} region`,
        },
      ]);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Auto-export failed");
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

  return (
    <div className="md-panel p-2 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-xs font-semibold md-text-accent">Pattern Architect</h3>
        <div className="flex gap-1">
          <button
            className={mode === "manual" ? BTN_ACCENT : BTN}
            onClick={() => setMode("manual")}
          >
            Manual
          </button>
          <button
            className={mode === "auto" ? BTN_ACCENT : BTN}
            onClick={() => setMode("auto")}
          >
            Auto-Detect
          </button>
        </div>
      </div>
      {error && <p className="text-[10px] text-red-400">{error}</p>}

      {mode === "manual" && (
        <>
          {/* Step 1 */}
          <div className="space-y-1">
            <p className="text-[10px] md-text-muted font-semibold">
              Step 1: Region Selection + Static Check
            </p>
            {!hasSelection ? (
              <p className="text-[10px] md-text-muted">Select a region in the hex viewer first</p>
            ) : (
              <p className="text-[10px] font-mono">
                Offset 0x{selStart.toString(16).toUpperCase()} &mdash; {selLen} bytes
              </p>
            )}
            <p className="text-[10px] md-text-muted">{dumpPaths.length} dump(s) loaded</p>
            {!hasDumps && (
              <p className="text-[10px] text-yellow-400">Need 2+ dumps for cross-dump comparison</p>
            )}
            <button
              className={BTN}
              disabled={!hasSelection || !hasDumps || loading}
              onClick={runStaticCheck}
            >
              {loading && step === 1 ? "Checking..." : "Check Static"}
            </button>
            {staticResult && (
              <div className="text-[10px] space-y-0.5">
                <p>Static ratio: <span className="md-text-accent font-semibold">
                  {(staticResult.static_ratio * 100).toFixed(1)}%
                </span></p>
                <p>{staticResult.anchors.length} anchor region(s)</p>
              </div>
            )}
          </div>

          {/* Step 2 */}
          <div className={`space-y-1 ${step < 2 ? "opacity-40 pointer-events-none" : ""}`}>
            <p className="text-[10px] md-text-muted font-semibold">Step 2: Pattern Generation</p>
            <input
              className={INPUT}
              value={patternName}
              onChange={(e) => setPatternName(e.target.value)}
              placeholder="Pattern name"
            />
            <button className={BTN} disabled={!staticResult || loading} onClick={handleGeneratePattern}>
              {loading && step === 2 ? "Generating..." : "Generate Pattern"}
            </button>
            {patternResult && (
              <div className="text-[10px] space-y-0.5">
                <pre className="font-mono p-1 rounded bg-[var(--md-bg)] border border-[var(--md-border)] overflow-x-auto max-h-20 text-[9px]">
                  {patternResult.wildcard_pattern}
                </pre>
                <p>
                  {patternResult.static_count} static / {patternResult.volatile_count} volatile
                  &mdash; {patternResult.length} bytes
                </p>
              </div>
            )}
          </div>

          {/* Step 3 */}
          <div className={`space-y-1 ${step < 3 ? "opacity-40 pointer-events-none" : ""}`}>
            <p className="text-[10px] md-text-muted font-semibold">Step 3: Export</p>
            <div className="flex gap-1">
              <button
                className={exportFormat === "yara" ? BTN_ACCENT : BTN}
                onClick={() => { setExportFormat("yara"); setExportOutput(null); }}
              >YARA</button>
              <button
                className={exportFormat === "json" ? BTN_ACCENT : BTN}
                onClick={() => { setExportFormat("json"); setExportOutput(null); }}
              >JSON</button>
              <button
                className={exportFormat === "volatility3" ? BTN_ACCENT : BTN}
                onClick={() => { setExportFormat("volatility3"); setExportOutput(null); }}
              >Vol3 Plugin</button>
            </div>
            <button className={BTN} disabled={!patternResult || loading} onClick={runExport}>
              {loading && step === 3 ? "Exporting..." : "Export"}
            </button>
            {exportOutput && (
              <div className="space-y-1">
                <pre className="font-mono p-1 rounded bg-[var(--md-bg)] border border-[var(--md-border)] overflow-x-auto max-h-40 text-[9px]">
                  {exportOutput}
                </pre>
                <div className="flex gap-1">
                  <button className={BTN} onClick={() => copyToClipboard(exportOutput)}>Copy to Clipboard</button>
                  {exportFormat === "volatility3" && (
                    <button className={BTN} onClick={() => downloadVol3(exportOutput!)}>Download .py</button>
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
            Runs consensus across all loaded dumps, picks the highest-entropy volatile region as the key
            candidate, and exports a pattern in one step. Skips manual region selection.
          </p>

          <div className="text-[10px] space-y-0.5">
            <p>{dumpPaths.length} dump(s) loaded</p>
            {!hasDumps && (
              <p className="text-yellow-400">Need 2+ dumps for auto-detection</p>
            )}
          </div>

          <div className="flex gap-1">
            <button
              className={exportFormat === "yara" ? BTN_ACCENT : BTN}
              onClick={() => setExportFormat("yara")}
            >YARA</button>
            <button
              className={exportFormat === "json" ? BTN_ACCENT : BTN}
              onClick={() => setExportFormat("json")}
            >JSON</button>
            <button
              className={exportFormat === "volatility3" ? BTN_ACCENT : BTN}
              onClick={() => setExportFormat("volatility3")}
            >Vol3 Plugin</button>
          </div>

          <input
            className={INPUT}
            value={patternName}
            onChange={(e) => setPatternName(e.target.value)}
            placeholder="Pattern name"
          />

          <label className="flex items-center gap-1.5 text-[10px]">
            <input
              type="checkbox"
              checked={autoAlign}
              onChange={(e) => setAutoAlign(e.target.checked)}
              className="accent-[var(--md-accent-blue)]"
            />
            Align candidates (recommended)
          </label>

          <label className="block text-[10px]">
            <span className="md-text-muted">Context padding: {autoContext} byte(s)</span>
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
            {loading ? "Auto-detecting..." : "Auto-Detect & Export"}
          </button>

          {autoResult && (
            <div className="space-y-1">
              <p className="text-[10px]">
                <span className="md-text-accent font-semibold">Detected region</span>{" "}
                offset 0x{autoResult.region.offset.toString(16).toUpperCase()} &mdash;{" "}
                {autoResult.region.length} bytes
                {" "}(key 0x{autoResult.region.key_start.toString(16).toUpperCase()} &rarr;
                {" "}0x{autoResult.region.key_end.toString(16).toUpperCase()})
              </p>
              <pre className="font-mono p-1 rounded bg-[var(--md-bg)] border border-[var(--md-border)] overflow-x-auto max-h-40 text-[9px]">
                {autoResult.content}
              </pre>
              <div className="flex gap-1">
                <button className={BTN} onClick={() => copyToClipboard(autoResult.content)}>
                  Copy to Clipboard
                </button>
                {autoResult.format === "volatility3" && (
                  <button className={BTN} onClick={() => downloadVol3(autoResult.content)}>
                    Download .py
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
