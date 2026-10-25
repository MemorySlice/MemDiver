import { useCallback, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { readableFailure } from "@/api/client";
import {
  listKeyFinders, type HeapPolicy, type KeyFinderInfo, type KeyFindersResult,
} from "@/api/keyfinders";
import { DetectorFixtureBadge } from "@/components/detectors/DetectorFixtureBadge";
import { useActiveDump } from "@/hooks/useActiveDump";
import { useHexStore } from "@/stores/hex-store";
import { useImageStore } from "@/stores/image-store";
import { KeyHitsTable } from "./KeyHitsTable";
import {
  goToHit, handOffToVerification, paintKeyHits, planKeyHitHighlights, scanAddressOf,
} from "./keyfinder-hits";
import { useKeyFinderScan } from "./useKeyFinderScan";

const HEAP_POLICIES: readonly HeapPolicy[] = ["off", "annotate", "mask"];
const buttonClass =
  "px-2 py-1 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40";

type Region = "view" | "selection";

/** Recognise key material by structure (AES schedules, RSA keys, PEM, entropy) in the open dump. */
export function KeyFindersPanel() {
  const { t } = useTranslation("keyfinders");
  const dumpPath = useActiveDump()?.path ?? "";
  const caseDir = useImageStore((s) => s.caseDir);
  const selection = useHexStore((s) => s.selection);
  const viewMode = useHexStore((s) => s.viewMode);
  const multiView = useHexStore((s) => s.availableViews.length > 1);
  const vaSpanStart = useHexStore((s) => s.vaSpanStart);
  const pageStatesLoaded = useHexStore((s) => s.pageStatesLoaded);
  const [finders, setFinders] = useState<KeyFinderInfo[]>([]);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [loadError, setLoadError] = useState<string | null>(null);
  const [heapPolicy, setHeapPolicy] = useState<HeapPolicy>("annotate");
  const [region, setRegion] = useState<Region>("view");
  const [note, setNote] = useState<string | null>(null);
  const [active, setActive] = useState<number | null>(null);

  const paintResult = useCallback((result: KeyFindersResult) => {
    paintKeyHits(planKeyHitHighlights(
      result.rows, result.view, useHexStore.getState().vaSpanStart, result.dump_path).regions);
  }, []);
  const showResult = useCallback((result: KeyFindersResult) => {
    paintResult(result);
    setActive(null);
    setNote(null);
  }, [paintResult]);
  const { state, run, cancel } = useKeyFinderScan(showResult);
  const result = state.result;

  // The `va` view's span start arrives with the page states; hits placed before then were
  // rebased by 0. Re-paint them once it is known (the highlight store is external state).
  useEffect(() => {
    if (result?.view === "va" && vaSpanStart !== 0) paintResult(result);
  }, [vaSpanStart]); // eslint-disable-line react-hooks/exhaustive-deps

  // Derived, so it follows the span start instead of keeping the count of the first placement.
  const skippedNote = useMemo(() => {
    if (!result) return null;
    const { skipped } = planKeyHitHighlights(result.rows, result.view, vaSpanStart, result.dump_path);
    return skipped > 0 ? t("results.skipped", { count: skipped }) : null;
  }, [result, vaSpanStart, t]);
  const shownNote = note ?? skippedNote;

  useEffect(() => {
    listKeyFinders()
      .then((l) => {
        setFinders(l.finders);
        setChecked(new Set(l.default_finders));
      })
      .catch((e) => setLoadError(readableFailure(e)));
  }, []);

  const hasSelection = selection !== null;
  const effectiveRegion: Region = hasSelection ? region : "view";
  const running = state.status === "running";
  const canRun = dumpPath !== "" && checked.size > 0 && !running;

  const toggle = (name: string) => setChecked((prev) => {
    const next = new Set(prev);
    if (!next.delete(name)) next.add(name);
    return next;
  });

  const start = () => {
    // A packed dump's "raw" file view is not a scannable address space: omit the view so the
    // backend scans the captured bytes (its default, "va").
    const rawOfPacked = multiView && viewMode === "raw";
    const scanView = multiView && !rawOfPacked ? viewMode : undefined;
    const span = effectiveRegion === "selection" && selection
      ? { start: Math.min(selection.anchor, selection.active),
          length: Math.abs(selection.active - selection.anchor) + 1 }
      : null;
    const offset = span && !rawOfPacked
      ? scanAddressOf(span.start, scanView ?? "raw", useHexStore.getState().vaSpanStart) : null;
    if (span && offset === null) { setNote(t("region.unsafe")); return; }
    setNote(null);
    // The `va` view's address map is only fetched on demand; hits cannot be placed without it.
    useHexStore.getState().fetchPageStates();
    void run({
      dump_path: dumpPath, finders: [...checked], heap_policy: heapPolicy,
      ...(scanView ? { view: scanView } : {}),
      ...(span && offset !== null ? { offset, length: span.length } : {}),
      case_dir: caseDir.trim() || undefined,
    });
  };

  const rows = useMemo(() => result?.rows ?? [], [result]);
  const notReady = result?.view === "va" && !pageStatesLoaded;
  const click = (i: number) => {
    if (!result) return;
    if (notReady) { useHexStore.getState().fetchPageStates(); setNote(t("results.notReady")); return; }
    setActive(i);
    setNote(goToHit(rows[i], result.view) ? null : t("results.unplaceable"));
  };
  const verify = (i: number) => {
    if (!result) return;
    if (notReady) { setNote(t("results.notReady")); return; }
    setActive(i);
    setNote(handOffToVerification(rows[i], result.view) ? null : t("results.unplaceable"));
  };

  const pct = state.pct === null ? null : Math.round(state.pct * 100);
  return (
    <div data-testid="keyfinders-panel" className="p-2 space-y-3 overflow-auto h-full text-xs">
      <h3 className="font-semibold md-text-accent">{t("title")}</h3>
      {loadError && (
        <p role="alert" data-testid="keyfinders-load-error" style={{ color: "var(--md-accent-red)" }}>
          {t("error.load", { message: loadError })}
        </p>
      )}
      {!dumpPath && <p className="md-text-muted" data-testid="keyfinders-no-dump">{t("noDump")}</p>}
      <fieldset className="space-y-1" data-testid="keyfinders-list">
        <legend className="md-text-secondary">{t("finders.legend")}</legend>
        {finders.map((f) => (
          <div key={f.name} data-testid={`keyfinders-item-${f.name}`}>
          <label className="flex items-start gap-1.5">
            <input type="checkbox" checked={checked.has(f.name)} onChange={() => toggle(f.name)}
              data-testid={`keyfinders-finder-${f.name}`} />
            <span>
              <span className="font-medium">{t(`finders.${f.name}.label`, { defaultValue: f.name })}</span>
              <span className="block md-text-muted">
                {t(`finders.${f.name}.desc`, { defaultValue: f.description })}
              </span>
            </span>
          </label>
            <div className="pl-5 pt-0.5">
              <DetectorFixtureBadge artifactKind="keyfinder" artifact={f.name} caseDir={caseDir.trim() || undefined} />
            </div>
          </div>
        ))}
      </fieldset>
      <fieldset className="space-y-1">
        <legend className="md-text-secondary">{t("region.legend")}</legend>
        {(["view", "selection"] as const).map((r) => (
          <label key={r} className="flex items-center gap-1.5">
            <input type="radio" name="keyfinders-region" checked={effectiveRegion === r}
              disabled={r === "selection" && !hasSelection} onChange={() => setRegion(r)}
              data-testid={`keyfinders-region-${r}`} />
            <span>{t(`region.${r}`)}</span>
          </label>
        ))}
      </fieldset>
      <div role="group" aria-label={t("heap.legend")} className="flex flex-wrap items-center gap-1"
        data-testid="keyfinders-heap-policy">
        <span className="md-text-secondary">{t("heap.legend")}</span>
        {HEAP_POLICIES.map((p) => (
          <button key={p} type="button" aria-pressed={heapPolicy === p} title={t(`heap.policyHint.${p}`)}
            data-testid={`keyfinders-heap-${p}`} onClick={() => setHeapPolicy(p)}
            className={`${buttonClass} ${heapPolicy === p ? "bg-[var(--md-bg-hover)] md-text-accent" : ""}`}>
            {t(`heap.policy.${p}`)}
          </button>
        ))}
      </div>
      <button type="button" className={buttonClass} disabled={!canRun} onClick={start}
        data-testid="keyfinders-run">{t("run.button")}</button>
      {running && (
        <div role="status" data-testid="keyfinders-progress" className="space-y-1 md-text-secondary">
          <div className="flex items-center gap-2">
            <span>{state.msg ?? t("run.running")}{pct !== null ? ` ${t("run.pct", { pct })}` : ""}</span>
            {state.taskId && (
              <button type="button" className={buttonClass} onClick={() => void cancel()}
                data-testid="keyfinders-cancel">{t("run.cancel")}</button>
            )}
          </div>
          <div role="progressbar" aria-label={t("run.running")} aria-busy="true" aria-valuemin={0}
            aria-valuemax={100} {...(pct !== null ? { "aria-valuenow": pct } : {})}
            className="h-1 rounded bg-[var(--md-border)] overflow-hidden">
            <div className="h-full bg-[var(--md-accent-blue)]" style={{ width: `${pct ?? 33}%` }} />
          </div>
        </div>
      )}
      {state.status === "cancelled" && <p data-testid="keyfinders-cancelled" className="md-text-muted">{t("run.cancelled")}</p>}
      {state.status === "error" && state.error && (
        <p role="alert" data-testid="keyfinders-error" style={{ color: "var(--md-accent-red)" }}>
          {t("error.scan", { message: state.error })}
        </p>
      )}
      {shownNote && (
        <p role="status" data-testid="keyfinders-note" className="md-text-muted">{shownNote}</p>
      )}
      {result && (
        <section className="space-y-1" aria-label={t("results.title")}>
          <p data-testid="keyfinders-summary" className="md-text-secondary">
            {t("results.summary", { count: result.row_count, view: result.view })}
          </p>
          {result.truncated && (
            <p role="alert" data-testid="keyfinders-truncated" style={{ color: "var(--md-accent-orange)" }}>
              {t("results.truncated", { limit: result.limit })}
            </p>
          )}
          {rows.length === 0
            ? <p data-testid="keyfinders-empty" className="md-text-muted">{t("results.empty")}</p>
            : <KeyHitsTable rows={rows} active={active} onRowClick={click} onVerify={verify} />}
        </section>
      )}
    </div>
  );
}
