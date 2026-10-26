import { useState } from "react";
import { useTranslation } from "react-i18next";

import {
  FEEDABLE_PROBES, PROBES, getIsfJobPayload, startIsfProbeJob,
  type DraftRef, type ProbeResult, type ProbeRow, type WireLocation,
} from "@/api/isf";
import { wireIntToBigInt } from "@/api/lossless-json";
import { JobStatus } from "@/components/image/JobStatus";
import { isMdview } from "@/components/image/open-view-in-workspace";
import { useImageJob } from "@/components/image/useImageJob";
import { useViewContext } from "@/components/vol3/useViewContext";
import { resolveOffset } from "@/components/vol3/vol3-navigation";
import { useActiveDump } from "@/hooks/useActiveDump";
import { useHexStore } from "@/stores/hex-store";
import { buttonClass, inputClass } from "./ui";

const ARCHES = ["auto", "x86_64", "aarch64", "arm", "x86"] as const;
const LOCATION_KEYS = ["location", "va_location"];

const isLocation = (v: unknown): v is WireLocation =>
  typeof v === "object" && v !== null && "space" in v && "value" in v;
const brief = (v: unknown): string => {
  const text = typeof v === "string" ? v : JSON.stringify(v) ?? "";
  return text.length > 60 ? `${text.slice(0, 57)}...` : text;
};
const columnsOf = (rows: ProbeRow[]): string[] => {
  const seen = new Set<string>();
  rows.slice(0, 20).forEach((r) => Object.keys(r).forEach((k) => { if (!LOCATION_KEYS.includes(k)) seen.add(k); }));
  return [...seen];
};

function LocationButton({ loc, onGo }: { loc: WireLocation; onGo: () => void }) {
  const { t } = useTranslation("isf");
  const exact = wireIntToBigInt(loc.value);
  if (exact === null) {
    return <span data-testid="probe-location-unavailable" className="md-text-muted font-mono">
      {loc.space} {t("probe.unavailable")}</span>;
  }
  return <button type="button" className={`${buttonClass} font-mono`} data-testid="probe-location" onClick={onGo}>
    {loc.space} 0x{exact.toString(16)}</button>;
}

/** Run one pakunoda probe on the image (optionally feeding a draft) and show what it found. */
export function ProbeRunner({ imagePath, draftRef, drafts }: {
  imagePath: string; draftRef: DraftRef | null; drafts: string[];
}) {
  const { t } = useTranslation("isf");
  const activePath = useActiveDump()?.path ?? "";
  const viewPath = isMdview(activePath) ? activePath : "";
  const { ctx, loadIntervals } = useViewContext(viewPath, null);
  const [probe, setProbe] = useState<string>("viability");
  const [arch, setArch] = useState<string>("auto");
  const [feed, setFeed] = useState("");
  const [hint, setHint] = useState<string | null>(null);
  const job = useImageJob<ProbeResult>(undefined, getIsfJobPayload<ProbeResult>);
  const feedable = FEEDABLE_PROBES.includes(probe);
  const result = job.state.result;
  const running = job.state.status === "running";

  const run = () => {
    setHint(null);
    void job.start(() => startIsfProbeJob({
      imagePath, probe, arch,
      ...(feedable && feed && draftRef ? { caseDir: draftRef.caseDir, draft: feed } : {}),
    }));
  };

  const go = async (loc: WireLocation) => {
    if (viewPath === "") { setHint(t("probe.nav.noView")); return; }
    const exact = wireIntToBigInt(loc.value);
    if (exact === null) { setHint(t("probe.nav.inexact")); return; }
    // A kernel-scale `va` span start is a rounded number: place such an address by the
    // packed (`vas`) offset instead, and switch the viewer there.
    const inexactSpan = ctx.mode === "va" && !Number.isSafeInteger(ctx.vaSpanStart);
    const usedCtx = inexactSpan ? { ...ctx, mode: "vas" as const } : ctx;
    const intervals = usedCtx.mode === "vas" ? await loadIntervals() : null;
    const res = resolveOffset({ value: exact, space: loc.space, pid: ctx.pid }, usedCtx, intervals);
    if (!res.ok) { setHint(t(`vol3:${res.hint}`, res.params)); return; }
    setHint(null);
    const hex = useHexStore.getState();
    if (inexactSpan) hex.showView("vas");
    hex.scrollToOffset(res.offset);
  };

  const cols = result ? columnsOf(result.rows) : [];
  return (
    <section className="space-y-1" data-testid="isf-probe">
      <h4 className="font-semibold">{t("probe.title")}</h4>
      <div className="grid grid-cols-2 gap-1">
        <select value={probe} className={inputClass} data-testid="probe-select" aria-label={t("probe.probe")}
          onChange={(e) => setProbe(e.target.value)}>
          {PROBES.map((p) => <option key={p} value={p}>{p}</option>)}</select>
        <select value={arch} className={inputClass} data-testid="probe-arch" aria-label={t("probe.arch")}
          onChange={(e) => setArch(e.target.value)}>
          {ARCHES.map((a) => <option key={a} value={a}>{a}</option>)}</select>
      </div>
      <label className="block space-y-0.5"><span className="md-text-secondary">{t("probe.feed")}</span>
        <select value={feedable ? feed : ""} disabled={!feedable} className={inputClass} data-testid="probe-feed"
          onChange={(e) => setFeed(e.target.value)}>
          <option value="">{t("probe.feedNone")}</option>
          {drafts.map((d) => <option key={d} value={d}>{d}</option>)}</select></label>
      {!feedable && <p className="md-text-muted">{t("probe.notFeedable")}</p>}
      <button type="button" className={buttonClass} disabled={running || imagePath.trim() === ""}
        data-testid="probe-run" onClick={run}>{t("probe.run")}</button>
      <JobStatus state={job.state} label={t("probe.running")} testId="probe-job" onCancel={() => void job.cancel()} />
      {job.state.status === "cancelled" && <p data-testid="probe-cancelled" className="md-text-muted">{t("job.cancelled")}</p>}
      {hint && <p role="status" data-testid="probe-hint" className="md-text-muted">{hint}</p>}
      {result && (
        <div data-testid="probe-result" className="space-y-1">
          <p>{t("probe.summary", { probe: result.probe, arch: result.arch })}</p>
          <p data-testid="probe-counts" className="md-text-secondary">
            {Object.entries(result.counts).map(([k, v]) => `${k}: ${v}`).join(" · ")}</p>
          <p data-testid="probe-timings" className="md-text-muted">
            {Object.entries(result.timings).map(([k, v]) => `${k} ${v}s`).join(" · ")}</p>
          {result.truncated && (
            <p role="status" data-testid="probe-truncated" style={{ color: "var(--md-accent-orange)" }}>
              {t("probe.truncated", { shown: result.rows.length, limit: result.limit })}</p>
          )}
          {result.warnings.map((w) => <p key={w} data-testid="probe-warning" style={{ color: "var(--md-accent-orange)" }}>{w}</p>)}
          {result.imported && <p data-testid="probe-imported" className="md-text-secondary">
            {t("probe.imported", { draft: String(result.imported.draft ?? "") })}</p>}
          <div className="overflow-auto max-h-64">
            <table className="text-xs"><thead><tr>
              <th className="text-left pr-2">{t("probe.location")}</th>
              {cols.map((c) => <th key={c} className="text-left pr-2">{c}</th>)}</tr></thead>
            <tbody>{result.rows.map((row, i) => (
              <tr key={i} data-testid="probe-row">
                <td className="pr-2">{LOCATION_KEYS.map((k) => row[k]).filter(isLocation).map((loc) => (
                  <LocationButton key={`${loc.space}:${loc.value}`} loc={loc} onGo={() => void go(loc)} />))}</td>
                {cols.map((c) => <td key={c} className="pr-2 font-mono">{brief(row[c])}</td>)}
              </tr>))}
            </tbody></table>
          </div>
        </div>
      )}
    </section>
  );
}
