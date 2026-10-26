import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { readableFailure } from "@/api/client";
import {
  listImageProcesses, probeImage, startExtractProcessJob, startOpenViewJob, startProfileJob,
  type ExtractResult, type ImageProbe, type ImageViewKind, type OpenViewResult,
  type OpenViewArgs, type ProcessRow, type ProfileResult,
} from "@/api/image";
import { useActiveDump } from "@/hooks/useActiveDump";
import { invalidateImageViewFacts, useImageViewFacts } from "@/hooks/useImageViewFacts";
import { useImageStore } from "@/stores/image-store";
import { useSelectionStore } from "@/stores/selection-store";
import { KernelViewVariants } from "./KernelViewVariants";
import { ImageError } from "./ImageError";
import { JobStatus } from "./JobStatus";
import { ProbeCard } from "./ProbeCard";
import { failureCode } from "./failure-details";
import { ProcessTable } from "./ProcessTable";
import { isMdview, openViewInWorkspace } from "./open-view-in-workspace";
import { processListGate } from "./process-list-gate";
import { useImageJob } from "./useImageJob";

type Intent = { kind: "open" } | { kind: "kernel" } | { kind: "extract"; pid: number };

const inputClass =
  "w-full px-2 py-1 text-xs rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)]";
const buttonClass =
  "px-2 py-1 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40";

/** Probe, profile and view actions for a full memory image, plus its process list. */
export function ImagePanel() {
  const { t } = useTranslation("image");
  const imagePath = useImageStore((s) => s.imagePath);
  const isfPath = useImageStore((s) => s.isfPath);
  const caseDir = useImageStore((s) => s.caseDir);
  const storedKernelView = useImageStore((s) => s.kernelViewPath);
  const selectedPid = useSelectionStore((s) => s.pid);
  const { setImagePath, setIsfPath, setCaseDir, setKernelViewPath } = useImageStore.getState();
  const activePath = useActiveDump()?.path ?? "";
  // The process list reads a kernel/process view: the one opened here, or the active .mdview.
  const kernelView = storedKernelView || (isMdview(activePath) ? activePath : "");

  const probe: ImageProbe | null = useImageStore((s) => s.probes[imagePath.trim()]) ?? null;
  const [probing, setProbing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rows, setRows] = useState<ProcessRow[]>([]);
  const [isfDraft, setIsfDraft] = useState(isfPath);
  const intent = useRef<Intent>({ kind: "open" });

  const runProbe = useCallback(async (banners: boolean) => {
    if (!imagePath.trim()) return;
    setProbing(true);
    setError(null);
    try {
      const next = await probeImage(imagePath.trim(), banners, isfPath || undefined);
      // A re-probe without the (slow) banner scan, e.g. after "Use ISF", must not
      // wipe banners already scanned for the same image.
      const prev = useImageStore.getState().probes[imagePath.trim()];
      useImageStore.getState().setProbe(imagePath.trim(), !banners && prev?.banners && prev.image === next.image
        ? { ...next, banners: prev.banners } : next);
    } catch (err) {
      useImageStore.getState().setProbe(imagePath.trim(), null);
      setError(readableFailure(err));
    } finally {
      setProbing(false);
    }
  }, [imagePath, isfPath]);

  useEffect(() => { void runProbe(false); }, [runProbe]);

  const profileJob = useImageJob<ProfileResult>(() => { void runProbe(false); });
  const extractJob = useImageJob<ExtractResult>();
  const viewJob = useImageJob<OpenViewResult>((result) => {
    const current = intent.current;
    // The backend's `ViewDescriptor.to_dict()` OMITS `profile` when the view has none, so
    // a descriptor without the key (or with `profile: null`) is a profile-less view.
    invalidateImageViewFacts(result.view_path);
    if (result.descriptor) {
      useImageStore.getState().setViewHasProfile(result.view_path, Boolean(result.descriptor.profile));
    }
    if (current.kind === "extract") {
      void extractJob.start(() => startExtractProcessJob(
        result.view_path, result.view_path.replace(/\.mdview$/i, ".msl")));
      return;
    }
    if (current.kind === "kernel") setKernelViewPath(result.view_path);
    void openViewInWorkspace(result.view_path);
  });

  // The view's own facts decide whether it can list processes (physical views and
  // profile-less kernel views cannot: the backend answers 400 `kernel_view_required`).
  // The signal is the VIEW's descriptor, not the image probe: an image can have a cached
  // profile while this view has none. `viewHasProfile` (primed by this panel's open-view
  // job) is the fast path; when the facts request fails the list is requested anyway and
  // that answer is shown as the note.
  const [needsProfile, setNeedsProfile] = useState(false);
  const primedProfile = useImageStore((s) => s.viewHasProfile[kernelView]);
  const facts = useImageViewFacts(kernelView);
  const gate = processListGate(kernelView, facts, primedProfile);
  useEffect(() => {
    setNeedsProfile(false);
    if (gate !== "list") { setRows([]); return; }
    let cancelled = false;
    listImageProcesses(kernelView)
      .then((list) => { if (!cancelled) setRows(list.processes); })
      .catch((err) => {
        if (cancelled) return;
        setRows([]);
        if (failureCode(err) === "kernel_view_required") setNeedsProfile(true);
        else setError(readableFailure(err));
      });
    return () => { cancelled = true; };
  }, [kernelView, gate]);

  const openView = (view: ImageViewKind, next: Intent, pid?: number, extra: Partial<OpenViewArgs> = {}) => {
    intent.current = next;
    void viewJob.start(() => startOpenViewJob({
      image_path: imagePath.trim(), view, pid, isf: isfPath || undefined, case_dir: caseDir.trim(), ...extra,
    }));
  };
  const rowOpen = (row: ProcessRow) => openView("process", { kind: "open" }, row.pid);
  const rowExtract = (row: ProcessRow) => openView("process", { kind: "extract", pid: row.pid }, row.pid);
  const busy = viewJob.state.status === "running" || extractJob.state.status === "running";
  const hasImage = imagePath.trim() !== "";
  const extracted = extractJob.state.result;

  return (
    <div data-testid="image-panel" className="p-2 space-y-3 overflow-auto h-full text-xs">
      <h3 className="font-semibold md-text-accent">{t("title")}</h3>
      <label className="block space-y-1">
        <span className="md-text-secondary">{t("pathLabel")}</span>
        <input type="text" value={imagePath} onChange={(e) => setImagePath(e.target.value)}
          placeholder={t("pathPlaceholder")} className={inputClass} data-testid="image-path-input" />
      </label>
      {probing && <p role="status" className="md-text-muted">{t("probe.loading")}</p>}
      {probe && <ProbeCard probe={probe} onScanBanners={() => void runProbe(true)} />}
      {error && <ImageError message={error} />}

      <div className="space-y-1">
        <div className="flex gap-2 flex-wrap">
          <button disabled={!hasImage || profileJob.state.status === "running"} className={buttonClass}
            onClick={() => void profileJob.start(() => startProfileJob(imagePath.trim(), isfPath || undefined))}>
            {t("profile.extract")}
          </button>
        </div>
        <JobStatus state={profileJob.state} label={t("profile.running")} testId="profile-progress"
          onCancel={() => void profileJob.cancel()} />
        {profileJob.state.status === "cancelled" && (
          <p role="status" data-testid="profile-cancelled" className="md-text-secondary">
            {t("profile.cancelled")}</p>
        )}
        {profileJob.state.result?.isf && (
          <p data-testid="profile-done" className="md-text-secondary">
            {t("profile.done", { isf: profileJob.state.result.isf })}</p>
        )}
        <div className="flex gap-1">
          <input type="text" value={isfDraft} onChange={(e) => setIsfDraft(e.target.value)}
            aria-label={t("profile.isfLabel")} placeholder={t("profile.isfPlaceholder")}
            className={inputClass} data-testid="isf-input" />
          <button className={buttonClass} disabled={!isfDraft.trim()}
            onClick={() => setIsfPath(isfDraft.trim())}>{t("profile.isfApply")}</button>
        </div>
      </div>

      <label className="block space-y-1">
        <span className="md-text-secondary">{t("case.label")}</span>
        <input type="text" value={caseDir} onChange={(e) => setCaseDir(e.target.value)}
          placeholder={t("case.placeholder")} className={inputClass} data-testid="case-dir-input" />
      </label>
      <div className="flex gap-2">
        <button disabled={!hasImage || busy} className={buttonClass}
          onClick={() => openView("kernel", { kind: "kernel" })}>{t("views.openKernel")}</button>
        <button disabled={!hasImage || busy} className={buttonClass}
          onClick={() => openView("physical", { kind: "open" })}>{t("views.openPhysical")}</button>
      </div>
      <KernelViewVariants disabled={!hasImage || busy} caseDir={caseDir}
        onOpen={(extra) => openView("kernel", { kind: "kernel" }, undefined, extra)} />
      <JobStatus state={viewJob.state} label={t("views.opening")} testId="view-progress" />
      <JobStatus state={extractJob.state} label={t("extract.running", {
        pid: intent.current.kind === "extract" ? intent.current.pid : "" })} testId="extract-progress" />
      {extracted && (
        <p data-testid="extract-result" className="md-text-secondary">
          {t("extract.done", { regions: extracted.regions_written, path: extracted.output_path })}{" "}
          <button className="underline md-text-accent"
            onClick={() => void openViewInWorkspace(extracted.output_path)}>{t("extract.open")}</button>
        </p>
      )}

      <h4 className="font-semibold md-text-secondary">{t("processes.title")}</h4>
      {gate === "wait" && <p role="status" className="md-text-muted">{t("processes.loading")}</p>}
      {(gate === "needProfile" || (gate === "list" && needsProfile)) &&
        <p className="md-text-muted" data-testid="processes-need-profile">{t("processes.needProfile")}</p>}
      {gate === "list" && !needsProfile &&
        <ProcessTable rows={rows} onOpen={rowOpen} onExtract={rowExtract} busy={busy}
          selectedPid={selectedPid} onSelect={(row) => useSelectionStore.getState().setPid(row.pid)} />}
      {(gate === "none" || gate === "physical") &&
        <p className="md-text-muted" data-testid="processes-need-kernel-view">{t("processes.needKernelView")}</p>}
    </div>
  );
}
