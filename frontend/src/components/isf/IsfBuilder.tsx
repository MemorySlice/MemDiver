import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { ApiError, readableFailure } from "@/api/client";
import { listIsfDrafts, type DraftRef, type DraftSummaryRow, type IsfSection } from "@/api/isf";
import { isMdview } from "@/components/image/open-view-in-workspace";
import { useViewContext } from "@/components/vol3/useViewContext";
import { useActiveDump } from "@/hooks/useActiveDump";
import { useImageStore } from "@/stores/image-store";
import { DraftList } from "./DraftList";
import { DraftTree } from "./DraftTree";
import { caseDirOfView, rememberCaseDir, rememberedCaseDir } from "./case-dir";
import { entryOfImplicated, type EntryRef } from "./isf-format";
import { OpForms, type EditFocus } from "./OpForms";
import { ProbeRunner } from "./ProbeRunner";
import { TryPanel } from "./TryPanel";
import { ValidateCards } from "./ValidateCards";
import { VersionsPanel } from "./VersionsPanel";
import { buttonClass, inputClass } from "./ui";

const isCaseNotFound = (e: unknown) => e instanceof ApiError && e.body.includes("case.not_found");

/** ISF Builder: draft a Volatility symbol table by hand, probe the image, try it, keep the history. */
export function IsfBuilder() {
  const { t } = useTranslation("isf");
  const storedImage = useImageStore((s) => s.imagePath);
  const caseDir = useImageStore((s) => s.caseDir);
  const probeSha = useImageStore((s) => s.probes[s.imagePath.trim()]?.image_sha256 ?? null);
  const activePath = useActiveDump()?.path ?? "";
  const viewPath = isMdview(activePath) ? activePath : "";
  const { view } = useViewContext(viewPath, null);
  const [typedImage, setTypedImage] = useState("");
  // The active image view's own facts come first: its image and capture are the truth
  // for that view; the image store / probe / typed path are only the fallback.
  const viewImage = (view?.image_path ?? "").trim();
  const imagePath = (viewImage || storedImage || typedImage).trim();
  // The backend resolves a path to its sha256 too, so a path is a valid capture id.
  const captureId = view?.capture_id ?? view?.image_sha256 ?? probeSha ?? imagePath;
  const draftRef: DraftRef | null = caseDir.trim() && captureId ? { caseDir: caseDir.trim(), captureId } : null;

  const [drafts, setDrafts] = useState<DraftSummaryRow[]>([]);
  const [listError, setListError] = useState<string | null>(null);
  const [noCase, setNoCase] = useState(false);
  const [listRev, setListRev] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);
  const [rev, setRev] = useState(0);
  const [section, setSection] = useState<IsfSection>("symbols");
  const [query, setQuery] = useState("");
  const [entry, setEntry] = useState<EntryRef | null>(null);
  const [focus, setFocus] = useState<EditFocus | null>(null);

  // An empty case directory is prefilled: the open view's case, else the last one used for this capture.
  useEffect(() => {
    if (!captureId || useImageStore.getState().caseDir.trim() !== "") return;
    const prefill = caseDirOfView(viewPath) || rememberedCaseDir(captureId);
    if (prefill) useImageStore.getState().setCaseDir(prefill);
  }, [captureId, viewPath]);
  // The field is edited freely; only blur / Enter / Load commits it (and so lists drafts).
  const [typedCaseDir, setTypedCaseDir] = useState(caseDir);
  const [seenCaseDir, setSeenCaseDir] = useState(caseDir);
  if (seenCaseDir !== caseDir) { setSeenCaseDir(caseDir); setTypedCaseDir(caseDir); }
  const commitCaseDir = () => {
    const value = typedCaseDir.trim();
    useImageStore.getState().setCaseDir(value);
    rememberCaseDir(captureId, value);
    if (value === caseDir.trim()) setListRev((r) => r + 1);
  };
  const refCaseDir = draftRef?.caseDir ?? "";
  const refCapture = draftRef?.captureId ?? "";

  useEffect(() => {
    if (!refCaseDir || !refCapture) return;
    let live = true;
    listIsfDrafts({ caseDir: refCaseDir, captureId: refCapture })
      .then((r) => { if (live) { setDrafts(r.drafts); setListError(null); setNoCase(false); } })
      .catch((e) => { if (live) {
        setDrafts([]);
        setNoCase(isCaseNotFound(e));
        setListError(isCaseNotFound(e) ? null : readableFailure(e));
      } });
    return () => { live = false; };
  }, [refCaseDir, refCapture, listRev, rev]);

  const changed = useCallback(() => setRev((r) => r + 1), []);
  const select = (name: string) => { setSelected(name); setEntry(null); setQuery(""); setSection("symbols"); };
  const showImplicated = (item: string) => {
    const ref = entryOfImplicated(item);
    if (!ref) return;
    setSection(ref.section);
    setQuery(ref.name);
    setEntry(ref);
  };
  const listed = draftRef ? drafts : [];
  const draft = selected && draftRef && listed.some((d) => d.name === selected) ? selected : null;

  return (
    <div data-testid="isf-builder" className="p-2 space-y-3 overflow-auto h-full text-xs">
      <h3 className="font-semibold md-text-accent">{t("title")}</h3>
      <label className="block space-y-0.5"><span className="md-text-secondary">{t("caseDir")}</span>
        <span className="flex gap-1">
          <input type="text" value={typedCaseDir} className={inputClass} data-testid="isf-case-dir"
            placeholder={t("caseDirPlaceholder")}
            onChange={(e) => setTypedCaseDir(e.target.value)} onBlur={commitCaseDir}
            onKeyDown={(e) => { if (e.key === "Enter") commitCaseDir(); }} />
          <button type="button" className={buttonClass} data-testid="isf-case-load"
            onClick={commitCaseDir}>{t("caseDirLoad")}</button>
        </span></label>
      {viewImage === "" && storedImage === "" && (
        <label className="block space-y-0.5"><span className="md-text-secondary">{t("imagePath")}</span>
          <input type="text" value={typedImage} className={inputClass} data-testid="isf-image-path"
            onChange={(e) => setTypedImage(e.target.value)} /></label>
      )}
      {draftRef === null && <p data-testid="isf-needs-case" className="md-text-muted">{t("needsCase")}</p>}
      <DraftList draftRef={draftRef} drafts={listed} selected={draft} error={listError} noCase={noCase}
        onSelect={select} onCreated={(n) => { select(n); setListRev((r) => r + 1); }}
        onRefresh={() => setListRev((r) => r + 1)} />
      {draftRef && draft && (
        <>
          <DraftTree draftRef={draftRef} draft={draft} rev={rev} section={section} query={query}
            selected={entry} onSection={setSection} onQuery={(q) => { setQuery(q); setEntry(null); }}
            onEdit={setFocus} onChanged={changed} />
          <OpForms draftRef={draftRef} draft={draft} focus={focus} onApplied={changed} />
          <ValidateCards draftRef={draftRef} draft={draft} rev={rev} />
          <TryPanel imagePath={imagePath} draftRef={draftRef} draft={draft} rev={rev} onImplicated={showImplicated} />
          <VersionsPanel draftRef={draftRef} draft={draft} rev={rev} onChanged={changed} />
        </>
      )}
      <ProbeRunner imagePath={imagePath} draftRef={draftRef} drafts={listed.map((d) => d.name)} />
    </div>
  );
}
