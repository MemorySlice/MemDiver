import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { previewImport, readableFailure } from "@/api/client";
import type { ImportLayout, ImportPreview, KeyMaterial, RegionCategory } from "@/api/types";
import { formatBytes } from "@/utils/format-bytes";
import { RegionCategoryChecklist } from "./RegionCategoryChecklist";
import { RegionPreviewTable } from "./RegionPreviewTable";
import { MaterializeOption } from "./MaterializeOption";
import { EncryptedMslOptions } from "./EncryptedMslOptions";
import { MapsFileOption } from "./MapsFileOption";
import {
  DEFAULT_REGION_CATEGORIES,
  REGION_CATEGORIES,
  isAllCategories,
  selectionCounts,
} from "./region-categories";

export interface RegionSelectStepProps {
  /** Dumps the selection applies to. Only the first is previewed; empty = no preview. */
  paths: string[];
  /**
   * How many dumps the selection covers, when known. `null` = "every dump in
   * the directory" without a count. Defaults to `paths.length`.
   */
  dumpCount?: number | null;
  selected: readonly RegionCategory[];
  onSelectedChange: (next: RegionCategory[]) => void;
  materialize: boolean;
  onMaterializeChange: (materialize: boolean) => void;
  /** Told about every preview that lands (or `null` while none is available). */
  onPreviewChange?: (preview: ImportPreview | null) => void;
  /**
   * Encrypted `.msl`: key inputs (controlled when given, else local state).
   * Secrets live in component state only and travel in POST bodies.
   */
  keyMaterial?: KeyMaterial;
  onKeyMaterialChange?: (next: KeyMaterial) => void;
  /** Encrypted `.msl` + materialize: write the copy as plaintext (opt-in). */
  decryptOutput?: boolean;
  onDecryptOutputChange?: (next: boolean) => void;
  /**
   * Raw single-dump input: offer a `.maps` memory-map picker. Off for
   * directory inputs, where each dump's own sidecar is auto-detected.
   */
  allowMapsFile?: boolean;
  /** Memory map the preview is run with (controlled when given, else local state). */
  mapsPath?: string | null;
  onMapsPathChange?: (next: string | null) => void;
}

/** Controlled-or-local value: the prop wins when the caller supplies it. */
function useMaybeControlled<T>(value: T | undefined, onChange: ((v: T) => void) | undefined, initial: T) {
  const [local, setLocal] = useState<T>(initial);
  const current = value === undefined ? local : value;
  const set = (next: T) => {
    if (value === undefined) setLocal(next);
    onChange?.(next);
  };
  return [current, set] as const;
}

type PreviewState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "ready"; preview: ImportPreview }
  | { status: "error"; message: string };

/**
 * Fetch the preview of `path` (re-run when `attempt` changes). `keyRef` holds
 * the key material applied by the last "unlock" — read at request time so the
 * secret never becomes part of a dependency/cache key.
 */
function usePreview(
  path: string | undefined,
  attempt: number,
  keyRef: { current: KeyMaterial | undefined },
  mapsPath: string | null,
): PreviewState {
  // Each settled answer is tagged with the request it answers, so "loading"
  // is derived (answer for an older request) rather than set inside the effect.
  const requestKey = path ? `${attempt}:${mapsPath ?? ""}:${path}` : null;
  const [settled, setSettled] = useState<{ key: string; state: PreviewState } | null>(null);
  useEffect(() => {
    if (!path || !requestKey) return;
    let cancelled = false;
    const key = keyRef.current;
    const pending = previewWith(path, key, mapsPath);
    pending
      .then((preview) => {
        if (!cancelled) setSettled({ key: requestKey, state: { status: "ready", preview } });
      })
      .catch((e: unknown) => {
        if (!cancelled) {
          setSettled({ key: requestKey, state: { status: "error", message: readableFailure(e) } });
        }
      });
    return () => { cancelled = true; };
  }, [path, requestKey, keyRef, mapsPath]);
  if (!requestKey) return { status: "idle" };
  if (settled?.key !== requestKey) return { status: "loading" };
  return settled.state;
}

/** `previewImport` with only the optional inputs that are actually set. */
function previewWith(path: string, key: KeyMaterial | undefined, mapsPath: string | null) {
  if (mapsPath) return previewImport(path, undefined, undefined, key, { mapsPath });
  return key ? previewImport(path, undefined, undefined, key) : previewImport(path);
}

/**
 * Wizard step: choose which memory region categories to import / analyse.
 *
 * Previews the first dump server-side (metadata only), shows per-category
 * counts and bytes, keeps the included/excluded totals live as the user
 * toggles, and — for `.msl` input only — offers the opt-in filtered copy.
 */
export function RegionSelectStep({
  paths,
  dumpCount,
  selected,
  onSelectedChange,
  materialize,
  onMaterializeChange,
  onPreviewChange,
  keyMaterial: keyMaterialProp,
  onKeyMaterialChange,
  decryptOutput: decryptOutputProp,
  onDecryptOutputChange,
  allowMapsFile = false,
  mapsPath: mapsPathProp,
  onMapsPathChange,
}: RegionSelectStepProps) {
  const { t } = useTranslation("import");
  const [attempt, setAttempt] = useState(0);
  const firstPath = paths[0];
  const appliedKey = useRef<KeyMaterial | undefined>(undefined);
  const [mapsPath, setMapsPath] = useMaybeControlled<string | null>(
    mapsPathProp, onMapsPathChange, null);
  const state = usePreview(firstPath, attempt, appliedKey, mapsPath);
  const preview = state.status === "ready" ? state.preview : null;
  const [keyMaterial, setKeyMaterial] = useMaybeControlled<KeyMaterial>(
    keyMaterialProp, onKeyMaterialChange, {});
  const [decryptOutput, setDecryptOutput] = useMaybeControlled<boolean>(
    decryptOutputProp, onDecryptOutputChange, false);
  const unlock = () => {
    appliedKey.current = { ...keyMaterial };
    setAttempt((n) => n + 1);
  };
  const applyMaps = (next: string) => {
    setMapsPath(next);
    setAttempt((n) => n + 1); // re-applying the same file still re-reads it
  };

  useEffect(() => {
    onPreviewChange?.(preview);
  }, [preview, onPreviewChange]);

  // A raw dump without a memory layout is one unclassified region: categories
  // can't be separated, so the selection is pinned to "all" (no filter).
  const noLayout = preview?.layout === "none";
  // A physical / kernel image view has no mappings to choose between either.
  const noSelection = preview?.selection_applicable === false;
  const pinned = noLayout || noSelection;
  useEffect(() => {
    if (pinned && !isAllCategories(selected)) onSelectedChange([...REGION_CATEGORIES]);
  }, [pinned, selected, onSelectedChange]);
  useDefaultsOnceLayoutAppears(preview?.layout, onSelectedChange);

  const count = dumpCount === undefined ? paths.length : dumpCount;

  return (
    <section className="space-y-4" aria-labelledby="region-step-title" data-testid="region-select-step">
      <h2 id="region-step-title" className="text-lg font-semibold md-text-accent">
        {t("step.title")}
      </h2>
      <p className="text-sm md-text-secondary">{t("step.description")}</p>
      <ScopeNote firstPath={firstPath} count={count} />

      <PreviewStatus state={state} onRetry={() => setAttempt((n) => n + 1)} />

      {noLayout && (
        <InfoCallout text={t("step.noLayoutInfo")} testId="region-no-layout-info" />
      )}

      {allowMapsFile && offersMapsFile(state, mapsPath) && (
        <MapsFileOption
          activeMapsPath={preview?.layout === "maps" ? (preview.maps_path ?? mapsPath) : null}
          chosen={Boolean(mapsPath)}
          initialPath={mapsPath ?? ""}
          onApply={applyMaps}
        />
      )}

      {noSelection && preview && (
        <InfoCallout
          text={preview.view_kind === "process"
            ? t("step.imageView.processInfo")
            : t("step.imageView.noSelection", { kind: preview.view_kind ?? "" })}
          testId="region-no-selection-info"
        />
      )}

      <RegionCategoryChecklist
        selected={selected}
        onChange={onSelectedChange}
        totals={preview?.totals}
        disabled={pinned}
      />

      {preview && <RuntimeNotice preview={preview} />}

      {preview && !noSelection && <SelectionSummary preview={preview} selected={selected} />}

      <InfoCallout text={t("step.imageDataInfo")} />

      {preview && <FormatNotes preview={preview} />}

      {preview?.is_msl && (
        <MaterializeOption checked={materialize} onChange={onMaterializeChange} />
      )}

      {preview?.is_msl && preview.encrypted && (
        <EncryptedMslOptions
          keyMaterial={keyMaterial}
          onKeyMaterialChange={setKeyMaterial}
          onUnlock={unlock}
          decrypted={Boolean(preview.decrypted)}
          decryptOutput={decryptOutput}
          onDecryptOutputChange={setDecryptOutput}
        />
      )}

      {preview && preview.regions.length > 0 && (
        <RegionPreviewTable regions={preview.regions} selected={selected} />
      )}
    </section>
  );
}

/**
 * A memory map just turned a layout-less raw dump into real regions: the
 * selection was pinned to "all" only because categories could not be told
 * apart, so offer the usual defaults now that they can.
 */
function useDefaultsOnceLayoutAppears(
  layout: ImportLayout | undefined,
  onSelectedChange: (next: RegionCategory[]) => void,
) {
  const lastLayout = useRef<ImportLayout | undefined>(undefined);
  useEffect(() => {
    if (layout === undefined) return; // still loading: remember the last known one
    const previous = lastLayout.current;
    lastLayout.current = layout;
    if (previous === "none" && layout === "maps") onSelectedChange([...DEFAULT_REGION_CATEGORIES]);
  }, [layout, onSelectedChange]);
}

/**
 * Whether the memory-map picker applies: a raw preview (layout `none` or
 * `maps`), or a failed preview caused by a chosen map, so the user can fix
 * the path instead of retrying the same bad request.
 */
function offersMapsFile(state: PreviewState, mapsPath: string | null): boolean {
  if (state.status === "error") return Boolean(mapsPath);
  if (state.status !== "ready") return false;
  return state.preview.layout === "none" || state.preview.layout === "maps";
}

function ScopeNote({ firstPath, count }: { firstPath?: string; count: number | null }) {
  const { t } = useTranslation("import");
  const name = firstPath ? firstPath.split(/[\\/]/).pop() ?? firstPath : null;
  return (
    <p className="text-xs md-text-muted" data-testid="region-scope-note">
      {name && `${t("step.previewing", { name })} `}
      {count === null ? t("step.appliesToAllUnknown") : t("step.appliesToAll", { count })}
    </p>
  );
}

function PreviewStatus({ state, onRetry }: { state: PreviewState; onRetry: () => void }) {
  const { t } = useTranslation("import");
  if (state.status === "loading") {
    return (
      <p role="status" aria-live="polite" className="text-sm md-text-muted" data-testid="region-preview-loading">
        {t("step.loading")}
      </p>
    );
  }
  if (state.status === "error") {
    return (
      <div role="alert" className="text-sm flex items-center gap-2" data-testid="region-preview-error">
        <span style={{ color: "var(--md-accent-red)" }}>{t("step.error", { message: state.message })}</span>
        <button
          type="button"
          onClick={onRetry}
          className="text-xs px-2 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]"
        >
          {t("step.retry")}
        </button>
      </div>
    );
  }
  if (state.status === "idle") {
    return <p className="text-sm md-text-muted">{t("step.noPreview")}</p>;
  }
  return null;
}

function SelectionSummary({ preview, selected }: { preview: ImportPreview; selected: readonly RegionCategory[] }) {
  const { t } = useTranslation("import");
  const counts = selectionCounts(preview.totals, selected);
  return (
    <p
      role="status"
      aria-live="polite"
      aria-label={t("step.summaryLabel")}
      className="text-sm font-medium"
      data-testid="region-summary"
    >
      {t("step.summary", {
        keeping: t("step.summaryKeeping", {
          count: counts.included_count,
          bytes: formatBytes(counts.included_bytes),
        }),
        excluding: t("step.summaryExcluding", {
          count: counts.excluded_count,
          bytes: formatBytes(counts.excluded_bytes),
        }),
      })}
    </p>
  );
}

/**
 * Platform runtime regions (`runtime` category) are left out of the default
 * selection: say how many and how large, with Android-specific wording when
 * the preview detected an Android process. Built from the preview's fields,
 * not from the backend's English note.
 */
function RuntimeNotice({ preview }: { preview: ImportPreview }) {
  const { t } = useTranslation("import");
  const count = preview.runtime_count ?? 0;
  if (count <= 0) return null;
  const variant = preview.platform === "android" ? "android" : "generic";
  return (
    <InfoCallout
      text={t(`step.runtimeNotice.${variant}`, { count, bytes: formatBytes(preview.runtime_bytes ?? 0) })}
      testId="region-runtime-notice"
    />
  );
}

function FormatNotes({ preview }: { preview: ImportPreview }) {
  const { t } = useTranslation("import");
  return (
    <div className="text-xs md-text-secondary space-y-1">
      <p>
        {t("step.format", { format: preview.format })}{" — "}
        {preview.is_msl
          ? t("step.msl.nonDestructive")
          : preview.view_kind
            ? t("step.imageView.reads")
            : t("step.raw.writes")}
      </p>
      {preview.notes.length > 0 && (
        <ul aria-label={t("step.notes")} className="list-disc ml-4">
          {preview.notes.map((note, i) => <li key={i}>{note}</li>)}
        </ul>
      )}
    </div>
  );
}

function InfoCallout({ text, testId = "region-image-data-info" }: { text: string; testId?: string }) {
  return (
    <p
      role="note"
      className="text-xs flex items-start gap-1.5 p-2 rounded border border-[var(--md-border)]"
      data-testid={testId}
    >
      <span aria-hidden="true" style={{ color: "var(--md-accent-blue)" }}>i</span>
      <span>{text}</span>
    </p>
  );
}
