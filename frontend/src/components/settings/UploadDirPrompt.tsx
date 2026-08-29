/**
 * Configure-on-first-use prompt for the upload directory.
 *
 * MemDiver refuses to guess where uploaded captures should land, so the first
 * upload of a fresh install is rejected with a 409 (see ``upload-dir-error``)
 * and this modal is what turns that dead end into a one-click answer. It is
 * also the picker the Storage section of ``SettingsMenu`` reuses, so there is
 * exactly one place that knows how to POST the directory.
 *
 * The directory itself is picked with the existing ``wizard/FileBrowser``
 * (``GET /api/path/browse`` + its "Select This Directory" button) -- nothing
 * here re-implements browsing.
 */

import { useState } from "react";
import { useTranslation } from "react-i18next";

import type { SetUploadDirResult } from "@/api/settings";
import { FileBrowser } from "@/components/wizard/FileBrowser";
import { useUploadDir } from "./useUploadDir";

interface UploadDirPromptProps {
  /** Called after the backend has accepted the directory. */
  onSaved: (result: SetUploadDirResult) => void;
  onClose: () => void;
}

/** Local byte formatter for the legacy summary (matches FileBrowserEntryList). */
function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function UploadDirPrompt({ onSaved, onClose }: UploadDirPromptProps) {
  const { t } = useTranslation("misc");
  const { status, loading, error, save } = useUploadDir();

  const [chosenPath, setChosenPath] = useState<string | null>(null);
  const [migrateLegacy, setMigrateLegacy] = useState(false);
  const [browsing, setBrowsing] = useState(false);

  // The backend omits ``legacy`` entirely unless a migration is offerable, so
  // its presence -- not its file count -- is what gates the checkbox.
  const legacy = status?.legacy;
  // Pre-fill with whatever is already configured so re-choosing starts nearby.
  const path = chosenPath ?? status?.path ?? null;

  const handleSave = async (): Promise<void> => {
    if (!path) return;
    const result = await save(path, migrateLegacy);
    // A 400 leaves ``result`` null and the reason in ``error``: stay open and
    // render it inline rather than dropping the user back to a broken upload.
    if (result) onSaved(result);
  };

  return (
    <>
      <div
        className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
        data-testid="upload-dir-prompt"
      >
        <div
          role="dialog"
          aria-modal="true"
          aria-label={t("settings.uploadDirPromptTitle")}
          className="w-full max-w-lg mx-4 rounded-lg shadow-xl border border-[var(--md-border)]"
          style={{ background: "var(--md-bg-secondary)" }}
        >
          <div className="flex items-center justify-between p-3 border-b border-[var(--md-border)]">
            <h3 className="text-sm font-semibold md-text-accent">
              {t("settings.uploadDirPromptTitle")}
            </h3>
            <button
              type="button"
              onClick={onClose}
              className="px-2 py-0.5 text-sm rounded hover:bg-[var(--md-bg-hover)] transition-colors"
              title={t("common:close")}
              aria-label={t("common:close")}
            >
              x
            </button>
          </div>

          <div className="p-3 space-y-3 text-xs md-text-secondary">
            <p>{t("settings.uploadDirPromptBody")}</p>

            <div className="flex items-center gap-2">
              <span
                data-testid="upload-dir-chosen-path"
                className="flex-1 font-mono text-[10px] break-all px-2 py-1.5 rounded border border-[var(--md-border)] md-text-muted"
              >
                {path ?? t("settings.uploadDirNotConfigured")}
              </span>
              <button
                type="button"
                data-testid="upload-dir-choose"
                onClick={() => setBrowsing(true)}
                className="px-3 py-1.5 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] transition-colors md-text-secondary"
              >
                {t("settings.uploadDirChoose")}
              </button>
            </div>

            {legacy && (
              <div
                data-testid="upload-dir-legacy"
                className="space-y-1 p-2 rounded border border-[var(--md-border)]"
              >
                <div className="font-mono text-[10px] break-all md-text-muted">{legacy.path}</div>
                <label className="flex items-center gap-2 md-text-secondary">
                  <input
                    type="checkbox"
                    data-testid="upload-dir-migrate"
                    checked={migrateLegacy}
                    onChange={(e) => setMigrateLegacy(e.target.checked)}
                    className="accent-[var(--md-accent-blue)] cursor-pointer"
                  />
                  <span>
                    {/* ``files`` rather than ``count``: ``count`` would switch
                        i18next into plural mode and demand _one/_other keys. */}
                    {t("settings.uploadDirMigrate", {
                      files: legacy.file_count,
                      size: formatBytes(legacy.total_bytes),
                    })}
                  </span>
                </label>
              </div>
            )}

            {error && (
              <div data-testid="upload-dir-error" className="md-text-error">
                {error}
              </div>
            )}
          </div>

          <div className="flex items-center justify-between p-3 border-t border-[var(--md-border)]">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 text-sm rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] transition-colors md-text-secondary"
            >
              {t("common:cancel")}
            </button>
            <button
              type="button"
              data-testid="upload-dir-save"
              onClick={() => void handleSave()}
              disabled={!path || loading}
              className="px-3 py-1.5 text-sm rounded bg-[var(--md-accent-blue)] text-white hover:opacity-90 transition-opacity disabled:opacity-40"
            >
              {t("common:save")}
            </button>
          </div>
        </div>
      </div>

      {/* Rendered after the dialog so it stacks above it at the same z-index. */}
      {browsing && (
        <FileBrowser
          onSelect={(selected) => {
            setChosenPath(selected);
            setBrowsing(false);
          }}
          onClose={() => setBrowsing(false)}
        />
      )}
    </>
  );
}
