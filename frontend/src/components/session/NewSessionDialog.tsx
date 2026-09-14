/**
 * The prompt shown when "New Session" would discard unsaved work.
 *
 * Purely presentational: every decision lives in `useNewSessionGuard`, so this
 * component owns nothing but the editable name. That split is what lets the
 * button and Ctrl+N share one policy while only this file knows how it looks.
 */

import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { Modal } from "@/components/common/Modal";
import type { NewSessionGuard } from "@/hooks/useNewSessionGuard";

export interface NewSessionDialogProps {
  guard: NewSessionGuard;
  /** Names already taken, so an accidental overwrite can be flagged. */
  existingNames?: readonly string[];
}

export function NewSessionDialog({ guard, existingNames = [] }: NewSessionDialogProps) {
  const { t } = useTranslation("session");
  const [name, setName] = useState(guard.defaultName);
  const nameRef = useRef<HTMLInputElement>(null);

  // The suggestion is computed when the dialog opens, which is after this
  // component first mounts in practice; keep the field in step with it until
  // the user types something of their own.
  useEffect(() => setName(guard.defaultName), [guard.defaultName]);

  const trimmed = name.trim();
  // Saving over an existing name silently overwrites it server-side, so say so
  // before the click rather than after.
  const overwrites = trimmed.length > 0 && existingNames.includes(trimmed);

  const { summary } = guard;
  const stakes = [
    summary.dumps > 0 && t("newSessionGuard.summaryDumps", { count: summary.dumps }),
    summary.hasAnalysisResult && t("newSessionGuard.summaryAnalysis"),
    summary.bookmarks > 0 &&
      t("newSessionGuard.summaryBookmarks", { count: summary.bookmarks }),
  ].filter(Boolean) as string[];

  return (
    <Modal
      title={t("newSessionGuard.title")}
      onClose={guard.cancel}
      // A three-way choice about losing work should be made deliberately, not
      // dismissed by a stray click on the backdrop.
      closeOnBackdrop={false}
      initialFocusRef={nameRef}
      testId="new-session-dialog"
      footer={
        <>
          <button
            onClick={guard.cancel}
            disabled={guard.busy}
            data-testid="new-session-cancel"
            className="px-3 py-1.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] transition-colors disabled:opacity-50"
          >
            {t("common:cancel")}
          </button>
          <button
            onClick={() =>
              guard.recoveryFailed
                ? guard.forceDiscardAndStartNew()
                : void guard.discardAndStartNew()
            }
            disabled={guard.busy}
            data-testid="new-session-discard"
            className="px-3 py-1.5 rounded border transition-colors disabled:opacity-50"
            style={{ borderColor: "var(--md-accent-red)", color: "var(--md-accent-red)" }}
          >
            {guard.recoveryFailed
              ? t("newSessionGuard.discardAnyway")
              : t("newSessionGuard.discard")}
          </button>
          <button
            onClick={() => void guard.saveAndStartNew(name)}
            disabled={guard.busy}
            data-testid="new-session-save"
            className="px-3 py-1.5 rounded md-text-on-accent transition-opacity hover:opacity-90 disabled:opacity-50"
            style={{ background: "var(--md-accent-blue)" }}
          >
            {guard.busy ? t("newSessionGuard.saving") : t("newSessionGuard.save")}
          </button>
        </>
      }
    >
      <div className="space-y-[var(--space-3)]">
        <p>{t("newSessionGuard.body")}</p>

        {stakes.length > 0 && (
          <ul className="list-disc pl-5 md-text-secondary">
            {stakes.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        )}

        <label className="block space-y-1">
          <span className="md-text-secondary">{t("newSessionGuard.nameLabel")}</span>
          <input
            ref={nameRef}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={t("newSessionGuard.namePlaceholder")}
            data-testid="new-session-name"
            className="w-full px-2 py-1 rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)] text-[var(--md-text-primary)] focus:border-[var(--md-accent-blue)]"
          />
        </label>

        {overwrites && (
          <p style={{ color: "var(--md-accent-orange)" }}>
            {t("newSessionGuard.nameTaken", { name: trimmed })}
          </p>
        )}

        <p className="text-xs md-text-muted">{t("newSessionGuard.discardHint")}</p>

        {guard.error && (
          <p style={{ color: "var(--md-accent-red)" }} data-testid="new-session-error">
            {guard.recoveryFailed
              ? t("newSessionGuard.recoveryFailed")
              : t("newSessionGuard.saveFailed")}{" "}
            {guard.error}
          </p>
        )}
      </div>
    </Modal>
  );
}
