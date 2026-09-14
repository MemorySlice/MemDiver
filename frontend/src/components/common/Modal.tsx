/**
 * A centred modal with the accessibility contract that copy-paste keeps losing.
 *
 * The repo had two bespoke dialogs before this one, and they disagree: only
 * `DocPanel` traps focus, handles Escape and restores focus on close;
 * `UploadDirPrompt` does none of the three. That is the usual outcome of
 * duplicating chrome by hand — the invisible half is the half that gets
 * dropped — and it is why the behaviour below is lifted from `DocPanel` rather
 * than written afresh.
 *
 * Scope is deliberately chrome only: backdrop, framing, and the focus/keyboard
 * contract. What goes inside is the caller's business, so this stays a shell
 * rather than becoming a configurable `ConfirmDialog` with an N-button API.
 *
 * `DocPanel` and `UploadDirPrompt` are NOT migrated onto this yet. Both have
 * dedicated tests and awkward shapes (a slide-over with in-panel navigation; a
 * `FileBrowser` stacked at the same z-index), so moving them is its own change
 * under its own test run.
 */

import { useCallback, useEffect, useId, useRef } from "react";
import { useTranslation } from "react-i18next";

export interface ModalProps {
  /** Accessible name for the dialog, rendered as its heading. */
  title: string;
  /** Escape, the backdrop and the header close button all route here. */
  onClose: () => void;
  /** Set false for a dialog whose choices must be made deliberately. */
  closeOnBackdrop?: boolean;
  /**
   * Focused on open. Defaults to the close button. Point it at the safest
   * control — for a destructive choice, that is not the destructive one.
   */
  initialFocusRef?: React.RefObject<HTMLElement | null>;
  /** Rendered in the bordered footer row, typically the action buttons. */
  footer?: React.ReactNode;
  testId?: string;
  children: React.ReactNode;
}

export function Modal({
  title,
  onClose,
  closeOnBackdrop = true,
  initialFocusRef,
  footer,
  testId = "modal",
  children,
}: ModalProps) {
  const { t } = useTranslation("common");
  const titleId = useId();
  const closeRef = useRef<HTMLButtonElement>(null);

  // Focus on open, restore on close. `previous` is captured at mount so the
  // control that opened the dialog gets focus back when it goes away.
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    (initialFocusRef?.current ?? closeRef.current)?.focus();
    return () => previous?.focus?.();
    // Intentionally mount-only: re-running would steal focus mid-interaction.

  }, []);

  // Escape closes from anywhere, not just from inside the dialog subtree: a
  // click on the backdrop moves focus to <body>, and someone who lands there
  // still expects Escape to work.
  useEffect(() => {
    const onEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onEscape);
    return () => document.removeEventListener("keydown", onEscape);
  }, [onClose]);

  const handleKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLDivElement>) => {
      if (event.key !== "Tab") return;
      // Minimal focus trap: cycle within the dialog's own tabbables.
      const focusable = event.currentTarget.querySelectorAll<HTMLElement>(
        'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
      );
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    },
    [],
  );

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-[var(--space-4)]"
      onClick={closeOnBackdrop ? onClose : undefined}
      onKeyDown={handleKeyDown}
      data-testid={`${testId}-overlay`}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        data-testid={testId}
        onClick={(event) => event.stopPropagation()}
        className="flex max-h-full w-full max-w-lg flex-col rounded border shadow-xl text-[var(--text-sm)]"
        style={{
          background: "var(--md-bg-primary)",
          borderColor: "var(--md-border)",
          color: "var(--md-text-primary)",
        }}
      >
        <header
          className="flex items-center justify-between gap-[var(--space-3)] px-[var(--space-4)] py-[var(--space-3)] border-b"
          style={{ borderColor: "var(--md-border)" }}
        >
          <h2 id={titleId} className="text-[var(--text-sm)] font-semibold truncate">
            {title}
          </h2>
          <button
            ref={closeRef}
            onClick={onClose}
            aria-label={t("close")}
            className="px-[var(--space-2)] rounded hover:bg-[var(--md-bg-hover)] transition-colors md-text-secondary"
          >
            ×
          </button>
        </header>

        <div className="flex-1 overflow-auto px-[var(--space-4)] py-[var(--space-3)]">
          {children}
        </div>

        {footer && (
          <footer
            className="flex items-center justify-end gap-[var(--space-2)] px-[var(--space-4)] py-[var(--space-3)] border-t"
            style={{ borderColor: "var(--md-border)" }}
          >
            {footer}
          </footer>
        )}
      </div>
    </div>
  );
}
