/**
 * The "run anyway?" question for a request the server's memory guard refused.
 *
 * Mounted once at the app root. It renders nothing until
 * `withMemoryBudgetOverride` (see `@/api/memory-budget`) raises a question in
 * `useMemoryBudgetStore`, then resolves it with the user's choice.
 */

import { useRef } from "react";
import { useTranslation } from "react-i18next";
import { Modal } from "@/components/common/Modal";
import { useMemoryBudgetStore } from "@/stores/memory-budget-store";
import { formatBytes } from "@/utils/format-bytes";

export function MemoryBudgetDialog() {
  const { t } = useTranslation("memoryBudget");
  const pending = useMemoryBudgetStore((s) => s.pending);
  const answer = useMemoryBudgetStore((s) => s.answer);
  const cancelRef = useRef<HTMLButtonElement>(null);

  if (!pending) return null;
  const { info } = pending;
  const bytes = (value: number | null) =>
    value === null ? t("dialog.unknown") : formatBytes(value);

  return (
    <Modal
      title={t("dialog.title")}
      onClose={() => answer(false)}
      closeOnBackdrop={false}
      initialFocusRef={cancelRef}
      testId="memory-budget-dialog"
      footer={
        <>
          <button
            ref={cancelRef}
            onClick={() => answer(false)}
            data-testid="memory-budget-cancel"
            className="px-3 py-1.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] transition-colors"
          >
            {t("common:cancel")}
          </button>
          <button
            onClick={() => answer(true)}
            data-testid="memory-budget-run-anyway"
            className="px-3 py-1.5 rounded border transition-colors"
            style={{ borderColor: "var(--md-accent-red)", color: "var(--md-accent-red)" }}
          >
            {t("dialog.runAnyway")}
          </button>
        </>
      }
    >
      <div className="space-y-[var(--space-3)]">
        <p>{t("dialog.intro")}</p>
        <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
          <dt className="md-text-secondary">{t("dialog.estimate")}</dt>
          <dd data-testid="memory-budget-estimate">{bytes(info.estimateBytes)}</dd>
          <dt className="md-text-secondary">{t("dialog.budget")}</dt>
          <dd data-testid="memory-budget-budget">{bytes(info.budgetBytes)}</dd>
        </dl>
        <p
          data-testid="memory-budget-message"
          className="text-xs md-text-muted whitespace-pre-wrap break-words"
        >
          {info.message}
        </p>
        <p>{t("dialog.suggestion")}</p>
        <p className="text-xs" style={{ color: "var(--md-accent-red)" }}>
          {t("dialog.warning")}
        </p>
      </div>
    </Modal>
  );
}
