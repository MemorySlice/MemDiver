import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import type { TranscriptItem } from "@/stores/agent-reducer";

type ApprovalItem = Extract<TranscriptItem, { kind: "approval" }>;
export type Decide = (id: string, allow: boolean, scope: "once" | "chat", message?: string) => void;

export function ApprovalCard({ item, onDecide }: { item: ApprovalItem; onDecide: Decide }) {
  const { t } = useTranslation("agent");
  const [note, setNote] = useState("");
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => { if (!item.resolved) ref.current?.focus(); }, [item.resolved]);
  const btn = "px-2 py-1 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]";
  const message = note.trim() || undefined;
  return (
    <div ref={ref} tabIndex={-1} role="group" aria-label={t("approval.title")} data-testid="approval-card"
      className="rounded border border-[var(--md-accent-orange)] bg-[var(--md-bg-secondary)] p-2 text-xs space-y-1">
      <p className="font-semibold">{t("approval.title")}</p>
      <p>{t("approval.body", { tool: item.tool, access: item.access })}</p>
      <pre className="font-mono text-[11px] overflow-auto max-h-32 whitespace-pre-wrap break-all">{JSON.stringify(item.input, null, 2)}</pre>
      {item.resolved ? (
        <p data-testid="approval-resolved"
          style={{ color: item.resolved.allowed ? "var(--md-accent-green)" : "var(--md-accent-red)" }}>
          {t(item.resolved.allowed ? "approval.allowed" : "approval.denied")}
          {item.resolved.message ? `: ${item.resolved.message}` : ""}
        </p>
      ) : (
        <>
          <input type="text" value={note} onChange={(e) => setNote(e.target.value)}
            aria-label={t("approval.note")} placeholder={t("approval.note")}
            className="w-full px-1 py-0.5 rounded border border-[var(--md-border)] bg-[var(--md-bg-primary)]" />
          <div className="flex gap-2 flex-wrap">
            <button type="button" className={btn} onClick={() => onDecide(item.id, true, "once", message)}>{t("approval.allowOnce")}</button>
            {item.scopes.includes("chat") && (
              <button type="button" className={btn} onClick={() => onDecide(item.id, true, "chat", message)}>{t("approval.allowChat")}</button>
            )}
            <button type="button" className={btn} onClick={() => onDecide(item.id, false, "once", message)}>{t("approval.deny")}</button>
          </div>
        </>
      )}
    </div>
  );
}
