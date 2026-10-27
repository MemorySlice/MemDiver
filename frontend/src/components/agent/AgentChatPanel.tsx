import { memo, useEffect, useRef, useState, type KeyboardEvent } from "react";
import { useTranslation } from "react-i18next";

import { listPlaybooks, renderPlaybook, type Playbook } from "@/api/agent";
import { readableFailure } from "@/api/client";
import type { TranscriptItem } from "@/stores/agent-reducer";
import { AgentSettingsForm } from "./AgentSettingsForm";
import { AgentStatusBanner } from "./AgentStatusBanner";
import { ApprovalCard } from "./ApprovalCard";
import { EvidenceText } from "./EvidenceText";
import { ToolCallCard } from "./ToolCallCard";
import { UsageMeter } from "./UsageMeter";
import { chatScope, useAgentChat } from "./useAgentChat";

const btn = "px-2 py-1 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-50 text-xs";

function PlaybookMenu({ onText }: { onText: (text: string) => void }) {
  const { t } = useTranslation("agent");
  const [books, setBooks] = useState<Playbook[]>([]);
  const [name, setName] = useState("");
  const [args, setArgs] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { listPlaybooks().then(setBooks).catch(() => setBooks([])); }, []);
  const book = books.find((b) => b.name === name);
  const fill = async () => {
    try { onText((await renderPlaybook(name, args)).text); setError(null); }
    catch (e) { setError(t("playbooks.failed", { error: readableFailure(e) })); }
  };
  if (books.length === 0) return null;
  return (
    <div className="space-y-1 text-xs">
      <label className="block">
        <span>{t("playbooks.label")}</span>
        <select value={name} onChange={(e) => { setName(e.target.value); setArgs({}); }}
          className="w-full px-1 py-0.5 rounded border border-[var(--md-border)] bg-[var(--md-bg-primary)]">
          <option value="">{t("playbooks.choose")}</option>
          {books.map((b) => <option key={b.name} value={b.name} title={b.summary}>{b.name}</option>)}
        </select>
      </label>
      {book && <p className="md-text-muted">{book.summary}</p>}
      {book?.params.map((p) => (
        <input key={p} aria-label={t("playbooks.param", { name: p })} placeholder={p} value={args[p] ?? ""}
          onChange={(e) => setArgs((a) => ({ ...a, [p]: e.target.value }))}
          className="w-full px-1 py-0.5 rounded border border-[var(--md-border)] bg-[var(--md-bg-primary)]" />
      ))}
      {book && <button type="button" className={btn} onClick={() => void fill()}>{t("playbooks.render")}</button>}
      {error && <p role="alert" style={{ color: "var(--md-accent-red)" }}>{error}</p>}
    </div>
  );
}

/**
 * Memoized: the reducer keeps every settled item's identity on a streamed token, so only
 * the bubble that is still streaming re-renders (onDecide is a stable store action).
 */
const Bubble = memo(function Bubble({ item, onDecide }: { item: TranscriptItem; onDecide: ReturnType<typeof useAgentChat>["sendApproval"] }) {
  const { t } = useTranslation("agent");
  switch (item.kind) {
    case "user":
      return (
        <div className="self-end max-w-[90%] rounded p-2 bg-[var(--md-bg-selected)] text-xs whitespace-pre-wrap break-words" data-testid="user-bubble">
          <span className="sr-only">{t("chat.you")}: </span>{item.text}
        </div>
      );
    case "assistant":
      return (
        <div className="max-w-[95%] rounded p-2 bg-[var(--md-bg-secondary)]" data-testid="assistant-bubble" aria-busy={item.streaming}>
          <span className="sr-only">{t("chat.assistant")}: </span><EvidenceText text={item.text} />
        </div>
      );
    case "tool": return <ToolCallCard item={item} />;
    case "approval": return <ApprovalCard item={item} onDecide={onDecide} />;
    case "error":
      return <p role="alert" className="text-xs" style={{ color: "var(--md-accent-red)" }}>{t("chat.error", { code: item.code, message: item.message })}</p>;
  }
});

export function AgentChatPanel() {
  const { t } = useTranslation("agent");
  const chat = useAgentChat();
  const [draft, setDraft] = useState("");
  const endRef = useRef<HTMLDivElement>(null);
  useEffect(() => { endRef.current?.scrollIntoView?.({ block: "end" }); }, [chat.items]);

  const live = chat.state === "ready" || chat.state === "running";
  const canStart = !!chat.status?.available && chat.state !== "starting";
  const scope = chatScope();
  const send = () => { if (chat.sendMessage(draft)) setDraft(""); };
  const onKey = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) { e.preventDefault(); send(); }
  };

  return (
    <section aria-label={t("panelAria")} className="flex flex-col gap-2 p-2 h-full overflow-hidden">
      <AgentStatusBanner status={chat.status} error={chat.statusError} />
      <details className="shrink-0">
        <summary className="text-xs cursor-pointer">{t("settings.title")}</summary>
        {chat.bundle && (
          <div className="max-h-56 overflow-auto">
            <AgentSettingsForm bundle={chat.bundle} onSave={chat.saveSettings} />
          </div>
        )}
      </details>
      <div className="flex items-center gap-2 flex-wrap shrink-0">
        {!live ? (
          <button type="button" className={btn} disabled={!canStart} onClick={() => void chat.start()}>
            {chat.state === "starting" ? t("chat.starting") : t("chat.start")}
          </button>
        ) : (
          <button type="button" className={btn} onClick={() => void chat.endChat()}>{t("chat.end")}</button>
        )}
        <span className="text-[11px] md-text-muted" aria-live="polite">{t(`chat.state.${chat.state}`)}</span>
        <span className="text-[11px] md-text-muted">
          {scope.case_dir || scope.dump_paths
            ? t("chat.scope", { case: scope.case_dir ?? "-", count: scope.dump_paths?.length ?? 0 })
            : t("chat.noScope")}
        </span>
      </div>
      {chat.connectionError && chat.connectionError !== "connection" && (
        <p role="alert" className="text-xs" style={{ color: "var(--md-accent-red)" }}>{chat.connectionError}</p>
      )}
      <UsageMeter usage={chat.usage} />
      <div role="log" aria-label={t("chat.transcriptAria")} aria-live="polite"
        className="flex-1 min-h-24 overflow-auto flex flex-col gap-2">
        {chat.items.map((item, i) => <Bubble key={i} item={item} onDecide={chat.sendApproval} />)}
        {chat.state === "closed" && <p className="text-xs md-text-muted">{t("chat.closedNotice")}</p>}
        <div ref={endRef} />
      </div>
      <PlaybookMenu onText={setDraft} />
      <div className="flex flex-col gap-1 shrink-0">
        <label className="text-xs" htmlFor="agent-composer">{t("composer.label")}</label>
        <textarea id="agent-composer" rows={3} value={draft} disabled={!live} onKeyDown={onKey}
          onChange={(e) => setDraft(e.target.value)} placeholder={t("composer.placeholder")}
          className="w-full px-1 py-0.5 rounded border border-[var(--md-border)] bg-[var(--md-bg-primary)] text-xs" />
        <div className="flex gap-2">
          <button type="button" className={btn} disabled={!live || !draft.trim()} onClick={send}>{t("composer.send")}</button>
          {chat.state === "running" && (
            <button type="button" className={btn} onClick={() => chat.interrupt()}>{t("composer.interrupt")}</button>
          )}
        </div>
      </div>
    </section>
  );
}
