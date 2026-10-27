import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { readableFailure } from "@/api/client";
import type { AgentSettings, AgentSettingsBundle, NumericSettingName } from "@/api/agent";

const NUMERIC: { name: NumericSettingName; label: string }[] = [
  { name: "max_turns", label: "settings.maxTurns" },
  { name: "max_budget_usd", label: "settings.maxBudget" },
  { name: "result_budget_bytes", label: "settings.resultBudget" },
];

type Draft = Record<keyof AgentSettings, string>;
const toDraft = (s: AgentSettings): Draft => ({
  model: s.model, effort: s.effort, max_turns: String(s.max_turns),
  max_budget_usd: String(s.max_budget_usd), result_budget_bytes: String(s.result_budget_bytes),
});

function numericProblem(raw: string, name: NumericSettingName, [lo, hi]: [number, number]): boolean {
  const v = Number(raw);
  if (raw.trim() === "" || !Number.isFinite(v) || v < lo || v > hi) return true;
  return name !== "max_budget_usd" && !Number.isInteger(v);
}

export function AgentSettingsForm({ bundle, onSave }: {
  bundle: AgentSettingsBundle; onSave: (changes: Partial<AgentSettings>) => Promise<void>;
}) {
  const { t } = useTranslation("agent");
  const [draft, setDraft] = useState<Draft>(() => toDraft(bundle.settings));
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  useEffect(() => { setDraft(toDraft(bundle.settings)); }, [bundle.settings]);

  const problems = NUMERIC.filter((n) => numericProblem(draft[n.name], n.name, bundle.limits[n.name]));
  const set = (k: keyof AgentSettings, v: string) => { setDraft((d) => ({ ...d, [k]: v })); setMessage(null); };

  const submit = async (changes: Partial<AgentSettings>) => {
    try { await onSave(changes); setMessage({ ok: true, text: t("settings.saved") }); }
    catch (e) { setMessage({ ok: false, text: t("settings.saveFailed", { error: readableFailure(e) }) }); }
  };
  const save = () => void submit({
    model: draft.model, effort: draft.effort, max_turns: Number(draft.max_turns),
    max_budget_usd: Number(draft.max_budget_usd), result_budget_bytes: Number(draft.result_budget_bytes),
  });
  const input = "w-full px-1 py-0.5 rounded border border-[var(--md-border)] bg-[var(--md-bg-primary)]";

  const select = (name: "model" | "effort", label: string) => (
    <label className="block">
      <span>{t(label)}</span>
      <select className={input} value={draft[name]} onChange={(e) => set(name, e.target.value)}>
        {bundle.choices[name].map((c) => <option key={c} value={c}>{c}</option>)}
      </select>
      <span className="md-text-muted">{t("settings.choiceDefault", { value: bundle.defaults[name] })}</span>
    </label>
  );

  return (
    <form data-testid="agent-settings" className="space-y-2 text-xs"
      onSubmit={(e) => { e.preventDefault(); if (problems.length === 0) save(); }}>
      <h3 className="font-semibold">{t("settings.title")}</h3>
      {bundle.warning && <p role="note" style={{ color: "var(--md-accent-orange)" }}>{t("settings.warning")}</p>}
      {select("model", "settings.model")}
      {select("effort", "settings.effort")}
      {NUMERIC.map(({ name, label }) => {
        const [lo, hi] = bundle.limits[name];
        const bad = numericProblem(draft[name], name, [lo, hi]);
        const id = `agent-setting-${name}`;
        return (
          <div key={name}>
            <label htmlFor={id}>{t(label)}</label>
            <input id={id} className={input} inputMode="decimal" value={draft[name]}
              aria-invalid={bad} aria-describedby={`${id}-hint`} onChange={(e) => set(name, e.target.value)} />
            <span id={`${id}-hint`} className={bad ? "" : "md-text-muted"}
              style={bad ? { color: "var(--md-accent-red)" } : undefined} role={bad ? "alert" : undefined}>
              {bad ? t("settings.invalid", { low: lo, high: hi }) : t("settings.range", { low: lo, high: hi, default: bundle.defaults[name] })}
            </span>
          </div>
        );
      })}
      <div className="flex gap-2">
        <button type="submit" disabled={problems.length > 0}
          className="px-2 py-1 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-50">
          {t("settings.save")}
        </button>
        <button type="button" onClick={() => void submit({ ...bundle.defaults })}
          className="px-2 py-1 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]">
          {t("settings.reset")}
        </button>
      </div>
      {message && (
        <p role="status" style={{ color: message.ok ? "var(--md-accent-green)" : "var(--md-accent-red)" }}>{message.text}</p>
      )}
    </form>
  );
}
