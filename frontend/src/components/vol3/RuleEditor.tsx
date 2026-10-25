import { useState } from "react";
import { useTranslation } from "react-i18next";

import {
  DEFAULT_RULES, RULE_OPS, RULE_STYLES, isValidRegex, parseRuleValue,
  type HighlightRule, type RuleOp, type RuleStyle, type StoredRule,
} from "./highlight-rules";
import { RULE_MARKERS } from "./rule-markers";

const fieldClass =
  "px-1 py-0.5 text-xs rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)]";
const buttonClass =
  "px-2 py-1 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40";

const describe = (r: HighlightRule) =>
  `${r.table} · ${r.column} ${r.op} ${Array.isArray(r.value) ? r.value.join(", ") : String(r.value)}`;

function RuleItem({ rule, onDisable }: { rule: HighlightRule; onDisable?: () => void }) {
  const { t } = useTranslation("vol3");
  const marker = RULE_MARKERS[rule.style];
  return (
    <li className="flex items-center gap-2" data-testid="rule-item">
      <span style={{ color: `var(${marker.token})` }} title={t(`rules.style.${rule.style}`)}
        aria-label={t(`rules.style.${rule.style}`)}>{marker.glyph}</span>
      <span className="flex-1 truncate font-mono" title={describe(rule)}>{describe(rule)}
        {rule.also?.length ? ` +${rule.also.length}` : ""}</span>
      {onDisable
        ? <button type="button" className={buttonClass} onClick={onDisable} data-testid="rule-disable"
            aria-label={`${t("rules.disable")} ${rule.id}`}>{t("rules.disable")}</button>
        : <span className="md-text-muted">{t("rules.builtIn")}</span>}
    </li>
  );
}

/** List the built-in and stored rules; add a rule; disable (retract) a stored one. */
export function RuleEditor({ stored, ready, error, plugin, columns, onAdd, onDisable }: {
  stored: readonly StoredRule[];
  /** A case and a capture are known, so rules can be saved. */
  ready: boolean;
  error: string | null;
  /** Prefill for the new rule's table / column choices. */
  plugin: string;
  columns: readonly string[];
  onAdd: (rule: Omit<HighlightRule, "id">) => void;
  onDisable: (rule: StoredRule) => void;
}) {
  const { t } = useTranslation("vol3");
  const [table, setTable] = useState("");
  const [column, setColumn] = useState("");
  const [op, setOp] = useState<RuleOp>("eq");
  const [value, setValue] = useState("");
  const [style, setStyle] = useState<RuleStyle>("warn");
  const [invalid, setInvalid] = useState<"regex" | "fields" | null>(null);
  const tableText = table || plugin;
  const columnText = column || columns[0] || "";

  const submit = () => {
    if (!tableText.trim() || !columnText.trim()) { setInvalid("fields"); return; }
    if (op === "regex" && !isValidRegex(value)) { setInvalid("regex"); return; }
    setInvalid(null);
    onAdd({ table: tableText.trim(), column: columnText.trim(), op, value: parseRuleValue(op, value), style });
    setValue("");
  };

  return (
    <div className="space-y-2" data-testid="rule-editor">
      {error && <p role="alert" style={{ color: "var(--md-accent-red)" }}>{error}</p>}
      <ul className="space-y-0.5">
        {DEFAULT_RULES.map((r) => <RuleItem key={r.id} rule={r} />)}
        {stored.map((r) => <RuleItem key={r.entryId} rule={r} onDisable={() => onDisable(r)} />)}
      </ul>
      {!ready && <p className="md-text-muted" data-testid="rules-need-case">{t("rules.needCase")}</p>}
      <div className="flex flex-wrap items-center gap-1">
        <input value={tableText} onChange={(e) => setTable(e.target.value)} className={`${fieldClass} w-28`}
          aria-label={t("rules.table")} placeholder={t("rules.table")} data-testid="rule-table" />
        <input value={columnText} onChange={(e) => setColumn(e.target.value)} className={`${fieldClass} w-24`}
          aria-label={t("rules.column")} placeholder={t("rules.column")} data-testid="rule-column" list="vol3-rule-columns" />
        <datalist id="vol3-rule-columns">{columns.map((c) => <option key={c} value={c} />)}</datalist>
        <select value={op} onChange={(e) => setOp(e.target.value as RuleOp)} className={fieldClass}
          aria-label={t("rules.op")} data-testid="rule-op">
          {RULE_OPS.map((o) => <option key={o} value={o}>{t(`rules.ops.${o}`)}</option>)}
        </select>
        <input value={value} onChange={(e) => setValue(e.target.value)} className={`${fieldClass} w-28`}
          aria-label={t("rules.value")} placeholder={t("rules.value")} data-testid="rule-value" />
        <select value={style} onChange={(e) => setStyle(e.target.value as RuleStyle)} className={fieldClass}
          aria-label={t("rules.styleLabel")} data-testid="rule-style">
          {RULE_STYLES.map((s) => <option key={s} value={s}>{RULE_MARKERS[s].glyph} {t(`rules.style.${s}`)}</option>)}
        </select>
        <button type="button" className={buttonClass} disabled={!ready} onClick={submit}
          data-testid="rule-add">{t("rules.add")}</button>
      </div>
      {invalid && <p role="alert" data-testid="rule-invalid" style={{ color: "var(--md-accent-red)" }}>
        {t(`rules.invalid.${invalid}`)}</p>}
    </div>
  );
}
