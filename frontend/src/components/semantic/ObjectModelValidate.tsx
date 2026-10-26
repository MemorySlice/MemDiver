import { useState } from "react";
import { useTranslation } from "react-i18next";

import { readableFailure } from "@/api/client";
import {
  validateArtifactModel, type ValidateModelRequest, type ValidateModelResult,
} from "@/api/semantic";
import { KeylogFilePicker, type LoadedKeylog } from "./KeylogInput";
import { leakedPaths, verdictColorVar } from "./object-model-helpers";
import { KeylogParseReport } from "./ObjectModelResults";

const inputClass =
  "w-full px-1 py-0.5 text-xs rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)]";
const buttonClass =
  "px-2 py-1 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40";
const cell = "px-1 py-0.5 text-left align-top";
const KNOWN_VERDICTS = ["pass", "fail", "indeterminate"];

interface Row { id: number; dump: string; keylog: string }
type SharedMode = "perRow" | "file" | "path";

/** Pass is the only success styling; indeterminate and anything unknown stay muted. */
export function VerdictBadge({ verdict }: { verdict: string }) {
  const { t } = useTranslation("objectModel");
  return (
    <span
      data-testid="verdict-badge" data-verdict={verdict}
      className={`px-1 rounded text-[10px] border ${verdict === "indeterminate" ? "border-dashed" : "border-current"}`}
      style={{ color: verdictColorVar(verdict) }}
    >
      {KNOWN_VERDICTS.includes(verdict) ? t(`validate.verdict.${verdict}`) : t("validate.unknownVerdict", { verdict })}
    </span>
  );
}

export function ValidateSection({ modelPath, learnedOn }: { modelPath: string; learnedOn: string[] }) {
  const { t } = useTranslation("objectModel");
  const [rows, setRows] = useState<Row[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ValidateModelResult | null>(null);
  const [sharedMode, setSharedMode] = useState<SharedMode>("perRow");
  const [sharedFile, setSharedFile] = useState<LoadedKeylog | null>(null);
  const [sharedPath, setSharedPath] = useState("");
  const leaked = leakedPaths(rows.map((r) => r.dump), learnedOn);
  const patch = (id: number, change: Partial<Row>) =>
    setRows(rows.map((r) => (r.id === id ? { ...r, ...change } : r)));

  /** One shared key log (file or path) for every held-out dump, or one per row. */
  const validateBody = (): ValidateModelRequest | null => {
    if (sharedMode === "perRow") {
      const held = rows.filter((r) => r.dump.trim() !== "" && r.keylog.trim() !== "");
      if (held.length === 0) { setError(t("validate.needEntries")); return null; }
      return {
        model_path: modelPath,
        held_out: held.map((r) => ({ dump_path: r.dump.trim(), keylog_path: r.keylog.trim() })),
      };
    }
    const held = rows.filter((r) => r.dump.trim() !== "");
    if (held.length === 0) { setError(t("validate.needDumps")); return null; }
    const keylog = sharedMode === "file"
      ? (sharedFile ? { text: sharedFile.text } : null)
      : (sharedPath.trim() !== "" ? { path: sharedPath.trim() } : null);
    if (keylog === null) { setError(t("validate.needSharedKeylog")); return null; }
    return { model_path: modelPath, held_out: held.map((r) => ({ dump_path: r.dump.trim() })), keylog };
  };

  const run = async () => {
    setError(null);
    const body = validateBody();
    if (body === null) return;
    setBusy(true);
    try {
      setResult(await validateArtifactModel(body));
    } catch (e) {
      setResult(null);
      setError(t("validate.refused", { message: readableFailure(e) }));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="flex flex-col gap-1 border-t border-[var(--md-border)] pt-2" data-testid="validate-model">
      <h4 className="font-semibold">{t("validate.title")}</h4>
      <select aria-label={t("validate.keylogMode")} className={inputClass} value={sharedMode}
        onChange={(e) => setSharedMode(e.target.value as SharedMode)}>
        {(["perRow", "file", "path"] as const).map((m) => (
          <option key={m} value={m}>{t(`validate.keylogModes.${m}`)}</option>
        ))}
      </select>
      {sharedMode !== "perRow" && <p className="md-text-muted">{t("keylog.explain")}</p>}
      {sharedMode === "file" && (
        <KeylogFilePicker loaded={sharedFile} onLoaded={setSharedFile} />
      )}
      {sharedMode === "path" && (
        <input aria-label={t("validate.sharedPath")} placeholder={t("validate.sharedPath")}
          className={inputClass} value={sharedPath} onChange={(e) => setSharedPath(e.target.value)} />
      )}
      {rows.map((r) => (
        <div key={r.id} className="flex flex-col gap-0.5 border-l border-[var(--md-border)] pl-1">
          <div className="flex gap-1">
            <input aria-label={t("validate.dump")} placeholder={t("validate.dump")} className={inputClass}
              value={r.dump} onChange={(e) => patch(r.id, { dump: e.target.value })} />
            {sharedMode === "perRow" && (
              <input aria-label={t("validate.keylog")} placeholder={t("validate.keylog")} className={inputClass}
                value={r.keylog} onChange={(e) => patch(r.id, { keylog: e.target.value })} />
            )}
            <button className={buttonClass} onClick={() => setRows(rows.filter((x) => x.id !== r.id))}>
              {t("validate.remove")}
            </button>
          </div>
          {leaked.has(r.dump.trim()) && (
            <p role="alert" data-testid="leak-warning" className="text-[var(--md-variance-key-candidate)]">
              {t("validate.leakWarning", { dump: r.dump.trim() })}
            </p>
          )}
        </div>
      ))}
      <div className="flex gap-1">
        <button className={buttonClass}
          onClick={() => setRows([...rows, { id: rows.reduce((m, r) => Math.max(m, r.id), 0) + 1, dump: "", keylog: "" }])}>
          {t("validate.add")}
        </button>
        <button className={buttonClass} disabled={busy} onClick={() => void run()}>
          {busy ? t("actions.running") : t("validate.action")}
        </button>
      </div>
      {error && <p role="alert" data-testid="validate-error" className="text-[var(--md-variance-key-candidate)]">{error}</p>}
      {result && <ValidationTable result={result} />}
    </section>
  );
}

function ValidationTable({ result }: { result: ValidateModelResult }) {
  const { t } = useTranslation("objectModel");
  const tot = result.totals;
  return (
    <div data-testid="validate-result">
      <p>{t("validate.verdictLabel")}: <VerdictBadge verdict={result.verdict} /></p>
      {(result.keylog_summary ?? []).map((summary, i) => (
        <KeylogParseReport key={i} summary={summary} />
      ))}
      <table className="w-full text-xs">
        <thead><tr>
          {["capture", "expected", "tp", "fp", "fn", "relationships", "detail"].map((k) => (
            <th key={k} className={cell}>{t(`validate.${k}`)}</th>
          ))}
        </tr></thead>
        <tbody>
          {result.captures.map((c) => (
            <tr key={c.capture} data-testid="validate-row" data-verdict={c.verdict ?? ""}>
              <td className={cell} title={c.capture}>{c.capture}</td>
              <td className={cell}>{c.expected}</td>
              <td className={cell}>{c.true_positives}</td>
              <td className={cell}>{c.false_positives}</td>
              <td className={cell}>{c.false_negatives}</td>
              <td className={cell}>{c.relationships_correct}/{c.relationships_checked}</td>
              <td className={cell}>
                {c.verdict !== undefined && <VerdictBadge verdict={c.verdict} />}{" "}
                {c.verdict === "indeterminate" && (
                  <span data-testid="indeterminate-note">{t("validate.indeterminateNote")} </span>
                )}
                {c.detail}
              </td>
            </tr>
          ))}
          <tr data-testid="validate-totals" className="font-semibold">
            <td className={cell}>{t("validate.totals")}</td>
            <td className={cell}>{tot.expected}</td>
            <td className={cell}>{tot.tp}</td>
            <td className={cell}>{tot.fp}</td>
            <td className={cell}>{tot.fn}</td>
            <td className={cell}>{tot.relationships_correct}/{tot.relationships_checked}</td>
            <td className={cell} />
          </tr>
        </tbody>
      </table>
    </div>
  );
}
