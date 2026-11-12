import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import {
  execVol3Plugin, getVol3PluginDir, vol3ErrorOf,
  type Vol3ExecResult, type Vol3SynthesizeResult, type Vol3SynthStatus, type Vol3SynthVerdict, type Vol3Verdict,
} from "@/api/vol3";
import { SynthExecResult } from "./SynthExecResult";
import { VerdictBadge } from "./VerdictBadge";
import { buttonClass } from "./styles";
import { execRequestForVerdict } from "./synth-utils";

const BADGE: Record<Vol3SynthStatus, Vol3Verdict> = {
  proven: "pass", not_proven: "fail", error: "indeterminate",
};

/** The dump's directory and file name: runs of one dataset share the file name. */
const shortPath = (path: string) => path.split(/[\\/]/).filter(Boolean).slice(-2).join("/") || path;

function downloadSource(source: string, fileName: string) {
  const url = URL.createObjectURL(new Blob([source], { type: "text/x-python" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = fileName;
  a.click();
  URL.revokeObjectURL(url);
}

type ExecState =
  | { status: "idle" }
  | { status: "running"; index: number }
  | { status: "done"; index: number; result: Vol3ExecResult }
  | { status: "error"; index: number; code: string | null; message: string };

/**
 * What `POST /api/vol3/synthesize` answered: a badge per verify target, the
 * Proven count, diagnostics, the source, and "Run under vol" per target, which
 * reruns the target's own `vol_command` through `POST /api/vol3/exec`.
 */
export function SynthesizeResult({ result }: { result: Vol3SynthesizeResult }) {
  const { t } = useTranslation("vol3");
  const [pluginDir, setPluginDir] = useState<string | null | undefined>(undefined);
  const [exec, setExec] = useState<ExecState>({ status: "idle" });
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let live = true;
    getVol3PluginDir().then((d) => live && setPluginDir(d.path)).catch(() => live && setPluginDir(null));
    return () => { live = false; };
  }, []);

  const runUnderVol = async (verdict: Vol3SynthVerdict, index: number) => {
    setExec({ status: "running", index });
    const req = execRequestForVerdict(result, verdict, pluginDir ?? null);
    try {
      // Without the installed dir's path the command's own -p list is replayed as is.
      const answer = await execVol3Plugin(pluginDir ? req : { ...req, include_memdiver_plugins: false });
      setExec({ status: "done", index, result: answer });
    } catch (e) {
      setExec({ status: "error", index, ...vol3ErrorOf(e) });
    }
  };

  const copyCommand = async () => {
    try {
      await navigator.clipboard.writeText(result.vol_command);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };

  const fileName = `${result.recipe.name}.py`;
  return (
    <section className="space-y-2 text-xs" data-testid="synth-result" aria-label={t("synth.result.title")}>
      <div className="flex flex-wrap items-center gap-2">
        <VerdictBadge verdict={result.proven ? "pass" : "fail"}
          label={result.proven ? t("synth.status.proven") : t("synth.status.not_proven")} />
        <span data-testid="synth-proven-count">{t("synth.result.provenHits", { n: result.proven_hits })}</span>
        <span className="font-mono md-text-secondary">{result.recipe.name}.{result.recipe.class_name}</span>
      </div>
      {result.stored
        ? <p className="md-text-muted break-all" data-testid="synth-stored">{t("synth.result.stored", { path: result.stored.path })}</p>
        : <p className="md-text-muted" data-testid="synth-not-stored">{t("synth.result.notStored")}</p>}
      {result.self_test && (
        <p data-testid="synth-self-test" className="md-text-secondary">
          {result.self_test.error
            ? t("synth.result.selfTestError", { message: result.self_test.error })
            : t("synth.result.selfTest", { rows: result.self_test.rows, proven: result.self_test.proven })}
        </p>
      )}
      <table className="w-full text-left" data-testid="synth-verdicts">
        <caption className="sr-only">{t("synth.result.verdicts")}</caption>
        <thead className="md-text-secondary">
          <tr>{["verdict", "target", "dump", "rows", "proven", "actions"].map((c) => (
            <th key={c} scope="col" className="px-1 py-0.5 font-normal">{t(`synth.result.col.${c}`)}</th>
          ))}</tr>
        </thead>
        <tbody>
          {result.verdicts.map((v, i) => (
            <tr key={`${v.target}:${v.dump_path}:${i}`} data-testid="synth-verdict" data-status={v.status}>
              <td className="px-1 py-0.5"><VerdictBadge verdict={BADGE[v.status] ?? "indeterminate"}
                label={t(`synth.status.${v.status}`, { defaultValue: v.status })} /></td>
              <td className="px-1 py-0.5">{t(`synth.target.${v.target}`, { defaultValue: v.target })}</td>
              <td className="px-1 py-0.5 font-mono" title={v.dump_path}>{shortPath(v.dump_path)}</td>
              <td className="px-1 py-0.5">{v.rows}</td>
              <td className="px-1 py-0.5">{v.proven_hits.length}</td>
              <td className="px-1 py-0.5">
                <button type="button" className={buttonClass} data-testid="synth-run-under-vol"
                  disabled={exec.status === "running" || pluginDir === undefined}
                  aria-label={t("synth.result.runAria", { name: shortPath(v.dump_path) })}
                  onClick={() => void runUnderVol(v, i)}>{t("synth.result.run")}</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {result.verdicts.some((v) => v.error) && (
        <ul className="space-y-0.5" data-testid="synth-verdict-errors">
          {result.verdicts.filter((v) => v.error).map((v, i) => (
            <li key={i} style={{ color: "var(--md-accent-red)" }}>
              {v.error_code ? `${v.error_code}: ` : ""}{v.error}</li>
          ))}
        </ul>
      )}
      {result.verdicts.some((v) => v.pid_honoured === false) && (
        <p role="note" data-testid="synth-pid-not-honoured" style={{ color: "var(--md-accent-orange)" }}>
          {t("synth.result.pidNotHonoured")}</p>
      )}
      {result.diagnostics.length > 0 && (
        <details data-testid="synth-diagnostics" open={result.diagnostics.some((d) => d.severity !== "info")}>
          <summary className="cursor-pointer md-text-secondary">
            {t("synth.result.diagnostics", { n: result.diagnostics.length })}</summary>
          <ul className="space-y-0.5 pl-2">
            {result.diagnostics.map((d, i) => (
              <li key={`${d.code}:${i}`} data-testid="synth-diagnostic" data-severity={d.severity}>
                <span className="font-mono">{d.severity} · {d.code}</span> — {d.message}
              </li>
            ))}
          </ul>
        </details>
      )}
      <div className="flex flex-wrap gap-2">
        <button type="button" className={buttonClass} data-testid="synth-download"
          onClick={() => downloadSource(result.source, fileName)}>{t("synth.result.download", { file: fileName })}</button>
        <button type="button" className={buttonClass} data-testid="synth-copy-command"
          onClick={() => void copyCommand()}>{t("synth.result.copyCommand")}</button>
        {copied && <span role="status" className="md-text-muted" data-testid="synth-copied">{t("synth.result.copied")}</span>}
      </div>
      <pre className="text-[10px] p-1 rounded border border-[var(--md-border)] overflow-x-auto whitespace-pre-wrap break-all"
        data-testid="synth-vol-command">{result.vol_command}</pre>
      <details data-testid="synth-source">
        <summary className="cursor-pointer md-text-secondary">
          {t("synth.result.source", { lines: result.source.split("\n").length })}</summary>
        <pre className="text-[10px] p-1 rounded border border-[var(--md-border)] overflow-auto max-h-64">{result.source}</pre>
      </details>
      {exec.status === "running" && (
        <p role="status" data-testid="synth-exec-running">{t("exec.running", {
          name: shortPath(result.verdicts[exec.index]?.dump_path ?? "") })}</p>
      )}
      {exec.status === "error" && (
        <p role="alert" data-testid="synth-exec-error" style={{ color: "var(--md-accent-red)" }}>
          {exec.code ? `${exec.code}: ` : ""}{exec.message}</p>
      )}
      {exec.status === "done" && <SynthExecResult result={exec.result} />}
    </section>
  );
}
