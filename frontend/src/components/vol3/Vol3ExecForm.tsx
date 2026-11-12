import { useState } from "react";
import { useTranslation } from "react-i18next";

import { execVol3Plugin, vol3ErrorOf, type Vol3ExecResult } from "@/api/vol3";
import { ApiErrorHint } from "@/components/common/ApiErrorHint";
import { ExportPluginButton } from "./ExportPluginButton";
import { SynthExecResult } from "./SynthExecResult";
import { buttonClass, inputClass } from "./styles";
import { lines, shellSplit } from "./synth-utils";

/**
 * A `.msl` (or any image stock vol reads) run by plugin NAME under stock `vol`
 * (`POST /api/vol3/exec`): the in-process runner above needs an `.mdview`,
 * while `vol -f <x>.msl` works through MemDiver's own vol3 plugins.
 */
export function Vol3ExecForm({ imagePath, caseDir }: { imagePath: string; caseDir: string }) {
  const { t } = useTranslation("vol3");
  const [plugin, setPlugin] = useState("msl.info");
  const [pluginDirs, setPluginDirs] = useState("");
  const [args, setArgs] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<{ text: string; code?: string } | null>(null);
  const [result, setResult] = useState<Vol3ExecResult | null>(null);

  const run = async () => {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await execVol3Plugin({
        plugin: plugin.trim(), image_path: imagePath, plugin_dirs: lines(pluginDirs), args: shellSplit(args),
      }));
    } catch (e) {
      const { code, message } = vol3ErrorOf(e);
      setError({ text: code ? `${code}: ${message}` : message, code: code ?? undefined });
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="space-y-2" data-testid="vol3-exec-form" aria-label={t("exec.title")}>
      <p className="font-medium">{t("exec.title")}</p>
      <p className="md-text-muted">{t("exec.mslHint")}</p>
      <p className="font-mono md-text-secondary break-all" data-testid="vol3-exec-image">{imagePath}</p>
      <label className="block space-y-0.5"><span className="md-text-secondary">{t("exec.plugin")}</span>
        <input type="text" className={`${inputClass} font-mono`} value={plugin}
          onChange={(e) => setPlugin(e.target.value)} data-testid="vol3-exec-plugin" /></label>
      <label className="block space-y-0.5"><span className="md-text-secondary">{t("exec.pluginDirs")}</span>
        <textarea rows={2} className={`${inputClass} font-mono`} value={pluginDirs}
          onChange={(e) => setPluginDirs(e.target.value)} data-testid="vol3-exec-plugin-dirs" /></label>
      <label className="block space-y-0.5"><span className="md-text-secondary">{t("exec.args")}</span>
        <input type="text" className={`${inputClass} font-mono`} value={args}
          onChange={(e) => setArgs(e.target.value)} data-testid="vol3-exec-args" /></label>
      <div className="flex flex-wrap gap-2">
        <button type="button" className={buttonClass} disabled={busy || plugin.trim() === ""}
          onClick={() => void run()} data-testid="vol3-exec-run">{busy ? t("exec.busy") : t("exec.run")}</button>
        <ExportPluginButton dumps={() => [imagePath]} caseDir={caseDir} testId="vol3-export-plugin" />
      </div>
      {error && (
        <>
          <p role="alert" data-testid="vol3-exec-error" style={{ color: "var(--md-accent-red)" }}>{error.text}</p>
          <ApiErrorHint code={error.code} />
        </>
      )}
      {result && <SynthExecResult result={result} />}
    </section>
  );
}
