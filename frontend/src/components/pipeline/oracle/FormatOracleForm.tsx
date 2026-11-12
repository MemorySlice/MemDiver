/**
 * "Add a built-in format oracle": pick one of the server's `format:<kind>`
 * oracles and a sample path, register it unarmed, then arm it with the same
 * controls as an uploaded file. No code is uploaded.
 */

import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { readableFailure } from "@/api/client";
import { addFormatOracle } from "@/api/oracles";
import { KNOWN_ORACLE_KINDS, listFormatOracles } from "@/api/vol3";
import { useOracleStore } from "@/stores/oracle-store";

export function FormatOracleForm() {
  const { t } = useTranslation("pipeline");
  const refresh = useOracleStore((s) => s.refresh);
  const [kinds, setKinds] = useState<readonly string[]>(KNOWN_ORACLE_KINDS);
  const [kind, setKind] = useState<string>(KNOWN_ORACLE_KINDS[0]);
  const [samplePath, setSamplePath] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    listFormatOracles()
      .then((r) => {
        if (!alive || r.formats.length === 0) return;
        const listed = r.formats.map((f) => f.kind);
        setKinds(listed);
        setKind((k) => (listed.includes(k) ? k : listed[0]));
      })
      .catch(() => { /* keep the offline fallback */ });
    return () => { alive = false; };
  }, []);

  async function handleAdd(): Promise<void> {
    setBusy(true);
    setError(null);
    try {
      await addFormatOracle(kind, samplePath.trim());
      await refresh();
    } catch (err) {
      setError(readableFailure(err));
    } finally {
      setBusy(false);
    }
  }

  const fieldClass = "w-full px-2 py-1 text-xs bg-[var(--md-bg-primary)] border border-[var(--md-border)] rounded";
  return (
    <div className="md-panel p-3 space-y-2" data-testid="format-oracle-form">
      <div className="text-xs md-text-muted font-semibold">{t("oracle.upload.format.heading")}</div>
      <div className="grid grid-cols-2 gap-2">
        <label className="text-xs md-text-muted space-y-0.5">
          <span>{t("oracle.upload.format.kind")}</span>
          <select className={fieldClass} value={kind} onChange={(e) => setKind(e.target.value)}
            data-testid="format-oracle-kind">
            {kinds.map((k) => <option key={k} value={k}>{k}</option>)}
          </select>
        </label>
        <label className="text-xs md-text-muted space-y-0.5">
          <span>{t("oracle.upload.format.samplePath")}</span>
          <input type="text" className={`${fieldClass} font-mono`} value={samplePath}
            placeholder={t("oracle.upload.format.samplePlaceholder")}
            onChange={(e) => setSamplePath(e.target.value)} data-testid="format-oracle-sample" />
        </label>
      </div>
      <button type="button" disabled={busy} onClick={() => void handleAdd()} data-testid="format-oracle-add"
        className="text-xs px-3 py-1 rounded bg-[var(--md-accent-blue)] md-text-on-accent disabled:opacity-50 hover:opacity-90">
        {busy ? t("oracle.upload.format.adding") : t("oracle.upload.format.add")}
      </button>
      {error && (
        <div className="text-xs md-text-error" data-testid="format-oracle-error">
          {t("oracle.upload.format.error", { error })}
        </div>
      )}
    </div>
  );
}
