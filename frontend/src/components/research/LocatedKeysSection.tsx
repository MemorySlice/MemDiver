import { useState } from "react";
import { useTranslation } from "react-i18next";

import { locateKey, type DumpKeyLocation, type LocateKeyResponse } from "@/api/locate-key";
import { vol3ErrorOf } from "@/api/vol3";
import { ExportPluginButton } from "@/components/vol3/ExportPluginButton";
import { isHexSecret, maskSecret } from "@/components/vol3/synth-utils";
import { normalizeHex } from "@/utils/hex";
import { useDumpStore } from "@/stores/dump-store";

const BTN = "px-2 py-1 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] text-xs disabled:opacity-40";
const INPUT = "w-full px-1.5 py-1 rounded border border-[var(--md-border)] bg-[var(--md-bg-primary)] text-[10px] font-mono";

const presence = (row: DumpKeyLocation) =>
  row.present === true ? "found" : row.present === false ? "absent" : "unknown";

/**
 * Locate a KNOWN key in the loaded dumps (`POST /api/analysis/locate-key`) and
 * export it, from any dump that holds it, as a Volatility 3 plugin. The key
 * lives in this component's state only and is shown masked.
 */
export function LocatedKeysSection({ dumpPaths }: { dumpPaths: readonly string[] }) {
  const { t } = useTranslation("vol3");
  const [secret, setSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [located, setLocated] = useState<{ response: LocateKeyResponse; secret: string } | null>(null);

  const locate = async () => {
    setBusy(true);
    setError(null);
    setLocated(null);
    const hex = normalizeHex(secret);
    try {
      const response = await locateKey({
        dump_paths: [...dumpPaths], secret_hex: hex, allocator: "off",
        // Dumps in a set share one container key; carry the first available one.
        ...useDumpStore.getState().getKeyMaterialByPath(dumpPaths[0]),
      });
      setLocated({ response, secret: hex });
    } catch (e) {
      const { code, message } = vol3ErrorOf(e);
      setError(code ? `${code}: ${message}` : message);
    } finally {
      setBusy(false);
    }
  };

  const holding = located?.response.dumps.filter((d) => d.present === true).map((d) => d.dump_path) ?? [];
  return (
    <section className="space-y-1" data-testid="located-keys" aria-label={t("locate.title")}>
      <p className="text-[10px] md-text-muted font-semibold">{t("locate.title")}</p>
      <p className="text-[10px] md-text-muted">{t("locate.hint")}</p>
      <div className="flex items-center gap-1">
        <input type="password" autoComplete="off" spellCheck={false} className={INPUT} value={secret}
          aria-label={t("locate.secret")} placeholder={t("locate.secretPlaceholder")}
          onChange={(e) => setSecret(e.target.value)} data-testid="locate-secret" />
        {secret && <span className="text-[10px] font-mono md-text-muted whitespace-nowrap"
          data-testid="locate-secret-mask">{maskSecret(secret)}</span>}
        <button type="button" className={BTN} disabled={busy || dumpPaths.length === 0 || !isHexSecret(secret)}
          onClick={() => void locate()} data-testid="locate-run">
          {busy ? t("locate.busy") : t("locate.run")}</button>
      </div>
      {error && <p role="alert" className="text-[10px] md-text-error" data-testid="locate-error">{error}</p>}
      {located && (
        <>
          <p role="status" className="text-[10px]" data-testid="locate-summary">
            {t(`locate.verdict.${located.response.verdict}`, {
              present: located.response.dumps_present, searched: located.response.dumps_searched,
            })}</p>
          <table className="w-full text-left text-[10px]" data-testid="locate-table">
            <caption className="sr-only">{t("locate.caption")}</caption>
            <thead className="md-text-secondary">
              <tr>{["dump", "status", "hits", "offset", "actions"].map((c) => (
                <th key={c} scope="col" className="px-1 py-0.5 font-normal">{t(`locate.col.${c}`)}</th>
              ))}</tr>
            </thead>
            <tbody>
              {located.response.dumps.map((row) => (
                <tr key={row.dump_path} data-testid="locate-row" data-present={String(row.present)}>
                  <td className="px-1 py-0.5 font-mono" title={row.dump_path}>{row.name}</td>
                  <td className="px-1 py-0.5">{t(`locate.presence.${presence(row)}`)}</td>
                  <td className="px-1 py-0.5">{row.hit_count}</td>
                  <td className="px-1 py-0.5 font-mono">
                    {row.first_offset === null ? "—" : `0x${row.first_offset.toString(16).toUpperCase()}`}</td>
                  <td className="px-1 py-0.5">
                    {row.present === true && (
                      <ExportPluginButton testId="locate-export"
                        ariaLabel={t("synth.buttonAria", { name: row.name })}
                        dumps={() => [row.dump_path, ...holding.filter((p) => p !== row.dump_path)]}
                        secretHex={() => located.secret} />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </section>
  );
}
