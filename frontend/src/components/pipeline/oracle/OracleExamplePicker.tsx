/**
 * Example oracle picker.
 *
 * Fetches the bundled oracles from ``docs/oracle_examples/`` via
 * ``GET /api/oracles/examples`` and renders them as selectable cards.
 * Example oracles are read-only server-side — they cannot be armed or
 * uploaded. A Phase 25 pipeline run always uses a server-vetted
 * example oracle OR a user-uploaded one armed via {@link OracleUpload}.
 *
 * The picker is used inside the "Oracle" wizard stage. Clicking a card
 * calls {@link onSelect} with the example filename; the parent stage
 * decides what to do with it (for v1 it simply informs the user the
 * example is a template to copy from since example oracles can't be
 * armed, and steers them to Upload instead).
 */

import { useEffect } from "react";
import { useTranslation } from "react-i18next";

import type { OracleExample } from "@/api/oracles";
import { useOracleStore } from "@/stores/oracle-store";

interface Props {
  selected: string | null;
  onSelect: (example: OracleExample) => void;
}

export function OracleExamplePicker({ selected, onSelect }: Props) {
  const { t } = useTranslation("pipeline");
  const examples = useOracleStore((s) => s.examples);
  const loading = useOracleStore((s) => s.loading);
  const error = useOracleStore((s) => s.error);
  const refresh = useOracleStore((s) => s.refresh);

  useEffect(() => {
    if (examples.length === 0) {
      void refresh();
    }
  }, [examples.length, refresh]);

  if (loading && examples.length === 0) {
    return (
      <p className="p-3 text-xs md-text-muted">{t("oracle.examples.loading")}</p>
    );
  }

  if (error && examples.length === 0) {
    return (
      <p className="p-3 text-xs md-text-error">
        {t("oracle.examples.loadError", { error })}
      </p>
    );
  }

  if (examples.length === 0) {
    return (
      <p className="p-3 text-xs md-text-muted">
        {t("oracle.examples.noneBundledPrefix")} <code>docs/oracle_examples/</code>.
      </p>
    );
  }

  return (
    <div className="space-y-2">
      <p className="text-xs md-text-muted">
        {t("oracle.examples.intro")} <code>.py</code>{" "}
        {t("oracle.examples.introMid")}{" "}
        <em>{t("oracle.examples.introUpload")}</em>{" "}
        {t("oracle.examples.introTail")}
      </p>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
        {examples.map((ex) => {
          const isSelected = selected === ex.filename;
          return (
            <button
              key={ex.filename}
              type="button"
              onClick={() => onSelect(ex)}
              className={`md-panel text-left p-3 space-y-1 transition-colors ${
                isSelected
                  ? "border-2 border-[var(--md-accent-blue)]"
                  : "hover:bg-[var(--md-bg-hover)]"
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="md-text-accent font-mono text-xs">
                  {ex.filename}
                </span>
                <span className="inline-block text-[10px] uppercase tracking-wide text-white rounded px-1.5 py-0.5 bg-[var(--md-accent-purple)]">
                  {t("oracle.examples.shape", { shape: ex.shape })}
                </span>
              </div>
              <div className="text-xs md-text-muted truncate">
                {ex.summary || t("oracle.examples.noSummary")}
              </div>
              <div className="text-[10px] md-text-muted font-mono">
                {t("oracle.examples.shaMeta", { sha: ex.sha256.slice(0, 12), size: ex.size })}
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
