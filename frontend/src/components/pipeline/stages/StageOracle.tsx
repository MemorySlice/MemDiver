/**
 * Stage 2 — oracle workbench composition.
 *
 * Three sub-tabs:
 *  - **Upload** — drop a .py, arm it by sha256. This is the path that
 *    produces an armed oracle the pipeline actually runs.
 *  - **Examples** — browse bundled templates under
 *    ``docs/oracle/examples/``. "Use this example" registers one
 *    server-side (with its config, for Shape 2) so it becomes an armed
 *    oracle without leaving the page; the hint to copy the template and
 *    upload an edited copy stays available beside it.
 *  - **Help** — collapsible Shape 1 vs Shape 2 explainer.
 *
 * An oracle "dry-run" smoke test sits below the active tab so the
 * user can verify their uploaded oracle responds before committing
 * to a full 9000-candidate run.
 */

import { useState } from "react";
import { useTranslation } from "react-i18next";

import {
  ORACLE_EXAMPLES_DIR,
  type OracleEntry,
  type OracleExample,
} from "@/api/oracles";
import { OracleDryRunBar } from "@/components/pipeline/oracle/OracleDryRunBar";
import { OracleExamplePicker } from "@/components/pipeline/oracle/OracleExamplePicker";
import { OracleShapeExplainer } from "@/components/pipeline/oracle/OracleShapeExplainer";
import { OracleUpload } from "@/components/pipeline/oracle/OracleUpload";
import { PcapUpload } from "@/components/pipeline/oracle/PcapUpload";
import { usePcapArm } from "@/components/pipeline/oracle/use-pcap-arm";
import type { WizardStage } from "@/stores/pipeline-store";
import { useOracleStore } from "@/stores/oracle-store";
import { usePipelineStore } from "@/stores/pipeline-store";

type OracleTab = "upload" | "examples";

// Sixteen short base64 samples for dry-run. In a real investigation a
// future enhancement will pull these from high-entropy regions of the
// first dump; for v1 we just use a deterministic pattern so the dots
// are always the same across runs and easy to debug.
const DRY_RUN_SAMPLES = Array.from({ length: 16 }, (_, i) => {
  const bytes = new Uint8Array(32);
  for (let j = 0; j < 32; j++) bytes[j] = (i * 31 + j) & 0xff;
  return btoa(String.fromCharCode(...bytes));
});

interface Props {
  onAdvance: (next: WizardStage) => void;
}

export function StageOracle({ onAdvance }: Props) {
  const { t } = useTranslation("pipeline");
  const oracleId = usePipelineStore((s) => s.form.oracleId);
  const oracleSha256 = usePipelineStore((s) => s.form.oracleSha256);
  const pcapPath = usePipelineStore((s) => s.form.pcapPath);
  const tlsClientRandom = usePipelineStore((s) => s.form.tlsClientRandom);
  const updateForm = usePipelineStore((s) => s.updateForm);
  const uploaded = useOracleStore((s) => s.uploaded);
  const selectOracle = useOracleStore((s) => s.selectOracle);
  // Same validate/arm flow the dropzone uses, driven here from a typed path.
  const { arm, isArming, error: armError } = usePcapArm();
  const [tab, setTab] = useState<OracleTab>("upload");
  const [exampleHint, setExampleHint] = useState<string | null>(null);

  const activeEntry = uploaded.find((o) => o.id === oracleId) ?? null;
  const hasArmedOracle = !!activeEntry && activeEntry.armed && !!oracleSha256;
  const hasPcap = !!pcapPath && pcapPath.trim().length > 0;
  const canArmPcap = hasPcap && !isArming;
  // Either oracle source unlocks the next stage; the run request sends whichever
  // is set (a pcap takes precedence when both happen to be filled).
  const canAdvance = hasArmedOracle || hasPcap;

  /**
   * A card was picked. This no longer switches tabs on its own.
   *
   * It used to, and that was the whole of the interaction: the user asked for
   * an example and got directions to a file on disk. The hint below still
   * offers that route -- someone who wants to EDIT the template first needs
   * it -- but the picker now also registers the example server-side, so the
   * tab must stay put for its config editor to be usable.
   */
  const handleExample = (ex: OracleExample): void => {
    setExampleHint(ex.filename);
  };

  /**
   * An example is now a real oracle server-side.
   *
   * The wizard form is what gates ``Next``: ``canAdvance`` reads
   * ``hasArmedOracle``, which needs BOTH ids. An unarmed entry deliberately
   * clears the sha -- the run endpoint only accepts an armed oracle, so
   * advertising one that is not armed would just fail later.
   */
  const handleExampleLoaded = (entry: OracleEntry): void => {
    selectOracle(entry.id);
    updateForm({
      oracleId: entry.id,
      oracleSha256: entry.armed ? entry.sha256 : null,
    });
  };

  return (
    <div className="p-4 space-y-3">
      <div>
        <h3 className="text-sm font-semibold md-text-accent">
          {t("stages.oracle.title")}
        </h3>
        <p className="text-xs md-text-muted">
          {t("stages.oracle.subtitlePrefix")} <code>.py</code>{" "}
          {t("stages.oracle.subtitleMid")} <code>verify(candidate)</code>{" "}
          {t("stages.oracle.subtitleOr")}{" "}
          <code>build_oracle(cfg)</code>
          {t("stages.oracle.subtitleTail")}
        </p>
      </div>

      <div data-tour-id="pipeline-oracle-help">
        <OracleShapeExplainer />
      </div>

      <div role="tablist" className="flex gap-2 border-b border-[var(--md-border)]">
        {(["upload", "examples"] as const).map((tabKey) => (
          <button
            key={tabKey}
            type="button"
            role="tab"
            aria-selected={tab === tabKey}
            onClick={() => setTab(tabKey)}
            className={`text-xs px-3 py-1.5 transition-colors ${
              tab === tabKey
                ? "font-semibold border-b-2 border-[var(--md-accent-blue)] md-text-accent"
                : "md-text-muted hover:md-text-secondary"
            }`}
          >
            {t(`stages.oracle.tab.${tabKey}`)}
          </button>
        ))}
      </div>

      {/*
        Shown on BOTH tabs now. On Examples it is the alternative to "Use this
        example" -- copy the template and edit it -- so it carries the jump to
        Upload that the click itself no longer performs.
      */}
      {exampleHint && (
        <div className="md-panel p-2 text-xs md-text-muted">
          {t("stages.oracle.exampleHintPrefix")}{" "}
          <code className="md-text-accent">{exampleHint}</code>{" "}
          {t("stages.oracle.exampleHintMid")}{" "}
          <code>{ORACLE_EXAMPLES_DIR}</code>
          {t("stages.oracle.exampleHintTail")}
          {tab === "examples" && (
            <button
              type="button"
              data-testid="oracle-example-goto-upload"
              onClick={() => setTab("upload")}
              className="ml-2 text-xs px-2 py-0.5 rounded bg-[var(--md-bg-hover)] md-text-secondary hover:bg-[var(--md-border)]"
            >
              {t("stages.oracle.exampleHintGoUpload")}
            </button>
          )}
        </div>
      )}

      <div role="tabpanel">
        {tab === "upload" && <OracleUpload />}
        {tab === "examples" && (
          <OracleExamplePicker
            selected={exampleHint}
            onSelect={handleExample}
            onLoaded={handleExampleLoaded}
          />
        )}
      </div>

      <div className="pt-1" data-tour-id="pipeline-oracle-dryrun">
        <OracleDryRunBar oracleId={oracleId} samplesB64={DRY_RUN_SAMPLES} />
      </div>

      <div className="md-panel p-3 space-y-2" data-tour-id="pipeline-oracle-pcap">
        <p className="text-xs md-text-muted">{t("stages.oracle.pcap.hint")}</p>
        <PcapUpload />
        {/*
          A typed path (or one restored from a reload -- ``form.pcapPath`` is
          persisted while ``pcapSessions`` is not) is inert until it has been
          validated: without arming, the session picker and the key-log
          composer's client_random prefill stay silently empty even though the
          run looks armed. The button beside the field runs that validation.
        */}
        <div className="space-y-1">
          <label
            htmlFor="pcap-path-input"
            className="block text-xs md-text-secondary"
          >
            {t("stages.oracle.pcap.pathLabel")}
          </label>
          <div className="flex gap-2 items-start">
            <input
              id="pcap-path-input"
              type="text"
              value={pcapPath ?? ""}
              onChange={(e) => updateForm({ pcapPath: e.target.value })}
              placeholder={t("stages.oracle.pcap.pathPlaceholder")}
              className="flex-1 min-w-0 text-xs px-2 py-1 rounded bg-[var(--md-bg-hover)] md-text-primary border border-[var(--md-border)]"
            />
            <button
              type="button"
              data-testid="pcap-arm-btn"
              disabled={!canArmPcap}
              aria-busy={isArming}
              onClick={() =>
                void arm((pcapPath ?? "").trim(), { clearPathOnFailure: false })
              }
              className="shrink-0 text-xs px-3 py-1 rounded bg-[var(--md-accent-blue)] md-text-on-accent disabled:opacity-50"
            >
              {isArming
                ? t("stages.oracle.pcap.arming")
                : t("stages.oracle.pcap.arm")}
            </button>
          </div>
          <p className="text-[10px] md-text-muted">
            {t("stages.oracle.pcap.armHint")}
          </p>
          {isArming && (
            <div data-testid="pcap-arm-status" className="text-xs md-text-muted">
              {t("stages.oracle.pcap.validating")}
            </div>
          )}
          {armError && (
            <div data-testid="pcap-arm-error" className="text-xs md-text-error">
              {t("stages.oracle.pcap.armError", { error: armError })}
            </div>
          )}
        </div>
        <label className="block text-xs md-text-secondary">
          {t("stages.oracle.pcap.clientRandomLabel")}
          <input
            type="text"
            value={tlsClientRandom ?? ""}
            onChange={(e) => updateForm({ tlsClientRandom: e.target.value })}
            placeholder={t("stages.oracle.pcap.clientRandomPlaceholder")}
            className="mt-1 w-full text-xs px-2 py-1 rounded bg-[var(--md-bg-hover)] md-text-primary border border-[var(--md-border)]"
          />
        </label>
      </div>

      <div className="flex justify-between items-center pt-2">
        <button
          type="button"
          onClick={() => onAdvance("dumps")}
          className="text-xs px-3 py-1.5 rounded bg-[var(--md-bg-hover)] md-text-secondary hover:bg-[var(--md-border)]"
        >
          {t("stages.oracle.back")}
        </button>
        <button
          type="button"
          disabled={!canAdvance}
          onClick={() => onAdvance("thresholds")}
          className="text-xs px-3 py-1.5 rounded bg-[var(--md-accent-blue)] md-text-on-accent disabled:opacity-50"
          title={
            canAdvance
              ? t("stages.oracle.nextTitleEnabled")
              : t("stages.oracle.nextTitleDisabled")
          }
        >
          {t("stages.oracle.next")}
        </button>
      </div>
    </div>
  );
}
