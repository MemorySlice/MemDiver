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
 * An oracle smoke test sits below the active tab so the user can verify
 * their oracle actually DISCRIMINATES before committing to a full
 * 9000-candidate run. The samples are composed server-side from the dumps
 * picked on the previous stage -- this stage only forwards ``sourcePaths``
 * and the sweep's first key size.
 *
 * Layout note: the Back/Next row is pinned to the bottom of the scrolling
 * stage panel. It used to sit below the whole pcap block, far off-screen, and
 * users reported the stage as having no way forward at all.
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

interface Props {
  onAdvance: (next: WizardStage) => void;
}

export function StageOracle({ onAdvance }: Props) {
  const { t } = useTranslation("pipeline");
  const oracleId = usePipelineStore((s) => s.form.oracleId);
  const oracleSha256 = usePipelineStore((s) => s.form.oracleSha256);
  const pcapPath = usePipelineStore((s) => s.form.pcapPath);
  const tlsClientRandom = usePipelineStore((s) => s.form.tlsClientRandom);
  /*
    Read here, not inside the picker: the picker stays a dumb component that is
    told which dumps are in play. It hands them to the server, which derives a
    Shape 2 example's config from a sibling of the dump the user already picked
    -- so the config editor is not a form of questions nobody can answer.
  */
  const sourcePaths = usePipelineStore((s) => s.form.sourcePaths);
  /*
    Only the first key size is read, and only to size the smoke test's decoys:
    the sweep may enumerate several widths, but the bar tests one shape and the
    first is the one the run starts with.
  */
  const keySizes = usePipelineStore((s) => s.form.bruteForce.key_sizes);
  const updateForm = usePipelineStore((s) => s.updateForm);
  const uploaded = useOracleStore((s) => s.uploaded);
  const selectOracle = useOracleStore((s) => s.selectOracle);
  const clearOracleError = useOracleStore((s) => s.clearError);
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
   * Switch tabs, dropping whatever failure the departing tab left behind.
   *
   * ``useOracleStore.error`` is one field shared by upload, arm, load-example,
   * dry-run and delete, and both tabs render it. Without this, a refused
   * "Use this example" is still on screen after switching to Upload, where it
   * reads as a failed upload the user never attempted.
   */
  const handleTabChange = (next: OracleTab): void => {
    clearOracleError();
    setTab(next);
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
            onClick={() => handleTabChange(tabKey)}
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
              onClick={() => handleTabChange("upload")}
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
            sourcePaths={sourcePaths}
          />
        )}
      </div>

      <div className="pt-1" data-tour-id="pipeline-oracle-dryrun">
        {/*
          ``keySize`` follows the sweep's first configured width so the decoys
          the server cuts are the same shape as the candidates the oracle will
          really be handed. A smoke test at 32 bytes proves nothing about an
          oracle that is about to be fed 16-byte candidates.
        */}
        <OracleDryRunBar
          oracleId={oracleId}
          sourcePaths={sourcePaths}
          keySize={keySizes?.[0] ?? 32}
          negativeCount={15}
          onContinue={() => onAdvance("thresholds")}
        />
      </div>

      {/*
        Collapsed by default. This is the ALTERNATIVE route -- a first-party
        pcap oracle instead of a BYO one -- and expanded it ran to several
        screens of upload box, path field, session picker and field list, which
        is what pushed the Back/Next row out of sight entirely. Everything
        inside is unchanged; it is only closed until asked for.
      */}
      <details className="md-panel" data-tour-id="pipeline-oracle-pcap">
        <summary className="cursor-pointer text-xs md-text-secondary p-3">
          {t("stages.oracle.pcap.disclosure")}
        </summary>
        <div className="p-3 pt-0 space-y-2">
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
      </details>

      {/*
        Pinned to the bottom of PipelinePanel's scroll viewport.

        Reported bug: this row was the last child of a stage several screens
        tall, so on any normal window the user saw the pcap block and concluded
        the wizard was stuck. Sticky keeps the only two exits from the stage
        permanently on screen. The negative margins cancel the stage's `p-4` so
        the bar spans the full width and its top border reads as a real edge,
        and the opaque background stops content scrolling through it.
      */}
      <div className="sticky bottom-0 -mx-4 -mb-4 mt-2 px-4 py-2 border-t border-[var(--md-border)] bg-[var(--md-bg-primary)] space-y-1">
        {/*
          Stated, not hovered. The reason used to live only in the disabled
          button's `title`, which never appears on touch, never appears to a
          screen reader in any dependable way, and requires the user to suspect
          there is something to hover in the first place.
        */}
        {!canAdvance && (
          <p
            data-testid="oracle-next-blocked"
            className="text-[10px] md-text-warning"
          >
            {t("stages.oracle.nextTitleDisabled")}
          </p>
        )}
        <div className="flex justify-between items-center">
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
    </div>
  );
}
