/**
 * Stage 2 — oracle workbench composition.
 *
 * Three sub-tabs:
 *  - **Upload** — drop a .py, arm it by sha256. This is the path that
 *    produces an armed oracle the pipeline actually runs.
 *  - **Examples** — browse bundled templates under
 *    ``docs/oracle_examples/``. These are read-only; clicking one
 *    jumps the user back to Upload with a hint to copy the template.
 *  - **Help** — collapsible Shape 1 vs Shape 2 explainer.
 *
 * An oracle "dry-run" smoke test sits below the active tab so the
 * user can verify their uploaded oracle responds before committing
 * to a full 9000-candidate run.
 */

import { useState } from "react";

import type { OracleExample } from "@/api/oracles";
import { OracleDryRunBar } from "@/components/pipeline/oracle/OracleDryRunBar";
import { OracleExamplePicker } from "@/components/pipeline/oracle/OracleExamplePicker";
import { OracleShapeExplainer } from "@/components/pipeline/oracle/OracleShapeExplainer";
import { OracleUpload } from "@/components/pipeline/oracle/OracleUpload";
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
  const oracleId = usePipelineStore((s) => s.form.oracleId);
  const oracleSha256 = usePipelineStore((s) => s.form.oracleSha256);
  const uploaded = useOracleStore((s) => s.uploaded);
  const [tab, setTab] = useState<OracleTab>("upload");
  const [exampleHint, setExampleHint] = useState<string | null>(null);

  const activeEntry = uploaded.find((o) => o.id === oracleId) ?? null;
  const canAdvance = !!activeEntry && activeEntry.armed && !!oracleSha256;

  const handleExample = (ex: OracleExample): void => {
    setExampleHint(ex.filename);
    setTab("upload");
  };

  return (
    <div className="p-4 space-y-3">
      <div>
        <h3 className="text-sm font-semibold md-text-accent">
          Pick or upload your oracle
        </h3>
        <p className="text-xs md-text-muted">
          The oracle is your decryption check. Upload a <code>.py</code>{" "}
          file that exports <code>verify(candidate)</code> or{" "}
          <code>build_oracle(cfg)</code>, then arm it. The armed file's
          sha256 is what the worker runs.
        </p>
      </div>

      <div data-tour-id="pipeline-oracle-help">
        <OracleShapeExplainer />
      </div>

      <div className="flex gap-2 border-b border-[var(--md-border)]">
        {(["upload", "examples"] as const).map((t) => (
          <button
            key={t}
            type="button"
            onClick={() => setTab(t)}
            className={`text-xs px-3 py-1.5 capitalize transition-colors ${
              tab === t
                ? "font-semibold border-b-2 border-[var(--md-accent-blue)] md-text-accent"
                : "md-text-muted hover:md-text-secondary"
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      {exampleHint && tab === "upload" && (
        <div className="md-panel p-2 text-xs md-text-muted">
          Copy <code className="md-text-accent">{exampleHint}</code> from{" "}
          <code>docs/oracle_examples/</code>, tweak it for your dataset,
          then drop the edited file below to upload + arm it.
        </div>
      )}

      {tab === "upload" && <OracleUpload />}
      {tab === "examples" && (
        <OracleExamplePicker
          selected={exampleHint}
          onSelect={handleExample}
        />
      )}

      <div className="pt-1" data-tour-id="pipeline-oracle-dryrun">
        <OracleDryRunBar oracleId={oracleId} samplesB64={DRY_RUN_SAMPLES} />
      </div>

      <div className="flex justify-between items-center pt-2">
        <button
          type="button"
          onClick={() => onAdvance("dumps")}
          className="text-xs px-3 py-1.5 rounded bg-[var(--md-bg-hover)] md-text-secondary hover:bg-[var(--md-border)]"
        >
          ← Back
        </button>
        <button
          type="button"
          disabled={!canAdvance}
          onClick={() => onAdvance("thresholds")}
          className="text-xs px-3 py-1.5 rounded bg-[var(--md-accent-blue)] text-white disabled:opacity-50"
          title={
            canAdvance
              ? "Continue to threshold configuration"
              : "Upload and arm an oracle to continue"
          }
        >
          Next: Thresholds →
        </button>
      </div>
    </div>
  );
}
