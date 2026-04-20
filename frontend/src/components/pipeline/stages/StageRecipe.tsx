/**
 * Stage 0 — recipe picker.
 *
 * For v1 we ship two built-in starting points:
 *
 *  - **Blank**: empty form, user fills in everything. The default for
 *    power users who already know what they're pointing at.
 *  - **Replicate gocryptfs DFRWS**: pre-populated with the thresholds
 *    from the paper's section 4.2 so a peer reviewer can reproduce
 *    the published numbers in one click. Dump paths remain empty —
 *    they need to come from disk.
 *
 * Recipe *save/load* (localStorage + JSON import/export) is deferred
 * to a later sub-phase when `recipe-store.ts` lands. This stage is the
 * placeholder that hooks in cleanly once that store exists.
 */

import type { WizardStage } from "@/stores/pipeline-store";
import { usePipelineStore } from "@/stores/pipeline-store";

const GOCRYPTFS_RECIPE = {
  reduce: {
    alignment: 8,
    block_size: 32,
    density_threshold: 0.5,
    min_variance: 1500.0,
    entropy_window: 32,
    entropy_threshold: 4.5,
    min_region: 16,
  },
  bruteForce: {
    key_sizes: [32],
    stride: 8,
    jobs: 1,
    exhaustive: true,
    top_k: 10,
  },
};

interface Props {
  onAdvance: (next: WizardStage) => void;
}

export function StageRecipe({ onAdvance }: Props) {
  const updateForm = usePipelineStore((s) => s.updateForm);

  function startBlank(): void {
    onAdvance("dumps");
  }

  function startGocryptfs(): void {
    updateForm({
      reduce: GOCRYPTFS_RECIPE.reduce,
      bruteForce: GOCRYPTFS_RECIPE.bruteForce,
    });
    onAdvance("dumps");
  }

  return (
    <div className="p-4 space-y-3">
      <div>
        <h3 className="text-sm font-semibold md-text-accent">
          Start your pipeline
        </h3>
        <p className="text-xs md-text-muted">
          Pick a starting point. You can still edit every field on the
          following steps.
        </p>
      </div>

      <div
        className="grid grid-cols-1 md:grid-cols-2 gap-3"
        data-tour-id="pipeline-recipe-card"
      >
        <button
          type="button"
          onClick={startBlank}
          className="md-panel p-4 text-left hover:bg-[var(--md-bg-hover)] transition-colors"
        >
          <div className="md-text-accent font-semibold text-sm mb-1">
            Start blank
          </div>
          <div className="text-xs md-text-muted">
            Empty form. Bring your own dumps and oracle; set every
            threshold yourself. Best for power users running on a new
            target.
          </div>
        </button>

        <button
          type="button"
          data-tour-id="pipeline-recipe-gocryptfs"
          onClick={startGocryptfs}
          className="md-panel p-4 text-left hover:bg-[var(--md-bg-hover)] transition-colors"
        >
          <div className="md-text-accent font-semibold text-sm mb-1">
            Replicate gocryptfs DFRWS result
          </div>
          <div className="text-xs md-text-muted">
            Loads the thresholds from the DFRWS paper's section 4.2
            (variance ≥ 1500, 8-byte alignment, entropy ≥ 4.5). Point
            it at <code>dataset_gocryptfs/run_*</code> and upload the
            gocryptfs oracle on the next step to reproduce both
            verified hits.
          </div>
        </button>
      </div>

      <p className="text-[10px] md-text-muted">
        Recipe save / load / share is planned for a later release; for
        now the two presets above cover the DFRWS demo and the blank
        starting point.
      </p>
    </div>
  );
}
