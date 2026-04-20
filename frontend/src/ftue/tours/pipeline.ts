import { useAppStore } from "@/stores/app-store";
import { useOracleStore } from "@/stores/oracle-store";
import type { Tour } from "../types";

/**
 * Pipeline-101 tour: walks a first-time user through the Phase 25
 * pipeline (consensus → reduce → oracle → n-sweep → emit-plugin).
 * Ungated — fires on first entry to the Pipeline bottom tab. The
 * real trigger lives in PipelinePanel's mount effect; this predicate
 * is just the framework-level "we're in the workspace" gate.
 */
export const pipelineTour: Tour = {
  id: "pipeline-101",
  version: 1,
  priority: 30,
  trigger: {
    kind: "on-condition",
    predicate: () => useAppStore.getState().appView === "workspace",
  },
  steps: [
    {
      id: "welcome",
      placement: "center",
      title: "The Phase 25 pipeline",
      body: "Five stages take you from raw dumps to a verified key and a ready-to-run Volatility 3 plugin. Let's walk through the UI in 90 seconds.",
    },
    {
      id: "funnel",
      target: "pipeline-funnel",
      placement: "top",
      title: "The reduction funnel",
      body: "While the pipeline runs, this bar shrinks with each filter stage: variance → alignment → entropy → candidates → verified. A 192 MB dump typically ends at a handful of 32-byte candidates.",
    },
    {
      id: "recipe",
      target: "pipeline-recipe-card",
      placement: "bottom",
      title: "Pick a recipe",
      body: "Recipes are pre-filled starting points. 'Replicate gocryptfs DFRWS' loads the thresholds from the paper so a reviewer can reproduce the published hits in one click.",
    },
    {
      id: "oracle-explain",
      target: "pipeline-oracle-help",
      placement: "right",
      title: "Bring your own oracle",
      body: "An oracle is a small Python file that tells the pipeline whether a candidate key decrypts your target. Shape 1 is a plain function; Shape 2 is a stateful class that caches setup cost.",
    },
    {
      id: "oracle-dryrun",
      target: "pipeline-oracle-dryrun",
      placement: "top",
      title: "Smoke-test your oracle",
      body: "Before committing to a 9000-candidate run, click 'Test on 16 samples'. Mostly-red dots are normal — random offsets almost never decrypt. We're just checking the oracle loads and answers.",
      requireAction: {
        description: "Click 'Test on 16 samples' to continue.",
        predicate: () => useOracleStore.getState().dryRun !== null,
      },
    },
    {
      id: "survivor-curve",
      target: "pipeline-survivor-curve",
      placement: "top",
      title: "Survivor curve",
      body: "If you enabled the n-sweep, each dump-count checkpoint produces a log-y point here. The curve mirrors the CLI's report.html exactly — it's how we claim reproducibility.",
    },
    {
      id: "artifacts",
      target: "pipeline-artifacts",
      placement: "top",
      title: "Artifacts — the payoff",
      body: "The Plugin tab shows the emitted Volatility 3 plugin source. The Report tab renders the nsweep report HTML inline. Raw has the JSON + markdown behind a collapsible.",
    },
    {
      id: "new-run",
      placement: "center",
      title: "Ready to run",
      body: "That's the whole loop: pick a recipe, arm an oracle, hit 'Run pipeline', watch the funnel shrink, and ship the emitted plugin. Re-run this tour anytime from Settings → Run onboarding tour.",
    },
  ],
};
