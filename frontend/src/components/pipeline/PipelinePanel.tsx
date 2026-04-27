/**
 * Pipeline bottom-tab — wizard shell.
 *
 * Owns the whole state machine for the Phase 25 Web UI: the four
 * wizard stages (recipe → dumps → oracle → thresholds), a live
 * run dashboard while the task is executing, and a results view
 * once it reaches a terminal state.
 *
 * The wizard's source of truth is `usePipelineStore`. The user's
 * form values, current stage, active task id, and last-seen seq
 * are all persisted to localStorage via the `persist` middleware,
 * so switching to another bottom tab mid-run and coming back
 * restores the exact view — including re-subscribing to the live
 * WebSocket from whatever seq was last observed.
 */

import { useEffect, useState } from "react";

import { cancelPipelineRun, getPipelineRun } from "@/api/pipeline";
import { useFtueStore } from "@/ftue/store";
import { useTaskProgress } from "@/hooks/useTaskProgress";
import { PipelineRunDashboard } from "@/components/pipeline/run/PipelineRunDashboard";
import { ArtifactsTabs } from "@/components/pipeline/results/ArtifactsTabs";
import { RefinePanel } from "@/components/pipeline/results/RefinePanel";
import { SurvivorCurve } from "@/components/pipeline/results/SurvivorCurve";
import { StageRecipe } from "@/components/pipeline/stages/StageRecipe";
import { StageDumps } from "@/components/pipeline/stages/StageDumps";
import { StageOracle } from "@/components/pipeline/stages/StageOracle";
import { StageThresholds } from "@/components/pipeline/stages/StageThresholds";
import type { TaskProgressEvent } from "@/api/websocket";
import type { WizardStage } from "@/stores/pipeline-store";
import { usePipelineStore } from "@/stores/pipeline-store";

// Wizard-stage order used by the stepper.
const WIZARD_STEPS: Array<{ id: WizardStage; label: string }> = [
  { id: "recipe", label: "Recipe" },
  { id: "dumps", label: "Dumps" },
  { id: "oracle", label: "Oracle" },
  { id: "thresholds", label: "Thresholds" },
  { id: "running", label: "Run" },
  { id: "results", label: "Results" },
];

const STATUS_BADGE_BG: Record<string, string> = {
  idle: "var(--md-text-muted)",
  pending: "var(--md-accent-blue)",
  running: "var(--md-accent-blue)",
  succeeded: "var(--md-accent-green)",
  failed: "var(--md-accent-red)",
  cancelled: "var(--md-accent-orange)",
};

function Stepper({
  stage,
  onJump,
}: {
  stage: WizardStage;
  onJump: (next: WizardStage) => void;
}) {
  const activeIdx = WIZARD_STEPS.findIndex((s) => s.id === stage);
  return (
    <div className="flex items-center gap-1 px-3 py-2 border-b border-[var(--md-border)]">
      {WIZARD_STEPS.map((step, idx) => {
        const isActive = idx === activeIdx;
        const isDone = idx < activeIdx;
        // Only allow jumping BACK to completed steps. Forward jumps
        // would skip required form fields and are handled by each
        // stage's own Next button.
        const canJump = idx < activeIdx;
        return (
          <div key={step.id} className="flex items-center gap-1">
            <button
              type="button"
              disabled={!canJump}
              onClick={() => (canJump ? onJump(step.id) : undefined)}
              className={`flex items-center gap-1.5 px-2 py-0.5 rounded transition-colors text-xs ${
                isActive
                  ? "bg-[var(--md-accent-blue)] text-white font-semibold"
                  : isDone
                    ? "md-text-secondary hover:bg-[var(--md-bg-hover)] cursor-pointer"
                    : "md-text-muted"
              }`}
            >
              <span
                className={`inline-flex items-center justify-center w-4 h-4 rounded-full text-[10px] ${
                  isActive
                    ? "bg-white text-[var(--md-accent-blue)]"
                    : isDone
                      ? "bg-[var(--md-bg-hover)] md-text-secondary"
                      : "bg-[var(--md-bg-hover)] md-text-muted"
                }`}
              >
                {idx + 1}
              </span>
              {step.label}
            </button>
            {idx < WIZARD_STEPS.length - 1 && (
              <span className="md-text-muted text-xs">›</span>
            )}
          </div>
        );
      })}
    </div>
  );
}

function HeaderBar() {
  const status = usePipelineStore((s) => s.status);
  const taskId = usePipelineStore((s) => s.taskId);
  const stage = usePipelineStore((s) => s.stage);
  const resetRun = usePipelineStore((s) => s.resetRun);
  const [cancelling, setCancelling] = useState(false);

  // Reset the debounce whenever the run transitions to a fresh task.
  useEffect(() => {
    setCancelling(false);
  }, [taskId]);

  return (
    <div className="flex items-center gap-3 px-3 py-2 border-b border-[var(--md-border)] md-bg-secondary">
      <h2 className="text-sm font-semibold md-text-accent">Pipeline</h2>
      <span
        className="inline-block text-[10px] uppercase tracking-wide text-white rounded px-2 py-0.5"
        style={{ background: STATUS_BADGE_BG[status] ?? "var(--md-text-muted)" }}
      >
        {status}
      </span>
      <span className="md-text-muted text-xs">stage: {stage}</span>
      {taskId && (
        <span className="md-text-muted text-[10px] font-mono truncate">
          task {taskId.slice(0, 12)}…
        </span>
      )}
      <div className="flex-1" />
      {(status === "running" || status === "pending") && taskId && (
        <button
          type="button"
          disabled={cancelling}
          onClick={() => {
            setCancelling(true);
            void cancelPipelineRun(taskId).catch(() => undefined);
          }}
          className="text-xs px-2 py-1 rounded bg-amber-800 text-amber-100 hover:bg-amber-700 disabled:opacity-50"
          title="Stop the running pipeline — best-effort, may take a few hundred ms"
        >
          {cancelling ? "Cancelling…" : "Cancel run"}
        </button>
      )}
      {(status === "succeeded" || status === "failed" || status === "cancelled") && (
        <button
          type="button"
          onClick={resetRun}
          className="text-xs px-2 py-1 rounded bg-[var(--md-bg-hover)] md-text-secondary hover:bg-[var(--md-border)]"
          title="Clear the finished run and start a new pipeline"
        >
          New run
        </button>
      )}
    </div>
  );
}

function ResumingBanner() {
  const taskId = usePipelineStore((s) => s.taskId);
  const status = usePipelineStore((s) => s.status);
  const stage = usePipelineStore((s) => s.stage);
  if (!taskId) return null;
  if (status !== "pending" && status !== "running") return null;
  return (
    <div className="mx-3 mt-3 p-2 text-xs rounded border border-[var(--md-accent-blue)] bg-[var(--md-bg-hover)] md-text-accent">
      Resuming pipeline run{" "}
      <span className="font-mono">{taskId.slice(0, 12)}…</span> ({stage}).
      Live progress will reattach via WebSocket.
    </div>
  );
}

function ResultsView() {
  return (
    <div className="p-4 space-y-4">
      <SurvivorCurve />
      <RefinePanel />
      <ArtifactsTabs />
    </div>
  );
}

export default function PipelinePanel() {
  const stage = usePipelineStore((s) => s.stage);
  const status = usePipelineStore((s) => s.status);
  const taskId = usePipelineStore((s) => s.taskId);
  const lastSeq = usePipelineStore((s) => s.lastSeq);
  const setStage = usePipelineStore((s) => s.setStage);
  const ingestEvent = usePipelineStore((s) => s.ingestEvent);

  // Subscribe to the task progress stream whenever there's an active
  // taskId. The hook is a no-op when taskId is null.
  useTaskProgress(taskId, {
    onEvent: (event: TaskProgressEvent) => ingestEvent(event),
    since: lastSeq,
  });

  // TourProvider only re-evaluates triggers on appView change, so
  // clicking into this tab from inside "workspace" wouldn't otherwise
  // fire pipeline-101. Kick the check manually on first mount.
  useEffect(() => {
    const ftue = useFtueStore.getState();
    if (ftue.activeTourId !== null) return;
    if (!ftue.seenTours.some((t) => t.id === "pipeline-101")) {
      ftue.startTour("pipeline-101");
    }
  }, []);

  // When the pipeline finishes, advance the wizard to results. When
  // the pipeline is actively running but we haven't entered the run
  // stage yet (e.g. because a re-mount landed on the old stage after
  // a tab switch), push the user forward.
  useEffect(() => {
    if (status === "succeeded" || status === "failed" || status === "cancelled") {
      if (stage !== "results") setStage("results");
      return;
    }
    if ((status === "running" || status === "pending") && stage !== "running") {
      setStage("running");
    }
  }, [status, stage, setStage]);

  // When a persisted taskId rehydrates from localStorage but the user
  // has since gone and deleted the backend task (or restarted the
  // server), fetch the canonical record once to sync our local status.
  //
  // When the task is already terminal on load (e.g. the user was away,
  // came back after completion), the WebSocket backfill won't fire — so
  // we manually replay the saved `record.stages` as synthetic
  // stage_start / stage_end events. Without this, the stepper jumps
  // straight to the terminal badge with an empty funnel; with it, the
  // full stage history repaints as if we'd watched it live.
  useEffect(() => {
    if (!taskId) return;
    let cancelled = false;
    void getPipelineRun(taskId)
      .then((record) => {
        if (cancelled) return;
        const isTerminal =
          record.status === "succeeded" ||
          record.status === "failed" ||
          record.status === "cancelled";
        if (!isTerminal) return;

        // Replay stage history. Use a local seq cursor advanced past
        // `lastSeq` so the reducer's "already seen" check never drops
        // a synthetic event.
        let seq = lastSeq;
        for (const stage of record.stages ?? []) {
          const startTs = stage.started_at ?? record.started_at ?? record.created_at;
          ingestEvent({
            task_id: taskId,
            type: "stage_start",
            stage: stage.name,
            seq: ++seq,
            ts: startTs ?? Date.now() / 1000,
            msg: stage.msg ?? null,
          });
          // If the stage itself finished, emit stage_end too. Stages
          // that were mid-flight when the task aborted stay at their
          // last-known pct/msg.
          if (
            stage.status === "succeeded" ||
            stage.status === "failed" ||
            stage.status === "cancelled"
          ) {
            const endTs = stage.ended_at ?? startTs;
            ingestEvent({
              task_id: taskId,
              type: "stage_end",
              stage: stage.name,
              seq: ++seq,
              ts: endTs ?? Date.now() / 1000,
              pct: 1,
              msg: stage.msg ?? null,
            });
          }
        }

        // Finally, emit the terminal event so `status` flips.
        ingestEvent({
          task_id: taskId,
          type: record.status === "succeeded" ? "done" : "error",
          seq: ++seq,
          ts: Date.now() / 1000,
          error: record.error ?? undefined,
        });
      })
      .catch(() => {
        // Backend forgot about this task; reset the store so the
        // stepper returns to the recipe stage.
        if (cancelled) return;
        usePipelineStore.getState().resetRun();
      });
    return () => {
      cancelled = true;
    };
    // Intentionally only re-runs on taskId change — re-running on
    // every lastSeq bump would hammer the endpoint.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [taskId]);

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <HeaderBar />
      <Stepper stage={stage} onJump={setStage} />
      <ResumingBanner />
      <div className="flex-1 overflow-auto">
        {stage === "recipe" && <StageRecipe onAdvance={setStage} />}
        {stage === "dumps" && <StageDumps onAdvance={setStage} />}
        {stage === "oracle" && <StageOracle onAdvance={setStage} />}
        {stage === "thresholds" && <StageThresholds onAdvance={setStage} />}
        {stage === "running" && <PipelineRunDashboard />}
        {stage === "results" && <ResultsView />}
      </div>
    </div>
  );
}
