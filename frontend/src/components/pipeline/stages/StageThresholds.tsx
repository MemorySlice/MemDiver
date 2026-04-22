/**
 * Stage 3 — threshold form + Run button.
 *
 * Exposes the `ReduceParams` numeric knobs and brute-force options
 * the user can tune before committing to a run. Sensible defaults
 * live in the store from {@link pipeline-store.ts}; the gocryptfs
 * recipe pre-populates these to the DFRWS paper values.
 *
 * Hitting "Run pipeline" POSTs `/api/pipeline/run` with the current
 * form + oracle id, persists the returned ``task_id`` to the store
 * (which flips ``status`` to ``"pending"``), and advances the
 * wizard to the ``running`` stage. The run dashboard then takes
 * over via the WebSocket subscription in PipelinePanel.
 */

import { useState } from "react";

import type { PipelineRunRequest } from "@/api/pipeline";
import { runPipeline } from "@/api/pipeline";
import type { WizardStage } from "@/stores/pipeline-store";
import { usePipelineStore } from "@/stores/pipeline-store";

interface NumericFieldProps {
  label: string;
  help: string;
  value: number;
  step?: number;
  min?: number;
  onChange: (value: number) => void;
}

function NumericField({
  label,
  help,
  value,
  step = 1,
  min,
  onChange,
}: NumericFieldProps) {
  return (
    <label className="block">
      <div className="flex items-center gap-1.5 text-xs">
        <span className="md-text-secondary">{label}</span>
        <span
          className="inline-block w-3.5 h-3.5 text-[9px] text-center leading-[14px] rounded-full bg-[var(--md-bg-hover)] md-text-muted cursor-help"
          title={help}
        >
          ?
        </span>
      </div>
      <input
        type="number"
        value={value}
        step={step}
        min={min}
        onChange={(e) => {
          const v = Number(e.target.value);
          if (!Number.isNaN(v)) onChange(v);
        }}
        className="mt-0.5 w-full px-2 py-1 text-xs bg-[var(--md-bg-primary)] border border-[var(--md-border)] rounded font-mono"
      />
    </label>
  );
}

interface Props {
  onAdvance: (next: WizardStage) => void;
}

export function StageThresholds({ onAdvance }: Props) {
  const form = usePipelineStore((s) => s.form);
  const updateForm = usePipelineStore((s) => s.updateForm);
  const setTaskId = usePipelineStore((s) => s.setTaskId);

  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const patchReduce = (patch: Partial<typeof form.reduce>): void => {
    updateForm({ reduce: { ...form.reduce, ...patch } });
  };
  const patchBrute = (patch: Partial<typeof form.bruteForce>): void => {
    updateForm({ bruteForce: { ...form.bruteForce, ...patch } });
  };

  async function submit(): Promise<void> {
    if (!form.oracleId) {
      setSubmitError("No oracle selected. Go back to the Oracle step.");
      return;
    }
    if (form.sourcePaths.length === 0) {
      setSubmitError("No dump paths provided. Go back to the Dumps step.");
      return;
    }
    setSubmitError(null);
    setSubmitting(true);
    try {
      const body: PipelineRunRequest = {
        source_paths: form.sourcePaths,
        oracle_id: form.oracleId,
        reduce: form.reduce,
        brute_force: form.bruteForce,
      };
      const resp = await runPipeline(body);
      setTaskId(resp.task_id);
      onAdvance("running");
    } catch (err) {
      setSubmitError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="p-4 space-y-3">
      <div>
        <h3 className="text-sm font-semibold md-text-accent">
          Configure thresholds
        </h3>
        <p className="text-xs md-text-muted">
          Tune the variance / alignment / entropy filter chain. Defaults
          come from the gocryptfs DFRWS case study; hover the{" "}
          <span className="md-text-accent">?</span> icons for per-field
          rationale.
        </p>
      </div>

      <div className="md-panel p-3 space-y-3">
        <div className="md-text-accent font-semibold text-xs uppercase tracking-wide">
          Search-reduce
        </div>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
          <NumericField
            label="min variance"
            help="Per-byte variance threshold. Higher values keep only very volatile bytes; in the DFRWS paper 1500 separated real crypto material from noise at N≥20."
            value={form.reduce.min_variance ?? 3000}
            step={100}
            onChange={(v) => patchReduce({ min_variance: v })}
          />
          <NumericField
            label="alignment"
            help="Byte alignment the key must land on. Go's allocator places keys on 8-byte boundaries; most allocators use 8 or 16."
            value={form.reduce.alignment ?? 8}
            step={1}
            min={1}
            onChange={(v) => patchReduce({ alignment: v })}
          />
          <NumericField
            label="block size"
            help="Window the aligned density filter scores. 32 bytes fits a single AES-256 key; wider windows score pairs of adjacent keys."
            value={form.reduce.block_size ?? 32}
            step={8}
            min={8}
            onChange={(v) => patchReduce({ block_size: v })}
          />
          <NumericField
            label="density"
            help="Minimum survivor fraction inside an aligned block before it's kept. 0.5 means half the bytes in the window must already be candidates."
            value={form.reduce.density_threshold ?? 0.5}
            step={0.05}
            min={0}
            onChange={(v) => patchReduce({ density_threshold: v })}
          />
          <NumericField
            label="entropy win"
            help="Sliding-window size for Shannon entropy in bytes. Must be larger than the entropy threshold in bits, raised to 2."
            value={form.reduce.entropy_window ?? 32}
            step={8}
            min={8}
            onChange={(v) => patchReduce({ entropy_window: v })}
          />
          <NumericField
            label="entropy min"
            help="Minimum Shannon entropy (bits) a window must hit. Cryptographic keys saturate near log2(window); keep this ≤ log2(window)."
            value={form.reduce.entropy_threshold ?? 4.5}
            step={0.1}
            min={0}
            onChange={(v) => patchReduce({ entropy_threshold: v })}
          />
          <NumericField
            label="min region"
            help="Smallest contiguous region the reducer will emit. Regions shorter than this are dropped before brute-force."
            value={form.reduce.min_region ?? 16}
            step={1}
            min={1}
            onChange={(v) => patchReduce({ min_region: v })}
          />
        </div>
      </div>

      <div className="md-panel p-3 space-y-3">
        <div className="md-text-accent font-semibold text-xs uppercase tracking-wide">
          Brute-force
        </div>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
          <NumericField
            label="stride"
            help="Candidate iteration step. Default = alignment. At stride=1 the hot loop wastes most oracle calls on misaligned offsets."
            value={form.bruteForce.stride ?? 8}
            step={1}
            min={1}
            onChange={(v) => patchBrute({ stride: v })}
          />
          <NumericField
            label="jobs"
            help="Inner worker count for the brute-force ProcessPool. 1 = serial (easiest debugging); >1 = parallel. Memdiver v1 caps concurrent pipelines at 1, so jobs × 1 is the CPU footprint."
            value={form.bruteForce.jobs ?? 1}
            step={1}
            min={1}
            onChange={(v) => patchBrute({ jobs: v })}
          />
          <NumericField
            label="top K"
            help="When no hit is found, how many highest-variance regions to report. Zero to disable the fallback."
            value={form.bruteForce.top_k ?? 10}
            step={1}
            min={0}
            onChange={(v) => patchBrute({ top_k: v })}
          />
        </div>
        <label className="flex items-center gap-2 text-xs">
          <input
            type="checkbox"
            checked={form.bruteForce.exhaustive ?? true}
            onChange={(e) => patchBrute({ exhaustive: e.target.checked })}
          />
          <span className="md-text-secondary">
            Exhaustive (try every candidate even after the first hit)
          </span>
        </label>
      </div>

      {submitError && (
        <div className="md-panel p-2 text-xs border border-red-700 md-text-error">
          {submitError}
        </div>
      )}

      <div className="flex justify-between items-center pt-2">
        <button
          type="button"
          onClick={() => onAdvance("oracle")}
          className="text-xs px-3 py-1.5 rounded bg-[var(--md-bg-hover)] md-text-secondary hover:bg-[var(--md-border)]"
        >
          ← Back
        </button>
        <button
          type="button"
          disabled={submitting}
          onClick={() => void submit()}
          className="text-xs px-4 py-1.5 rounded bg-[var(--md-accent-blue)] text-white disabled:opacity-50"
          title="Start consensus → reduce → verify → sweep → emit"
        >
          {submitting ? "Submitting…" : "Run pipeline"}
        </button>
      </div>
    </div>
  );
}
