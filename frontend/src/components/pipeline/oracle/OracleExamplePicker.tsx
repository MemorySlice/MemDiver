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

import type { OracleExample } from "@/api/oracles";
import { useOracleStore } from "@/stores/oracle-store";

interface Props {
  selected: string | null;
  onSelect: (example: OracleExample) => void;
}

export function OracleExamplePicker({ selected, onSelect }: Props) {
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
      <p className="p-3 text-xs md-text-muted">Loading example oracles…</p>
    );
  }

  if (error && examples.length === 0) {
    return (
      <p className="p-3 text-xs text-red-400">
        Failed to load examples: {error}
      </p>
    );
  }

  if (examples.length === 0) {
    return (
      <p className="p-3 text-xs md-text-muted">
        No example oracles bundled in <code>docs/oracle_examples/</code>.
      </p>
    );
  }

  return (
    <div className="space-y-2">
      <p className="text-xs md-text-muted">
        Pick a bundled template to inspect its shape. Examples are
        read-only — copy one into your own <code>.py</code> and upload it
        via the <em>Upload</em> tab to actually run a pipeline.
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
                <span className="inline-block text-[10px] uppercase tracking-wide text-white rounded px-1.5 py-0.5 bg-indigo-700">
                  Shape {ex.shape}
                </span>
              </div>
              <div className="text-xs md-text-muted truncate">
                {ex.summary || "(no summary)"}
              </div>
              <div className="text-[10px] md-text-muted font-mono">
                sha256: {ex.sha256.slice(0, 12)}… · {ex.size} bytes
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
