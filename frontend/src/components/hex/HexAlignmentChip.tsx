import { useState } from "react";
import { useTranslation } from "react-i18next";

import { useConsensusStore } from "@/stores/consensus-store";
import { useDumpStore } from "@/stores/dump-store";
import { useMultiHexStore } from "@/stores/multi-hex-store";

/**
 * Says, permanently and in words, WHAT put these bytes side by side.
 *
 * Silent misalignment is the worst failure mode of a multi-dump viewer: the
 * panes still line up, the bytes still look plausible, and the analyst draws a
 * conclusion about two addresses that were never the same address. A chip that
 * is only shown "when something is wrong" does not help, because the wrong case
 * is exactly the one that looks fine - so this renders on every window and
 * names the method every time.
 *
 * `file_offset` over `.msl` dumps is the case worth acting on: those dumps carry
 * a virtual-address map, so falling back to raw file offsets means no consensus
 * has aligned them yet. The chip offers to run one rather than leaving the user
 * to guess which button produces an alignment.
 */
export interface HexAlignmentChipProps {
  /** The dumps the window was built over, for the re-run action. */
  paths: string[];
  /** Whether any of them is an `.msl` (so a real alignment is possible). */
  hasMsl: boolean;
}

const METHOD_KEY = {
  virtual_address: "alignment.virtual_address",
  module_offset: "alignment.module_offset",
  file_offset: "alignment.file_offset",
} as const;

export function HexAlignmentChip({ paths, hasMsl }: HexAlignmentChipProps) {
  const { t } = useTranslation("hex");
  const alignment = useMultiHexStore((s) => s.alignment);
  const truncated = useMultiHexStore((s) => s.truncated);
  const aslrNormalize = useDumpStore((s) => s.aslrNormalize);
  const runConsensus = useConsensusStore((s) => s.runConsensus);
  const [running, setRunning] = useState(false);

  const method = alignment?.method;
  const label = method ? t(METHOD_KEY[method]) : t("alignment.pending");
  const warnings = alignment?.warnings ?? [];
  const offerRerun = method === "file_offset" && hasMsl && paths.length > 1;

  return (
    <div
      data-testid="hex-alignment-chip"
      role="status"
      aria-label={t("alignment.label")}
      className="flex items-center flex-wrap gap-2 px-3 py-1 text-xs border-b border-[var(--md-border)] md-bg-secondary"
    >
      <span
        data-testid="hex-alignment-method"
        data-method={method ?? "pending"}
        className="font-medium"
        title={
          alignment
            ? t("alignment.comparedTitle", {
                compared: alignment.bytes_compared,
                discarded: alignment.bytes_discarded,
                sources: alignment.n_sources,
              })
            : undefined
        }
      >
        {label}
      </span>

      {method === "file_offset" && (
        <span data-testid="hex-alignment-file-offset-warning" className="md-text-warning">
          {t("alignment.fileOffsetWarning")}
        </span>
      )}

      {warnings.map((warning) => (
        <span key={warning} data-testid="hex-alignment-warning" className="md-text-warning">
          {warning}
        </span>
      ))}

      {truncated && (
        <span
          data-testid="hex-alignment-truncated"
          className="md-text-warning"
          title={t("alignment.truncatedTitle")}
        >
          {t("alignment.truncated")}
        </span>
      )}

      {offerRerun && (
        <button
          type="button"
          data-testid="hex-alignment-run-consensus"
          disabled={running}
          className="ml-auto px-2 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-50"
          onClick={() => {
            setRunning(true);
            // The ASLR-normalize toggle is what turns raw file offsets into a
            // virtual-address alignment, so the re-run honours whatever the
            // user has set rather than silently choosing for them.
            void runConsensus(paths, aslrNormalize).finally(() => setRunning(false));
          }}
        >
          {running ? t("alignment.running") : t("alignment.runConsensus")}
        </button>
      )}
    </div>
  );
}
