/**
 * Scrolling tail of the most recent pipeline progress messages.
 *
 * Subscribes directly to the pipeline store so we only re-render
 * when ``activeStageMsg`` actually changes. Keeps the last 20 lines
 * in local component state; renders as a fixed-height monospace
 * scrollback window.
 */

import { useEffect, useRef, useState } from "react";
import type { JSX } from "react";
import { useTranslation } from "react-i18next";

import { usePipelineStore } from "@/stores/pipeline-store";

interface LogLine {
  ts: number;
  stage: string | null;
  msg: string;
}

const MAX_LINES = 20;

function formatTimestamp(ts: number): string {
  const d = new Date(ts);
  const hh = d.getHours().toString().padStart(2, "0");
  const mm = d.getMinutes().toString().padStart(2, "0");
  const ss = d.getSeconds().toString().padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}

export function LiveOracleLog(): JSX.Element {
  const { t } = useTranslation("pipeline");
  // Prime the log from the current store state (lazy initializer) so any
  // message that landed before this component mounted still shows up —
  // without a setState-in-effect that would cost an extra render.
  const [log, setLog] = useState<LogLine[]>(() => {
    const initial = usePipelineStore.getState();
    return initial.activeStageMsg
      ? [{ ts: Date.now(), stage: initial.activeStage, msg: initial.activeStageMsg }]
      : [];
  });
  const scrollRef = useRef<HTMLPreElement | null>(null);

  useEffect(() => {
    return usePipelineStore.subscribe((state, prev) => {
      // Append on every message change. NOTE: this still cannot
      // distinguish two identical consecutive message strings, since
      // the store exposes only the latest text, not a sequence — that
      // residual lossiness is acceptable for a cosmetic log.
      if (
        state.activeStageMsg !== prev.activeStageMsg &&
        state.activeStageMsg
      ) {
        setLog((l) => [
          ...l.slice(-(MAX_LINES - 1)),
          {
            ts: Date.now(),
            stage: state.activeStage,
            msg: state.activeStageMsg,
          },
        ]);
      }
    });
  }, []);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [log]);

  return (
    <div className="md-panel p-3 space-y-2 text-xs md-text-secondary">
      <div className="md-text-accent font-semibold">{t("run.log.title")}</div>
      <pre
        ref={scrollRef}
        className="font-mono text-[11px] leading-snug bg-[var(--md-bg-hover)] rounded p-2 overflow-y-auto"
        style={{ maxHeight: 160 }}
      >
        {log.length === 0 ? (
          <span className="md-text-muted italic">{t("run.log.waiting")}</span>
        ) : (
          log.map((line, i) => (
            <div key={`${line.ts}-${i}`}>
              <span className="md-text-muted">
                [{formatTimestamp(line.ts)}]
              </span>{" "}
              <span className="md-text-accent">
                {line.stage ?? "—"}
              </span>{" "}
              <span className="md-text-muted">›</span> {line.msg}
            </div>
          ))
        )}
      </pre>
    </div>
  );
}
