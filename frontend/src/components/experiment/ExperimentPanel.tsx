/**
 * Experiment control panel -- configure and run dump-and-analyze experiments.
 *
 * Wiring: ``Run Experiment`` POSTs ``/api/experiment/run`` and subscribes
 * to the returned ``task_id`` over the standard
 * :class:`TaskWebSocket`. Per-stage events update three local state
 * slices:
 *
 *   stage === "capture"   -> ``status`` (live progress text)
 *   stage === "consensus" -> ``convergenceData`` (passed to ConvergenceChart)
 *   stage === "verify"    -> ``toolResults`` (passed to MethodComparisonTable)
 *
 * Terminal ``done``/``error`` events flip ``running=false`` and close
 * the WebSocket. HTTP and WebSocket failures funnel through
 * :func:`notifyError` so the toast stack surfaces them.
 */
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ConvergenceChart } from '../charts/ConvergenceChart';
import { MethodComparisonTable } from '../results/MethodComparisonTable';
import type { ConvergenceSweepResult, ConvergencePoint } from '../../api/types';
import { TaskWebSocket } from '@/api/websocket';
import type { TaskProgressEvent } from '@/api/websocket';
import { notifyError } from '@/utils/errorNotifier';

export interface ExperimentConfig {
  targetScript: string;
  numRuns: number;
  tools: string[];
  convergence: boolean;
  maxFp: number;
  exportFormat: string;
}

interface ToolResult {
  tool: string;
  format: string;
  precision?: number;
  false_positives?: number;
  recall?: number;
  decryption_verified?: boolean;
  plugin_saved?: string | null;
}

const NOTIFY_CONTEXT = 'experiment-panel';

export function ExperimentPanel() {
  const { t } = useTranslation('misc');
  const [targetScript, setTargetScript] = useState('tests/fixtures/aes_sample_process.py');
  const [numRuns, setNumRuns] = useState(30);
  const [tools, setTools] = useState(['memslicer', 'lldb', 'fridump']);
  const [convergence, setConvergence] = useState(true);
  const [maxFp, setMaxFp] = useState(0);
  const [exportFormat, setExportFormat] = useState('volatility3');
  const [running, setRunning] = useState(false);
  const [convergenceData, setConvergenceData] = useState<ConvergenceSweepResult | null>(null);
  const [toolResults, setToolResults] = useState<ToolResult[]>([]);
  const [status, setStatus] = useState('');
  const [taskId, setTaskId] = useState<string | null>(null);

  const wsRef = useRef<TaskWebSocket | null>(null);

  // Close any live socket on unmount so the panel does not leak
  // connections when the user navigates away mid-run.
  useEffect(() => {
    return () => {
      wsRef.current?.close();
      wsRef.current = null;
    };
  }, []);

  const toggleTool = (tool: string) => {
    setTools(prev =>
      prev.includes(tool) ? prev.filter(t => t !== tool) : [...prev, tool]
    );
  };

  const buildConvergencePoint = (event: TaskProgressEvent): ConvergencePoint | null => {
    const extra = (event.extra ?? {}) as Record<string, unknown>;
    const numDumps = typeof extra.num_dumps === 'number' ? extra.num_dumps : null;
    const aligned = typeof extra.aligned_regions === 'number' ? extra.aligned_regions : null;
    const volatile = typeof extra.volatile_regions === 'number' ? extra.volatile_regions : null;
    if (numDumps === null || aligned === null) return null;
    return {
      n: numDumps,
      variance: {
        tp: aligned,
        fp: volatile ?? 0,
        precision: 0,
        recall: 0,
        candidates: aligned + (volatile ?? 0),
      },
      combined: null,
      aligned: {
        tp: aligned,
        fp: volatile ?? 0,
        precision: 0,
        recall: 0,
        candidates: aligned + (volatile ?? 0),
      },
      decryption_verified: null,
    };
  };

  const handleEvent = (event: TaskProgressEvent) => {
    switch (event.type) {
      case 'progress':
      case 'stage_start':
      case 'stage_end': {
        if (event.stage === 'capture') {
          setStatus(event.msg ?? t('experiment.capturePct', { pct: Math.round((event.pct ?? 0) * 100) }));
        } else if (event.stage === 'consensus') {
          setStatus(event.msg ?? t('experiment.buildingConsensus'));
          if (event.type === 'progress') {
            const point = buildConvergencePoint(event);
            if (point) {
              setConvergenceData(prev => {
                const points = [...(prev?.points ?? []), point];
                return {
                  points,
                  first_detection_n: prev?.first_detection_n ?? null,
                  first_decryption_n: prev?.first_decryption_n ?? null,
                  first_fp_target_n: prev?.first_fp_target_n ?? null,
                  total_dumps: point.n,
                  max_fp: prev?.max_fp ?? maxFp,
                };
              });
            }
          }
        } else if (event.stage === 'verify') {
          setStatus(event.msg ?? t('experiment.verifying'));
          if (event.type === 'progress' && event.extra) {
            const r = event.extra as unknown as ToolResult;
            if (r.tool) {
              setToolResults(prev => {
                const filtered = prev.filter(p => p.tool !== r.tool);
                return [...filtered, r];
              });
            }
          } else if (event.type === 'stage_end' && event.extra?.tool_results) {
            const map = event.extra.tool_results as Record<string, ToolResult>;
            setToolResults(Object.values(map));
          }
        }
        break;
      }
      case 'done': {
        setStatus(event.msg ?? t('experiment.complete'));
        setRunning(false);
        wsRef.current?.close();
        wsRef.current = null;
        break;
      }
      case 'error': {
        const err = event.error ?? t('experiment.failed');
        setStatus(err);
        setRunning(false);
        notifyError(err, NOTIFY_CONTEXT);
        wsRef.current?.close();
        wsRef.current = null;
        break;
      }
      default:
        break;
    }
  };

  const handleRun = async () => {
    setRunning(true);
    setStatus(t('experiment.starting'));
    setConvergenceData(null);
    setToolResults([]);

    const body = {
      target: targetScript,
      num_runs: numRuns,
      tools,
      export_format: exportFormat,
      protocol_version: 'TLS13',
      phase: 'pre_abort',
    };

    let resp: Response;
    try {
      resp = await fetch('/api/experiment/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setRunning(false);
      const networkErr = t('experiment.networkError', { msg });
      setStatus(networkErr);
      notifyError(networkErr, NOTIFY_CONTEXT);
      return;
    }

    if (!resp.ok) {
      const detail = await resp.text();
      setRunning(false);
      const httpErr = t('experiment.httpError', { status: resp.status, detail });
      setStatus(httpErr);
      notifyError(httpErr, NOTIFY_CONTEXT);
      return;
    }

    const data = await resp.json() as { task_id: string; status: string };
    setTaskId(data.task_id);

    const ws = new TaskWebSocket();
    wsRef.current = ws;
    ws.onProgress(handleEvent);
    ws.connect(data.task_id);
  };

  return (
    <div
      className="flex flex-col gap-4 p-4 h-full overflow-auto"
      data-testid="experiment-panel"
    >
      <h2 className="text-sm font-semibold text-[var(--md-text-primary)]">{t('experiment.heading')}</h2>

      {/* Target script */}
      <div className="flex flex-col gap-1">
        <label className="text-xs md-text-secondary">{t('experiment.targetScript')}</label>
        <input
          type="text"
          value={targetScript}
          onChange={e => setTargetScript(e.target.value)}
          className="bg-[var(--md-bg-tertiary)] border border-[var(--md-border)] rounded px-2 py-1 text-xs text-[var(--md-text-primary)]"
          placeholder={t('experiment.targetScriptPlaceholder')}
          data-testid="experiment-target"
        />
      </div>

      {/* Num runs */}
      <div className="flex items-center gap-3">
        <label className="text-xs md-text-secondary w-24">{t('experiment.runsPerTool')}</label>
        <input
          type="range"
          min={2}
          max={100}
          value={numRuns}
          onChange={e => setNumRuns(Number(e.target.value))}
          className="flex-1"
          aria-label={t('experiment.runsPerTool')}
          data-testid="experiment-num-runs"
        />
        <span className="text-xs text-[var(--md-text-primary)] w-8">{numRuns}</span>
      </div>

      {/* Tool selection */}
      <div className="flex flex-col gap-1">
        <label className="text-xs md-text-secondary">{t('experiment.dumpTools')}</label>
        <div className="flex gap-3">
          {['memslicer', 'lldb', 'fridump'].map(tool => (
            <label key={tool} className="flex items-center gap-1 text-xs cursor-pointer">
              <input
                type="checkbox"
                checked={tools.includes(tool)}
                onChange={() => toggleTool(tool)}
                className="w-3 h-3"
              />
              <span className={tools.includes(tool) ? 'text-[var(--md-text-primary)]' : 'md-text-muted'}>
                {tool}
              </span>
            </label>
          ))}
        </div>
      </div>

      {/* Options */}
      <div className="flex gap-4">
        <label className="flex items-center gap-1 text-xs cursor-pointer">
          <input
            type="checkbox"
            checked={convergence}
            onChange={e => setConvergence(e.target.checked)}
            className="w-3 h-3"
          />
          <span className="md-text-secondary">{t('experiment.convergenceSweep')}</span>
        </label>
        <div className="flex items-center gap-1">
          <span className="text-xs md-text-secondary">{t('experiment.maxFp')}</span>
          <input
            type="number"
            value={maxFp}
            onChange={e => setMaxFp(Number(e.target.value))}
            className="w-12 bg-[var(--md-bg-tertiary)] border border-[var(--md-border)] rounded px-1 text-xs text-[var(--md-text-primary)]"
            min={0}
            aria-label={t('experiment.maxFpAria')}
          />
        </div>
        <select
          value={exportFormat}
          onChange={e => setExportFormat(e.target.value)}
          className="bg-[var(--md-bg-tertiary)] border border-[var(--md-border)] rounded px-2 py-0.5 text-xs text-[var(--md-text-primary)]"
          aria-label={t('experiment.exportFormat')}
        >
          <option value="volatility3">{t('experiment.formatVol3')}</option>
          <option value="yara">{t('experiment.formatYara')}</option>
          <option value="json">{t('experiment.formatJson')}</option>
        </select>
      </div>

      {/* Run button */}
      <button
        onClick={handleRun}
        disabled={running || tools.length === 0}
        className="px-4 py-2 bg-[var(--md-accent-blue)] hover:opacity-90 disabled:bg-[var(--md-bg-hover)]
                   disabled:text-[var(--md-text-muted)] rounded text-xs font-medium md-text-on-accent"
        data-testid="experiment-run"
      >
        {running ? status || t('experiment.running') : t('experiment.runExperiment')}
      </button>

      {taskId && (
        <p className="text-xs md-text-muted" data-testid="experiment-task-id">
          {t('experiment.taskId', { taskId })}
        </p>
      )}

      {/* Results */}
      {toolResults.length > 0 && (
        <MethodComparisonTable results={toolResults} />
      )}
      {convergenceData && (
        <ConvergenceChart data={convergenceData} />
      )}
    </div>
  );
}
