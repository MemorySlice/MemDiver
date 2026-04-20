/**
 * Experiment control panel -- configure and run dump-and-analyze experiments.
 */
import { useState } from 'react';
import { ConvergenceChart } from '../charts/ConvergenceChart';
import { MethodComparisonTable } from '../results/MethodComparisonTable';
import type { ConvergenceSweepResult } from '../../api/types';

interface ExperimentPanelProps {
  onRunExperiment?: (config: ExperimentConfig) => void;
}

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

export function ExperimentPanel({ onRunExperiment }: ExperimentPanelProps) {
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

  const toggleTool = (tool: string) => {
    setTools(prev =>
      prev.includes(tool) ? prev.filter(t => t !== tool) : [...prev, tool]
    );
  };

  const handleRun = () => {
    setRunning(true);
    setStatus('Starting experiment...');
    onRunExperiment?.({
      targetScript,
      numRuns,
      tools,
      convergence,
      maxFp,
      exportFormat,
    });
  };

  // Suppress unused variable warnings -- these are wired to future WebSocket callbacks
  void convergenceData;
  void toolResults;
  void setConvergenceData;
  void setToolResults;
  void setStatus;
  void setRunning;

  return (
    <div className="flex flex-col gap-4 p-4 h-full overflow-auto">
      <h2 className="text-sm font-semibold text-zinc-200">Experiment Configuration</h2>

      {/* Target script */}
      <div className="flex flex-col gap-1">
        <label className="text-xs text-zinc-400">Target Script</label>
        <input
          type="text"
          value={targetScript}
          onChange={e => setTargetScript(e.target.value)}
          className="bg-zinc-800 border border-zinc-700 rounded px-2 py-1 text-xs text-zinc-200"
          placeholder="path/to/target_process.py"
        />
      </div>

      {/* Num runs */}
      <div className="flex items-center gap-3">
        <label className="text-xs text-zinc-400 w-24">Runs per tool</label>
        <input
          type="range"
          min={2}
          max={100}
          value={numRuns}
          onChange={e => setNumRuns(Number(e.target.value))}
          className="flex-1"
        />
        <span className="text-xs text-zinc-300 w-8">{numRuns}</span>
      </div>

      {/* Tool selection */}
      <div className="flex flex-col gap-1">
        <label className="text-xs text-zinc-400">Dump Tools</label>
        <div className="flex gap-3">
          {['memslicer', 'lldb', 'fridump'].map(tool => (
            <label key={tool} className="flex items-center gap-1 text-xs cursor-pointer">
              <input
                type="checkbox"
                checked={tools.includes(tool)}
                onChange={() => toggleTool(tool)}
                className="w-3 h-3"
              />
              <span className={tools.includes(tool) ? 'text-zinc-300' : 'text-zinc-500'}>
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
          <span className="text-zinc-400">Convergence sweep</span>
        </label>
        <div className="flex items-center gap-1">
          <span className="text-xs text-zinc-400">Max FP:</span>
          <input
            type="number"
            value={maxFp}
            onChange={e => setMaxFp(Number(e.target.value))}
            className="w-12 bg-zinc-800 border border-zinc-700 rounded px-1 text-xs text-zinc-200"
            min={0}
          />
        </div>
        <select
          value={exportFormat}
          onChange={e => setExportFormat(e.target.value)}
          className="bg-zinc-800 border border-zinc-700 rounded px-2 py-0.5 text-xs text-zinc-200"
        >
          <option value="volatility3">Volatility3</option>
          <option value="yara">YARA</option>
          <option value="json">JSON</option>
        </select>
      </div>

      {/* Run button */}
      <button
        onClick={handleRun}
        disabled={running || tools.length === 0}
        className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-zinc-700
                   disabled:text-zinc-500 rounded text-xs font-medium text-white"
      >
        {running ? status : 'Run Experiment'}
      </button>

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
