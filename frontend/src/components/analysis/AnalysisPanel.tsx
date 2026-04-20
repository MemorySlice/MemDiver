import { useCallback, useEffect, useRef, useState } from "react";
import { runAnalysis, runFileAnalysis, listPhases, listProtocols, listPatterns } from "@/api/client";
import type { PatternInfo } from "@/api/types";
import { useAppStore, ALL_ALGORITHMS, SINGLE_FILE_ALGORITHMS, VERIFICATION_ALGORITHMS } from "@/stores/app-store";
import type { AlgorithmName } from "@/stores/app-store";
import { useAnalysisStore } from "@/stores/analysis-store";
import { useResultsStore } from "@/stores/results-store";
import { getAlgorithmAvailability } from "@/utils/algorithm-availability";
import { applyHitsToStores } from "@/utils/apply-hits";
import type { SecretHit } from "@/api/types";

const PROGRESS_STEPS = [
  "Preparing analysis...",
  "Loading dump data...",
  "Running algorithms...",
  "Scanning for patterns...",
  "Processing results...",
];

const SELECT_CLASS = "w-full bg-[var(--md-bg-primary)] border border-[var(--md-border)] rounded px-1.5 py-1 text-xs";

const ALGO_LABELS: Record<AlgorithmName, string> = {
  entropy_scan: "Entropy Scan",
  pattern_match: "Pattern Match",
  change_point: "Change Point",
  structure_scan: "Structure Scan",
  user_regex: "User Regex",
  exact_match: "Exact Match",
  differential: "Differential",
  constraint_validator: "Constraint Validator",
};

const ALGO_DESCRIPTIONS: Record<AlgorithmName, string> = {
  entropy_scan: "Shannon entropy sliding window — finds high-entropy regions that may contain cryptographic keys or compressed data.",
  pattern_match: "Structural pattern matching from JSON definitions — uses before/after byte markers to locate key material.",
  change_point: "CUSUM entropy change-point detection — finds sharp entropy transitions indicating boundaries of key-material plateaus.",
  structure_scan: "Identifies known data structure layouts (TLS records, SSH key formats) via field-level overlay validation.",
  user_regex: "Custom regex byte pattern search on raw dump data. Enter your regex pattern below when selected.",
  exact_match: "Searches for known cryptographic key byte sequences using ground truth from keylog reference data.",
  differential: "Cross-run byte variance analysis (DPA-inspired) — compares multiple dumps to locate volatile key-sized regions.",
  constraint_validator: "Validates candidate keys against protocol-specific KDF constraints (key length, derivation relationships).",
};

export function AnalysisPanel() {
  // Per-field selectors so unrelated app-store writes (hexFocus, wizardStep,
  // fullWidthHex, chunk-load propagation via other stores) do not re-render
  // the algorithm checkbox list. AppState has 35 slice members; this
  // component only reads ~20 of them.
  const selectedLibraries = useAppStore((s) => s.selectedLibraries);
  const selectedPhase = useAppStore((s) => s.selectedPhase);
  const protocolVersion = useAppStore((s) => s.protocolVersion);
  const protocolName = useAppStore((s) => s.protocolName);
  const datasetRoot = useAppStore((s) => s.datasetRoot);
  const keylogFilename = useAppStore((s) => s.keylogFilename);
  const inputMode = useAppStore((s) => s.inputMode);
  const inputPath = useAppStore((s) => s.inputPath);
  const pathInfo = useAppStore((s) => s.pathInfo);
  const hasCandidateKeys = useAppStore((s) => s.hasCandidateKeys);
  const selectedAlgorithms = useAppStore((s) => s.selectedAlgorithms);
  const toggleAlgorithm = useAppStore((s) => s.toggleAlgorithm);
  const setLibraries = useAppStore((s) => s.setLibraries);
  const setPhase = useAppStore((s) => s.setPhase);
  const setProtocol = useAppStore((s) => s.setProtocol);
  const setDatasetRoot = useAppStore((s) => s.setDatasetRoot);
  const wizardComplete = useAppStore((s) => s.wizardComplete);
  const analysisApproach = useAppStore((s) => s.analysisApproach);
  const setAnalysisApproach = useAppStore((s) => s.setAnalysisApproach);
  const mode = useAppStore((s) => s.mode);
  const { isRunning, result, error, startAnalysis, setResult, setError, reset } = useAnalysisStore();

  const [availablePhases, setAvailablePhases] = useState<string[]>([]);
  const [availableProtocols, setAvailableProtocols] = useState<string[]>([]);
  const [loadingMeta, setLoadingMeta] = useState(false);
  const [stepIdx, setStepIdx] = useState(0);
  const [userRegex, setUserRegex] = useState("");
  const [builtinPatterns, setBuiltinPatterns] = useState<PatternInfo[]>([]);
  const [patternsExpanded, setPatternsExpanded] = useState(false);
  const [customPatternJson, setCustomPatternJson] = useState("");
  const [showPatternExample, setShowPatternExample] = useState(false);
  const autoRunTriggeredRef = useRef(false);

  useEffect(() => {
    if (!inputPath || inputMode === "file") return;
    let cancelled = false;
    setLoadingMeta(true);

    (async () => {
      try {
        const [phaseInfo, protocols] = await Promise.all([
          listPhases(inputPath),
          !protocolVersion ? listProtocols() : Promise.resolve(null),
        ]);
        if (cancelled) return;

        setAvailablePhases(phaseInfo.phases);
        if (phaseInfo.phases.length > 0 && !selectedPhase) {
          setPhase(phaseInfo.phases[0]);
        }

        if (inputMode === "directory" && selectedLibraries.length === 0) {
          setDatasetRoot("");
          setLibraries([inputPath]);
        }

        // Infer protocol from path (e.g., /TLS12/ → "12", /TLS13/ → "13")
        if (!protocolVersion) {
          const m = inputPath.match(/TLS(1[23])/i);
          if (m) {
            setProtocol("TLS", m[1]);
          } else if (protocols && protocols.protocols.length > 0) {
            const versions = protocols.protocols.flatMap((p) => p.versions);
            setAvailableProtocols(versions);
          }
        }
      } catch {
        // Selectors stay empty on failure
      } finally {
        if (!cancelled) setLoadingMeta(false);
      }
    })();

    return () => { cancelled = true; };
  }, [inputPath, inputMode]); // eslint-disable-line react-hooks/exhaustive-deps

  // Fetch built-in patterns when pattern_match is selected
  useEffect(() => {
    if (!selectedAlgorithms.includes("pattern_match")) return;
    if (builtinPatterns.length > 0) return;
    let cancelled = false;
    listPatterns()
      .then((res) => { if (!cancelled) setBuiltinPatterns(res.patterns); })
      .catch(() => { /* patterns list stays empty */ });
    return () => { cancelled = true; };
  }, [selectedAlgorithms, builtinPatterns.length]);

  // Cycle through progress step messages while analysis is running
  useEffect(() => {
    if (!isRunning) { setStepIdx(0); return; }
    const interval = setInterval(() => {
      setStepIdx((prev) => (prev + 1) % PROGRESS_STEPS.length);
    }, 2500);
    return () => clearInterval(interval);
  }, [isRunning]);

  // Build availability context for algorithm gating
  const availabilityContext = {
    inputMode,
    dumpCount: pathInfo?.dump_count ?? 1,
    hasKeylog: pathInfo?.has_keylog ?? !!keylogFilename,
    hasCandidateKeys,
  };

  const handleRun = useCallback(async () => {
    if (!selectedLibraries.length || !selectedPhase || !protocolVersion) return;
    useResultsStore.getState().clearResults();
    startAnalysis();
    try {
      const dirs = selectedLibraries.map((lib) =>
        datasetRoot ? `${datasetRoot}/${lib}` : lib
      );
      const res = await runAnalysis({
        library_dirs: dirs,
        phase: selectedPhase,
        protocol_version: protocolVersion,
        keylog_filename: keylogFilename,
        algorithms: selectedAlgorithms,
      });
      setResult(res);
      applyHitsToStores(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Analysis failed");
    }
  }, [selectedLibraries, selectedPhase, protocolVersion, datasetRoot, keylogFilename, selectedAlgorithms, startAnalysis, setResult, setError]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleRunFile = useCallback(async () => {
    if (!inputPath) return;
    useResultsStore.getState().clearResults();
    startAnalysis();
    try {
      const fileAlgos = selectedAlgorithms.filter((a) =>
        (SINGLE_FILE_ALGORITHMS as readonly string[]).includes(a)
      );
      let parsedPatterns: Record<string, unknown>[] | undefined;
      if (customPatternJson.trim()) {
        try { parsedPatterns = [JSON.parse(customPatternJson)]; } catch { /* ignore invalid JSON */ }
      }
      const res = await runFileAnalysis({
        dump_path: inputPath,
        algorithms: fileAlgos.length > 0 ? fileAlgos : [...SINGLE_FILE_ALGORITHMS],
        user_regex: userRegex || undefined,
        custom_patterns: parsedPatterns,
      });
      setResult(res);
      applyHitsToStores(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : "File analysis failed");
    }
  }, [inputPath, selectedAlgorithms, startAnalysis, setResult, setError]); // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-run analysis when wizard completes with "auto" approach
  useEffect(() => {
    if (autoRunTriggeredRef.current) return;
    if (!wizardComplete || analysisApproach !== "auto") return;
    if (isRunning || result) return;

    if (inputMode === "file") {
      if (!inputPath) return;
      autoRunTriggeredRef.current = true;
      setAnalysisApproach("inspect");
      handleRunFile();
    } else {
      if (loadingMeta) return;
      if (!selectedLibraries.length || !selectedPhase || !protocolVersion) return;
      autoRunTriggeredRef.current = true;
      setAnalysisApproach("inspect");
      handleRun();
    }
  }, [wizardComplete, analysisApproach, inputMode, inputPath, loadingMeta, selectedLibraries, selectedPhase, protocolVersion, isRunning, result, handleRunFile, handleRun, setAnalysisApproach]);

  const canRun = inputMode === "file"
    ? !!inputPath && selectedAlgorithms.some((a) => (SINGLE_FILE_ALGORITHMS as readonly string[]).includes(a)) && !isRunning
    : selectedLibraries.length > 0 && !!selectedPhase && !!protocolVersion && !isRunning;

  return (
    <div className="p-3 space-y-3 text-xs">
      {inputMode !== "file" && (
        <div className="space-y-2">
          <div>
            <label className="font-medium md-text-secondary block mb-0.5">Protocol</label>
            {protocolVersion ? (
              <span className="px-1.5 py-0.5 rounded bg-[var(--md-bg-hover)] text-xs">
                {protocolVersion}
              </span>
            ) : (
              <select className={SELECT_CLASS} value="" onChange={(e) => setProtocol(protocolName || "TLS", e.target.value)}>
                <option value="">Select...</option>
                {availableProtocols.map((v) => <option key={v} value={v}>{v}</option>)}
              </select>
            )}
          </div>
          <div>
            <label className="font-medium md-text-secondary block mb-0.5">Phase</label>
            <select className={SELECT_CLASS} value={selectedPhase} onChange={(e) => setPhase(e.target.value)}>
              <option value="">Select phase...</option>
              {availablePhases.map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
          </div>
          {/* Libraries */}
          <div>
            <label className="font-medium md-text-secondary block mb-0.5">Libraries</label>
            {selectedLibraries.length > 0 ? (
              <span className="md-text-muted">{selectedLibraries.length} selected</span>
            ) : loadingMeta ? (
              <span className="md-text-muted">Loading...</span>
            ) : (
              <span className="md-text-muted">None detected</span>
            )}
          </div>
        </div>
      )}
      {/* Algorithm checkboxes */}
      <div className="space-y-1">
        <p className="font-medium md-text-secondary mb-1">Algorithms</p>
        {(mode === "verification" ? VERIFICATION_ALGORITHMS : ALL_ALGORITHMS).map((algo) => {
          const avail = getAlgorithmAvailability(algo, availabilityContext);
          const checked = selectedAlgorithms.includes(algo);
          return (
            <div key={algo}>
              <label
                className={`flex items-center gap-2 p-0.5 rounded cursor-pointer hover:bg-[var(--md-bg-hover)] ${
                  !avail.available ? "opacity-50 cursor-not-allowed" : ""
                }`}
                title={avail.reason ?? undefined}
              >
                <input
                  type="checkbox"
                  checked={checked}
                  disabled={!avail.available}
                  onChange={() => toggleAlgorithm(algo)}
                  className="accent-[var(--md-accent-blue)]"
                />
                <span>{ALGO_LABELS[algo]}</span>
                <span
                  className="ml-auto inline-flex items-center justify-center w-3.5 h-3.5 rounded-full border border-[var(--md-border)] text-[9px] md-text-muted cursor-help shrink-0"
                  title={ALGO_DESCRIPTIONS[algo]}
                >
                  i
                </span>
              </label>
              {algo === "user_regex" && checked && (
                <div className="ml-6 mt-1 mb-1">
                  <input
                    type="text"
                    value={userRegex}
                    onChange={(e) => setUserRegex(e.target.value)}
                    placeholder='Regex pattern, e.g. \x00{16,32}'
                    className="w-full px-1.5 py-1 rounded border border-[var(--md-border)] bg-[var(--md-bg-primary)] text-xs font-mono"
                  />
                </div>
              )}
              {algo === "pattern_match" && checked && (
                <div className="ml-6 mt-1 mb-2 space-y-1.5">
                  {/* Built-in patterns */}
                  {builtinPatterns.length > 0 && (
                    <div>
                      <button
                        type="button"
                        onClick={() => setPatternsExpanded(!patternsExpanded)}
                        className="text-[10px] md-text-muted hover:md-text-primary flex items-center gap-1"
                      >
                        <span className="inline-block transition-transform" style={{ transform: patternsExpanded ? "rotate(90deg)" : "rotate(0deg)" }}>&#9654;</span>
                        Built-in patterns ({builtinPatterns.length})
                      </button>
                      {patternsExpanded && (
                        <div className="mt-1 space-y-0.5">
                          {builtinPatterns.map((p) => (
                            <div key={p.filename} className="flex items-start gap-1.5 text-[10px] pl-2">
                              <span className="font-mono font-medium shrink-0">{p.name}</span>
                              <span className="md-text-muted truncate">{p.description}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                  {/* Custom pattern JSON */}
                  <div>
                    <label className="text-[10px] md-text-secondary block mb-0.5">Custom Pattern (JSON)</label>
                    <textarea
                      value={customPatternJson}
                      onChange={(e) => setCustomPatternJson(e.target.value)}
                      placeholder="Paste a JSON pattern definition..."
                      rows={3}
                      className="w-full px-1.5 py-1 rounded border border-[var(--md-border)] bg-[var(--md-bg-primary)] text-[10px] font-mono resize-y"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPatternExample(!showPatternExample)}
                      className="text-[10px] md-text-muted hover:md-text-primary mt-0.5"
                    >
                      {showPatternExample ? "Hide Example" : "Show Example"}
                    </button>
                    {showPatternExample && (
                      <pre className="mt-1 p-1.5 rounded bg-[var(--md-bg-tertiary)] text-[9px] font-mono overflow-x-auto whitespace-pre">
{`{
  "name": "my_pattern",
  "description": "Custom pattern",
  "applicable_to": {"libraries": [], "protocol_versions": []},
  "key_spec": {"length": 32, "entropy_min": 7.0}
}`}
                      </pre>
                    )}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      <div className="flex items-center gap-2">
        <button onClick={inputMode === "file" ? handleRunFile : handleRun} disabled={!canRun}
          className="px-3 py-1.5 rounded text-white disabled:opacity-40 transition-opacity flex items-center gap-1.5"
          style={{ background: "var(--md-accent-blue)" }}>
          {isRunning && <span className="md-spinner" style={{ width: 10, height: 10, borderWidth: 1.5 }} />}
          {isRunning ? "Running..." : "Run Analysis"}
        </button>
        {result && <button onClick={reset} className="px-2 py-1 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]">Clear</button>}
      </div>

      {isRunning && (
        <div className="space-y-1">
          <div className="h-1.5 rounded-full bg-[var(--md-bg-tertiary)] overflow-hidden">
            <div className="h-full rounded-full md-progress-indeterminate" />
          </div>
          <p className="md-text-muted animate-pulse">{PROGRESS_STEPS[stepIdx]}</p>
        </div>
      )}

      {error && <p style={{ color: "var(--md-accent-red)" }}>{error}</p>}

      {result && <ResultsTable result={result} />}
    </div>
  );
}

function ResultsTable({ result }: { result: { libraries: { library: string; phase: string; hits: SecretHit[]; num_runs: number }[] } }) {
  const totalHits = result.libraries.reduce((s, l) => s + l.hits.length, 0);
  return (
    <div className="space-y-2">
      <p className="font-medium">{totalHits} hits across {result.libraries.length} libraries</p>
      {result.libraries.map((lib) => (
        <div key={lib.library} className="md-panel p-2">
          <div className="font-medium mb-1">{lib.library} -- {lib.hits.length} hits ({lib.num_runs} runs)</div>
          {lib.hits.length > 0 && (
            <table className="w-full text-[10px]">
              <thead>
                <tr className="md-text-muted">
                  <th className="text-left p-0.5">Type</th>
                  <th className="text-left p-0.5">Offset</th>
                  <th className="text-left p-0.5">Length</th>
                  <th className="text-left p-0.5">Run</th>
                </tr>
              </thead>
              <tbody>
                {lib.hits.slice(0, 50).map((h, i) => (
                  <tr key={i} className="hover:bg-[var(--md-bg-hover)]">
                    <td className="p-0.5 hb-key">{h.secret_type}</td>
                    <td className="p-0.5 font-mono">0x{h.offset.toString(16)}</td>
                    <td className="p-0.5">{h.length}</td>
                    <td className="p-0.5">{h.run_id}</td>
                  </tr>
                ))}
                {lib.hits.length > 50 && <tr><td colSpan={4} className="p-0.5 md-text-muted">...and {lib.hits.length - 50} more</td></tr>}
              </tbody>
            </table>
          )}
        </div>
      ))}
    </div>
  );
}
