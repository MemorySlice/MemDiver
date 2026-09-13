import { useCallback, useEffect, useRef, useState } from "react";
import { useShallow } from "zustand/react/shallow";
import { useTranslation } from "react-i18next";
import { runAnalysis, runFileAnalysis, listPhases, listProtocols, listPatterns } from "@/api/client";
import { fetchAnalysisResult } from "@/api/analysis";
import type { PatternInfo } from "@/api/types";
import { useAppStore, ALL_ALGORITHMS, SINGLE_FILE_ALGORITHMS, VERIFICATION_ALGORITHMS } from "@/stores/app-store";
import { useAnalysisStore } from "@/stores/analysis-store";
import { useResultsStore } from "@/stores/results-store";
import { useDumpStore } from "@/stores/dump-store";
import { useTaskProgress } from "@/hooks/useTaskProgress";
import { getAlgorithmAvailability, type AlgorithmAvailability } from "@/api/algorithms";
import { applyHitsToStores } from "@/utils/apply-hits";
import type { SecretHit } from "@/api/types";

const ALGO_AVAILABLE_PENDING: AlgorithmAvailability = { available: true, reason: null };

const PROGRESS_STEP_KEYS = [
  "progress.preparing",
  "progress.loadingDump",
  "progress.runningAlgorithms",
  "progress.scanningPatterns",
  "progress.processingResults",
];

const SELECT_CLASS = "w-full bg-[var(--md-bg-primary)] border border-[var(--md-border)] rounded px-1.5 py-1 text-xs";

export function AnalysisPanel() {
  const { t } = useTranslation("analysis");
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
  // NOTE: `message` changes on every progress tick (setProgress writes a fresh
  // string), so this selector still re-renders per tick — useShallow only stops
  // re-renders from the store's *other* fields. Fixing the per-tick storm needs
  // `message` split out into a leaf component; deliberately out of scope here.
  const {
    isRunning, result, error, message, taskId,
    startAnalysis, setTaskId, setProgress, setResult, setError, reset,
  } = useAnalysisStore(
    useShallow((s) => ({
      isRunning: s.isRunning,
      result: s.result,
      error: s.error,
      message: s.message,
      taskId: s.taskId,
      startAnalysis: s.startAnalysis,
      setTaskId: s.setTaskId,
      setProgress: s.setProgress,
      setResult: s.setResult,
      setError: s.setError,
      reset: s.reset,
    })),
  );

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
      setStepIdx((prev) => (prev + 1) % PROGRESS_STEP_KEYS.length);
    }, 2500);
    return () => clearInterval(interval);
  }, [isRunning]);

  // Algorithm availability is decided server-side (GET
  // /api/algorithms/availability). We fetch the map whenever the input
  // context changes and render from the resolved map; while a fetch is in
  // flight, algorithms are treated as available-but-pending (enabled) so the
  // checkbox list never flickers to a disabled state on a transient empty map.
  const algoList = mode === "verification" ? VERIFICATION_ALGORITHMS : ALL_ALGORITHMS;
  const dumpCount = pathInfo?.dump_count ?? 1;
  const hasKeylog = pathInfo?.has_keylog ?? !!keylogFilename;
  const [availabilityMap, setAvailabilityMap] = useState<Record<string, AlgorithmAvailability>>({});

  useEffect(() => {
    let cancelled = false;
    getAlgorithmAvailability({
      dumpCount,
      hasKeylog,
      hasCandidateKeys,
      mode: inputMode,
      algorithms: algoList,
    })
      .then((res) => { if (!cancelled) setAvailabilityMap(res.availability); })
      .catch(() => { /* leave the prior map; unknown algos treated as available */ });
    return () => { cancelled = true; };
  }, [dumpCount, hasKeylog, hasCandidateKeys, inputMode, mode, algoList]);

  // Both run paths now SUBMIT a task and store its id; progress + the
  // final result arrive over ``/ws/tasks/{taskId}`` (see useTaskProgress
  // wiring below). The GIL-bound algorithm work runs on the backend
  // TaskManager ProcessPool instead of blocking the request.
  const handleRun = useCallback(async () => {
    if (!selectedLibraries.length || !selectedPhase || !protocolVersion) return;
    useResultsStore.getState().clearResults();
    startAnalysis();
    try {
      const dirs = selectedLibraries.map((lib) =>
        datasetRoot ? `${datasetRoot}/${lib}` : lib
      );
      const { task_id } = await runAnalysis({
        library_dirs: dirs,
        phase: selectedPhase,
        protocol_version: protocolVersion,
        keylog_filename: keylogFilename,
        algorithms: selectedAlgorithms,
      });
      setTaskId(task_id);
    } catch (e) {
      setError(e instanceof Error ? e.message : t("panel.analysisFailed"));
    }
  }, [selectedLibraries, selectedPhase, protocolVersion, datasetRoot, keylogFilename, selectedAlgorithms, startAnalysis, setTaskId, setError]); // eslint-disable-line react-hooks/exhaustive-deps

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
      const { task_id } = await runFileAnalysis({
        dump_path: inputPath,
        algorithms: fileAlgos.length > 0 ? fileAlgos : [...SINGLE_FILE_ALGORITHMS],
        user_regex: userRegex || undefined,
        custom_patterns: parsedPatterns,
        ...useDumpStore.getState().getKeyMaterialByPath(inputPath),
      });
      setTaskId(task_id);
    } catch (e) {
      setError(e instanceof Error ? e.message : t("panel.fileAnalysisFailed"));
    }
  }, [inputPath, selectedAlgorithms, customPatternJson, userRegex, startAnalysis, setTaskId, setError]); // eslint-disable-line react-hooks/exhaustive-deps

  // Subscribe to the in-flight task's progress stream. The hook owns the
  // reconnecting WebSocket (websocket.ts) + HTTP backfill; we translate
  // its events into the analysis-store and, on completion, download the
  // full AnalysisResult from the ``analysis_result`` artifact.
  useTaskProgress(taskId, {
    onProgress: (pct, msg) =>
      setProgress(pct != null && pct >= 0 ? Math.round(pct * 100) : 0, msg ?? ""),
    onDone: () => {
      const activeTask = taskId;
      if (!activeTask) return;
      setProgress(100, t("progress.fetchingResult"));
      void (async () => {
        try {
          const res = await fetchAnalysisResult(activeTask);
          setResult(res);
          applyHitsToStores(res);
        } catch (e) {
          setError(e instanceof Error ? e.message : t("panel.analysisFailed"));
        }
      })();
    },
    onError: (err) => setError(err || t("panel.analysisFailed")),
  });

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
            <label className="font-medium md-text-secondary block mb-0.5">{t("panel.protocol")}</label>
            {protocolVersion ? (
              <span className="px-1.5 py-0.5 rounded bg-[var(--md-bg-hover)] text-xs">
                {protocolVersion}
              </span>
            ) : (
              <select className={SELECT_CLASS} value="" onChange={(e) => setProtocol(protocolName || "TLS", e.target.value)}>
                <option value="">{t("panel.selectProtocol")}</option>
                {availableProtocols.map((v) => <option key={v} value={v}>{v}</option>)}
              </select>
            )}
          </div>
          <div>
            <label className="font-medium md-text-secondary block mb-0.5">{t("panel.phase")}</label>
            <select className={SELECT_CLASS} value={selectedPhase} onChange={(e) => setPhase(e.target.value)}>
              <option value="">{t("panel.selectPhase")}</option>
              {availablePhases.map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
          </div>
          {/* Libraries */}
          <div>
            <label className="font-medium md-text-secondary block mb-0.5">{t("panel.libraries")}</label>
            {selectedLibraries.length > 0 ? (
              <span className="md-text-muted">{t("panel.selected", { count: selectedLibraries.length })}</span>
            ) : loadingMeta ? (
              <span className="md-text-muted">{t("panel.loading")}</span>
            ) : (
              <span className="md-text-muted">{t("panel.noneDetected")}</span>
            )}
          </div>
        </div>
      )}
      {/* Algorithm checkboxes */}
      <div className="space-y-1">
        <p className="font-medium md-text-secondary mb-1">{t("panel.algorithms")}</p>
        {algoList.map((algo) => {
          const avail = availabilityMap[algo] ?? ALGO_AVAILABLE_PENDING;
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
                <span>{t(`algoLabels.${algo}`)}</span>
                <span
                  className="ml-auto inline-flex items-center justify-center w-3.5 h-3.5 rounded-full border border-[var(--md-border)] text-[9px] md-text-muted cursor-help shrink-0"
                  title={t(`algoDescriptions.${algo}`)}
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
                    placeholder={t("panel.userRegexPlaceholder")}
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
                        {t("panel.builtinPatterns", { count: builtinPatterns.length })}
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
                    <label className="text-[10px] md-text-secondary block mb-0.5">{t("panel.customPattern")}</label>
                    <textarea
                      value={customPatternJson}
                      onChange={(e) => setCustomPatternJson(e.target.value)}
                      placeholder={t("panel.customPatternPlaceholder")}
                      rows={3}
                      className="w-full px-1.5 py-1 rounded border border-[var(--md-border)] bg-[var(--md-bg-primary)] text-[10px] font-mono resize-y"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPatternExample(!showPatternExample)}
                      className="text-[10px] md-text-muted hover:md-text-primary mt-0.5"
                    >
                      {showPatternExample ? t("panel.hideExample") : t("panel.showExample")}
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
          className="px-3 py-1.5 rounded md-text-on-accent disabled:opacity-40 transition-opacity flex items-center gap-1.5"
          style={{ background: "var(--md-accent-blue)" }}>
          {isRunning && <span className="md-spinner" style={{ width: 10, height: 10, borderWidth: 1.5 }} />}
          {isRunning ? t("panel.running") : t("panel.runAnalysis")}
        </button>
        {result && <button onClick={reset} className="px-2 py-1 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]">{t("common:clear")}</button>}
      </div>

      {isRunning && (
        <div className="space-y-1">
          <div className="h-1.5 rounded-full bg-[var(--md-bg-tertiary)] overflow-hidden">
            <div className="h-full rounded-full md-progress-indeterminate" />
          </div>
          <p className="md-text-muted animate-pulse">{message || t(PROGRESS_STEP_KEYS[stepIdx])}</p>
        </div>
      )}

      {error && <p style={{ color: "var(--md-accent-red)" }}>{error}</p>}

      {result && <ResultsTable result={result} />}
    </div>
  );
}

function ResultsTable({ result }: { result: { libraries: { library: string; phase: string; hits: SecretHit[]; num_runs: number }[] } }) {
  const { t } = useTranslation("analysis");
  const totalHits = result.libraries.reduce((s, l) => s + l.hits.length, 0);
  return (
    <div className="space-y-2">
      <p className="font-medium">{t("panel.hitsSummary", { hits: totalHits, libraries: result.libraries.length })}</p>
      {result.libraries.map((lib) => (
        <div key={lib.library} className="md-panel p-2">
          <div className="font-medium mb-1">{t("panel.libHits", { library: lib.library, hits: lib.hits.length, runs: lib.num_runs })}</div>
          {lib.hits.length > 0 && (
            <table className="w-full text-[10px]">
              <thead>
                <tr className="md-text-muted">
                  <th className="text-left p-0.5">{t("panel.colType")}</th>
                  <th className="text-left p-0.5">{t("panel.colOffset")}</th>
                  <th className="text-left p-0.5">{t("panel.colLength")}</th>
                  <th className="text-left p-0.5">{t("panel.colRun")}</th>
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
                {lib.hits.length > 50 && <tr><td colSpan={4} className="p-0.5 md-text-muted">{t("panel.more", { count: lib.hits.length - 50 })}</td></tr>}
              </tbody>
            </table>
          )}
        </div>
      ))}
    </div>
  );
}
