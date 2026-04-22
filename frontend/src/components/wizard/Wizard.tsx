import { useCallback, useEffect, useMemo, useState } from "react";
import { ThemeToggle } from "@/components/ThemeToggle";
import { FileBrowser } from "@/components/wizard/FileBrowser";
import { getPathInfo } from "@/api/client";
import { useAppStore, SINGLE_FILE_ALGORITHMS, REFERENCE_ALGORITHMS, MULTI_DUMP_ALGORITHMS, PROTOCOL_ALGORITHMS } from "@/stores/app-store";
import type { AlgorithmName } from "@/stores/app-store";
import { useKeyboardShortcuts } from "@/hooks/useKeyboardShortcuts";
import { getAlgorithmAvailability } from "@/utils/algorithm-availability";

const ALGO_LABELS: Record<AlgorithmName, { label: string; desc: string }> = {
  entropy_scan:          { label: "Entropy Scan",          desc: "Shannon entropy sliding window for high-entropy regions" },
  pattern_match:         { label: "Pattern Match",         desc: "Structural patterns from JSON definitions" },
  change_point:          { label: "Change Point",          desc: "CUSUM entropy change-point detection" },
  structure_scan:        { label: "Structure Scan",        desc: "Identify known data structures via overlay matching" },
  user_regex:            { label: "User Regex",            desc: "Custom regex pattern matching" },
  exact_match:           { label: "Exact Match",           desc: "Search for known key byte sequences" },
  differential:          { label: "Differential",          desc: "Cross-run byte variance analysis (needs 2+ dumps)" },
  constraint_validator:  { label: "Constraint Validator",  desc: "KDF relationship verification for candidates" },
};

function WizardHeader() {
  return (
    <div className="mb-8">
      <div className="fixed top-3 right-4 z-40">
        <ThemeToggle />
      </div>
      <div className="flex items-center gap-3">
        <img src="/memdiver-logo.svg" alt="" className="h-[96px] w-[96px]" />
        <span className="text-7xl font-bold md-text-accent">MemDiver</span>
      </div>
    </div>
  );
}

function StepIndicator({ steps, current }: { steps: string[]; current: number }) {
  return (
    <div className="flex mb-8 gap-1">
      {steps.map((label, i) => (
        <div key={label} className="flex-1 text-center">
          <div
            className={`h-1 rounded-full mb-1 ${
              i <= current ? "bg-[var(--md-accent-blue)]" : "bg-[var(--md-border)]"
            }`}
          />
          <span className={`text-xs ${i <= current ? "md-text-accent" : "md-text-muted"}`}>
            {label}
          </span>
        </div>
      ))}
    </div>
  );
}

function StepSelectData({ error }: { error: string | null }) {
  const { inputPath, setInputPath, keylogFilename } = useAppStore();
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [showBrowser, setShowBrowser] = useState(false);

  const handleBrowseSelect = (path: string) => {
    setInputPath(path);
    setShowBrowser(false);
  };

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold md-text-accent">Select Data</h2>
      <p className="text-sm md-text-secondary">
        Enter a path or browse to a dump file or directory.
      </p>

      <div className="flex gap-2">
        <input
          type="text"
          value={inputPath}
          onChange={(e) => setInputPath(e.target.value)}
          placeholder="Enter path to file or directory"
          className="flex-1 px-3 py-2 rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)] text-[var(--md-text-primary)] focus:border-[var(--md-accent-blue)]"
        />
        <button
          onClick={() => setShowBrowser(true)}
          className="px-4 py-2 rounded font-medium text-white transition-all"
          style={{ background: "var(--md-accent-blue)" }}
        >
          Open
        </button>
      </div>

      {error && <p className="text-sm" style={{ color: "var(--md-accent-red)" }}>{error}</p>}

      {/* Collapsible reference data section */}
      <button
        onClick={() => setShowAdvanced(!showAdvanced)}
        className="text-sm md-text-secondary hover:md-text-primary transition-colors"
      >
        {showAdvanced ? "\u25BE" : "\u25B8"} Reference Data (optional)
      </button>

      {showAdvanced && (
        <div className="ml-4 space-y-2 text-sm">
          <div>
            <label className="md-text-secondary">Keylog file:</label>
            <input
              type="text"
              value={keylogFilename}
              onChange={(e) => useAppStore.setState({ keylogFilename: e.target.value })}
              placeholder="keylog.csv"
              className="ml-2 px-2 py-1 rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)] text-[var(--md-text-primary)]"
            />
          </div>
          <p className="text-xs md-text-muted">
            Provide known keys, struct definitions, or other reference data for verification algorithms.
          </p>
        </div>
      )}


      {showBrowser && (
        <FileBrowser
          onSelect={handleBrowseSelect}
          onClose={() => setShowBrowser(false)}
        />
      )}
    </div>
  );
}

function StepDirectoryType() {
  const { inputMode, setInputMode, pathInfo } = useAppStore();
  const detectedMode = pathInfo?.detected_mode;

  // Auto-select on mount based on backend detection
  useEffect(() => {
    if (detectedMode === "run_directory") {
      setInputMode("directory");
    } else if (detectedMode === "dataset") {
      setInputMode("dataset");
    }
  }, [detectedMode, setInputMode]);

  const options = [
    {
      value: "directory" as const,
      label: "Library Directory",
      desc: "Contains runs of one library (e.g. openssl/)",
      detected: detectedMode === "run_directory",
    },
    {
      value: "dataset" as const,
      label: "Dataset Directory",
      desc: "Contains multiple library directories to compare",
      detected: detectedMode === "dataset",
    },
  ];

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold md-text-accent">What is this directory?</h2>
      {pathInfo && (
        <p className="text-sm md-text-muted">
          Found {pathInfo.dump_count} dump file{pathInfo.dump_count !== 1 ? "s" : ""}
          {pathInfo.has_keylog && " with keylog"}
        </p>
      )}
      <div className="flex gap-3">
        {options.map((o) => (
          <button
            key={o.value}
            onClick={() => setInputMode(o.value)}
            className={`flex-1 text-left p-4 rounded-lg border transition-colors ${
              inputMode === o.value
                ? "border-[var(--md-accent-blue)] bg-[var(--md-bg-selected)]"
                : "border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]"
            }`}
          >
            <div className="font-medium">
              {o.label}
              {o.detected && <span className="ml-2 text-xs md-text-muted">(detected)</span>}
            </div>
            <div className="text-sm md-text-secondary mt-1">{o.desc}</div>
          </button>
        ))}
      </div>
    </div>
  );
}

function StepAnalysis() {
  const {
    analysisApproach, setAnalysisApproach,
    selectedAlgorithms, toggleAlgorithm,
    pathInfo, inputMode, keylogFilename,
  } = useAppStore();

  const isSingleFile = inputMode === "file";

  const availabilityContext = useMemo(() => ({
    inputMode: isSingleFile ? "file" : (inputMode ?? null),
    dumpCount: pathInfo?.dump_count ?? 1,
    hasKeylog: pathInfo?.has_keylog ?? !!keylogFilename,
    hasCandidateKeys: false, // always false in wizard — no analysis has run yet
  }), [isSingleFile, inputMode, pathInfo, keylogFilename]);

  const allAlgos: AlgorithmName[] = useMemo(
    () => [...SINGLE_FILE_ALGORITHMS, ...REFERENCE_ALGORITHMS, ...MULTI_DUMP_ALGORITHMS, ...PROTOCOL_ALGORITHMS],
    [],
  );

  // Auto-deselect algorithms that become unavailable
  useEffect(() => {
    for (const algo of selectedAlgorithms) {
      const availability = getAlgorithmAvailability(algo, availabilityContext);
      if (!availability.available) {
        toggleAlgorithm(algo);
      }
    }
  }, [availabilityContext]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold md-text-accent">Analysis</h2>

      <div className="space-y-3">
        {/* Auto-Analyze option */}
        <button
          onClick={() => setAnalysisApproach("auto")}
          className={`w-full text-left p-4 rounded-lg border transition-colors ${
            analysisApproach === "auto"
              ? "border-[var(--md-accent-blue)] bg-[var(--md-bg-selected)]"
              : "border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]"
          }`}
        >
          <div className="font-medium">Auto-Analyze</div>
          <div className="text-sm md-text-secondary mt-1">
            Run selected algorithms to find key material and structures.
          </div>
        </button>

        {/* Algorithm checkboxes (only visible when auto is selected) */}
        {analysisApproach === "auto" && (
          <div className="ml-4 space-y-1.5">
            {allAlgos.map((algo) => {
              const meta = ALGO_LABELS[algo];
              const availability = getAlgorithmAvailability(algo, availabilityContext);
              const checked = selectedAlgorithms.includes(algo);
              return (
                <label
                  key={algo}
                  title={availability.reason ?? undefined}
                  className={`flex items-start gap-2 text-sm p-1 rounded ${
                    availability.available
                      ? "cursor-pointer hover:bg-[var(--md-bg-hover)]"
                      : "opacity-50 cursor-not-allowed"
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    disabled={!availability.available}
                    onChange={() => toggleAlgorithm(algo)}
                    className="mt-0.5 accent-[var(--md-accent-blue)]"
                  />
                  <div>
                    <span className="font-medium">{meta.label}</span>
                    <span className="ml-2 md-text-muted text-xs">{meta.desc}</span>
                    {!availability.available && availability.reason && (
                      <span className="block text-xs mt-0.5" style={{ color: "var(--md-text-muted)" }}>
                        {availability.reason}
                      </span>
                    )}
                  </div>
                </label>
              );
            })}
          </div>
        )}

        {/* Inspect Only option */}
        <button
          onClick={() => setAnalysisApproach("inspect")}
          className={`w-full text-left p-4 rounded-lg border transition-colors ${
            analysisApproach === "inspect"
              ? "border-[var(--md-accent-blue)] bg-[var(--md-bg-selected)]"
              : "border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]"
          }`}
        >
          <div className="font-medium">Inspect Only</div>
          <div className="text-sm md-text-secondary mt-1">
            View the dump without running analysis algorithms.
          </div>
        </button>
      </div>

      {/* Info note */}
      <p className="text-xs md-text-muted flex items-center gap-1.5">
        <span style={{ color: "var(--md-accent-blue)" }}>i</span>
        You can always run or toggle algorithms later from the workspace.
      </p>
    </div>
  );
}

export function Wizard() {
  const { wizardStep, setWizardStep, completeWizard, pathInfo, inputPath } = useAppStore();
  const [pathError, setPathError] = useState<string | null>(null);
  const [validating, setValidating] = useState(false);

  // Dynamic step list based on path detection
  const isDirectory = pathInfo?.is_directory ?? false;
  const steps = isDirectory
    ? ["Select Data", "Directory Type", "Analysis"]
    : ["Select Data", "Analysis"];

  // Map wizard step index to component
  const currentStepName = steps[wizardStep] ?? steps[0];

  // Clear error when user changes the path
  useEffect(() => {
    setPathError(null);
  }, [inputPath]);

  const goBack = useCallback(() => {
    const step = useAppStore.getState().wizardStep;
    if (step > 0) {
      setWizardStep(step - 1);
    }
  }, [setWizardStep]);

  const validateAndAdvance = useCallback(async () => {
    const path = useAppStore.getState().inputPath.trim();
    if (!path) return;
    setValidating(true);
    setPathError(null);
    try {
      const info = await getPathInfo(path);
      const store = useAppStore.getState();
      store.setPathInfo(info);
      if (!info.exists) {
        setPathError(`Path does not exist: "${path}"`);
        return;
      }
      if (info.is_file) {
        store.setInputMode("file");
      }
      if (info.is_directory && info.dump_count === 0 && info.detected_mode === "unknown") {
        setPathError("No dump files (.dump, .msl) found in this directory. Please select a directory containing memory dumps.");
        return;
      }
      setWizardStep(1);
    } catch {
      setPathError("Could not validate path. Is the backend running?");
    } finally {
      setValidating(false);
    }
  }, [setWizardStep]);

  const goForward = useCallback(async () => {
    if (currentStepName === "Select Data") {
      await validateAndAdvance();
    } else if (wizardStep < steps.length - 1) {
      setWizardStep(wizardStep + 1);
    } else {
      completeWizard();
    }
  }, [wizardStep, steps.length, setWizardStep, completeWizard, currentStepName, validateAndAdvance]);

  const shortcuts = useMemo(() => ({ escape: goBack }), [goBack]);
  useKeyboardShortcuts(shortcuts);

  const isLast = wizardStep === steps.length - 1;
  const nextDisabled =
    currentStepName === "Select Data"
      ? !inputPath.trim() || validating
      : false;

  return (
    <div className="min-h-screen flex flex-col" style={{ background: "var(--md-bg-primary)" }}>
      <div className="max-w-xl mx-auto mt-8 p-8 w-full">
        <WizardHeader />
        <StepIndicator steps={steps} current={wizardStep} />

        {/* Step content */}
        <div className="md-panel p-6 mb-6">
          {currentStepName === "Select Data" && <StepSelectData error={pathError} />}
          {currentStepName === "Directory Type" && <StepDirectoryType />}
          {currentStepName === "Analysis" && <StepAnalysis />}
        </div>

        {/* Navigation */}
        <div className="flex justify-between">
          <button
            onClick={goBack}
            disabled={wizardStep === 0}
            className="px-4 py-2 rounded border border-[var(--md-border)] disabled:opacity-30 hover:bg-[var(--md-bg-hover)] transition-colors"
          >
            Back
          </button>
          <button
            onClick={goForward}
            disabled={nextDisabled}
            className="px-4 py-2 rounded text-white transition-all disabled:opacity-30 disabled:cursor-not-allowed"
            style={{
              background: nextDisabled ? "var(--md-text-muted)" : "var(--md-accent-blue)",
            }}
          >
            {validating ? "\u23F3" : isLast ? "Start Analysis" : "Next"}
          </button>
        </div>
      </div>
    </div>
  );
}
