import { useCallback, useEffect, useMemo, useState } from "react";
import { useShallow } from "zustand/react/shallow";
import { useTranslation } from "react-i18next";
import { ThemeToggle } from "@/components/ThemeToggle";
import { FileBrowser } from "@/components/wizard/FileBrowser";
import { getPathInfo } from "@/api/client";
import { useAppStore, SINGLE_FILE_ALGORITHMS, REFERENCE_ALGORITHMS, MULTI_DUMP_ALGORITHMS, PROTOCOL_ALGORITHMS } from "@/stores/app-store";
import type { AlgorithmName } from "@/stores/app-store";
import { useKeyboardShortcuts } from "@/hooks/useKeyboardShortcuts";
import { getAlgorithmAvailability, type AlgorithmAvailability } from "@/api/algorithms";

const ALGO_AVAILABLE_PENDING: AlgorithmAvailability = { available: true, reason: null };

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

const STEP_INDICATOR_KEYS: Record<string, string> = {
  "Select Data": "step.indicator.selectData",
  "Directory Type": "step.indicator.directoryType",
  "Analysis": "step.indicator.analysis",
};

function StepIndicator({ steps, current }: { steps: string[]; current: number }) {
  const { t } = useTranslation("wizard");
  return (
    <div className="flex mb-8 gap-1">
      {steps.map((step, i) => (
        <div key={step} className="flex-1 text-center">
          <div
            className={`h-1 rounded-full mb-1 ${
              i <= current ? "bg-[var(--md-accent-blue)]" : "bg-[var(--md-border)]"
            }`}
          />
          <span className={`text-xs ${i <= current ? "md-text-accent" : "md-text-muted"}`}>
            {t(STEP_INDICATOR_KEYS[step] ?? step)}
          </span>
        </div>
      ))}
    </div>
  );
}

function StepSelectData({ error }: { error: string | null }) {
  const { t } = useTranslation("wizard");
  const { inputPath, setInputPath, keylogFilename } = useAppStore(
    useShallow((s) => ({
      inputPath: s.inputPath,
      setInputPath: s.setInputPath,
      keylogFilename: s.keylogFilename,
    })),
  );
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [showBrowser, setShowBrowser] = useState(false);

  const handleBrowseSelect = (path: string) => {
    setInputPath(path);
    setShowBrowser(false);
  };

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold md-text-accent">{t("step.selectData.title")}</h2>
      <p className="text-sm md-text-secondary">
        {t("step.selectData.description")}
      </p>

      <div className="flex gap-2">
        <input
          type="text"
          value={inputPath}
          onChange={(e) => setInputPath(e.target.value)}
          placeholder={t("step.selectData.pathPlaceholder")}
          className="flex-1 px-3 py-2 rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)] text-[var(--md-text-primary)] focus:border-[var(--md-accent-blue)]"
        />
        <button
          onClick={() => setShowBrowser(true)}
          className="px-4 py-2 rounded font-medium text-white transition-all"
          style={{ background: "var(--md-accent-blue)" }}
        >
          {t("step.selectData.open")}
        </button>
      </div>

      {error && <p className="text-sm" style={{ color: "var(--md-accent-red)" }}>{error}</p>}

      {/* Collapsible reference data section */}
      <button
        onClick={() => setShowAdvanced(!showAdvanced)}
        className="text-sm md-text-secondary hover:md-text-primary transition-colors"
      >
        {showAdvanced ? "\u25BE" : "\u25B8"} {t("step.selectData.referenceData")}
      </button>

      {showAdvanced && (
        <div className="ml-4 space-y-2 text-sm">
          <div>
            <label className="md-text-secondary">{t("step.selectData.keylogLabel")}</label>
            <input
              type="text"
              value={keylogFilename}
              onChange={(e) => useAppStore.setState({ keylogFilename: e.target.value })}
              placeholder={t("step.selectData.keylogPlaceholder")}
              className="ml-2 px-2 py-1 rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)] text-[var(--md-text-primary)]"
            />
          </div>
          <p className="text-xs md-text-muted">
            {t("step.selectData.referenceNote")}
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
  const { t } = useTranslation("wizard");
  const { inputMode, setInputMode, pathInfo } = useAppStore(
    useShallow((s) => ({
      inputMode: s.inputMode,
      setInputMode: s.setInputMode,
      pathInfo: s.pathInfo,
    })),
  );
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
      label: t("step.directoryType.library.label"),
      desc: t("step.directoryType.library.desc"),
      detected: detectedMode === "run_directory",
    },
    {
      value: "dataset" as const,
      label: t("step.directoryType.dataset.label"),
      desc: t("step.directoryType.dataset.desc"),
      detected: detectedMode === "dataset",
    },
  ];

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold md-text-accent">{t("step.directoryType.title")}</h2>
      {pathInfo && (
        <p className="text-sm md-text-muted">
          {t("step.directoryType.foundDumps", { count: pathInfo.dump_count })}
          {pathInfo.has_keylog && t("step.directoryType.withKeylog")}
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
              {o.detected && <span className="ml-2 text-xs md-text-muted">{t("step.directoryType.detected")}</span>}
            </div>
            <div className="text-sm md-text-secondary mt-1">{o.desc}</div>
          </button>
        ))}
      </div>
    </div>
  );
}

function StepAnalysis() {
  const { t } = useTranslation("wizard");
  const {
    analysisApproach, setAnalysisApproach,
    selectedAlgorithms, toggleAlgorithm,
    pathInfo, inputMode, keylogFilename,
  } = useAppStore(
    useShallow((s) => ({
      analysisApproach: s.analysisApproach,
      setAnalysisApproach: s.setAnalysisApproach,
      selectedAlgorithms: s.selectedAlgorithms,
      toggleAlgorithm: s.toggleAlgorithm,
      pathInfo: s.pathInfo,
      inputMode: s.inputMode,
      keylogFilename: s.keylogFilename,
    })),
  );

  const isSingleFile = inputMode === "file";

  const dumpCount = pathInfo?.dump_count ?? 1;
  const hasKeylog = pathInfo?.has_keylog ?? !!keylogFilename;
  const modeParam = isSingleFile ? "file" : (inputMode ?? undefined);

  const allAlgos: AlgorithmName[] = useMemo(
    () => [...SINGLE_FILE_ALGORITHMS, ...REFERENCE_ALGORITHMS, ...MULTI_DUMP_ALGORITHMS, ...PROTOCOL_ALGORITHMS],
    [],
  );

  // Algorithm availability is decided server-side (GET
  // /api/algorithms/availability). Fetch the map whenever the input context
  // changes. hasCandidateKeys is always false in the wizard — no analysis has
  // run yet.
  const [availabilityMap, setAvailabilityMap] = useState<Record<string, AlgorithmAvailability>>({});
  useEffect(() => {
    let cancelled = false;
    getAlgorithmAvailability({
      dumpCount,
      hasKeylog,
      hasCandidateKeys: false,
      mode: modeParam,
      algorithms: allAlgos,
    })
      .then((res) => { if (!cancelled) setAvailabilityMap(res.availability); })
      .catch(() => { /* keep prior map; unknown algos treated as available */ });
    return () => { cancelled = true; };
  }, [dumpCount, hasKeylog, modeParam, allAlgos]);

  // Auto-deselect algorithms that are unavailable. Depends on the RESOLVED
  // map (not the raw context) so it never deselects while a fetch is pending.
  useEffect(() => {
    for (const algo of selectedAlgorithms) {
      const availability = availabilityMap[algo];
      if (availability && !availability.available) {
        toggleAlgorithm(algo);
      }
    }
  }, [availabilityMap]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold md-text-accent">{t("step.analysis.title")}</h2>

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
          <div className="font-medium">{t("step.analysis.auto.label")}</div>
          <div className="text-sm md-text-secondary mt-1">
            {t("step.analysis.auto.desc")}
          </div>
        </button>

        {/* Algorithm checkboxes (only visible when auto is selected) */}
        {analysisApproach === "auto" && (
          <div className="ml-4 space-y-1.5">
            {allAlgos.map((algo) => {
              const availability = availabilityMap[algo] ?? ALGO_AVAILABLE_PENDING;
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
                    <span className="font-medium">{t(`algorithms.${algo}.label`)}</span>
                    <span className="ml-2 md-text-muted text-xs">{t(`algorithms.${algo}.desc`)}</span>
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
          <div className="font-medium">{t("step.analysis.inspect.label")}</div>
          <div className="text-sm md-text-secondary mt-1">
            {t("step.analysis.inspect.desc")}
          </div>
        </button>
      </div>

      {/* Info note */}
      <p className="text-xs md-text-muted flex items-center gap-1.5">
        <span style={{ color: "var(--md-accent-blue)" }}>i</span>
        {t("step.analysis.note")}
      </p>
    </div>
  );
}

export function Wizard() {
  const { t } = useTranslation("wizard");
  const { wizardStep, setWizardStep, completeWizard, pathInfo, inputPath } = useAppStore(
    useShallow((s) => ({
      wizardStep: s.wizardStep,
      setWizardStep: s.setWizardStep,
      completeWizard: s.completeWizard,
      pathInfo: s.pathInfo,
      inputPath: s.inputPath,
    })),
  );
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
        setPathError(t("validation.pathNotExist", { path }));
        return;
      }
      if (info.is_file) {
        store.setInputMode("file");
      }
      if (info.is_directory && info.dump_count === 0 && info.detected_mode === "unknown") {
        setPathError(t("validation.noDumps"));
        return;
      }
      setWizardStep(1);
    } catch {
      setPathError(t("validation.validateFailed"));
    } finally {
      setValidating(false);
    }
  }, [setWizardStep, t]);

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
            {t("common:back")}
          </button>
          <button
            onClick={goForward}
            disabled={nextDisabled}
            className="px-4 py-2 rounded text-white transition-all disabled:opacity-30 disabled:cursor-not-allowed"
            style={{
              background: nextDisabled ? "var(--md-text-muted)" : "var(--md-accent-blue)",
            }}
          >
            {validating ? "\u23F3" : isLast ? t("nav.startAnalysis") : t("common:next")}
          </button>
        </div>
      </div>
    </div>
  );
}
