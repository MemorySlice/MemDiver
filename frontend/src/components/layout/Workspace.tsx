import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import { useShallow } from "zustand/react/shallow";
import { useTranslation } from "react-i18next";
import { Panel, Group, Separator, type PanelImperativeHandle } from "react-resizable-panels";
import { ThemeToggle } from "@/components/ThemeToggle";
import { SettingsMenu } from "@/components/settings/SettingsMenu";
import { useAppStore } from "@/stores/app-store";
import { useAnalysisStore } from "@/stores/analysis-store";
import { useResultsStore } from "@/stores/results-store";
import { buildSessionSnapshot } from "@/utils/buildSessionSnapshot";
import { ModeBanner } from "@/components/analysis/ModeBanner";
import { AnalysisPanel } from "@/components/analysis/AnalysisPanel";
import { ConsensusBuilder } from "@/components/analysis/ConsensusBuilder";
import { ScanResultsPanel } from "@/components/results/ScanResultsPanel";
import { EntropyChart } from "@/components/charts/EntropyChart";
import { getEntropy, getVasRegions, saveSession, getNotebookStatus, listDatasetRuns } from "@/api/client";
import type { EntropyData, DatasetRun } from "@/api/types";
import type { VasEntry } from "@/components/charts/types";
import { BookmarkList } from "@/components/investigation/BookmarkList";
import { InvestigationPanel } from "@/components/investigation/InvestigationPanel";
import { FileUpload } from "@/components/upload/FileUpload";
import { SessionManager } from "@/components/session/SessionManager";
import { DumpList } from "@/components/dumps/DumpList";
import { DumpSelectionStrip } from "@/components/dumps/DumpSelectionStrip";
import { MainViewSwitcher } from "@/components/hex/MainViewSwitcher";
import { FormatNavigator } from "@/components/format/FormatNavigator";
import { StructureList } from "@/components/structures/StructureList";
import { StructureOverlayPanel } from "@/components/structures/StructureOverlayPanel";
import { BlockNavigator } from "@/components/blocks/BlockNavigator";
import { SessionInfoPanel } from "@/components/session/SessionInfoPanel";
import { ModuleList } from "@/components/msl/ModuleList";
import { ModuleIndex } from "@/components/msl/ModuleIndex";
import { ProcessList } from "@/components/msl/ProcessList";
import { ConnectionList } from "@/components/msl/ConnectionList";
import { HandleList } from "@/components/msl/HandleList";
import { ReservedBlocksList } from "@/components/msl/ReservedBlocksList";
import { useKeyboardShortcuts } from "@/hooks/useKeyboardShortcuts";
import { HexViewer } from "@/components/hex/HexViewer";
import { MultiHexViewer } from "@/components/hex/MultiHexViewer";
import { HexOverlayPane } from "@/components/hex/HexOverlayPane";
import { OverlayByteInspector } from "@/components/hex/OverlayByteInspector";
import { HexOverlay } from "@/components/hex/HexOverlay";
import { HexComparison } from "@/components/hex/HexComparison";
import { useHexStore } from "@/stores/hex-store";
import { NeighborhoodOverlayPanel } from "@/components/hex/NeighborhoodOverlayPanel";
import { useDumpStore } from "@/stores/dump-store";
import { useActiveDump } from "@/hooks/useActiveDump";
import { NotificationStack } from "@/components/NotificationStack";
import { ConsensusChart } from "@/components/charts/ConsensusChart";
import { CandidatePanel } from "@/components/charts/CandidatePanel";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { ArchitectPlaceholder } from "@/components/research/ArchitectPlaceholder";
import { StringsPanel } from "@/components/strings/StringsPanel";
import { ExperimentPanel } from "@/components/experiment/ExperimentPanel";
import { ConvergenceChart } from "@/components/charts/ConvergenceChart";
import { VarianceMap } from "@/components/charts/VarianceMap";
import { VasChart } from "@/components/charts/VasChart";
import { KeyVerificationPanel } from "@/components/verification/KeyVerificationPanel";
import PipelinePanel from "@/components/pipeline/PipelinePanel";
import { usePipelineStore } from "@/stores/pipeline-store";
import { notifyError } from "@/utils/errorNotifier";

function ResizeHandle({ orientation = "vertical" }: { orientation?: "horizontal" | "vertical" }) {
  const isHorizontal = orientation === "horizontal";
  return (
    <Separator className={`${isHorizontal ? "h-1" : "w-1"} flex items-center justify-center hover:bg-[var(--md-accent-blue)] transition-colors bg-[var(--md-border)] group`}>
      <div className={`flex ${isHorizontal ? "flex-row" : "flex-col"} gap-0.5 opacity-40 group-hover:opacity-100 transition-opacity`}>
        <div className="w-0.5 h-0.5 rounded-full bg-current" />
        <div className="w-0.5 h-0.5 rounded-full bg-current" />
        <div className="w-0.5 h-0.5 rounded-full bg-current" />
      </div>
    </Separator>
  );
}

function Toolbar() {
  const { t } = useTranslation("layout");
  const mode = useAppStore((s) => s.mode);
  const resetWizard = useAppStore((s) => s.resetWizard);
  const [notebookAvailable, setNotebookAvailable] = useState(false);
  useEffect(() => {
    getNotebookStatus().then((d) => setNotebookAvailable(d.available)).catch(() => {});
  }, []);
  return (
    <div data-tour-id="workspace-toolbar" className="flex items-center justify-between px-4 h-10 border-b border-[var(--md-border)] md-bg-secondary">
      <div className="flex items-center gap-2">
        <img src="/memdiver-logo.svg" alt="" className="h-6 w-6" />
        <span className="font-bold md-text-accent text-sm">MemDiver</span>
        <span
          className="text-xs px-2 py-0.5 rounded uppercase"
          style={{
            background: mode === "verification" ? "var(--md-accent-blue)" : "var(--md-accent-purple)",
            color: "white",
          }}
        >
          {t(`modeBadge.${mode}`)}
        </span>
      </div>
      <div className="flex items-center gap-2">
        {notebookAvailable && (
          <a
            href="/notebook"
            target="_blank"
            rel="noopener"
            className="text-xs px-2 py-1 rounded hover:bg-[var(--md-bg-hover)] transition-colors md-text-secondary"
            title={t("openNotebookTitle")}
          >
            {t("openNotebook")}
          </a>
        )}
        <button
          onClick={resetWizard}
          className="text-xs px-2 py-1 rounded hover:bg-[var(--md-bg-hover)] transition-colors md-text-secondary"
        >
          {t("newSession")}
        </button>
        <SettingsMenu />
        <ThemeToggle />
      </div>
    </div>
  );
}

type SideTab = "bookmarks" | "dumps" | "format" | "structures" | "sessions" | "import";
export type BottomTab = "analysis" | "results" | "strings" | "entropy" | "consensus" | "live-consensus" | "architect" | "experiment" | "convergence" | "variance" | "vas" | "verify-key" | "pipeline";

function Sidebar() {
  const { t } = useTranslation("layout");
  const [sideTab, setSideTab] = useState<SideTab>("bookmarks");
  const activeDump = useActiveDump();
  const dumpPath = activeDump?.path ?? "";
  const { bookmarks, addBookmark, removeBookmark } = useHexStore(
    useShallow((s) => ({
      bookmarks: s.bookmarks,
      addBookmark: s.addBookmark,
      removeBookmark: s.removeBookmark,
    })),
  );
  const cursorOffset = useHexStore((s) => s.cursorOffset);

  return (
    <div data-tour-id="workspace-sidebar" className="h-full flex flex-col overflow-hidden md-bg-secondary">
      <div className="flex border-b border-[var(--md-border)]">
        {(["bookmarks", "dumps", "format", "structures", "sessions", "import"] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setSideTab(tab)}
            title={t(`tabs.${tab}`)}
            data-testid={`tab-${tab}`}
            className={`flex-1 text-xs py-1.5 capitalize transition-colors truncate px-1 ${
              sideTab === tab ? "bg-[var(--md-bg-hover)]" : "md-text-secondary hover:bg-[var(--md-bg-hover)]"
            }`}
          >
            {t(`tabs.${tab}`)}
          </button>
        ))}
      </div>
      <div className="flex-1 overflow-auto">
        {sideTab === "bookmarks" && (
          <>
            <BookmarkList
              bookmarks={bookmarks}
              onAdd={addBookmark}
              onRemove={removeBookmark}
              onSelect={(off) => useHexStore.getState().scrollToOffset(off)}
            />
            {cursorOffset !== null && dumpPath && (
              <InvestigationPanel dumpPath={dumpPath} offset={cursorOffset} />
            )}
          </>
        )}
        {sideTab === "dumps" && <DumpList />}
        {sideTab === "format" && dumpPath && (
          <>
            <FormatNavigator dumpPath={dumpPath} />
            {dumpPath.endsWith(".msl") && (
              <>
                <SessionInfoPanel mslPath={dumpPath} />
                <div className="border-t border-[var(--md-border)] mt-2 pt-2 px-3">
                  <h4 className="text-xs font-semibold mb-1 md-text-muted">{t("mslBlocks")}</h4>
                </div>
                <BlockNavigator mslPath={dumpPath} onBlockClick={(off) => useHexStore.getState().scrollToOffset(off)} />
                <div className="border-t border-[var(--md-border)] mt-2 pt-2 px-3">
                  <h4 className="text-xs font-semibold mb-1 md-text-muted">{t("modules")}</h4>
                </div>
                <ModuleList mslPath={dumpPath} />
                <ModuleIndex mslPath={dumpPath} />
                <div className="border-t border-[var(--md-border)] mt-2 pt-2" />
                <ProcessList mslPath={dumpPath} />
                <ConnectionList mslPath={dumpPath} />
                <HandleList mslPath={dumpPath} />
                <div className="border-t border-[var(--md-border)] mt-2 pt-2" />
                <ReservedBlocksList
                  mslPath={dumpPath}
                  endpoint="thread-contexts"
                  title={t("threadContexts")}
                />
                <ReservedBlocksList
                  mslPath={dumpPath}
                  endpoint="file-descriptors"
                  title={t("fileDescriptors")}
                />
                <ReservedBlocksList
                  mslPath={dumpPath}
                  endpoint="network-connections"
                  title={t("networkConnections")}
                />
                <ReservedBlocksList
                  mslPath={dumpPath}
                  endpoint="env-blocks"
                  title={t("environmentBlocks")}
                />
                <ReservedBlocksList
                  mslPath={dumpPath}
                  endpoint="security-tokens"
                  title={t("securityTokens")}
                />
                <ReservedBlocksList
                  mslPath={dumpPath}
                  endpoint="system-context"
                  title={t("systemContext")}
                />
              </>
            )}
          </>
        )}
        {sideTab === "format" && !dumpPath && (
          <p className="p-3 text-xs md-text-muted">{t("loadFileToDetectFormat")}</p>
        )}
        {sideTab === "structures" && <StructureList />}
        {sideTab === "sessions" && <SessionManager />}
        {sideTab === "import" && <FileUpload />}
      </div>
    </div>
  );
}

function HexFocusBridge() {
  const hexFocus = useAppStore((s) => s.hexFocus);
  const setHexFocus = useAppStore((s) => s.setHexFocus);
  const scrollToOffset = useHexStore((s) => s.scrollToOffset);

  useEffect(() => {
    if (hexFocus) {
      scrollToOffset(hexFocus.offset);
      setHexFocus(null);
    }
  }, [hexFocus, scrollToOffset, setHexFocus]);

  return null;
}

function formatDumpSize(bytes: number): string {
  if (bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const exp = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** exp).toFixed(exp === 0 ? 0 : 1)} ${units[exp]}`;
}

const RUNS_PAGE = 50;

function DatasetOverview({ path }: { path: string }) {
  const { t } = useTranslation("layout");
  const { inputMode, pathInfo, setInputMode } = useAppStore(
    useShallow((s) => ({
      inputMode: s.inputMode,
      pathInfo: s.pathInfo,
      setInputMode: s.setInputMode,
    })),
  );
  const addDump = useDumpStore((s) => s.addDump);
  const setActiveDump = useDumpStore((s) => s.setActiveDump);
  const [runs, setRuns] = useState<DatasetRun[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState(false);

  // Enumerate the runs (and their dump files) under the selected directory so
  // the user can drill into an individual dump instead of only seeing a count.
  // Load only the first page here; subsequent pages are fetched on demand via
  // ``loadMore`` (button click or the IntersectionObserver sentinel below).
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(false);
    setRuns([]);
    setOffset(0);
    setTotal(0);
    listDatasetRuns(path, RUNS_PAGE, 0)
      .then((res) => {
        if (cancelled) return;
        setRuns(res.runs ?? []);
        setTotal(res.total ?? 0);
        setOffset(res.runs?.length ?? 0);
      })
      .catch(() => { if (!cancelled) setError(true); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [path]);

  const hasMore = total > 0 && runs.length < total;

  // Fetch and append the next page of runs. Guarded so overlapping triggers
  // (button click + sentinel scrolling into view) can't double-load, and stops
  // once every run has been accumulated.
  const loadMore = useCallback(() => {
    if (loadingMore || !hasMore) return;
    setLoadingMore(true);
    listDatasetRuns(path, RUNS_PAGE, offset)
      .then((res) => {
        setRuns((prev) => [...prev, ...(res.runs ?? [])]);
        setTotal(res.total ?? 0);
        setOffset((prev) => prev + (res.runs?.length ?? 0));
      })
      .catch(() => setError(true))
      .finally(() => setLoadingMore(false));
  }, [path, offset, loadingMore, hasMore]);

  // Auto-load the next page when the sentinel scrolls into view. The "Load
  // more" button remains as an accessible, keyboard-triggerable fallback.
  const sentinelRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const node = sentinelRef.current;
    if (!node || !hasMore) return;
    const observer = new IntersectionObserver((entries) => {
      if (entries.some((entry) => entry.isIntersecting)) loadMore();
    });
    observer.observe(node);
    return () => observer.disconnect();
  }, [hasMore, loadMore]);

  // Open a dataset dump: register it, make it active, and switch to file mode
  // so the hex viewer mounts on it (same path as the import flow).
  const openDump = (dumpPath: string, size: number) => {
    const name = dumpPath.split(/[\\/]/).pop() || dumpPath;
    const format = name.toLowerCase().endsWith(".msl") ? "msl" : "raw";
    const id = addDump({ path: dumpPath, name, size, format });
    setActiveDump(id);
    setInputMode("file");
  };

  return (
    <div className="h-full p-4 overflow-auto" data-testid="dataset-overview">
      <div className="max-w-3xl mx-auto">
        <p className="text-lg mb-1 md-text-accent">
          {t("loaded", { label: inputMode === "dataset" ? t("dataset") : t("libraryDirectory") })}
        </p>
        <p className="text-sm md-text-secondary mb-3 break-all">{path}</p>
        {pathInfo && (
          <div className="text-xs md-text-muted space-y-1 mb-4">
            <p>{t("dumpFilesFound", { n: pathInfo.dump_count })}</p>
            {pathInfo.has_keylog && <p>{t("keylogDetected")}</p>}
          </div>
        )}

        <h3 className="text-sm font-semibold md-text-secondary">{t("datasetRunsHeading")}</h3>
        <p className="text-xs md-text-muted mb-2">{t("datasetRunsHint")}</p>
        {loading && <p className="text-xs md-text-muted">{t("loadingRuns")}</p>}
        {error && <p className="text-xs" style={{ color: "var(--md-accent-red)" }}>{t("runsLoadFailed")}</p>}
        {!loading && !error && runs.length === 0 && (
          <p className="text-xs md-text-muted">{t("noRunsFound")}</p>
        )}
        <div className="space-y-3">
          {runs.map((run) => (
            <div key={run.path} className="md-panel p-2" data-testid="dataset-run">
              <p className="text-xs font-mono md-text-secondary truncate mb-1" title={run.path}>
                {run.path.split(/[\\/]/).pop()}
              </p>
              <ul className="space-y-0.5">
                {run.dumps.map((d) => (
                  <li key={d.path}>
                    <button
                      onClick={() => openDump(d.path, d.size)}
                      title={t("openDumpTitle")}
                      data-testid="dataset-dump"
                      className="w-full text-left text-xs font-mono px-2 py-1 rounded hover:bg-[var(--md-bg-hover)] flex items-center gap-2"
                    >
                      <span className="truncate flex-1">{d.path.split(/[\\/]/).pop()}</span>
                      {d.phase && <span className="md-text-muted shrink-0">{d.phase}</span>}
                      <span className="md-text-muted shrink-0">{d.kind}</span>
                      <span className="md-text-muted shrink-0 w-16 text-right">{formatDumpSize(d.size)}</span>
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
        {hasMore && (
          <>
            <div ref={sentinelRef} aria-hidden="true" />
            <button
              onClick={loadMore}
              disabled={loadingMore}
              data-testid="dataset-runs-load-more"
              className="w-full text-xs md-text-secondary px-2 py-1 mt-2 rounded md-panel hover:bg-[var(--md-bg-hover)] disabled:opacity-50"
            >
              {t("loadMoreRuns", { loaded: runs.length, total })}
            </button>
          </>
        )}

        <p className="text-sm md-text-secondary mt-4">
          {t("datasetAnalysisHint")}
        </p>
      </div>
    </div>
  );
}

/**
 * The persistent multi-dump bar above the main viewer.
 *
 * This is the fix for "I add a second dump and it disappears into a variance
 * number at the bottom of the screen": which dumps take part, which one is the
 * session's ORIGIN and which one is focused are now stated in the main area, at
 * the top, next to the control that lays them out.
 *
 * It renders the SAME `DumpSelectionStrip` the Import tab mounts, so the two
 * entry points cannot drift apart.
 */
function MainAreaDumpBar() {
  const inputMode = useAppStore((s) => s.inputMode);
  if (inputMode !== "file") return null;
  return (
    <div
      data-testid="main-area-dump-bar"
      className="flex items-center gap-2 px-3 py-1.5 border-b border-[var(--md-border)] md-bg-secondary min-w-0"
    >
      <MainViewSwitcher />
      <DumpSelectionStrip />
    </div>
  );
}

function MainContent() {
  const { t } = useTranslation("layout");
  const inputMode = useAppStore((s) => s.inputMode);
  const inputPath = useAppStore((s) => s.inputPath);
  const { viewMode, comparisonDumpIds, dumps } = useDumpStore(
    useShallow((s) => ({
      viewMode: s.viewMode,
      comparisonDumpIds: s.comparisonDumpIds,
      dumps: s.dumps,
    })),
  );
  // `mainView` is the N-dump layout over the whole selection; `viewMode` above
  // is the legacy PAIRWISE switch driven by `comparisonDumpIds`. Two fields,
  // two components, deliberately not merged — see the dump-store comment.
  const mainView = useDumpStore((s) => s.mainView);
  const activeDump = useActiveDump();
  const path = inputPath;

  if (!path) {
    return (
      <div className="h-full p-4 overflow-auto flex items-center justify-center md-text-muted">
        <div className="text-center">
          <p className="text-lg mb-2">{t("workspaceReady")}</p>
          <p className="text-sm">{t("noPathSelected")}</p>
          <p className="text-xs mt-4 md-text-muted">
            {t("shortcutsHint")}
          </p>
        </div>
      </div>
    );
  }

  if (inputMode === "file") {
    if ((viewMode === "overlay" || viewMode === "comparison") && comparisonDumpIds) {
      const pathA = dumps.find((d) => d.id === comparisonDumpIds[0])?.path;
      const pathB = dumps.find((d) => d.id === comparisonDumpIds[1])?.path;
      if (pathA && pathB) {
        return viewMode === "overlay"
          ? <HexOverlay pathA={pathA} pathB={pathB} />
          : <HexComparison pathA={pathA} pathB={pathB} />;
      }
      // A comparison target no longer resolves (e.g. a dump was removed).
      // Show an explicit message instead of silently falling through to
      // the single-dump hex view, which would be misleading.
      return (
        <div className="h-full p-4 overflow-auto flex items-center justify-center md-text-muted">
          <div className="text-center">
            <p className="text-lg mb-2">{t("comparisonUnavailable")}</p>
            <p className="text-sm">{t("comparisonUnavailableDetail", { viewMode })}</p>
          </div>
        </div>
      );
    }

    // The N-dump layouts are store-driven: they anchor on `activeDumpId` and
    // lay out the whole selection, so they take no path props. `reconcileSelection`
    // (I4) degrades `mainView` to "single" below two selected dumps, so neither
    // branch can be reached without something to lay out.
    if (mainView === "sideBySide") return <MultiHexViewer />;
    if (mainView === "overlay") return <HexOverlayPane />;

    const dumpPath = activeDump?.path ?? path;
    const fileSize = activeDump?.fileSize ?? 0;
    const format = activeDump?.format ?? "raw";
    return <HexViewer dumpPath={dumpPath} fileSize={fileSize} format={format} />;
  }

  return <DatasetOverview path={path} />;
}

function DetailPanel() {
  const { t } = useTranslation("layout");
  const neighborhoodOverlay = useHexStore((s) => s.activeNeighborhoodOverlay);
  const overlay = useHexStore((s) => s.activeStructureOverlay);
  const result = useAnalysisStore((s) => s.result);
  const mainView = useDumpStore((s) => s.mainView);
  const inputMode = useAppStore((s) => s.inputMode);

  // In the aligned overlay the detail panel answers the question the overlay
  // itself cannot: WHICH dumps disagree at the cursor. It outranks the
  // structure/neighborhood panels because the user is looking at a byte stream
  // whose whole point is the cross-dump comparison.
  if (mainView === "overlay" && inputMode === "file") {
    return <OverlayByteInspector />;
  }

  if (neighborhoodOverlay) {
    return <NeighborhoodOverlayPanel />;
  }

  if (overlay) {
    return <StructureOverlayPanel variant="detail" />;
  }

  if (!result) {
    return (
      <div className="h-full p-3 overflow-auto md-bg-secondary">
        <h3 className="text-xs font-semibold uppercase tracking-wider mb-2 md-text-muted">{t("details")}</h3>
        <p className="text-sm md-text-secondary">
          {t("detailsHint")}
        </p>
      </div>
    );
  }
  const totalHits = result.libraries.reduce((s, l) => s + l.hits.length, 0);
  return (
    <div className="h-full p-3 overflow-auto md-bg-secondary text-xs space-y-2">
      <h3 className="text-xs font-semibold uppercase tracking-wider md-text-muted">{t("resultsSummary")}</h3>
      <p>{t("hitsAcrossLibraries", { hits: totalHits, libraries: result.libraries.length })}</p>
      {result.libraries.map((lib) => (
        <div key={lib.library} className="md-panel p-2">
          <span className="font-medium">{lib.library}</span>
          <span className="ml-2 md-text-muted">{t("libraryHits", { n: lib.hits.length })}</span>
        </div>
      ))}
    </div>
  );
}

function BottomTabs() {
  const { t } = useTranslation("layout");
  // Aliased reference to the translate function: the tab-row `.map((t) => ...)`
  // below shadows `t` with the tab name, so the aria-label lookup inside that
  // callback must go through this alias instead of the shadowed `t`.
  const translate = t;
  const [tab, setTab] = useState<BottomTab>("analysis");
  const totalHits = useResultsStore((s) => s.getTotalHitCount());
  const isRunning = useAnalysisStore((s) => s.isRunning);
  const pipelineStatus = usePipelineStore((s) => s.status);
  const pipelineRunning =
    pipelineStatus === "running" || pipelineStatus === "pending";
  const prevHitsRef = useRef(totalHits);
  const activeDump = useActiveDump();
  const dumpPath = activeDump?.path ?? "";
  const [entropyData, setEntropyData] = useState<EntropyData | null>(null);
  const [entropyLoading, setEntropyLoading] = useState(false);
  const entropyPathRef = useRef("");
  // VAS entries are tagged with the dump path they were fetched for, so the
  // chart never briefly renders a previous dump's regions while the new
  // dump's fetch is still in flight (there is no VAS loading placeholder).
  const [vasData, setVasData] = useState<{ path: string; entries: VasEntry[] }>({
    path: "",
    entries: [],
  });
  const vasPathRef = useRef("");
  const mode = useAppStore((s) => s.mode);
  // The variance tab mirrors whatever neighborhood the user is currently
  // inspecting in the hex viewer (see NeighborhoodOverlayPanel), rather than
  // a pipeline-run-scoped hit — that overlay is the one "live" variance
  // series the workspace already tracks.
  const neighborhoodOverlay = useHexStore((s) => s.activeNeighborhoodOverlay);
  const availableTabs: BottomTab[] =
    mode === "verification"
      ? ["analysis", "results", "strings", "verify-key", "pipeline"]
      : ["analysis", "results", "strings", "entropy", "consensus", "live-consensus", "architect", "experiment", "convergence", "variance", "vas", "verify-key", "pipeline"];

  // Auto-switch to analysis tab when analysis starts — except when a
  // pipeline task is running; the user is watching the Pipeline tab
  // and we must not steal focus from it.
  useEffect(() => {
    if (isRunning && !pipelineRunning) setTab("analysis");
  }, [isRunning, pipelineRunning]);

  // Reset tab when mode hides the current tab
  useEffect(() => {
    if (!availableTabs.includes(tab)) setTab("analysis");
  }, [mode]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    // Don't hijack the bottom tab on first-hit notifications while a
    // pipeline run owns the stage.
    if (pipelineRunning) {
      prevHitsRef.current = totalHits;
      return;
    }
    if (totalHits > 0 && totalHits !== prevHitsRef.current) {
      setTab("results");
    }
    prevHitsRef.current = totalHits;
  }, [totalHits, pipelineRunning]);

  useEffect(() => {
    if (tab !== "entropy" || !dumpPath) return;
    if (entropyPathRef.current === dumpPath) return;
    entropyPathRef.current = dumpPath;
    let cancelled = false;
    setEntropyLoading(true);
    getEntropy(dumpPath, 0, 0, useDumpStore.getState().getKeyMaterialByPath(dumpPath))
      .then((d) => { if (!cancelled) setEntropyData(d); })
      .catch((err) => {
        if (!cancelled) setEntropyData(null);
        notifyError(
          `Entropy fetch failed: ${err instanceof Error ? err.message : String(err)}`,
          "entropy",
          { severity: "warning" },
        );
      })
      .finally(() => { if (!cancelled) setEntropyLoading(false); });
    return () => { cancelled = true; };
  }, [tab, dumpPath]);

  useEffect(() => {
    if (tab !== "vas" || !dumpPath) return;
    if (vasPathRef.current === dumpPath) return;
    vasPathRef.current = dumpPath;
    let cancelled = false;
    getVasRegions(dumpPath, useDumpStore.getState().getKeyMaterialByPath(dumpPath))
      .then((d) => { if (!cancelled) setVasData({ path: dumpPath, entries: d.vas_entries }); })
      .catch((err) => {
        if (!cancelled) setVasData({ path: dumpPath, entries: [] });
        notifyError(
          `VAS fetch failed: ${err instanceof Error ? err.message : String(err)}`,
          "vas",
          { severity: "warning" },
        );
      });
    return () => { cancelled = true; };
  }, [tab, dumpPath]);

  return (
    <div data-tour-id="workspace-bottom" className="h-full flex flex-col md-bg-secondary">
      <ModeBanner />
      <div className="flex gap-4 px-3 py-1.5 border-b border-[var(--md-border)]">
        {availableTabs.map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            data-testid={`tab-${t}`}
            className={`text-xs px-2 py-0.5 capitalize transition-colors flex items-center ${
              tab === t
                ? "font-semibold border-b-2 border-[var(--md-accent-blue)] bg-[var(--md-bg-hover)] rounded-t"
                : "md-text-secondary hover:bg-[var(--md-bg-hover)] rounded"
            }`}
          >
            {translate(`bottomTabs.${t}`, { defaultValue: t })}
            {t === "analysis" && isRunning && (
              <span
                className="ml-1 md-spinner"
                role="status"
                aria-live="polite"
                aria-label={translate("analysisRunningAria")}
              />
            )}
            {t === "results" && totalHits > 0 && (
              <span
                className="ml-1 px-1.5 py-0.5 text-[10px] rounded-full bg-[var(--md-accent-blue)] text-white"
                aria-live="polite"
              >
                {totalHits}
              </span>
            )}
          </button>
        ))}
      </div>
      <div className="flex-1 overflow-auto">
        {tab === "analysis" && <AnalysisPanel />}
        {tab === "results" && <ScanResultsPanel />}
        {tab === "entropy" && (
          <div aria-live="polite">
            {!dumpPath ? (
              <p className="p-3 text-sm md-text-muted">{t("loadDumpForEntropy")}</p>
            ) : entropyLoading ? (
              <p className="p-3 text-sm md-text-muted">{t("loadingEntropy")}</p>
            ) : entropyData ? (
              <EntropyChart data={entropyData} />
            ) : (
              <p className="p-3 text-sm md-text-muted">{t("entropyLoadFailed")}</p>
            )}
          </div>
        )}
        {tab === "strings" && (
          !dumpPath ? (
            <p className="p-3 text-sm md-text-muted">{t("loadDumpForStrings")}</p>
          ) : (
            <StringsPanel dumpPath={dumpPath} />
          )
        )}
        {tab === "consensus" && (
          <div className="space-y-2">
            <ConsensusChart onNavigate={setTab} />
            {/* The ranked candidate list belongs under the histogram it
                explains, not behind a new tab: the analyst who just ran a
                consensus is already here. */}
            <ErrorBoundary>
              <CandidatePanel />
            </ErrorBoundary>
          </div>
        )}
        {tab === "live-consensus" && <ConsensusBuilder />}
        {tab === "architect" && <ArchitectPlaceholder />}
        {tab === "experiment" && <ExperimentPanel />}
        {tab === "convergence" && <ConvergenceChart data={null} />}
        {tab === "variance" && (
          neighborhoodOverlay && neighborhoodOverlay.variance.length > 0 ? (
            <VarianceMap variance={neighborhoodOverlay.variance} />
          ) : (
            <p className="p-3 text-sm md-text-muted">{t("noVarianceData")}</p>
          )
        )}
        {tab === "vas" && (
          <VasChart entries={vasData.path === dumpPath ? vasData.entries : []} />
        )}
        {tab === "verify-key" && <KeyVerificationPanel />}
        {tab === "pipeline" && <PipelinePanel />}
      </div>
    </div>
  );
}

export function Workspace() {
  const resetWizard = useAppStore((s) => s.resetWizard);
  const sidebarRef = useRef<PanelImperativeHandle>(null);

  const toggleSidebar = useCallback(() => {
    const panel = sidebarRef.current;
    if (!panel) return;
    if (panel.isCollapsed()) {
      panel.expand();
    } else {
      panel.collapse();
    }
  }, []);

  const handleCtrlS = useCallback(() => {
    saveSession(buildSessionSnapshot("autosave"))
      .catch(() => {/* silently ignore autosave errors */});
  }, []);

  const shortcuts = useMemo(() => ({
    "ctrl+n": () => resetWizard(),
    "ctrl+s": handleCtrlS,
    "ctrl+g": () => {
      const input = document.querySelector<HTMLInputElement>('input[placeholder="0x offset"]');
      input?.focus();
    },
    "ctrl+b": () => toggleSidebar(),
  }), [resetWizard, handleCtrlS, toggleSidebar]);

  useKeyboardShortcuts(shortcuts);

  return (
    <div className="h-screen flex flex-col" style={{ background: "var(--md-bg-primary)" }}>
      <Toolbar />
      <Group orientation="vertical" id="memdiver-v-layout" className="flex-1">
        <Panel id="top" defaultSize="60%" minSize="25%">
          <Group orientation="horizontal" id="memdiver-h-layout">
            <Panel
              id="sidebar"
              defaultSize="25%"
              minSize="10%"
              maxSize="40%"
              collapsible={true}
              collapsedSize="0%"
              panelRef={sidebarRef}
            >
              <Sidebar />
            </Panel>
            <ResizeHandle />
            <Panel id="main" defaultSize="45%" minSize="20%">
              <HexFocusBridge />
              <div data-tour-id="workspace-main" className="h-full flex flex-col min-h-0">
                <MainAreaDumpBar />
                <div className="flex-1 min-h-0">
                  <MainContent />
                </div>
              </div>
            </Panel>
            <ResizeHandle />
            <Panel
              id="detail"
              defaultSize="30%"
              minSize="8%"
              maxSize="45%"
              collapsible={true}
              collapsedSize="0%"
            >
              <div data-tour-id="workspace-detail" className="h-full">
                <DetailPanel />
              </div>
            </Panel>
          </Group>
        </Panel>
        <ResizeHandle orientation="horizontal" />
        <Panel id="bottom" defaultSize="40%" minSize="12%" maxSize="60%">
          <BottomTabs />
        </Panel>
      </Group>
      <NotificationStack />
    </div>
  );
}
