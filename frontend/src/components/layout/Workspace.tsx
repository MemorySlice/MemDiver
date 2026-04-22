import { useEffect, useMemo, useRef, useState, useCallback } from "react";
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
import { getEntropy, saveSession, getNotebookStatus } from "@/api/client";
import type { EntropyData } from "@/api/types";
import { BookmarkList } from "@/components/investigation/BookmarkList";
import { InvestigationPanel } from "@/components/investigation/InvestigationPanel";
import { FileUpload } from "@/components/upload/FileUpload";
import { SessionManager } from "@/components/session/SessionManager";
import { DumpList } from "@/components/dumps/DumpList";
import { FormatNavigator } from "@/components/format/FormatNavigator";
import { StructureList } from "@/components/structures/StructureList";
import { StructureOverlayPanel } from "@/components/structures/StructureOverlayPanel";
import { BlockNavigator } from "@/components/blocks/BlockNavigator";
import { ModuleList } from "@/components/msl/ModuleList";
import { ModuleIndex } from "@/components/msl/ModuleIndex";
import { ProcessList } from "@/components/msl/ProcessList";
import { ConnectionList } from "@/components/msl/ConnectionList";
import { HandleList } from "@/components/msl/HandleList";
import { ReservedBlocksList } from "@/components/msl/ReservedBlocksList";
import { useKeyboardShortcuts } from "@/hooks/useKeyboardShortcuts";
import { HexViewer } from "@/components/hex/HexViewer";
import { HexOverlay } from "@/components/hex/HexOverlay";
import { HexComparison } from "@/components/hex/HexComparison";
import { useHexStore } from "@/stores/hex-store";
import { NeighborhoodOverlayPanel } from "@/components/hex/NeighborhoodOverlayPanel";
import { useDumpStore } from "@/stores/dump-store";
import { useActiveDump } from "@/hooks/useActiveDump";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { ConsensusChart } from "@/components/charts/ConsensusChart";
import { ArchitectPlaceholder } from "@/components/research/ArchitectPlaceholder";
import { StringsPanel } from "@/components/strings/StringsPanel";
import { ExperimentPanel } from "@/components/experiment/ExperimentPanel";
import { ConvergenceChart } from "@/components/charts/ConvergenceChart";
import { KeyVerificationPanel } from "@/components/verification/KeyVerificationPanel";
import PipelinePanel from "@/components/pipeline/PipelinePanel";
import { usePipelineStore } from "@/stores/pipeline-store";

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
  const { mode, resetWizard } = useAppStore();
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
          {mode}
        </span>
      </div>
      <div className="flex items-center gap-2">
        {mode === "exploration" && notebookAvailable && (
          <a
            href="/notebook"
            target="_blank"
            rel="noopener"
            className="text-xs px-2 py-1 rounded hover:bg-[var(--md-bg-hover)] transition-colors md-text-secondary"
            title="Open Marimo research notebook in new tab"
          >
            Open Notebook
          </a>
        )}
        <button
          onClick={resetWizard}
          className="text-xs px-2 py-1 rounded hover:bg-[var(--md-bg-hover)] transition-colors md-text-secondary"
        >
          New Session
        </button>
        <SettingsMenu />
        <ThemeToggle />
      </div>
    </div>
  );
}

type SideTab = "bookmarks" | "dumps" | "format" | "structures" | "sessions" | "import";
export type BottomTab = "analysis" | "results" | "strings" | "entropy" | "consensus" | "live-consensus" | "architect" | "experiment" | "convergence" | "verify-key" | "pipeline";

function Sidebar() {
  const [sideTab, setSideTab] = useState<SideTab>("bookmarks");
  const activeDump = useActiveDump();
  const dumpPath = activeDump?.path ?? "";
  const { bookmarks, addBookmark, removeBookmark } = useHexStore();
  const cursorOffset = useHexStore((s) => s.cursorOffset);

  return (
    <div data-tour-id="workspace-sidebar" className="h-full flex flex-col overflow-hidden md-bg-secondary">
      <div className="flex border-b border-[var(--md-border)]">
        {(["bookmarks", "dumps", "format", "structures", "sessions", "import"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setSideTab(t)}
            title={t}
            data-testid={`tab-${t}`}
            className={`flex-1 text-xs py-1.5 capitalize transition-colors truncate px-1 ${
              sideTab === t ? "bg-[var(--md-bg-hover)]" : "md-text-secondary hover:bg-[var(--md-bg-hover)]"
            }`}
          >
            {t}
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
                <div className="border-t border-[var(--md-border)] mt-2 pt-2 px-3">
                  <h4 className="text-xs font-semibold mb-1 md-text-muted">MSL Blocks</h4>
                </div>
                <BlockNavigator mslPath={dumpPath} onBlockClick={(off) => useHexStore.getState().scrollToOffset(off)} />
                <div className="border-t border-[var(--md-border)] mt-2 pt-2 px-3">
                  <h4 className="text-xs font-semibold mb-1 md-text-muted">Modules</h4>
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
                  title="Thread Contexts"
                />
                <ReservedBlocksList
                  mslPath={dumpPath}
                  endpoint="file-descriptors"
                  title="File Descriptors"
                />
                <ReservedBlocksList
                  mslPath={dumpPath}
                  endpoint="network-connections"
                  title="Network Connections"
                />
                <ReservedBlocksList
                  mslPath={dumpPath}
                  endpoint="env-blocks"
                  title="Environment Blocks"
                />
                <ReservedBlocksList
                  mslPath={dumpPath}
                  endpoint="security-tokens"
                  title="Security Tokens"
                />
                <ReservedBlocksList
                  mslPath={dumpPath}
                  endpoint="system-context"
                  title="System Context"
                />
              </>
            )}
          </>
        )}
        {sideTab === "format" && !dumpPath && (
          <p className="p-3 text-xs md-text-muted">Load a file to detect format.</p>
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
  const { scrollToOffset } = useHexStore();

  useEffect(() => {
    if (hexFocus) {
      scrollToOffset(hexFocus.offset);
      setHexFocus(null);
    }
  }, [hexFocus, scrollToOffset, setHexFocus]);

  return null;
}

function DatasetOverview({ path }: { path: string }) {
  const { inputMode, pathInfo } = useAppStore();
  return (
    <div className="h-full p-4 overflow-auto flex items-center justify-center">
      <div className="text-center max-w-md">
        <p className="text-lg mb-2 md-text-accent">
          {inputMode === "dataset" ? "Dataset" : "Library Directory"} Loaded
        </p>
        <p className="text-sm md-text-secondary mb-4 break-all">{path}</p>
        {pathInfo && (
          <div className="text-xs md-text-muted space-y-1">
            <p>{pathInfo.dump_count} dump files found</p>
            {pathInfo.has_keylog && <p>Keylog detected</p>}
          </div>
        )}
        <p className="text-sm md-text-secondary mt-4">
          Use the Analysis panel below to configure and run analysis on this dataset.
        </p>
      </div>
    </div>
  );
}

function MainContent() {
  const { inputMode, inputPath } = useAppStore();
  const { viewMode, comparisonDumpIds, dumps } = useDumpStore();
  const activeDump = useActiveDump();
  const path = inputPath;

  if (!path) {
    return (
      <div className="h-full p-4 overflow-auto flex items-center justify-center md-text-muted">
        <div className="text-center">
          <p className="text-lg mb-2">Workspace Ready</p>
          <p className="text-sm">No path selected.</p>
          <p className="text-xs mt-4 md-text-muted">
            Ctrl+G: Go to offset | Ctrl+S: Save session | Ctrl+N: New session | Ctrl+B: Toggle sidebar
          </p>
        </div>
      </div>
    );
  }

  if (inputMode === "file") {
    if (viewMode === "overlay" && comparisonDumpIds) {
      const pathA = dumps.find((d) => d.id === comparisonDumpIds[0])?.path;
      const pathB = dumps.find((d) => d.id === comparisonDumpIds[1])?.path;
      if (pathA && pathB) {
        return <HexOverlay pathA={pathA} pathB={pathB} />;
      }
    }

    if (viewMode === "comparison" && comparisonDumpIds) {
      const pathA = dumps.find((d) => d.id === comparisonDumpIds[0])?.path;
      const pathB = dumps.find((d) => d.id === comparisonDumpIds[1])?.path;
      if (pathA && pathB) {
        return <HexComparison pathA={pathA} pathB={pathB} />;
      }
    }

    const dumpPath = activeDump?.path ?? path;
    const fileSize = activeDump?.fileSize ?? 0;
    const format = activeDump?.format ?? "raw";
    return <HexViewer dumpPath={dumpPath} fileSize={fileSize} format={format} />;
  }

  return <DatasetOverview path={path} />;
}

function DetailPanel() {
  const neighborhoodOverlay = useHexStore((s) => s.activeNeighborhoodOverlay);
  const overlay = useHexStore((s) => s.activeStructureOverlay);
  const result = useAnalysisStore((s) => s.result);

  if (neighborhoodOverlay) {
    return <NeighborhoodOverlayPanel />;
  }

  if (overlay) {
    return <StructureOverlayPanel variant="detail" />;
  }

  if (!result) {
    return (
      <div className="h-full p-3 overflow-auto md-bg-secondary">
        <h3 className="text-xs font-semibold uppercase tracking-wider mb-2 md-text-muted">Details</h3>
        <p className="text-sm md-text-secondary">
          Click a structure in the Format or Structures tab to inspect parsed fields, or run analysis to see results.
        </p>
      </div>
    );
  }
  const totalHits = result.libraries.reduce((s, l) => s + l.hits.length, 0);
  return (
    <div className="h-full p-3 overflow-auto md-bg-secondary text-xs space-y-2">
      <h3 className="text-xs font-semibold uppercase tracking-wider md-text-muted">Results Summary</h3>
      <p>{totalHits} hits across {result.libraries.length} libraries</p>
      {result.libraries.map((lib) => (
        <div key={lib.library} className="md-panel p-2">
          <span className="font-medium">{lib.library}</span>
          <span className="ml-2 md-text-muted">{lib.hits.length} hits</span>
        </div>
      ))}
    </div>
  );
}

function BottomTabs() {
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
  const mode = useAppStore((s) => s.mode);
  const availableTabs: BottomTab[] =
    mode === "verification"
      ? ["analysis", "results", "strings", "verify-key", "pipeline"]
      : ["analysis", "results", "strings", "entropy", "consensus", "live-consensus", "architect", "experiment", "convergence", "verify-key", "pipeline"];

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
    getEntropy(dumpPath)
      .then((d) => { if (!cancelled) setEntropyData(d); })
      .catch(() => { if (!cancelled) setEntropyData(null); })
      .finally(() => { if (!cancelled) setEntropyLoading(false); });
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
            {t}
            {t === "analysis" && isRunning && (
              <span className="ml-1 md-spinner" />
            )}
            {t === "results" && totalHits > 0 && (
              <span className="ml-1 px-1.5 py-0.5 text-[10px] rounded-full bg-[var(--md-accent-blue)] text-white">
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
          !dumpPath ? (
            <p className="p-3 text-sm md-text-muted">Load a dump file to view entropy profile.</p>
          ) : entropyLoading ? (
            <p className="p-3 text-sm md-text-muted">Loading entropy data...</p>
          ) : entropyData ? (
            <ErrorBoundary fallback={<p className="p-3 text-sm md-text-muted">Entropy chart failed to render.</p>}>
              <EntropyChart data={entropyData} />
            </ErrorBoundary>
          ) : (
            <p className="p-3 text-sm md-text-muted">Failed to load entropy data.</p>
          )
        )}
        {tab === "strings" && (
          !dumpPath ? (
            <p className="p-3 text-sm md-text-muted">Load a dump file to extract strings.</p>
          ) : (
            <StringsPanel dumpPath={dumpPath} />
          )
        )}
        {tab === "consensus" && <ConsensusChart onNavigate={setTab} />}
        {tab === "live-consensus" && <ConsensusBuilder />}
        {tab === "architect" && <ArchitectPlaceholder />}
        {tab === "experiment" && <ExperimentPanel />}
        {tab === "convergence" && <ConvergenceChart data={null} />}
        {tab === "verify-key" && <KeyVerificationPanel />}
        {tab === "pipeline" && <PipelinePanel />}
      </div>
    </div>
  );
}

export function Workspace() {
  const { resetWizard } = useAppStore();
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
              <div data-tour-id="workspace-main" className="h-full">
                <MainContent />
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
    </div>
  );
}
