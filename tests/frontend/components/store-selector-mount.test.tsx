import { describe, it, expect, beforeEach, vi } from "vitest";
import { act, render } from "@testing-library/react";
// See the comment in `ErrorBoundary.test.tsx` — needed so `tsc -b` sees
// jest-dom's `Assertion` augmentation even though `tests/setup.ts` is
// excluded from that program.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { ConsensusChart } from "@/components/charts/ConsensusChart";
import { ConsensusBuilder } from "@/components/analysis/ConsensusBuilder";
import { ScanResultsPanel } from "@/components/results/ScanResultsPanel";
import { KeyVerificationPanel } from "@/components/verification/KeyVerificationPanel";
import { AnalysisPanel } from "@/components/analysis/AnalysisPanel";
import { DumpList } from "@/components/dumps/DumpList";
import { DumpSelectionStrip } from "@/components/dumps/DumpSelectionStrip";
import { MainViewSwitcher } from "@/components/hex/MainViewSwitcher";
import { MultiHexViewer } from "@/components/hex/MultiHexViewer";
import { HexOverlayPane } from "@/components/hex/HexOverlayPane";
import { HexPaneHeader } from "@/components/hex/HexPaneHeader";
import { HexAlignmentChip } from "@/components/hex/HexAlignmentChip";
import { OverlayByteInspector } from "@/components/hex/OverlayByteInspector";
import { FileUpload } from "@/components/upload/FileUpload";
import { useConsensusStore } from "@/stores/consensus-store";
import { renderWithCount } from "@tests/helpers/render-counter";

// The factories below are hoisted above every module-scope binding, so the
// never-settling promise has to be inlined rather than shared via a const.
vi.mock("@/api/client", () => ({
  runAnalysis: vi.fn(() => new Promise(() => {})),
  runFileAnalysis: vi.fn(() => new Promise(() => {})),
  listPhases: vi.fn(() => new Promise(() => {})),
  listProtocols: vi.fn(() => new Promise(() => {})),
  listPatterns: vi.fn(() => new Promise(() => {})),
  verifyKey: vi.fn(() => new Promise(() => {})),
  exportKeylog: vi.fn(() => new Promise(() => {})),
  getPageStates: vi.fn(() => new Promise(() => {})),
}));
vi.mock("@/api/analysis", () => ({
  runAnalysisAndWait: vi.fn(() => new Promise(() => {})),
  fetchAnalysisResult: vi.fn(() => new Promise(() => {})),
}));
vi.mock("@/api/algorithms", () => ({
  getAlgorithmAvailability: vi.fn(() => new Promise(() => {})),
}));

/**
 * Under zustand v5 the `equalityFn` second argument is gone, so a selector
 * returning a fresh object without a `useShallow` wrapper re-renders forever
 * inside `useSyncExternalStore`. `tsc` cannot see that — the types are
 * identical either way — so the only guard is mounting each converted
 * component and requiring it not to blow the update depth.
 */
describe("converted store selectors mount without an update-depth loop", () => {
  const components: [string, () => React.ReactElement][] = [
    ["ConsensusChart", () => <ConsensusChart />],
    ["ConsensusBuilder", () => <ConsensusBuilder />],
    ["ScanResultsPanel", () => <ScanResultsPanel />],
    ["KeyVerificationPanel", () => <KeyVerificationPanel />],
    ["AnalysisPanel", () => <AnalysisPanel />],
    ["DumpList", () => <DumpList />],
    ["DumpSelectionStrip", () => <DumpSelectionStrip />],
    ["MainViewSwitcher", () => <MainViewSwitcher />],
    ["MultiHexViewer", () => <MultiHexViewer />],
    ["HexOverlayPane", () => <HexOverlayPane />],
    ["HexAlignmentChip", () => <HexAlignmentChip paths={[]} hasMsl={false} />],
    ["OverlayByteInspector", () => <OverlayByteInspector />],
    [
      "HexPaneHeader",
      () => (
        <HexPaneHeader
          dump={{
            id: "d0",
            path: "/dumps/d0.msl",
            name: "d0.msl",
            size: 4096,
            format: "msl",
            sameProcess: true,
          }}
          isOrigin
          isFocused
          widthPx={588}
          onFocus={() => {}}
          onCollapse={() => {}}
        />
      ),
    ],
    ["FileUpload", () => <FileUpload />],
  ];

  for (const [name, make] of components) {
    it(`${name} mounts`, () => {
      expect(() => render(make())).not.toThrow();
    });
  }
});

describe("ConsensusChart subscription width", () => {
  beforeEach(() => {
    act(() => {
      useConsensusStore.getState().reset();
    });
  });

  it("does not re-render on consensus-store fields it never reads", () => {
    const { counter } = renderWithCount(<ConsensusChart />);
    const initial = counter.count;

    // `staticRegions` is a consensus-store field the chart does not display;
    // before the sweep each of these writes re-rendered the whole chart.
    for (let i = 1; i <= 5; i++) {
      act(() => {
        useConsensusStore.setState({ staticRegions: new Array(i).fill({ start: 0, end: i }) });
      });
    }

    expect(counter.count - initial).toBe(0);
  });
});
