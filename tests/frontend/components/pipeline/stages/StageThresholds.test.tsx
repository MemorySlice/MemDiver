import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
// Real i18n bundle on purpose: these tests assert the rendered ENGLISH strings,
// which is the only guard in this repo against a missing or typo'd key.
import "@/i18n";

import type { PipelineRunRequest } from "@/api/pipeline";
import { usePipelineStore } from "@/stores/pipeline-store";

/**
 * Threshold stage -> request body.
 *
 * `emit` (Volatility 3 plugin) and `nsweep` (interactive report) are fully
 * implemented on the backend and gated purely on their presence in the
 * `POST /api/pipeline/run` body. This form is the ONLY caller of
 * `runPipeline`, and it used to build the body without ever mentioning
 * either key -- so `ArtifactsTabs`' Plugin tab (which is the DEFAULT tab)
 * could never show anything but "No vol3_plugin artifact in this run."
 *
 * The load-bearing assertions below are the two directions of that gate:
 * the key must be ABSENT while the box is unchecked (so an existing run's
 * body is unchanged) and PRESENT once it is checked.
 */

const { runPipelineMock } = vi.hoisted(() => ({
  runPipelineMock: vi.fn(),
}));

vi.mock("@/api/pipeline", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/api/pipeline")>()),
  runPipeline: runPipelineMock,
}));

const DUMPS = ["/dumps/run-1/gcore.core", "/dumps/run-2/gcore.core"];

async function renderStage(): Promise<void> {
  const { StageThresholds } = await import(
    "@/components/pipeline/stages/StageThresholds"
  );
  render(<StageThresholds onAdvance={vi.fn()} />);
}

/** Click "Run pipeline" and return the body the form actually posted. */
async function submit(): Promise<PipelineRunRequest> {
  fireEvent.click(screen.getByRole("button", { name: "Run pipeline" }));
  await waitFor(() => expect(runPipelineMock).toHaveBeenCalledTimes(1));
  return runPipelineMock.mock.calls[0][0] as PipelineRunRequest;
}

describe("StageThresholds request body", () => {
  const PRISTINE = usePipelineStore.getState();

  beforeEach(() => {
    runPipelineMock.mockReset();
    runPipelineMock.mockResolvedValue({ task_id: "task-1", status: "pending" });
    usePipelineStore.setState({
      ...PRISTINE,
      stage: "thresholds",
      form: {
        ...PRISTINE.form,
        sourcePaths: DUMPS,
        oracleId: "oracle-1",
      },
    });
  });

  afterEach(() => {
    usePipelineStore.setState(PRISTINE, true);
  });

  it("omits emit and nsweep entirely while both boxes are unchecked", async () => {
    await renderStage();
    const body = await submit();

    // The exact pre-existing shape: opting out must not add null keys either,
    // or the backend's `Optional[...] is not None` gating would still fire.
    expect(Object.keys(body).sort()).toEqual([
      "brute_force",
      "oracle_id",
      "reduce",
      "source_paths",
    ]);
    expect("emit" in body).toBe(false);
    expect("nsweep" in body).toBe(false);
  });

  it("includes emit with the backend defaults once the plugin box is checked", async () => {
    await renderStage();
    fireEvent.click(screen.getByTestId("emit-enable"));
    const body = await submit();

    expect(body.emit).toEqual({
      name: "memdiver_plugin",
      min_static_ratio: 0.3,
    });
    // Enabling emit must not smuggle in nsweep.
    expect("nsweep" in body).toBe(false);
  });

  it("round-trips the plugin-name field into emit.name", async () => {
    await renderStage();
    fireEvent.click(screen.getByTestId("emit-enable"));
    fireEvent.change(screen.getByTestId("emit-name"), {
      target: { value: "gocryptfs_keys" },
    });
    const body = await submit();

    expect(body.emit?.name).toBe("gocryptfs_keys");
    expect(usePipelineStore.getState().form.emit?.name).toBe("gocryptfs_keys");
  });

  it("round-trips the min static ratio into emit.min_static_ratio", async () => {
    await renderStage();
    fireEvent.click(screen.getByTestId("emit-enable"));
    fireEvent.change(screen.getByTestId("emit-min-static-ratio"), {
      target: { value: "0.55" },
    });
    const body = await submit();

    expect(body.emit?.min_static_ratio).toBe(0.55);
  });

  it("drops emit again when the box is unchecked", async () => {
    await renderStage();
    const box = screen.getByTestId("emit-enable");
    fireEvent.click(box);
    fireEvent.click(box);
    const body = await submit();

    expect("emit" in body).toBe(false);
    expect(usePipelineStore.getState().form.emit).toBeNull();
  });

  it("includes nsweep with the N ladder clamped to the selected dumps", async () => {
    await renderStage();
    fireEvent.click(screen.getByTestId("nsweep-enable"));
    // Two dumps -> the CLI ladder (1,3,5,...) filtered to <= 2, plus the
    // corpus size itself so the sweep ends on the full fold.
    expect(screen.getByTestId("nsweep-n-values")).toHaveValue("1,2");
    const body = await submit();

    expect(body.nsweep).toEqual({ n_values: [1, 2] });
    expect("emit" in body).toBe(false);
  });

  it("round-trips edited N values into nsweep.n_values", async () => {
    await renderStage();
    fireEvent.click(screen.getByTestId("nsweep-enable"));
    fireEvent.change(screen.getByTestId("nsweep-n-values"), {
      target: { value: "1, 2, 4" },
    });
    const body = await submit();

    expect(body.nsweep?.n_values).toEqual([1, 2, 4]);
  });

  it("ignores a half-typed N list instead of posting NaN", async () => {
    await renderStage();
    fireEvent.click(screen.getByTestId("nsweep-enable"));
    fireEvent.change(screen.getByTestId("nsweep-n-values"), {
      target: { value: "2," },
    });
    const body = await submit();

    expect(body.nsweep?.n_values).toEqual([2]);
  });

  it("sends both keys when both boxes are checked", async () => {
    await renderStage();
    fireEvent.click(screen.getByTestId("emit-enable"));
    fireEvent.click(screen.getByTestId("nsweep-enable"));
    const body = await submit();

    expect(body.emit).toBeTruthy();
    expect(body.nsweep).toBeTruthy();
  });
});

describe("StageThresholds nsweep on a pcap-oracle run", () => {
  const PRISTINE = usePipelineStore.getState();

  beforeEach(() => {
    runPipelineMock.mockReset();
    runPipelineMock.mockResolvedValue({ task_id: "task-2", status: "pending" });
    usePipelineStore.setState({
      ...PRISTINE,
      stage: "thresholds",
      form: {
        ...PRISTINE.form,
        sourcePaths: DUMPS,
        oracleId: null,
        pcapPath: "/pcaps/session.pcapng",
        nsweep: { n_values: [1, 2] },
      },
    });
  });

  afterEach(() => {
    usePipelineStore.setState(PRISTINE, true);
  });

  it("offers the sweep and posts it alongside the capture", async () => {
    await renderStage();

    // P2.2: the sweep re-runs whichever oracle the run armed, so a pcap run
    // reaches it too — the checkbox that used to be hard-gated is live.
    expect(screen.getByTestId("nsweep-enable")).toBeEnabled();
    expect(screen.getByTestId("nsweep-enable")).toBeChecked();
    expect(
      screen.getByText(/through the same pcap oracle/i),
    ).toBeInTheDocument();

    const body = await submit();
    expect(body.nsweep).toEqual({ n_values: [1, 2] });
    expect(body.pcap_path).toBe("/pcaps/session.pcapng");
    // Still exactly one oracle source: no BYO oracle id rides along.
    expect(body.oracle_id).toBeUndefined();
  });

  it("still lets the sweep be turned off on a pcap run", async () => {
    await renderStage();

    fireEvent.click(screen.getByTestId("nsweep-enable"));
    expect(screen.getByTestId("nsweep-enable")).not.toBeChecked();

    const body = await submit();
    expect("nsweep" in body).toBe(false);
  });
});

describe("StageThresholds optional-stage labels", () => {
  const PRISTINE = usePipelineStore.getState();

  beforeEach(() => {
    usePipelineStore.setState({
      ...PRISTINE,
      stage: "thresholds",
      form: { ...PRISTINE.form, sourcePaths: DUMPS, oracleId: "oracle-1" },
    });
  });

  afterEach(() => {
    usePipelineStore.setState(PRISTINE, true);
  });

  it("renders the English section headings and opt-in labels", async () => {
    await renderStage();

    expect(screen.getByText("Volatility 3 plugin")).toBeInTheDocument();
    expect(screen.getByText("N-sweep report")).toBeInTheDocument();
    expect(
      screen.getByText("Emit a Volatility 3 plugin from the best hit"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "Run the N-sweep harness and build the interactive report",
      ),
    ).toBeInTheDocument();
  });

  it("advertises only the stages the run will actually execute", async () => {
    await renderStage();
    const runButton = screen.getByRole("button", { name: "Run pipeline" });

    // The old copy promised "-> sweep -> emit" unconditionally, on a form that
    // could not request either stage.
    expect(runButton).toHaveAttribute(
      "title",
      "Start consensus → reduce → verify",
    );

    fireEvent.click(screen.getByTestId("emit-enable"));
    expect(runButton).toHaveAttribute(
      "title",
      "Start consensus → reduce → verify → emit",
    );

    fireEvent.click(screen.getByTestId("nsweep-enable"));
    expect(runButton).toHaveAttribute(
      "title",
      "Start consensus → reduce → verify → sweep → emit",
    );
  });
});
