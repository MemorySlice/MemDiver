/**
 * The "Export as Volatility 3 plugin" dialog follows `POST /api/vol3/synthesize`
 * as a background job: queued -> running -> the stored payload, cancel, a
 * failed job's code, a refused POST's code, and the client-side elapsed time.
 * The real API module runs against a fetch stub; only the task WebSocket hook
 * is replaced, so the test drives its events.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { useDumpStore } from "@/stores/dump-store";
import { KEY1, REPO_PLUGINS, RUN1, SYNTH } from "./synth-fixtures";

const ws = vi.hoisted(() => ({
  taskId: null as string | null,
  cbs: {} as Record<string, ((...a: unknown[]) => void) | undefined>,
}));
vi.mock("@/hooks/useTaskProgress", () => ({
  useTaskProgress: (id: string | null, cbs: Record<string, (...a: unknown[]) => void>) => {
    ws.taskId = id;
    ws.cbs = cbs;
  },
}));

const { SynthesizeDialog } = await import("@/components/vol3/SynthesizeDialog");

const SYNTH_POST = "POST /api/vol3/synthesize";
const RESULT_GET = "GET /api/tasks/t1/result";
const CANCEL = "DELETE /api/tasks/t1";

/** `"<METHOD> <url>"` -> the reply the stubbed server gives. */
const routes = new Map<string, { status: number; body: string }>();
const keyOf = (url: string, init?: RequestInit) => `${init?.method ?? "GET"} ${url}`;
const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
  const reply = routes.get(keyOf(url, init)) ?? { status: 404, body: '{"detail":"Not Found"}' };
  return { ok: reply.status < 400, status: reply.status, text: async () => reply.body };
});
const route = (key: string, body: unknown, status = 200) => routes.set(key, { status, body: JSON.stringify(body) });
const calls = (key: string) => fetchMock.mock.calls.filter(([url, init]) => keyOf(url, init) === key);

/** What `useTaskProgress` does with one event: `onEvent` first, then the typed callback. */
function emit(event: Record<string, unknown>) {
  act(() => {
    ws.cbs.onEvent?.(event);
    if (event.type === "stage_start") ws.cbs.onStageStart?.(event.stage, event);
    if (event.type === "progress") ws.cbs.onProgress?.(event.pct ?? null, event.msg ?? null, event);
    if (event.type === "done") ws.cbs.onDone?.(event);
    if (event.type === "error") ws.cbs.onError?.(event.error ?? "Unknown error", event);
  });
}
const ADMITTED = { type: "stage_start", stage: "vol3_synth", msg: "task started" };

const onClose = vi.fn();
const onSynthesized = vi.fn();
const mount = () => render(
  <SynthesizeDialog initialDumps={[RUN1]} initialSecretHex={KEY1} initialCaseDir="my-case"
    onClose={onClose} onSynthesized={onSynthesized} />);

/** Mount, submit, and wait for the job ticket (the Cancel button appears with it). */
async function submitJob() {
  const view = mount();
  fireEvent.click(screen.getByTestId("synth-submit"));
  await screen.findByTestId("synth-job-cancel");
  return view;
}
const jobState = () => screen.getByTestId("synth-job-state");

beforeEach(() => {
  routes.clear();
  fetchMock.mockClear();
  vi.stubGlobal("fetch", fetchMock);
  route("GET /api/vol3/plugin-dir", { path: REPO_PLUGINS });
  route(SYNTH_POST, { task_id: "t1", status: "pending" });
  route(RESULT_GET, { task_id: "t1", payload: SYNTH });
  route(CANCEL, { task_id: "t1", cancelled: true });
  ws.taskId = null;
  ws.cbs = {};
  onClose.mockReset();
  onSynthesized.mockReset();
  useDumpStore.setState({ dumps: [] });
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("SynthesizeDialog job", () => {
  it("is queued until admitted, then running with the server's message, then shows the stored result", async () => {
    await submitJob();
    const body = JSON.parse(calls(SYNTH_POST)[0][1]!.body as string);
    expect(body).toMatchObject({ dump_paths: [RUN1], case_dir: "my-case", async: true });
    expect(ws.taskId).toBe("t1");
    expect(jobState()).toHaveAttribute("data-state", "queued");
    expect(jobState()).toHaveTextContent("Queued");
    expect(screen.getByTestId("synth-job-queued")).toHaveTextContent("Waiting for another job on the server to finish");
    expect(screen.getByTestId("synth-submit")).toBeDisabled();

    emit(ADMITTED);
    expect(jobState()).toHaveAttribute("data-state", "running");
    expect(jobState()).toHaveTextContent("Running");
    expect(screen.queryByTestId("synth-job-queued")).toBeNull();

    emit({ type: "progress", stage: "vol3_synth", pct: 0.4, msg: "verifying on dump 1/2: run_0001.msl" });
    expect(screen.getByTestId("synth-job-msg")).toHaveTextContent("verifying on dump 1/2: run_0001.msl");

    emit({ type: "done", extra: { proven: false } });
    await screen.findByTestId("synth-result");
    expect(calls(RESULT_GET)).toHaveLength(1);
    expect(screen.getByTestId("synth-proven-count")).toHaveTextContent("Proven hits: 4");
    expect(onSynthesized).toHaveBeenCalledWith(SYNTH);
    expect(screen.queryByTestId("synth-job")).toBeNull();
    expect(screen.getByTestId("synth-submit")).toBeEnabled();
    expect(document.body.textContent ?? "").not.toContain(KEY1);
  });

  it("a job that succeeds despite a Cancel click shows its result and reports it", async () => {
    await submitJob();
    emit(ADMITTED);
    await act(async () => { fireEvent.click(screen.getByTestId("synth-job-cancel")); });
    expect(jobState()).toHaveAttribute("data-state", "cancelling");
    emit({ type: "done", extra: { proven: false } });
    await screen.findByTestId("synth-result");
    expect(onSynthesized).toHaveBeenCalledWith(SYNTH);
    expect(screen.queryByTestId("synth-job")).toBeNull();
    expect(screen.queryByTestId("synth-job-cancelled")).toBeNull();
  });

  it("cancels: DELETE, cancelling until the terminal event, then cancelled", async () => {
    await submitJob();
    emit(ADMITTED);
    await act(async () => { fireEvent.click(screen.getByTestId("synth-job-cancel")); });
    expect(calls(CANCEL)).toHaveLength(1);
    expect(jobState()).toHaveAttribute("data-state", "cancelling");
    expect(screen.getByTestId("synth-job-cancel")).toBeDisabled();

    emit({ type: "error", error: "cancelled" });
    expect(screen.getByTestId("synth-job-cancelled")).toHaveTextContent("Synthesis cancelled.");
    expect(screen.queryByTestId("synth-job")).toBeNull();
    expect(screen.queryByTestId("synth-error")).toBeNull();
    expect(calls(RESULT_GET)).toHaveLength(0);
    expect(onSynthesized).not.toHaveBeenCalled();
  });

  it("a job cancelled elsewhere (API, another tab, shutdown) reads as cancelled, not as a failure", async () => {
    await submitJob();
    emit(ADMITTED);
    emit({ type: "error", error: "cancelled" });
    expect(screen.getByTestId("synth-job-cancelled")).toHaveTextContent("Synthesis cancelled.");
    expect(screen.queryByTestId("synth-error")).toBeNull();
    expect(screen.queryByTestId("synth-job")).toBeNull();
    expect(calls(CANCEL)).toHaveLength(0);
  });

  it("shows a failed job's message with its code", async () => {
    await submitJob();
    emit(ADMITTED);
    emit({ type: "error", error: "oracle sample not found: /data/run_0001/cipher",
      extra: { code: "vol3.synth.oracle_sample", category: "INVALID_INPUT" } });
    const alert = screen.getByTestId("synth-error");
    expect(within(alert).getByTestId("synth-error-code")).toHaveTextContent("vol3.synth.oracle_sample");
    expect(alert).toHaveTextContent("oracle sample not found: /data/run_0001/cipher");
    expect(screen.queryByTestId("synth-job")).toBeNull();
  });

  it("a job that failed on a locked dump (tampered past block 0) shows the code and its hint", async () => {
    await submitJob();
    emit(ADMITTED);
    emit({ type: "error", error: "AEAD verification failed (wrong key or tampered file)",
      extra: { code: "encrypted_dump_locked", category: "PRECONDITION" } });
    const alert = screen.getByTestId("synth-error");
    expect(within(alert).getByTestId("synth-error-code")).toHaveTextContent("encrypted_dump_locked");
    const hint = screen.getByTestId("api-error-hint");
    expect(hint).toHaveAttribute("data-error-code", "encrypted_dump_locked");
    expect(hint).toHaveTextContent(/encrypted \.msl/);
  });

  it("a finished job without a stored result is an error without a code", async () => {
    route(RESULT_GET, { task_id: "t1", payload: null });
    await submitJob();
    emit(ADMITTED);
    emit({ type: "done", extra: SYNTH });
    const alert = await screen.findByTestId("synth-error");
    expect(alert).toHaveTextContent("The synthesize job finished but its stored result could not be read.");
    expect(within(alert).queryByTestId("synth-error-code")).toBeNull();
    expect(screen.queryByTestId("synth-result")).toBeNull();
  });

  it("shows the code of a refused POST without following a job, and drops it on the next run", async () => {
    route(SYNTH_POST, { error: "not a MemDiver case: /tmp/x", code: "case.not_a_case", category: "INVALID_INPUT" }, 400);
    mount();
    fireEvent.click(screen.getByTestId("synth-submit"));
    const alert = await screen.findByTestId("synth-error");
    expect(within(alert).getByTestId("synth-error-code")).toHaveTextContent("case.not_a_case");
    expect(alert).toHaveTextContent("not a MemDiver case: /tmp/x");
    expect(ws.taskId).toBeNull();
    expect(screen.queryByTestId("synth-job")).toBeNull();

    route(SYNTH_POST, { task_id: "t1", status: "pending" });
    fireEvent.click(screen.getByTestId("synth-submit"));
    await screen.findByTestId("synth-job-cancel");
    emit({ type: "error", error: "worker died" });
    expect(screen.getByTestId("synth-error")).toHaveTextContent("worker died");
    expect(screen.queryByTestId("synth-error-code")).toBeNull();
  });

  it("ticks the elapsed time once a second while active, and stops at the end", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "Date"] });
    await submitJob();
    const elapsed = () => screen.getByTestId("synth-job-elapsed");
    expect(elapsed()).toHaveTextContent("Elapsed 0:00");
    act(() => { vi.advanceTimersByTime(3000); });
    expect(elapsed()).toHaveTextContent("Elapsed 0:03");

    emit(ADMITTED);
    act(() => { vi.advanceTimersByTime(62_000); });
    expect(elapsed()).toHaveTextContent("Elapsed 1:05");

    emit({ type: "done" });
    await screen.findByTestId("synth-result");
    expect(screen.queryByTestId("synth-job-elapsed")).toBeNull();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("cancels an active job when the dialog goes away, and leaves a finished one alone", async () => {
    const active = await submitJob();
    active.unmount();
    expect(calls(CANCEL)).toHaveLength(1);

    fetchMock.mockClear();
    const finished = await submitJob();
    emit(ADMITTED);
    emit({ type: "done" });
    await screen.findByTestId("synth-result");
    finished.unmount();
    await waitFor(() => expect(calls(RESULT_GET)).toHaveLength(1));
    expect(calls(CANCEL)).toHaveLength(0);
  });
});
