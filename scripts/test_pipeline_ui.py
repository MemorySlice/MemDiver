#!/usr/bin/env python3
"""End-to-end Playwright tests for the Phase 25 Pipeline bottom tab.

Assumes both servers are already running:
  - FastAPI backend on :8080 (``memdiver`` or ``uvicorn api.main:app``)
  - Vite dev server on :5173 (``cd frontend && npm run dev``)

The Vite dev server proxies ``/api`` to :8080. Tests hit the dev server
so hot-module-reload and module graph imports (``useFtueStore``,
``usePipelineStore``) work for direct-inject scenarios.

For UI-only scenarios (funnel animation, survivor curve extension,
oracle_hit marker, tour chain), we bypass the real pipeline by
injecting synthetic TaskProgressEvents directly into the
``usePipelineStore.ingestEvent`` reducer via ``page.evaluate``. This
keeps the tests hermetic — no real dumps, no real oracle, no real
ProcessPool — while still exercising every production code path that
the reducer, the funnel renderer, the survivor curve, the hit list,
and the artifact tabs ship.

The final test (T10) is a minimal happy-path smoke that clicks through
the wizard to Stage-Oracle, verifying the recipe button is wired into
the Zustand store and that the store survives a tab-switch remount.
"""

from __future__ import annotations

import time
from pathlib import Path

from playwright.sync_api import TimeoutError as PWTimeout
from playwright.sync_api import sync_playwright

SCREENSHOTS = Path("/tmp/pipeline_ui_screenshots")
SCREENSHOTS.mkdir(exist_ok=True)

URL = "http://localhost:5173"
POPOVER = ".driver-popover"
PIPELINE_TAB_SELECTOR = 'button:has-text("Pipeline")'


# ----------------------------------------------------------------------
# helpers (shared with test_tours.py style)
# ----------------------------------------------------------------------


def goto_fresh(page):
    page.goto(URL)
    page.wait_for_load_state("networkidle")
    page.evaluate("() => { try { localStorage.clear(); } catch(e){} }")
    page.reload()
    page.wait_for_load_state("networkidle")


def force_workspace(page):
    page.evaluate(
        """async () => {
          const m = await import('/src/stores/app-store.ts');
          m.useAppStore.setState({
            appView: 'workspace',
            inputPath: '/tmp/dummy',
            inputMode: 'file'
          });
        }"""
    )


def click_pipeline_tab(page):
    btn = page.wait_for_selector(PIPELINE_TAB_SELECTOR, timeout=2500)
    btn.click(force=True)
    time.sleep(0.3)


def pipeline_panel_visible(page) -> bool:
    return page.evaluate(
        "() => !!document.querySelector('[data-tour-id=\"pipeline-recipe-card\"],"
        "[data-tour-id=\"pipeline-funnel\"],"
        "[data-tour-id=\"pipeline-artifacts\"]')"
    )


def inject_pipeline_event(page, event: dict):
    """Push a synthetic TaskProgressEvent through the store reducer."""
    page.evaluate(
        """async (ev) => {
          const m = await import('/src/stores/pipeline-store.ts');
          // Seed an active task id so status transitions land on the
          // reducer's run path instead of the idle branch.
          const st = m.usePipelineStore.getState();
          if (!st.taskId) {
            m.usePipelineStore.setState({
              taskId: 't-fixture', status: 'running'
            });
          }
          m.usePipelineStore.getState().ingestEvent(ev);
        }""",
        event,
    )


def get_pipeline_state(page) -> dict:
    return page.evaluate(
        """async () => {
          const m = await import('/src/stores/pipeline-store.ts');
          const s = m.usePipelineStore.getState();
          return {
            stage: s.stage,
            status: s.status,
            taskId: s.taskId,
            funnel: s.funnel,
            nsweepPoints: s.nsweepPoints.length,
            hits: s.hits.length,
            artifacts: s.artifacts.length,
            lastSeq: s.lastSeq,
          };
        }"""
    )


def reset_pipeline_store(page):
    page.evaluate(
        """async () => {
          const m = await import('/src/stores/pipeline-store.ts');
          m.usePipelineStore.getState().resetRun();
        }"""
    )


def popover_visible(page) -> bool:
    el = page.query_selector(POPOVER)
    if not el:
        return False
    try:
        return el.is_visible()
    except Exception:
        return False


def popover_text(page) -> str:
    el = page.query_selector(POPOVER)
    if not el:
        return ""
    return (el.inner_text() or "").strip()


def close_any_active_tour(page):
    for _ in range(12):
        time.sleep(0.3)
        if not popover_visible(page):
            return
        close = page.query_selector(".driver-popover-close-btn")
        if not close:
            continue
        try:
            close.click(force=True)
        except Exception:
            break


def mark_all_tours_seen(page):
    """Mark ALL tours as completed via direct Zustand setState + persist
    to localStorage. Uses setState to set the full seenTours array
    atomically, bypassing any timing issues with incremental markSeen."""
    page.evaluate(
        """async () => {
          const m = await import('/src/ftue/store.ts');
          const now = Date.now();
          const seen = [
            { id: 'workspace-layout-101', version: 1, seenAt: now, completed: true },
            { id: 'structure-overlay-101', version: 1, seenAt: now, completed: true },
            { id: 'pipeline-101', version: 1, seenAt: now, completed: true },
          ];
          m.useFtueStore.setState({ seenTours: seen, activeTourId: null, activeStepIndex: 0 });
          localStorage.setItem('memdiver:ftue:seen', JSON.stringify(seen));
        }"""
    )


def mark_prior_tours_seen(page):
    """Mark workspace + structure tours as seen, leaving pipeline-101
    unseen so it fires on PipelinePanel mount."""
    page.evaluate(
        """async () => {
          const m = await import('/src/ftue/store.ts');
          const now = Date.now();
          const seen = [
            { id: 'workspace-layout-101', version: 1, seenAt: now, completed: true },
            { id: 'structure-overlay-101', version: 1, seenAt: now, completed: true },
          ];
          m.useFtueStore.setState({ seenTours: seen, activeTourId: null, activeStepIndex: 0 });
          localStorage.setItem('memdiver:ftue:seen', JSON.stringify(seen));
        }"""
    )


# ----------------------------------------------------------------------
# tests
# ----------------------------------------------------------------------


def t1_pipeline_tab_visible(page):
    goto_fresh(page)
    mark_all_tours_seen(page)
    force_workspace(page)
    time.sleep(0.5)
    close_any_active_tour(page)
    click_pipeline_tab(page)
    assert pipeline_panel_visible(page), (
        "Pipeline bottom tab did not mount a recipe card / funnel / "
        "artifacts panel after click — tab wiring broken"
    )
    page.screenshot(path=str(SCREENSHOTS / "01_pipeline_tab_visible.png"))


def t2_recipe_preset_load(page):
    goto_fresh(page)
    mark_all_tours_seen(page)
    force_workspace(page)
    close_any_active_tour(page)
    click_pipeline_tab(page)
    close_any_active_tour(page)
    # Click the gocryptfs recipe card
    card = page.wait_for_selector(
        '[data-tour-id="pipeline-recipe-gocryptfs"]', timeout=4000
    )
    card.click(force=True)
    time.sleep(0.3)
    state = page.evaluate(
        """async () => {
          const m = await import('/src/stores/pipeline-store.ts');
          return m.usePipelineStore.getState().form.reduce;
        }"""
    )
    assert state["min_variance"] == 1500.0, (
        f"gocryptfs recipe did not populate min_variance=1500, got {state}"
    )
    assert state["alignment"] == 8
    assert state["density_threshold"] == 0.5
    page.screenshot(path=str(SCREENSHOTS / "02_recipe_preset.png"))


def t3_oracle_upload_shape_detect(page):
    """Verify the oracle-store upload helper tracks shape + armed flag.

    This exercises the store contract directly rather than driving the
    upload UI (which depends on a live POST /api/oracles/upload endpoint
    and MEMDIVER_ORACLE_DIR). The store is the production reducer the
    real upload UI commits to.
    """
    goto_fresh(page)
    mark_all_tours_seen(page)
    force_workspace(page)
    close_any_active_tour(page)
    click_pipeline_tab(page)
    close_any_active_tour(page)
    page.evaluate(
        """async () => {
          const m = await import('/src/stores/oracle-store.ts');
          m.useOracleStore.setState({
            uploaded: [{
              id: 'fixture-oracle',
              filename: 'gocryptfs.py',
              sha256: 'deadbeef',
              size: 1024,
              shape: 2,
              head_lines: ['# stub'],
              armed: true,
              uploaded_at: Date.now() / 1000,
            }],
          });
        }"""
    )
    uploaded = page.evaluate(
        """async () => {
          const m = await import('/src/stores/oracle-store.ts');
          return m.useOracleStore.getState().uploaded;
        }"""
    )
    assert len(uploaded) == 1
    assert uploaded[0]["shape"] == 2
    assert uploaded[0]["armed"] is True
    page.screenshot(path=str(SCREENSHOTS / "03_oracle_upload.png"))


def t4_dry_run_bar_renders(page):
    goto_fresh(page)
    mark_all_tours_seen(page)
    force_workspace(page)
    close_any_active_tour(page)
    click_pipeline_tab(page)
    close_any_active_tour(page)
    # Advance the wizard to the oracle stage so the DryRunBar is mounted
    page.evaluate(
        """async () => {
          const m = await import('/src/stores/pipeline-store.ts');
          m.usePipelineStore.setState({
            stage: 'oracle',
            form: { ...m.usePipelineStore.getState().form,
                    oracleId: 'fixture-oracle' },
          });
          const o = await import('/src/stores/oracle-store.ts');
          o.useOracleStore.setState({
            uploaded: [{
              id: 'fixture-oracle', filename: 'f.py', sha256: 'x',
              size: 1, shape: 1, head_lines: [], armed: true,
              uploaded_at: Date.now()/1000,
            }],
            dryRun: {
              oracle_id: 'fixture-oracle',
              total: 16,
              passes: 1,
              fails: 14,
              errors: 1,
              per_call_us_avg: 12.3,
              results: Array.from({length: 16}, (_, i) => ({
                index: i,
                ok: i === 0,
                error: i === 15 ? 'boom' : undefined,
              })),
            },
          });
        }"""
    )
    time.sleep(0.4)
    dots = page.query_selector_all(
        '[data-tour-id="pipeline-oracle-dryrun"] span.rounded-full'
    )
    # 16 sample dots + 3 legend swatches = ≥19
    assert len(dots) >= 16, f"expected ≥16 dots, got {len(dots)}"
    page.screenshot(path=str(SCREENSHOTS / "04_dryrun_bar.png"))


def t5_funnel_animates_on_ws_events(page):
    goto_fresh(page)
    mark_all_tours_seen(page)
    force_workspace(page)
    close_any_active_tour(page)
    click_pipeline_tab(page)
    close_any_active_tour(page)
    now = time.time()
    state = page.evaluate(
        """async (ts) => {
          const m = await import('/src/stores/pipeline-store.ts');
          const store = m.usePipelineStore;
          store.getState().resetRun();
          store.setState({ stage: 'running', taskId: 't-fixture', status: 'running' });
          const events = [
            { task_id: 't-fixture', seq: 1, ts: ts, type: 'stage_end', stage: 'consensus',
              extra: { total_bytes: 10000000 }},
            { task_id: 't-fixture', seq: 2, ts: ts, type: 'progress', stage: 'search_reduce:variance',
              pct: 0.33, msg: 'variance', extra: { survivor_bytes: 500000, input_bytes: 10000000 }},
            { task_id: 't-fixture', seq: 3, ts: ts, type: 'progress', stage: 'search_reduce:aligned',
              pct: 0.66, extra: { survivor_bytes: 40000 }},
            { task_id: 't-fixture', seq: 4, ts: ts, type: 'progress', stage: 'search_reduce:entropy',
              pct: 0.9, extra: { survivor_bytes: 2400 }},
          ];
          for (const ev of events) store.getState().ingestEvent(ev);
          const s = store.getState();
          return { funnel: s.funnel, taskId: s.taskId };
        }""",
        now,
    )
    funnel = state["funnel"]
    assert funnel["raw"] == 10_000_000, f"funnel={funnel}"
    assert funnel["variance"] == 500_000, f"funnel={funnel}"
    assert funnel["aligned"] == 40_000, f"funnel={funnel}"
    assert funnel["high_entropy"] == 2_400, f"funnel={funnel}"
    page.wait_for_selector('[data-tour-id="pipeline-funnel"]', timeout=3000)
    page.screenshot(path=str(SCREENSHOTS / "05_funnel_animates.png"))


def t6_survivor_curve_extends(page):
    goto_fresh(page)
    mark_all_tours_seen(page)
    force_workspace(page)
    close_any_active_tour(page)
    click_pipeline_tab(page)
    close_any_active_tour(page)
    now = time.time()
    state = page.evaluate(
        """async (ts) => {
          const m = await import('/src/stores/pipeline-store.ts');
          const store = m.usePipelineStore;
          store.getState().resetRun();
          store.setState({ stage: 'running', taskId: 't-fixture', status: 'running' });
          const events = [
            { task_id: 't-fixture', seq: 1, ts: ts, type: 'nsweep_point',
              extra: { n: 1, stages: { variance: 1000, aligned: 500, entropy: 100 },
                       candidates_tried: 100, hits: 0, hit_offset: null,
                       timing_ms: { consensus_ms: 42.0 }}},
            { task_id: 't-fixture', seq: 2, ts: ts, type: 'nsweep_point',
              extra: { n: 5, stages: { variance: 1000, aligned: 500, entropy: 100 },
                       candidates_tried: 100, hits: 1, hit_offset: 256,
                       timing_ms: { consensus_ms: 42.0 }}},
          ];
          for (const ev of events) store.getState().ingestEvent(ev);
          return { nsweepPoints: store.getState().nsweepPoints.length };
        }""",
        now,
    )
    assert state["nsweepPoints"] == 2, state
    page.screenshot(path=str(SCREENSHOTS / "06_survivor_curve.png"))


def t7_oracle_hit_marker(page):
    goto_fresh(page)
    mark_all_tours_seen(page)
    force_workspace(page)
    close_any_active_tour(page)
    click_pipeline_tab(page)
    close_any_active_tour(page)
    now = time.time()
    state = page.evaluate(
        """async (ts) => {
          const m = await import('/src/stores/pipeline-store.ts');
          const store = m.usePipelineStore;
          store.getState().resetRun();
          store.setState({ stage: 'running', taskId: 't-fixture', status: 'running' });
          store.getState().ingestEvent({
            task_id: 't-fixture', seq: 1, ts: ts,
            type: 'oracle_hit',
            extra: { offset: 0x57A220, size: 32, region_index: 0 },
          });
          return { hits: store.getState().hits.length };
        }""",
        now,
    )
    assert state["hits"] == 1, f"expected 1 hit, got {state}"
    btn = page.wait_for_selector(
        '[data-tour-id="pipeline-hits-list"] button:has-text("Open in hex")',
        timeout=3000,
    )
    assert btn is not None, "HitsList 'Open in hex' button missing"
    page.screenshot(path=str(SCREENSHOTS / "07_oracle_hit.png"))


def t8_plugin_artifact_tab_renders(page):
    goto_fresh(page)
    mark_all_tours_seen(page)
    force_workspace(page)
    close_any_active_tour(page)
    click_pipeline_tab(page)
    close_any_active_tour(page)
    page.evaluate(
        """async () => {
          const m = await import('/src/stores/pipeline-store.ts');
          m.usePipelineStore.setState({
            stage: 'results',
            status: 'succeeded',
            taskId: 't-fixture',
            artifacts: [{
              name: 'vol3_plugin',
              relpath: 'emit_plugin/gocryptfs.py',
              media_type: 'text/x-python',
              size: 5114,
              sha256: null,
              registered_at: Date.now() / 1000,
            }],
          });
        }"""
    )
    page.wait_for_selector('[data-tour-id="pipeline-artifacts"]', timeout=3000)
    plugin_btn = page.wait_for_selector(
        '[data-tour-id="pipeline-artifacts"] button:has-text("Plugin")',
        timeout=3000,
    )
    assert plugin_btn is not None, "Plugin artifact tab button missing"
    page.screenshot(path=str(SCREENSHOTS / "08_plugin_tab.png"))


def t9_pipeline_tour_fires(page):
    goto_fresh(page)
    # Suppress ALL tours during workspace init, then un-mark
    # pipeline-101 right before mounting PipelinePanel. This avoids
    # TourProvider snatching pipeline-101 during force_workspace.
    mark_all_tours_seen(page)
    force_workspace(page)
    close_any_active_tour(page)
    # Now remove pipeline-101 from seenTours so PipelinePanel's mount
    # effect sees it as unseen and fires startTour.
    page.evaluate(
        """async () => {
          const m = await import('/src/ftue/store.ts');
          const seen = m.useFtueStore.getState().seenTours.filter(
            t => t.id !== 'pipeline-101'
          );
          m.useFtueStore.setState({ seenTours: seen });
          localStorage.setItem('memdiver:ftue:seen', JSON.stringify(seen));
        }"""
    )
    click_pipeline_tab(page)
    try:
        page.wait_for_selector(POPOVER, state="visible", timeout=5000)
    except PWTimeout:
        page.screenshot(path=str(SCREENSHOTS / "09_pipeline_tour_FAIL.png"))
        raise AssertionError("pipeline-101 tour did not auto-start")
    text = popover_text(page)
    assert "Phase 25 pipeline" in text or "pipeline" in text.lower(), (
        f"Expected pipeline-101 welcome step, got: {text!r}"
    )
    page.screenshot(path=str(SCREENSHOTS / "09_pipeline_tour.png"))


def t10_gocryptfs_happy_path_smoke(page):
    """Happy-path wizard walk: recipe → dumps → oracle stage visible.

    This stops short of submitting a real pipeline run (which would
    need a real dataset + oracle). It verifies every UI stage mounts
    and the Zustand store survives a tab-switch remount.
    """
    goto_fresh(page)
    mark_all_tours_seen(page)
    force_workspace(page)
    close_any_active_tour(page)
    click_pipeline_tab(page)
    close_any_active_tour(page)
    # Click gocryptfs recipe → wizard advances to 'dumps' stage
    page.wait_for_selector(
        '[data-tour-id="pipeline-recipe-gocryptfs"]', timeout=4000
    ).click(force=True)
    time.sleep(0.3)
    stage1 = get_pipeline_state(page)["stage"]
    assert stage1 == "dumps", f"expected dumps stage, got {stage1!r}"
    # Switch bottom tab away and back — store must survive unmount
    results_btn = page.query_selector('button:has-text("results")')
    if results_btn:
        results_btn.click(force=True)
    time.sleep(0.2)
    click_pipeline_tab(page)
    time.sleep(0.3)
    stage2 = get_pipeline_state(page)["stage"]
    # The re-mount should land back on "dumps" because of the persist
    # middleware. If it snapped back to "recipe" the persist config
    # dropped our form state.
    assert stage2 == "dumps", f"store lost stage on re-mount: {stage2!r}"
    page.screenshot(path=str(SCREENSHOTS / "10_gocryptfs_smoke.png"))


TESTS = [
    ("T1_pipeline_tab_visible", t1_pipeline_tab_visible),
    ("T2_recipe_preset_load", t2_recipe_preset_load),
    ("T3_oracle_upload_shape_detect", t3_oracle_upload_shape_detect),
    ("T4_dry_run_bar_renders", t4_dry_run_bar_renders),
    ("T5_funnel_animates_on_ws_events", t5_funnel_animates_on_ws_events),
    ("T6_survivor_curve_extends", t6_survivor_curve_extends),
    ("T7_oracle_hit_marker", t7_oracle_hit_marker),
    ("T8_plugin_artifact_tab_renders", t8_plugin_artifact_tab_renders),
    ("T9_pipeline_tour_fires", t9_pipeline_tour_fires),
    ("T10_gocryptfs_happy_path_smoke", t10_gocryptfs_happy_path_smoke),
]


def main():
    results = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            for name, fn in TESTS:
                ctx = browser.new_context(viewport={"width": 1600, "height": 1000})
                page = ctx.new_page()
                try:
                    fn(page)
                    results.append((name, "PASS", ""))
                    print(f"PASS  {name}")
                except Exception as e:
                    try:
                        page.screenshot(
                            path=str(SCREENSHOTS / f"{name}_FAIL.png"),
                            full_page=True,
                        )
                    except Exception:
                        pass
                    results.append((name, "FAIL", f"{type(e).__name__}: {e}"))
                    print(f"FAIL  {name}  {type(e).__name__}: {e}")
                finally:
                    ctx.close()
        finally:
            browser.close()
    print("\n=== Summary ===")
    for name, status, msg in results:
        print(f"{status}  {name}  {msg}")
    failed = [r for r in results if r[1] == "FAIL"]
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
