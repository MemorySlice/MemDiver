"""MemDiver - Memory Dump Analysis Platform.

Entry point: marimo run run.py

Wizard-driven flow:
  1. Setup wizard collects input mode, data path, ground truth, analysis mode
  2. Unified analysis workspace with accordion sections
  3. Session save/load for persistence
"""

import marimo

__generated_with = "0.20.1"
app = marimo.App(width="full", app_title="MemDiver")


@app.cell
def boot():
    """Initialize core systems and wizard sentinel."""
    import marimo as mo
    import os
    import sys
    from pathlib import Path

    memdiver_root = Path(__file__).parent
    if str(memdiver_root) not in sys.path:
        sys.path.insert(0, str(memdiver_root))

    from core.log import setup_logging
    config_path = memdiver_root / "config.json"
    logger = setup_logging(config_path=config_path)
    logger.info("MemDiver starting from run.py")

    from ui.state import AppState
    from ui.mode import ModeManager
    from core.discovery import RunDiscovery

    state = AppState(config_path=config_path)
    # Allow ASGI mount to pass dataset context via environment
    env_root = os.environ.get("MEMDIVER_DATASET_ROOT")
    if env_root:
        state.dataset_root = env_root
    mode_mgr = ModeManager(initial_mode=state.mode)

    # ProjectDB (optional)
    project_db = None
    try:
        from engine.project_db import ProjectDB, default_db_path, check_deps
        if check_deps().get("ready"):
            project_db = ProjectDB(default_db_path())
            project_db.open()
    except Exception:
        pass

    # Wizard sentinel: False = show wizard, True = show workspace
    get_wizard_done, set_wizard_done = mo.state(False)
    return (
        Path,
        RunDiscovery,
        get_wizard_done,
        logger,
        mo,
        mode_mgr,
        project_db,
        set_wizard_done,
        state,
    )


@app.cell
def wizard_header(get_wizard_done, mo):
    """Render wizard header with logo."""
    mo.stop(get_wizard_done())
    from ui.components.header import render_header as _render_header
    wiz_header = _render_header(mo)
    return (wiz_header,)


@app.cell
def wizard_session_load(Path, get_wizard_done, mo):
    """Session load controls at top of wizard."""
    mo.stop(get_wizard_done())
    session_load_browser = mo.ui.file_browser(
        initial_path=str(Path.home()),
        selection_mode="file",
        multiple=False,
        label="Load a saved session (.memdiver)",
    )
    return (session_load_browser,)


@app.cell
def wizard_step1(get_wizard_done, mo):
    """Step 1: What are you analyzing?"""
    mo.stop(get_wizard_done())
    input_type_radio = mo.ui.radio(
        options={
            "single_file": "Single File (.dump / .msl)",
            "run_directory": "Run Directory (dumps from one process)",
            "dataset": "Research Dataset (multi-library protocol tree)",
        },
        label="What are you analyzing?",
    )
    return (input_type_radio,)


@app.cell
def wizard_step2(Path, get_wizard_done, input_type_radio, mo, state):
    """Step 2: Select your data."""
    mo.stop(get_wizard_done())
    mo.stop(not input_type_radio.value)
    itype = input_type_radio.value
    if itype == "single_file":
        data_picker = mo.ui.file_browser(
            initial_path=str(Path.home()),
            selection_mode="file", multiple=False,
            label="Select dump file (.dump or .msl)",
        )
    else:
        _init = state.dataset_root or str(Path.home())
        data_picker = mo.ui.file_browser(
            initial_path=_init,
            selection_mode="directory", multiple=False,
            label="Select directory",
        )
    return (data_picker,)


@app.cell
def wizard_step3(Path, data_picker, get_wizard_done, mo):
    """Step 3: Ground truth (optional)."""
    mo.stop(get_wizard_done())
    mo.stop(not data_picker.value)

    _path = Path(data_picker.value[0].path) if data_picker.value else None
    auto_hints = []
    if _path and _path.suffix == ".msl":
        auto_hints.append("MSL key hints detected in file")
    if _path:
        _parent = _path if _path.is_dir() else _path.parent
        if (_parent / "keylog.csv").exists():
            auto_hints.append("keylog.csv found nearby")

    gt_radio = mo.ui.radio(
        options={
            "auto": "Auto-detect (recommended)",
            "keylog": "Specify keylog file",
            "none": "Skip ground truth",
        },
        value="auto",
        label="Ground truth",
    )
    from core.keylog_templates import list_template_names
    gt_template_dd = mo.ui.dropdown(
        options=list_template_names(), value="Auto-detect",
        label="Keylog Template",
    )
    gt_keylog_input = mo.ui.text(
        value="keylog.csv", label="Keylog Filename (optional)",
        placeholder="Leave empty to skip",
    )
    gt_hints_md = mo.md("\n".join(f"- {h}" for h in auto_hints)) if auto_hints else None
    return gt_hints_md, gt_keylog_input, gt_radio, gt_template_dd


@app.cell
def wizard_step4(data_picker, get_wizard_done, mo):
    """Step 4: Analysis mode."""
    mo.stop(get_wizard_done())
    mo.stop(not data_picker.value)
    mode_radio = mo.ui.radio(
        options={
            "testing": "Testing -- validate known patterns against dumps",
            "research": "Research -- discover unknown key patterns (full suite)",
        },
        value="testing",
        label="Analysis mode",
    )
    return (mode_radio,)


@app.cell
def wizard_launch(data_picker, get_wizard_done, mo, mode_radio):
    """Launch button."""
    mo.stop(get_wizard_done())
    mo.stop(not data_picker.value)
    mo.stop(not mode_radio.value)
    launch_btn = mo.ui.button(
        label="Launch Analysis", kind="success",
        value=0, on_click=lambda v: v + 1,
    )
    return (launch_btn,)


@app.cell
def wizard_finalize(
    Path,
    data_picker,
    gt_keylog_input,
    gt_radio,
    gt_template_dd,
    input_type_radio,
    launch_btn,
    logger,
    mo,
    mode_mgr,
    mode_radio,
    session_load_browser,
    set_wizard_done,
    state,
):
    """Process wizard completion or session load."""
    # Check for session load first
    _session_loaded = False
    if session_load_browser.value:
        try:
            from engine.session_store import SessionStore as _SL, restore_state as _restore
            _sf = Path(session_load_browser.value[0].path)
            _loaded_snap = _SL.load(_sf)
            _restore(state, _loaded_snap, mode_mgr)
            logger.info("Session loaded from %s", _sf)
            set_wizard_done(True)
            _session_loaded = True
        except Exception as e:
            logger.warning("Session load failed: %s", e)

    if not _session_loaded:
        mo.stop(launch_btn.value == 0)
        _path = Path(data_picker.value[0].path)
        state.input_mode = input_type_radio.value
        state.input_path = str(_path)
        if input_type_radio.value == "dataset":
            state.dataset_root = str(_path)
        elif input_type_radio.value == "single_file":
            state.single_file_path = str(_path)
            state.single_file_format = "msl" if _path.suffix == ".msl" else "raw"
        state.ground_truth_mode = gt_radio.value
        state.template_name = gt_template_dd.value
        state.keylog_filename = gt_keylog_input.value or ""
        state.mode = mode_radio.value
        mode_mgr.mode = mode_radio.value
        logger.info("Wizard complete: mode=%s, input=%s", state.input_mode, state.input_path)
        set_wizard_done(True)
    return


@app.cell
def wizard_layout(
    data_picker,
    get_wizard_done,
    gt_hints_md,
    gt_keylog_input,
    gt_radio,
    gt_template_dd,
    input_type_radio,
    launch_btn,
    mo,
    mode_radio,
    session_load_browser,
    wiz_header,
):
    """Assemble wizard UI — only visible before launch."""
    mo.stop(get_wizard_done())

    steps = [wiz_header, mo.md("---")]
    # Session load
    steps.append(mo.accordion({"Load Saved Session": session_load_browser}))
    steps.append(mo.md("---"))
    # Step 1
    steps.append(mo.md("### Step 1: Input Type"))
    steps.append(input_type_radio)
    # Step 2 (conditional)
    if input_type_radio.value:
        steps.append(mo.md("### Step 2: Select Data"))
        steps.append(data_picker)
    # Step 3 (conditional)
    if data_picker.value if hasattr(data_picker, 'value') else False:
        steps.append(mo.md("### Step 3: Ground Truth (optional)"))
        if gt_hints_md:
            steps.append(gt_hints_md)
        steps.append(gt_radio)
        if gt_radio.value == "keylog":
            steps.append(mo.hstack([gt_keylog_input, gt_template_dd], gap=1))
    # Step 4 + launch (conditional)
    if data_picker.value if hasattr(data_picker, 'value') else False:
        steps.append(mo.md("### Step 4: Analysis Mode"))
        steps.append(mode_radio)
        steps.append(mo.md("---"))
        steps.append(launch_btn)

    return mo.vstack(steps)


@app.cell
def workspace_toolbar(get_wizard_done, mo, mode_mgr):
    """Toolbar: header + mode toggle + new analysis + save session."""
    from types import SimpleNamespace as _NS
    mo.stop(not get_wizard_done())
    from ui.components.header import render_header as _render_header
    ws_header = _render_header(mo)
    mode_toggle = mo.ui.switch(value=mode_mgr.is_research, label="Research Mode")
    new_btn = mo.ui.button(label="New Analysis", value=0, on_click=lambda v: v + 1)
    save_btn = mo.ui.button(label="Save Session", value=0, on_click=lambda v: v + 1)
    ws_toolbar = _NS(
        header=ws_header, mode_toggle=mode_toggle,
        new_btn=new_btn, save_btn=save_btn,
    )
    return (ws_toolbar,)


@app.cell
def handle_mode_toggle(get_wizard_done, mode_mgr, state, ws_toolbar):
    """Sync workspace mode toggle to mode_mgr and state."""
    if not get_wizard_done():
        ws_mode_state = mode_mgr.mode
    else:
        from core.constants import RESEARCH, TESTING
        mode_mgr.mode = RESEARCH if ws_toolbar.mode_toggle.value else TESTING
        state.mode = mode_mgr.mode
        ws_mode_state = mode_mgr.mode
    return


@app.cell
def handle_new_analysis(get_wizard_done, set_wizard_done, state, ws_toolbar):
    """Reset to wizard when New Analysis clicked."""
    if get_wizard_done() and ws_toolbar.new_btn.value > 0:
        state.reset_analysis()
        set_wizard_done(False)
    return


@app.cell
def handle_save_session(get_wizard_done, logger, mo, state, ws_toolbar):
    """Save session to file."""
    save_toast = None
    if get_wizard_done() and ws_toolbar.save_btn.value > 0:
        try:
            from engine.session_store import SessionStore as _SS, snapshot_from_state as _snap_from
            _snap = _snap_from(state)
            _snap.session_name = f"{state.protocol_name}_{state.protocol_version}"
            path = _SS.save(_snap, _SS.auto_save_path(_snap.session_name))
            save_toast = mo.callout(
                mo.md(f"Session saved: `{path.name}`"), kind="success",
            )
            logger.info("Session saved to %s", path)
        except Exception as e:
            save_toast = mo.callout(mo.md(f"Save failed: {e}"), kind="danger")
    return (save_toast,)


@app.cell
def import_tool(Path, get_wizard_done, mo):
    """MSL import tool controls."""
    mo.stop(not get_wizard_done())
    from types import SimpleNamespace as _NS
    import_file_browser = mo.ui.file_browser(
        initial_path=str(Path.home()),
        selection_mode="file", multiple=False,
        label="Raw dump file to convert",
    )
    import_btn = mo.ui.button(
        label="Import to MSL", value=0, on_click=lambda v: v + 1, kind="neutral",
    )
    import_widgets = _NS(file_browser=import_file_browser, btn=import_btn)
    return (import_widgets,)


@app.cell
def run_import_tool(Path, get_wizard_done, import_widgets, logger, mo):
    """Execute MSL import."""
    mo.stop(not get_wizard_done())
    import_result_el = None
    if import_widgets.btn.value > 0 and import_widgets.file_browser.value:
        from msl.importer import import_raw_dump
        raw = Path(import_widgets.file_browser.value[0].path)
        out = raw.with_suffix(".msl")
        try:
            with mo.status.spinner(title="Importing to MSL..."):
                res = import_raw_dump(raw, out)
            import_result_el = mo.callout(
                mo.md(f"Imported **{raw.name}** -> **{out.name}**  \n"
                       f"Regions: {res.regions_written}, Key hints: {res.key_hints_written}"),
                kind="success",
            )
            logger.info("Imported %s -> %s", raw, out)
        except Exception as e:
            import_result_el = mo.callout(mo.md(f"Import failed: {e}"), kind="danger")
    return (import_result_el,)


@app.cell
def dataset_scan(Path, get_wizard_done, logger, mo, state):
    """Scan dataset if in dataset mode."""
    mo.stop(not get_wizard_done())
    dataset_info = None
    if state.input_mode == "dataset" and state.dataset_root:
        from core.discovery import DatasetScanner
        with mo.status.spinner(title="Scanning dataset..."):
            scanner = DatasetScanner(
                Path(state.dataset_root),
                keylog_filename=state.keylog_filename,
            )
            dataset_info = scanner.fast_scan()
        state.dataset_info = dataset_info
        logger.info("Scanned: %d versions, %d runs",
                     len(dataset_info.tls_versions), dataset_info.total_runs)
    return (dataset_info,)


@app.cell
def dataset_selectors(dataset_info, get_wizard_done, mo, state):
    """Cascading selectors for dataset mode."""
    mo.stop(not get_wizard_done())
    if state.input_mode != "dataset" or dataset_info is None:
        ds_proto_dd = mo.ui.dropdown(options=["TLS"], value="TLS", label="Protocol")
        ds_tls_dd = mo.ui.dropdown(options=["13"], value="13", label="Version")
        ds_scenario_dd = mo.ui.dropdown(options=["default"], value="default", label="Scenario")
        ds_lib_select = mo.ui.multiselect(options=[], label="Libraries")
        ds_phase_dd = mo.ui.dropdown(options=["pre_abort"], value="pre_abort", label="Phase")
        ds_normalize_cb = mo.ui.checkbox(value=False, label="Normalize phases")
        ds_max_runs = mo.ui.slider(start=1, stop=20, value=10, step=1, label="Max runs")
    else:
        from ui.controls.selector_panel import (
            create_protocol_dropdown, create_selector_controls,
            create_scenario_dropdown, create_library_controls, resolve_phases,
        )
        ds_proto_dd = create_protocol_dropdown(mo, dataset_info)
        (ds_tls_dd,) = create_selector_controls(mo, dataset_info, protocol_name=ds_proto_dd.value)
        ds_scenario_dd = create_scenario_dropdown(mo, dataset_info, ds_tls_dd.value)
        ds_lib_select, _pd, ds_normalize_cb, ds_max_runs = create_library_controls(
            mo, dataset_info, ds_tls_dd.value, ds_scenario_dd.value,
        )
        libs = sorted(dataset_info.libraries.get(ds_scenario_dd.value, set()))
        _phases = resolve_phases(dataset_info, ds_tls_dd.value, ds_scenario_dd.value, libs,
                                 normalize=ds_normalize_cb.value)
        ds_phase_dd = mo.ui.dropdown(
            options=_phases or ["pre_abort"],
            value=_phases[0] if _phases else "pre_abort", label="Phase",
        )
    from types import SimpleNamespace as _NS
    ds_widgets = _NS(
        proto_dd=ds_proto_dd, tls_dd=ds_tls_dd, scenario_dd=ds_scenario_dd,
        lib_select=ds_lib_select, phase_dd=ds_phase_dd,
        normalize_cb=ds_normalize_cb, max_runs=ds_max_runs,
    )
    return (ds_widgets,)


@app.cell
def dataset_analysis_controls(get_wizard_done, mo, mode_mgr, state):
    """Algorithm + run button for dataset mode."""
    mo.stop(not get_wizard_done())
    mo.stop(state.input_mode != "dataset")
    from types import SimpleNamespace as _NS
    from ui.controls.analysis_panel import create_analysis_controls as _create_ac
    ds_algo_dd, ds_run_btn, _toggle = _create_ac(mo, mode_mgr)
    ds_controls = _NS(algo_dd=ds_algo_dd, run_btn=ds_run_btn)
    return (ds_controls,)


@app.cell
async def dataset_run_analysis(
    ds_controls,
    ds_widgets,
    get_wizard_done,
    logger,
    mo,
    mode_mgr,
    project_db,
    state,
):
    """Run dataset analysis."""
    import asyncio
    mo.stop(not get_wizard_done())
    ds_result = None
    if state.input_mode == "dataset" and ds_controls.run_btn.value > 0 and ds_widgets.lib_select.value:
        state.protocol_version = ds_widgets.tls_dd.value
        state.protocol_name = ds_widgets.proto_dd.value
        state.scenario = ds_widgets.scenario_dd.value
        state.selected_libraries = list(ds_widgets.lib_select.value)
        state.selected_phase = ds_widgets.phase_dd.value
        state.normalize_phases = ds_widgets.normalize_cb.value
        state.max_runs = ds_widgets.max_runs.value
        state.algorithm = ds_controls.algo_dd.value

        from core.keylog_templates import get_template
        from engine.pipeline import AnalysisPipeline
        from engine.results import AnalysisResult

        template = get_template(state.template_name)
        pipeline = AnalysisPipeline(project_db=project_db)
        ds_result = AnalysisResult()
        _n = len(state.selected_libraries)
        with mo.status.spinner(title=f"Analyzing {_n} libraries..."):
            for lib_name in state.selected_libraries:
                _ld = state.build_lib_dir(lib_name)
                await asyncio.sleep(0)
                report = pipeline.analyze_library(
                    _ld, phase=state.selected_phase,
                    protocol_version=state.protocol_version,
                    keylog_filename=state.keylog_filename,
                    max_runs=state.max_runs,
                    expand_keys=mode_mgr.should_expand_keys(),
                    template=template, normalize=state.normalize_phases,
                )
                ds_result.libraries.append(report)
        state.analysis_result = ds_result
        state.library_reports = {r.library: r for r in ds_result.libraries}
        logger.info("Analysis: %d libs, %d hits", len(ds_result.libraries), ds_result.total_hits)

        # Auto-save session after analysis
        try:
            from engine.session_store import SessionStore as _SS2, snapshot_from_state as _snap_from2
            _snap2 = _snap_from2(state)
            _snap2.session_name = f"{state.protocol_name}_{state.protocol_version}_auto"
            _SS2.save(_snap2, _SS2.auto_save_path(_snap2.session_name))
            logger.info("Auto-saved session after analysis")
        except Exception:
            pass
    return (ds_result,)


@app.cell
def dataset_views(
    RunDiscovery,
    ds_result,
    get_wizard_done,
    mo,
    mode_mgr,
    state,
):
    """Build dataset analysis view sections."""
    mo.stop(not get_wizard_done())
    mo.stop(state.input_mode != "dataset")
    ds_view_sections = {}
    if ds_result and ds_result.libraries:
        # Results summary
        from ui.controls.analysis_panel import render_results_summary
        ds_view_sections["Results Summary"] = render_results_summary(mo, ds_result)

        # Heatmap
        from ui.views.heatmap import render_heatmap, build_presence_data
        reports = ds_result.libraries
        all_types = sorted(set(h.secret_type for r in reports for h in r.hits))
        if all_types:
            presence = build_presence_data(reports, all_types)
            libraries = [r.library for r in reports]
            ds_view_sections["Key Presence Heatmap"] = render_heatmap(
                mo, libraries, all_types, presence, state.protocol_version,
            )

        # Load first library dump once, reuse for hex + entropy
        first_data = None
        first_rpt = None
        for rpt in reports:
            if rpt.hits:
                _ld = state.build_lib_dir(rpt.library)
                _runs = RunDiscovery.discover_library_runs(_ld, max_runs=1)
                if _runs:
                    dump = _runs[0].get_dump_for_phase(state.selected_phase)
                    if dump:
                        first_data = dump.path.read_bytes()
                        first_rpt = rpt
                        break

        if first_data and first_rpt:
            hit = first_rpt.hits[0]
            start = max(0, hit.offset - 256)
            end = min(len(first_data), hit.offset + hit.length + 256)
            from ui.views.hex_viewer import render_hex_viewer, render_hit_details
            ds_view_sections["Hex Viewer"] = mo.vstack([
                render_hex_viewer(
                    mo, first_data[start:end], start_offset=start,
                    title=f"Hex: {first_rpt.library} @ {state.selected_phase}",
                ),
                render_hit_details(mo, first_rpt.hits, first_data),
            ])

        # Research views
        if mode_mgr.is_research:
            from ui.views.consensus_view import render_consensus_view
            from engine.consensus import ConsensusVector
            for rpt_c in reports:
                counts = rpt_c.metadata.get("consensus", {})
                if counts:
                    cm = ConsensusVector()
                    cm.size = sum(counts.values())
                    cm.num_dumps = rpt_c.num_runs
                    cm.classifications = []
                    for cls, cnt in counts.items():
                        cm.classifications.extend([cls] * cnt)
                    ds_view_sections["Consensus Matrix"] = render_consensus_view(
                        mo, cm, title=f"Consensus: {rpt_c.library}",
                    )
                    break

            if first_data and first_rpt:
                from core.entropy import compute_entropy_profile
                from ui.views.entropy_chart import render_entropy_chart
                profile = compute_entropy_profile(first_data, window=32, step=16)
                key_regions = [(h.offset, h.offset + h.length, h.secret_type)
                               for h in first_rpt.hits[:5]]
                ds_view_sections["Entropy Profile"] = render_entropy_chart(
                    mo, profile, key_offsets=key_regions,
                    title=f"Entropy: {first_rpt.library}",
                )
    return (ds_view_sections,)


@app.cell
def file_load(Path, get_wizard_done, logger, mo, state):
    """Load a single dump file."""
    mo.stop(not get_wizard_done())
    file_data = None
    file_source = None
    if state.input_mode == "single_file" and state.single_file_path:
        from core.dump_source import open_dump
        with mo.status.spinner(title="Loading dump file..."):
            file_source = open_dump(Path(state.single_file_path))
            file_source.open()
            file_data = file_source.read_all()
        logger.info("Loaded %s: %d bytes", state.single_file_path, len(file_data))
    return file_data, file_source


@app.cell
def file_views(
    Path,
    file_data,
    file_source,
    get_wizard_done,
    mo,
    mode_mgr,
    state,
):
    """Build single-file view sections."""
    mo.stop(not get_wizard_done())
    mo.stop(state.input_mode != "single_file")
    file_view_sections = {}
    if file_data is not None:
        _build_file_views(mo, state, file_data, file_source, mode_mgr, file_view_sections, Path)
    return (file_view_sections,)


@app.cell
def _():
    def _build_file_views(mo, state, file_data, file_source, mode_mgr, file_view_sections, Path):
        """Build view sections for a loaded file."""
        # Hex viewer
        from ui.views.hex_viewer import render_hex_viewer as _render_hex
        _end = min(len(file_data), 4096)
        file_view_sections["Hex Viewer"] = _render_hex(
            mo, file_data[:_end], start_offset=0,
            title=f"Hex: {Path(state.single_file_path).name}",
        )

        # Entropy
        if mode_mgr.is_research:
            from core.entropy import compute_entropy_profile
            from ui.views.entropy_chart import render_entropy_chart
            profile = compute_entropy_profile(file_data, window=32, step=16)
            file_view_sections["Entropy Profile"] = render_entropy_chart(
                mo, profile, title=f"Entropy: {Path(state.single_file_path).name}",
            )

        # Strings
        from core.strings import extract_strings
        from ui.components.html_builder import table as html_table
        strings = extract_strings(file_data, min_length=6)
        if strings:
            str_rows = [[f"0x{s.offset:X}", s.text[:60]] for s in strings[:50]]
            file_view_sections["Strings"] = mo.Html(
                html_table(["Offset", "String"], str_rows,
                           col_styles={0: "font-family:monospace;"})
                + f"<div style='color:#808080; font-size:12px;'>{len(strings)} strings found</div>"
            )

        # Structure detection (works for both raw and MSL)
        try:
            from core.structure_overlay import best_match_structure
            from core.structure_library import get_structure_library
            lib = get_structure_library()
            match = best_match_structure(file_data, 0, lib)
            if match:
                struct_def, overlays, confidence = match
                if confidence > 0.3:
                    overlay_rows = []
                    for ov in overlays:
                        color = "#4CAF50" if ov.valid else "#F44336"
                        overlay_rows.append([
                            f"0x{ov.offset:X}", str(ov.length), ov.field_name,
                            f"<span style='color:{color};'>{ov.display}</span>",
                        ])
                    file_view_sections["Structure Detection"] = mo.vstack([
                        mo.md(f"**Detected**: {struct_def.name} "
                              f"({confidence:.0%} confidence)"),
                        mo.Html(html_table(
                            ["Offset", "Size", "Field", "Value"], overlay_rows,
                            col_styles={0: "font-family:monospace;"},
                        )),
                    ])
        except Exception:
            pass

        # MSL-specific views
        if state.single_file_format == "msl" and file_source:
            try:
                reader = file_source.get_reader()
                # Session overview
                from msl.session_extract import extract_session_report
                from ui.views.session_view import render_session_view
                report = extract_session_report(reader)
                file_view_sections["Session Overview"] = render_session_view(mo, report)

                # VAS map
                vas_maps = reader.collect_vas_map()
                if vas_maps:
                    from ui.views.vas_view import render_vas_map, render_vas_table
                    all_vas_entries = []
                    for vm in vas_maps:
                        all_vas_entries.extend(vm.entries)
                    regions = reader.collect_regions()
                    file_view_sections["Virtual Address Space"] = mo.vstack([
                        render_vas_map(mo, all_vas_entries, regions),
                        render_vas_table(mo, all_vas_entries, regions),
                    ])

                # Block navigator
                from ui.views.block_navigator import render_block_navigator
                file_view_sections["MSL Blocks"] = render_block_navigator(mo, reader)

                # Cross-references
                try:
                    related = reader.collect_related_dumps()
                    if related:
                        xref_rows = [
                            [f"<span style='font-family:monospace; font-size:12px;'>"
                             f"{rd.related_dump_uuid.hex()[:12]}...</span>",
                             f"PID {rd.related_pid}", str(rd.relationship)]
                            for rd in related
                        ]
                        file_view_sections["Cross-References"] = mo.Html(
                            html_table(["UUID", "PID", "Relationship"], xref_rows)
                        )
                except Exception:
                    pass
            except Exception as e:
                file_view_sections["MSL Info"] = mo.callout(
                    mo.md(f"Could not parse MSL metadata: {e}"), kind="warn",
                )

    return


@app.cell
def dir_views(Path, RunDiscovery, get_wizard_done, mo, runs, state):
    """Build directory mode view sections."""
    mo.stop(not get_wizard_done())
    dir_view_sections = {}
    if state.input_mode == "run_directory":
        _dir = Path(state.input_path)
        _runs = RunDiscovery.discover_library_runs(_dir, max_runs=10)
        if not _runs:
            dir_view_sections["Info"] = mo.callout(
                mo.md(f"No dump files found in `{_dir.name}`"), kind="warn",
            )
        else:
            # Show available phases
            _phases = sorted(set(d.phase for r in _runs for d in r.dumps))
            dir_view_sections["Directory Info"] = mo.md(
                f"**{len(_runs)} runs** found, **{len(_phases)} phases**: {', '.join(_phases)}"
            )
            # Show hex of first dump
            if _runs[0].dumps:
                _first_dump = runs[0].dumps[0]
                _data = _first_dump.path.read_bytes()
                from ui.views.hex_viewer import render_hex_viewer as _render_hex
                dir_view_sections["Hex Viewer"] = _render_hex(
                    mo, _data[:4096], start_offset=0,
                    title=f"Hex: {_first_dump.path.name}",
                )
    return (dir_view_sections,)


@app.cell
def workspace_sidebar(get_wizard_done, mo, mode_mgr, state):
    """Persistent sidebar with metadata."""
    mo.stop(not get_wizard_done())
    _mode_color = "#4A90D9" if mode_mgr.is_research else "#808080"
    _mode_label = "Research" if mode_mgr.is_research else "Testing"
    _items = [
        mo.md(f"**Mode**: <span style='color:{_mode_color};'>{_mode_label}</span>"),
        mo.md(f"**Input**: {state.input_mode}"),
    ]
    if state.input_path:
        from pathlib import Path as _P
        _items.append(mo.md(f"**Path**: `{_P(state.input_path).name}`"))
    if state.input_mode == "dataset" and state.dataset_info:
        _items.append(mo.md(f"**Runs**: {state.dataset_info.total_runs}"))
    mo.sidebar(mo.vstack(_items))
    return


@app.cell
def workspace_layout(
    dir_view_sections,
    ds_controls,
    ds_view_sections,
    ds_widgets,
    file_view_sections,
    get_wizard_done,
    import_result_el,
    import_widgets,
    mo,
    mode_mgr,
    save_toast,
    state,
    ws_toolbar,
):
    """Assemble the unified workspace."""
    mo.stop(not get_wizard_done())

    from ui.controls.analysis_panel import render_mode_banner

    toolbar = mo.hstack([
        ws_toolbar.mode_toggle, mo.md(""), ws_toolbar.save_btn, ws_toolbar.new_btn,
    ], justify="space-between")

    elements = [ws_toolbar.header, toolbar]
    if save_toast:
        elements.append(save_toast)
    elements.append(mo.md("---"))

    elements.append(render_mode_banner(mo, mode_mgr))

    # Build accordion sections based on input mode
    sections = {}

    if state.input_mode == "dataset":
        selector_ui = mo.vstack([
            mo.hstack([ds_widgets.proto_dd, ds_widgets.tls_dd, ds_widgets.scenario_dd],
                       justify="start", gap=1),
            mo.hstack([ds_widgets.lib_select, ds_widgets.phase_dd,
                        ds_widgets.normalize_cb, ds_widgets.max_runs],
                       justify="start", gap=1, wrap=True),
            mo.hstack([ds_controls.algo_dd, ds_controls.run_btn], justify="start", gap=1),
        ])
        sections["Data Selection & Analysis"] = selector_ui
        sections.update(ds_view_sections)

    elif state.input_mode == "single_file":
        sections.update(file_view_sections)

    elif state.input_mode == "run_directory":
        sections.update(dir_view_sections)

    # Tools section (always available)
    import_ui = mo.vstack([
        import_widgets.file_browser, import_widgets.btn,
        import_result_el if import_result_el else mo.md(""),
    ])
    sections["Import Raw Dump to MSL"] = import_ui

    if sections:
        elements.append(mo.accordion(sections, lazy=True))
    else:
        elements.append(mo.md("*Loading...*"))

    return mo.vstack(elements)


if __name__ == "__main__":
    app.run()
