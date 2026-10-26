"""MCP prompts: the agent playbooks for MemDiver's semantic workbench (P6 T6.1).

Each prompt renders a numbered, copy-able procedure that names the EXACT tools
(and their key parameters), what to check in each result, and the traps that
were hit on real data. Conventions the structural test relies on:

* a tool is always written as ``tool_name(...)`` in backticks (so a rename or a
  typo fails ``tests/test_mcp_prompts_resources.py``);
* a parameter is written as ``param=value`` and never followed by ``(``.

Imports no ``mcp`` SDK symbol: ``register_prompts`` takes the server instance.
"""

from __future__ import annotations

from typing import Optional

_SANDBOX = (
    "Sandbox: when `MEMDIVER_ALLOWED_ROOTS` is set, every path argument must lie in those roots "
    "and output paths in MemDiver home; a denial returns the usual JSON error "
    "(`code=path.outside_sandbox`) - fix the path, do not retry."
)

_ERRORS = (
    "Errors: every tool returns JSON; on failure the body is `{\"error\": ..., \"code\": ..., "
    "\"details\": ...}`. Read `code` and `details` (they name the missing extra, the implicated "
    "entries, the install hint) before retrying. An empty result is never silent success: look "
    "at `coverage`, `truncated` and `warnings`."
)


def _arg(value: Optional[str], placeholder: str) -> str:
    return value if value else placeholder


def _start() -> str:
    return f"""MemDiver is an evidence-preserving workbench for memory forensics. Full memory images,
`.msl` captures and raw dumps are read through ONE path-addressed, stateless tool surface.
A *case directory* holds what you derive: views (`.mdview`), extracted `.msl` files, annotations,
ISF drafts, plugins and DuckDB tables of every plugin run.

Playbooks (fetch the prompt for the full step list):
1. `vol3_inside_memdiver` - open an image, resolve a profile, run Volatility 3 plugins, query rows, annotate.
2. `vol3_plugin_dev` - scaffold, store, check, run and fixture-test your own vol3 plugin.
3. `isf_workbench` - hand-build an ISF kernel profile when automatic profile resolution fails.
4. `image_to_process_keys` - process -> `.msl` -> heap -> key finders -> oracle verification.
5. `n_image_variance` - cohorts, consensus and anchor consensus over N dumps.
6. `object_model_from_keylog` - key log -> layout -> artifact model -> exported plugin -> held-out validation.
7. `code_evidence` - which struct fields does a kernel function touch (joined to an ISF).

Workhorses: `case_query(case_dir, sql)` is ONE read-only SELECT over every table (plugin rows,
regions, heap chunks, key hits, annotations); call `case_schema(case_dir)` first for table and
column names. `context_at(case_dir, location)` answers "what contains this address?".
`case_manifest(case_dir)` inventories a case; `case_init(case)` creates one.

Resources: `memdiver://case/{{case_dir}}/manifest`, `memdiver://case/{{case_dir}}/schema`,
`memdiver://case/{{case_dir}}/annotations/{{capture}}`,
`memdiver://case/{{case_dir}}/isf/{{capture}}/{{draft}}` (URL-encode the case directory).

Conventions: addresses are `Location` dicts (`space`, `value`, `capture_id`, ...); results carry
`coverage`; large address values are exact integers. Tools never overwrite: `out_path` must be a
NEW file.

{_ERRORS}
{_SANDBOX}"""


#: Example query cited by a playbook (kept out of the f-string: bandit B608 reads
#: SQL keywords inside a formatted string as an injectable query).
_EXAMPLE_SQL = "SELECT * FROM <table> LIMIT 20"


def _vol3_inside(image_path: Optional[str], case: Optional[str]) -> str:
    image = _arg(image_path, "<IMAGE>")
    case_dir = _arg(case, "<CASE>")
    return f"""Playbook: Volatility 3 inside MemDiver on image `{image}`, case `{case_dir}`.

1. `case_init(case="{case_dir}")` (a bare name files under MemDiver home) and keep the returned case dir.
2. `image_probe(image_path="{image}", banners=true)` - size, physical layers, profile status
   (`unknown` until hashed) and the Linux banners. Never hashes the image.
3. Profile: `image_profile(image_path="{image}")`. It resolves explicit -> cache -> pakunoda -> vol3 dirs;
   a first run is slow (~15-30 s for an 8 GB image; opening the first kernel view takes about as long again)
   and is then cached. Check `origin` and `isf_name`, and trust the resolved banner over the file name.
   Traps: on 5-level-paging (LA57) kernels vol3 can return 0 rows silently - if `image_processes` is
   empty, suspect the paging depth, not the process list. If no profile is found, switch to the
   `isf_workbench` playbook (or open a profile-less view with `image_open_view(image_path="{image}", view="kernel", no_profile=true, case_dir="{case_dir}")`).
4. `image_open_view(image_path="{image}", view="kernel", case_dir="{case_dir}")` writes a `.mdview`
   under `<case>/views/` and returns its path (`view_path`). Use `view="physical"` for raw physical
   space. Every hex/search/regions tool accepts the `.mdview` like any dump.
5. `image_processes(view_path=...)` - pid, ppid, comm, uid, has_mm, `kernel_va` Location. Zero tasks
   is an error (wrong profile or paging depth), never an empty success.
6. `vol3_plugins(os_family="linux")` lists bundled plugins; `vol3_describe(plugin="linux.pslist")`
   shows the requirements to pass as `args`.
7. `vol3_run(view_path=..., plugin="linux.pslist", case_dir="{case_dir}")` blocks until done. Check
   `truncated` / `stop_reason` (the `limit` and `timeout_s` caps), then look at the registered table
   `vol3__<os>_<plugin>` (standard columns `addr`, `size`, `space`). A process view scopes `pid`
   automatically.
8. Rows as tables: `case_schema(case_dir="{case_dir}")` then
   `case_query(case_dir="{case_dir}", sql="{_EXAMPLE_SQL}")`. Bind values with `params`
   (positional `?`), never by string formatting. Every `vol3_run` APPENDS a run to the plugin's table (two
   pslist runs = twice the rows): filter with `WHERE run_id = ?` (the `run_id` the run returned).
   `vol3_query(case_dir=...)` with neither `sql` nor `saved` lists the built-in saved queries; e.g. after
   running both `linux.pslist` and `linux.psscan`, `vol3_query(case_dir=..., saved="hidden_processes")` lists
   tasks psscan sees but pslist does not (mostly `exit_state` EXIT_DEAD remnants - check before calling
   anything hidden). Ground truth taken at acquisition (`ps` output) can differ by a few short-lived pids.
9. Highlights: `vol3_annotate(case_dir="{case_dir}", table=<table>, run_id=<the run_id vol3_run returned>,
   column=<a location column>, rows=[<row numbers>])` files one `plugin_row` annotation per row (only rows
   with an address; omit `rows` for all of them). Manual notes:
   `annotations_add(case_dir=..., capture_id=..., kind=..., author="agent", locations=[...], label=...)`
   (`author` is `human`, `agent` or `tool:<name>`; a location is a Location dict such as the `kernel_va`
   one `image_processes` returns, or `{{"space": "kernel_va", "value": <int>, "capture_id": <id>}}`);
   read back with `annotations_list(case_dir=..., capture_id=...)`. Annotations are append-only:
   fix with `annotations_supersede`, withdraw with `annotations_retract`.
10. Views: kernel view (kernel_va space) for kernel structures, `image_open_view(image_path="{image}", view="process", pid=N, case_dir="{case_dir}")`
    for one process. `context_at(case_dir=..., location={{"space": "kernel_va", "value": <addr>,
    "capture_id": <id>}})` says which row/VMA/chunk/annotation contains an address.
11. Extract a process: open its process view, then `image_extract_process(view_path=..., out_path=<NEW .msl>)`.
    The `.msl` is a normal capture for `heap_detect`, `keyfinders_scan` and consensus tools
    (continue with `image_to_process_keys`).

Checks after each step: `coverage` of the result, `truncated`, the `warnings` list.
{_ERRORS}
{_SANDBOX}"""


def _plugin_dev(case: Optional[str], view_path: Optional[str]) -> str:
    case_dir = _arg(case, "<CASE>")
    view = _arg(view_path, "<VIEW.mdview>")
    return f"""Playbook: develop a Volatility 3 plugin in case `{case_dir}` against view `{view}`.

1. `vol3_scaffold(name="my_plugin", os_family="linux", per_process=true)` returns the plugin source text
   (kernel module with an optional `pid` filter). Edit the text.
2. `vol3_source_put(case_dir="{case_dir}", name="my_plugin", source=<text>, view_path="{view}")` stores it
   under `<case>/plugins/` (an overwrite keeps the old text under `plugins/history`) and checks it.
   A plugin that fails to load is still saved: read the structured failure (error type, line).
   WARNING: user plugins are EXECUTED unsandboxed in the server process - only run text you wrote or reviewed.
3. `vol3_check(source_name="my_plugin", case_dir="{case_dir}", view_path="{view}")` re-checks; with
   `view_path` it also lists requirements the view leaves unsatisfied.
4. `vol3_describe(source_name="my_plugin", case_dir="{case_dir}")` shows the `args` to pass.
5. `vol3_run(view_path="{view}", source_name="my_plugin", case_dir="{case_dir}")` runs it; rows land in the
   case table named in the result. Iterate: edit, `vol3_source_put`, run again.
   Stored plugins are listed with `vol3_source_list(case_dir=...)` and read with `vol3_source_get(case_dir=..., name=...)`.
6. Fixtures: `vol3_fixture_put(case_dir="{case_dir}", name="finds_sshd", plugin=..., view_path="{view}",
   expect=[{{"row_where": {{"COMM": "sshd"}}, "count_at_least": 1}}])` (predicates: `min_rows`, `max_rows`,
   `row_where` + `count_at_least`, `column_all`, `column_any`). Run with
   `vol3_fixture_run(case_dir="{case_dir}", name="finds_sshd")`: verdict `pass` / `fail` / `indeterminate`.
   `indeterminate` proves nothing (truncated or timed-out run, unreadable view) - never read it as pass.
   `vol3_fixture_list(case_dir=...)` lists them. The verdict is filed as a `fixture_verdict` annotation.
7. Ship: `vol3_write_config(view_path="{view}", out_path=<NEW file>, source_name="my_plugin", case_dir="{case_dir}")`
   writes the run configuration for stand-alone `vol` use.

Trap: a plugin returning rows without an address column cannot be highlighted; keep `addr`/`size`/`space`
columns where it makes sense.
{_ERRORS}
{_SANDBOX}"""


def _isf_workbench(image_path: Optional[str], case: Optional[str], draft: Optional[str]) -> str:
    image = _arg(image_path, "<IMAGE>")
    case_dir = _arg(case, "<CASE>")
    name = _arg(draft, "draft1")
    return f"""Playbook: build an ISF kernel profile by hand for `{image}` (case `{case_dir}`, draft `{name}`),
for kernels where automatic profile resolution fails. Reference run: the arista-eos gate
(docs/dev/semantic_workbench_p4_gate/, 123/123 processes vs ground truth, 0 disagreements).

HARD RULES: wrong offsets are SILENT in Volatility 3 (it loads the profile and returns plausible wrong
rows) - never trust a profile you have not tried against ground truth. Never export void members.
Use only a VERIFIED init_task (pakunoda's `find_init_task`; an unverified one is refused, not guessed).

1. Facts: `image_probe(image_path="{image}", banners=true)`; then `isf_probe(image_path="{image}", probe="viability")`
   and `probe="banner"`, `probe="vmcoreinfo"`, `probe="page_table_root"`, `probe="utsname"`. Rows carry `Location`s;
   check `counts`, `truncated`, `timings`. LA57 images use 5-level paging: pass `params={{"va_bits": 57}}` only
   when the probes say so.
2. Create the draft: `isf_draft_create(case_dir="{case_dir}", capture_id=<id>, name="{name}", arch="x86_64", banner=<banner>)`.
3. Feed symbols: `isf_probe(image_path="{image}", probe="kallsyms", case_dir="{case_dir}", draft="{name}")`
   (also `btf`, `vmcoreinfo`, `layout_legs`) feeds findings straight into the draft with provenance. kallsyms on a
   multi-GB image can take over a minute (it runs inline). `probe="layout_legs"` yields many claims AND refusals -
   read the refusals.
4. Manual claims: `isf_draft_set(case_dir=..., capture_id=..., name="{name}", op="struct", args={{"struct": "task_struct", "size": N}},
   source=..., tier=..., evidence=...)`; ops are `symbol`, `struct`, `field`, `base_type`, `enum`, `remove`. Every
   claim carries provenance (source, tier, evidence, witnesses): cite where each number came from.
   `code_evidence(image_path="{image}", function="__x64_sys_getuid")` decodes which struct offsets kernel code
   uses (see the `code_evidence` prompt) - the strongest evidence for a field offset.
   `disasm(dump_path=<kernel view>, address=<va>, length=..., arch=...)` shows the instructions at an address.
5. Check the draft: `isf_draft_get(case_dir=..., capture_id=..., name="{name}", include_origins=true, search=...)`
   (paged: `offset`/`limit`; `untyped_fields` counts placeholder offsets that are NOT exported), then
   `isf_draft_validate(case_dir=..., capture_id=..., name="{name}", check_schema=true)` which lists the
   vol3-required types still missing.
6. Try: `isf_try(image_path="{image}", case_dir="{case_dir}", draft="{name}", plugin="linux.pslist",
   ground_truth=<known-good plugin output file>)`. It builds the profile, runs the plugin, diffs against ground
   truth (`min_recall`, `min_precision`) and returns `implicated` draft entries. A load failure
   (`profile_build_failed`) lists the missing required types: add field-less stub structs for them first.
   Each draft try is filed as an `isf_try` annotation (`annotations_list(case_dir=..., capture_id=..., kind="isf_try")` is the history).
7. Iterate: fix the implicated entries (`isf_draft_set`, `isf_draft_retract(..., entry_id=...)`), compare versions with
   `isf_draft_versions(...)` / `isf_draft_diff(..., against_version=...)`, try again until the verdict passes.
8. Use it: `image_open_view(image_path="{image}", view="kernel", case_dir="{case_dir}", draft="{name}")` (pin
   `draft_version`), then the `vol3_inside_memdiver` steps. Export: `isf_draft_export(case_dir=..., capture_id=...,
   name="{name}", out_path=<NEW .isf.json outside annotations/>)`. `isf_draft_import(..., isf_path=...)` seeds a draft
   from an existing ISF (e.g. to diff your claims against a shipped profile).
{_ERRORS}
{_SANDBOX}"""


def _image_to_keys(image_path: Optional[str], case: Optional[str], pid: Optional[str]) -> str:
    image = _arg(image_path, "<IMAGE>")
    case_dir = _arg(case, "<CASE>")
    process = _arg(pid, "<PID>")
    return f"""Playbook: image `{image}` -> process {process} -> keys (case `{case_dir}`).

1. Follow `vol3_inside_memdiver` up to `image_processes(view_path=...)` and pick the process
   (`vol3_run` with `linux.pslist`/`linux.sockstat` and `case_query` help identify it).
2. `image_open_view(image_path="{image}", view="process", pid={process}, case_dir="{case_dir}")` then
   `image_extract_process(view_path=<process view>, out_path=<NEW .msl>)`. Long (minutes on big images).
3. Inspect the capture: `get_session_info(msl_path=...)`, `vas_regions(msl_path=...)`, `get_modules(msl_path=...)`.
4. Heap: `heap_detect(dump_path=<.msl>)` (START HERE; check `best` and `platform`), `heap_summary(dump_path=..., allocator=...)`,
   then `heap_chunks(dump_path=..., state="in_use")` / `heap_roles(...)` as needed. Treat `partial` / `heuristic`
   allocators (jemalloc, generic) with suspicion.
5. Key finders: `keyfinders_list()` shows the finders and their `params`; then
   `keyfinders_scan(dump_path=<.msl>, finders=["aes_schedule"], heap_policy="annotate", case_dir="{case_dir}")`.
   `heap_policy="mask"` keeps only hits inside one chunk's user data. Every hit has `addr` + `space` +
   `location`; check `coverage` (a structure straddling a capture gap is never found in invented zeros) and
   `truncated`. Hits become the `key_hits` case table: join to `heap_chunks` / `msl_regions` with `case_query`.
6. Verify - a hit is a CANDIDATE, not a key. `verify(dump_path=..., offset=..., ciphertext_hex=..., cipher=...,
   iv_hex=...)` tests a candidate against known ciphertext; for TLS use `inspect_pcap(pcap_path=...)` and
   `locate_key(dump_paths=[...], key_hex=...)` / `brute_force(candidates_path=..., oracle_path=..., ...)` with the
   candidates the scan produced (`candidates_out`). Report the verification result, never the raw hit count alone.
7. Highlight: `keyfinders_scan(..., annotate=true)` files `key_hit` annotations; add context with
   `annotations_add(...)`.
{_ERRORS}
{_SANDBOX}"""


def _n_image_variance(corpus_dir: Optional[str]) -> str:
    corpus = _arg(corpus_dir, "<CORPUS_DIR>")
    return f"""Playbook: variance across N dumps from `{corpus}`.

1. Inventory: `scan_dataset(dataset_root="{corpus}")` -> protocols/libraries/phases; `list_phases(library_dir=...)`.
   Each run's `meta.json` may declare a `cohort` (e.g. library+workload); a mix of cohorts is refused
   with `code=cohort.mixed` unless `mixed_ok=true`. Do NOT set `mixed_ok` to silence the refusal - build one
   consensus per cohort with `group_by="cohort"`.
2. Pre-check each dump: `get_session_info(msl_path=...)` / `detect_format(dump_path=...)`. `.msl` captures
   with a VA view align automatically across dumps; raw dumps do not.
3. Consensus: `consensus(dump_paths=[...], output_dir=<NEW dir>, group_by="cohort")` -> `variance_path`,
   `reference_path`, `num_dumps`. Large inputs are refused with `memory_budget_exceeded` unless `force_memory=true`.
4. Where do values differ? `consensus_regions(dump_paths=[...], classes=[...], sort=..., limit=...)` pages every
   occurrence of a variance class with a navigable offset; `aligned_window(dump_paths=[...], offset=..., length=...)`
   reads ONE window in EVERY dump at the aligned address (never apply a coordinate yourself).
5. Anchor consensus - heap objects are not at the same address per run, so flat consensus is wrong around them:
   anchor each dump on a verified value (a key you located with `locate_key(dump_paths=[...], key_hex=...)`) and
   compare windows at `anchor+delta`: `anchor_consensus(needles={{<dump>: <hex>}}, dump_paths=[...],
   delta_start=-64, length=256)`. Classes are keyed by delta; `UNDETERMINED` means fewer than `min_instances`
   dumps held captured bytes there - not "constant". Several occurrences per dump are ALTERNATIVES
   (`occurrence=N`), never merged.
6. Who points here? `xref_pointers(dump_path=..., target_va=...)` lists captured words pointing at an address,
   with coverage.
7. Next: turn a stable layout into a reusable model with `object_model_from_keylog`, or emit a pattern with
   `export_pattern(dump_paths=[...], output_dir=...)` / `emit_plugin(...)`.
{_ERRORS}
{_SANDBOX}"""


def _object_model(corpus_dir: Optional[str], keylog: Optional[str]) -> str:
    corpus = _arg(corpus_dir, "<CORPUS_DIR>")
    keylog_path = _arg(keylog, "<KEYLOG>")
    return f"""Playbook: object model from a key log (dumps in `{corpus}`, NSS key log `{keylog_path}`).

REQUIREMENTS: the dumps must be `.msl` captures with a VA view (raw dumps are refused with an import hint -
`import_raw_dump(raw_path=..., output_path=<NEW .msl>)` first). HELD-OUT means disjoint runs: the validation
dumps must NOT be among the learning dumps (the tool refuses a leak with `semantic.held_out_leak`).
Split the runs first, e.g. learn on runs 1-8, validate on runs 9-16.

1. Anchors: `anchor_consensus(dump_paths=[<learning dumps>], keylog={{"path": "{keylog_path}"}})`
   (leave `anchor_label` unset = auto: `CLIENT_TRAFFIC_SECRET_0`, else the TLS 1.2 master secret; set it to force one label). Read `keylog_resolution`:
   each dump must resolve to ITS session (the one whose secret is present); absent or ambiguous dumps are
   reported unanchored with a reason - never guessed. When each run directory holds its OWN key log (the usual
   experiment layout: `<run>/dumps/msl/*.msl` + a key log file in `<run>/`), pass per-dump key logs:
   `keylog={{"per_dump": {{<dump>: <keylog>}}}}`; a single concatenated log works as `{{"path": ...}}` too.
   Check `suggested_meanings`.
2. Layout: `propose_layout(dump_paths=[<learning dumps>], keylog={{"path": "{keylog_path}"}}, heap=true)` proposes
   field boundaries around the anchor from variance classes, pointer-likeness and (with `heap`) allocator chunk
   bounds, with alternatives preserved. Review `fields` and their `evidence`.
3. Build: `artifact_model_build(name="<model>", out_path=<NEW .json>, dump_paths=[<learning dumps>],
   keylog={{"path": "{keylog_path}"}})`. With `meanings`/`relationships` omitted they default from the key log
   (each secret labelled with its NSS label, `owned_by` client_random). Naming an unproposed field is refused.
   The result carries `path` and `sha256`; never overwrite - use a new `out_path` per build.
4. Export: `artifact_model_export(model_path=<model .json>, out_path=<NEW .py>)` writes a Volatility 3 plugin
   (the model must pass its own consistency check; volatility3 itself is not needed to export).
5. Validate on HELD-OUT dumps: `artifact_model_validate(model_path=..., held_out=[{{"dump_path": <held-out>,
   "keylog_path": "{keylog_path}"}}], out_path=<NEW .json>)`, or pass a shared `keylog={{"path": ...}}`. The
   EXPECTED set of a capture = the key-log sessions whose asserted secrets are actually PRESENT in it (exact
   search, independent of the plugin; secrets not in memory are reported `not_in_memory`, never counted as FN);
   a capture with no such session is `indeterminate`. Needs the volatility3 extra.
6. Read the verdict: `totals` (expected / tp / fp / fn / relationships) and `verdict`. A capture passes only when exact (all expected found, no false positive, every
   relationship right); one failing capture fails the set; `indeterminate` captures prove nothing. Report held-out numbers only - the learning dumps'
   numbers are circular.
7. Robustness: read the model's `warnings` (also echoed in the validation payload) and `window_redundancy`.
   The plugin matches a primary prefilter window OR its alternatives (column `Windows`); a
   `prefilter.low_information` warning means the primary rests on a few literal bytes - if
   `tps_found_by_multiple_windows` is below `tp_total`, some hits depend on ONE window, and a different
   workload/platform may miss them. Same-cohort held-out runs cannot reveal that; say so in your report.
{_ERRORS}
{_SANDBOX}"""


def _code_evidence(image_path: Optional[str], function: Optional[str]) -> str:
    image = _arg(image_path, "<IMAGE>")
    func = _arg(function, "__x64_sys_getuid")
    return f"""Playbook: code evidence for kernel function `{func}` in `{image}`.

REQUIREMENT: a FULL kernel image with kallsyms and a VERIFIED init_task + page-table root (pakunoda's
`find_init_task`). Without them reads are refused (`code_evidence.image_reads_failed`) - the tool never guesses.

1. `isf_probe(image_path="{image}", probe="init_task")` and `probe="page_table_root"` - confirm they verify.
2. `code_evidence(image_path="{image}", function="{func}")` - `function` is a kallsyms name or a `0x` VA. It decodes
   the body and returns one `kernel_va` Location per access with its symbolic base (pakunoda keys, verbatim): current, arg0,
   static(sym), deref(current+0x678). A declining architecture shows in `coverage.declined`, never as an
   empty success. Session setup is slow (~35 s the first time).
3. Join to an ISF: `code_evidence(image_path="{image}", function="{func}", isf=<ISF path>, base="current")` matches
   `current`-based accesses against `task_struct` members. Real example: `__x64_sys_getuid` -> current+0x678 =
   task_struct.cred, deref +4 = cred.uid.
4. Use it as support for ISF claims: cite each matched access as `evidence` in `isf_draft_set(...)` (see
   `isf_workbench`), and prefer offsets that two independent functions agree on.
5. Trap: only `current`-based accesses join to task_struct; `arg0`-based accesses are reported but not joined.
{_ERRORS}
{_SANDBOX}"""


def register_prompts(mcp) -> None:
    """Register the playbook prompts on an ``MCPServer`` instance."""

    @mcp.prompt(name="memdiver_start",
                description="What MemDiver is, the playbooks, the resources and the conventions.")
    def memdiver_start() -> str:
        return _start()

    @mcp.prompt(name="vol3_inside_memdiver",
                description="Open a memory image, resolve a profile, run Volatility 3 plugins, query and annotate rows.")
    def vol3_inside_memdiver(image_path: Optional[str] = None, case: Optional[str] = None) -> str:
        return _vol3_inside(image_path, case)

    @mcp.prompt(name="vol3_plugin_dev",
                description="Scaffold, store, check, run and fixture-test a Volatility 3 plugin in a case.")
    def vol3_plugin_dev(case: Optional[str] = None, view_path: Optional[str] = None) -> str:
        return _plugin_dev(case, view_path)

    @mcp.prompt(name="isf_workbench",
                description="Hand-build an ISF kernel profile: probes, draft ops, isf_try with a ground-truth diff.")
    def isf_workbench(image_path: Optional[str] = None, case: Optional[str] = None,
                      draft: Optional[str] = None) -> str:
        return _isf_workbench(image_path, case, draft)

    @mcp.prompt(name="image_to_process_keys",
                description="Process -> .msl -> heap -> key finders -> oracle verification.")
    def image_to_process_keys(image_path: Optional[str] = None, case: Optional[str] = None,
                              pid: Optional[str] = None) -> str:
        return _image_to_keys(image_path, case, pid)

    @mcp.prompt(name="n_image_variance",
                description="Cohorts, consensus and anchor consensus across N dumps.")
    def n_image_variance(corpus_dir: Optional[str] = None) -> str:
        return _n_image_variance(corpus_dir)

    @mcp.prompt(name="object_model_from_keylog",
                description="Key log -> layout -> artifact model -> exported plugin -> held-out validation.")
    def object_model_from_keylog(corpus_dir: Optional[str] = None, keylog: Optional[str] = None) -> str:
        return _object_model(corpus_dir, keylog)

    @mcp.prompt(name="code_evidence",
                description="Which struct fields does a kernel function touch, joined to an ISF.")
    def code_evidence(image_path: Optional[str] = None, function: Optional[str] = None) -> str:
        return _code_evidence(image_path, function)
