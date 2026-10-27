"""MemDiver case explorer: a marimo notebook for analysts.

Open it with ``memdiver notebook <case>`` (needs the ``marimo`` extra). The case
comes from ``--case <dir>`` after ``--`` or from the ``MEMDIVER_CASE``
environment variable. It is an analyst companion, not a parity surface.
"""

import marimo

__generated_with = "0.24.0"
app = marimo.App(width="medium")


@app.cell
def _():
    import marimo as mo

    import memdiver
    from memdiver.ui.notebooks import case_explorer_data as data
    return data, memdiver, mo


@app.cell
def _(data, memdiver, mo):
    case_ref = data.case_arg(mo.cli_args())
    case = None
    if case_ref is None:
        mo.output.replace(mo.md("**No case given.** Start with "
                                "`memdiver notebook <case>` or set `MEMDIVER_CASE`."))
    else:
        try:
            case = memdiver.open_case(case_ref)
        except Exception as exc:  # shown to the analyst, not raised
            mo.output.replace(mo.md(f"**Cannot open case `{case_ref}`:** {exc}"))
    return (case,)


@app.cell
def _(case, mo):
    mo.stop(case is None)
    manifest = case.manifest()
    mo.md(f"## Case `{case.name}`\n\nDirectory: `{case.dir}`\n\n"
          f"Created: {manifest.get('created', 'unknown')} "
          f"(manifest version {manifest.get('v', '?')})")
    return


@app.cell
def _(case, data, mo):
    mo.stop(case is None)
    _rows = data.table_rows(case)
    mo.vstack([mo.md("## Tables and runs"),
               mo.ui.table(_rows, selection=None) if _rows
               else mo.md("This case has no tables yet.")])
    return


@app.cell
def _(case, mo):
    mo.stop(case is None)
    sql_editor = mo.ui.code_editor(
        value="SELECT pid, ppid, comm FROM vol3__linux_pslist LIMIT 20",
        language="sql", label="SQL (read-only)")
    run_sql = mo.ui.run_button(label="Run query")
    mo.vstack([mo.md("## SQL"), sql_editor, run_sql])
    return run_sql, sql_editor


@app.cell
def _(case, mo, run_sql, sql_editor):
    mo.stop(case is None or not run_sql.value)
    try:
        _result = case.query(sql_editor.value, limit=1000).to_dict(max_rows=1000)
        _note = "Result was truncated." if _result["truncated"] else "Complete result."
        mo.output.replace(mo.vstack([
            mo.md(f"{len(_result['rows'])} rows. {_note}"),
            mo.ui.table([dict(zip(_result["columns"], r)) for r in _result["rows"]],
                        selection=None)]))
    except Exception as exc:
        mo.output.replace(mo.md(f"**Query refused or failed:** {exc}"))
    return


@app.cell
def _(case, data, mo):
    mo.stop(case is None)
    tree = data.process_tree(case)
    if tree["message"]:
        mo.output.replace(mo.md(f"## Process tree\n\n{tree['message']}"))
    else:
        _lines = data.tree_lines(tree)
        _note = (f"\n\n**Truncated:** the query cap of {data.PSLIST_ROW_LIMIT:,} rows was "
                 "hit, so this tree is incomplete." if tree["truncated"] else "")
        mo.output.replace(mo.vstack([
            mo.md(f"## Process tree\n\nLatest pslist run `{tree['run_id']}`: "
                  f"{len(tree['roots'])} root(s), {len(tree['nodes'])} processes."
                  f"{_note}"),
            mo.ui.table(_lines, selection=None, page_size=25)]))
    return (tree,)


@app.cell
def _(mo, tree):
    mo.stop(not tree["nodes"])
    pick = mo.ui.dropdown(
        {f"{n['pid']}  {n['comm']}": pid for pid, n in tree["nodes"].items()},
        value=None, label="Process for hex context")
    mo.vstack([mo.md("## Hex context"), pick])
    return (pick,)


@app.cell
def _(case, data, mo, pick, tree):
    mo.stop(case is None or pick.value is None)
    _node = tree["nodes"][pick.value]
    _views = data.kernel_view_paths(case.dir)
    _ctx = data.context_for_row(case.dir, _node, _views[0] if _views else None)
    mo.vstack([
        mo.md(f"`{_node['comm']}` task struct at `{hex(_node['offset_v'])}`. "
              "Bytes shown as `--` were not captured."),
        mo.ui.table(_ctx["layers"], selection=None) if _ctx["layers"]
        else mo.md("No case rows contain this address."),
        mo.md(f"```\n{_ctx['dump']}\n```")])
    return


if __name__ == "__main__":
    app.run()
