"""Session metadata navigator view."""

import logging
from typing import Any

from ui.components.html_builder import format_size as _format_size
from ui.locales import _

logger = logging.getLogger("memdiver.ui.views.session_view")


def _info_row(label: str, value: str, cs) -> str:
    """Build a single key-value info row."""
    return (
        f'<tr><td style="padding:4px 12px 4px 0;color:{cs.TEXT_SECONDARY};'
        f'white-space:nowrap;">{label}</td>'
        f'<td style="padding:4px 0;color:{cs.TEXT_PRIMARY};">{value}</td></tr>'
    )


def render_session_view(mo, report) -> Any:
    """Render session info panel with process, modules, and dump metadata.

    Args:
        mo: marimo module.
        report: SessionReport from msl.session_extract.

    Returns:
        mo.Html with the rendered session navigator.
    """
    from ui.components import color_scheme as cs

    if report is None:
        return mo.md(_("*No session data available.*"))

    sections = []

    # -- Process Info --
    info_rows = [
        _info_row(_("Dump UUID"), str(report.dump_uuid), cs),
        _info_row(_("PID"), str(report.pid), cs),
        _info_row(_("OS"), report.os_type, cs),
        _info_row(_("Architecture"), report.arch_type, cs),
        _info_row(_("Timestamp"), report.timestamp_iso, cs),
    ]
    if report.process_identity:
        pi = report.process_identity
        info_rows.extend([
            _info_row(_("Parent PID"), str(pi.ppid), cs),
            _info_row(_("Session ID"), str(pi.session_id), cs),
            _info_row(_("Executable"), f"<code>{pi.exe_path}</code>", cs),
            _info_row(_("Command Line"), f"<code>{pi.cmd_line}</code>", cs),
        ])
    sections.append(
        f'<div class="memdiver-header">{_("Process Info")}</div>'
        f'<table style="border-collapse:collapse;">{"".join(info_rows)}</table>'
    )

    # -- Summary Stats --
    stats_rows = [
        _info_row(_("Memory Regions"), str(report.region_count), cs),
        _info_row(_("Total Region Size"), _format_size(report.total_region_size), cs),
        _info_row(_("Captured Pages"), str(report.captured_page_count), cs),
        _info_row(_("Captured Size"), _format_size(report.total_captured_bytes), cs),
        _info_row(_("Key Hints"), str(report.key_hint_count), cs),
        _info_row(_("VAS Entries"), str(len(report.vas_entries)), cs),
    ]
    sections.append(
        f'<div class="memdiver-header" style="margin-top:12px;">{_("Summary")}</div>'
        f'<table style="border-collapse:collapse;">{"".join(stats_rows)}</table>'
    )

    # -- Module List --
    if report.modules:
        th = f'padding:4px 10px;color:{cs.TEXT_SECONDARY};text-align:left;'
        mod_hdr = (
            f'<tr><th style="{th}">{_("Base Address")}</th>'
            f'<th style="{th}text-align:right;">{_("Size")}</th>'
            f'<th style="{th}">{_("Path")}</th>'
            f'<th style="{th}">{_("Version")}</th></tr>'
        )
        mod_rows = []
        for m in report.modules:
            mod_rows.append(
                f'<tr>'
                f'<td style="padding:3px 10px;color:{cs.ACCENT_CYAN};'
                f'font-family:monospace;">0x{m.base_addr:X}</td>'
                f'<td style="padding:3px 10px;color:{cs.TEXT_PRIMARY};'
                f'text-align:right;">{_format_size(m.module_size)}</td>'
                f'<td style="padding:3px 10px;color:{cs.TEXT_PRIMARY};">'
                f'{m.path}</td>'
                f'<td style="padding:3px 10px;color:{cs.TEXT_MUTED};">'
                f'{m.version or "—"}</td></tr>'
            )
        sections.append(
            f'<div class="memdiver-header" style="margin-top:12px;">'
            + _("Modules ({count})").format(count=len(report.modules)) + '</div>'
            f'<table style="border-collapse:collapse;width:100%;">'
            f'<thead>{mod_hdr}</thead>'
            f'<tbody>{"".join(mod_rows)}</tbody></table>'
        )

    # -- Related Dumps --
    if report.related_dumps:
        th = f'padding:4px 10px;color:{cs.TEXT_SECONDARY};text-align:left;'
        rel_hdr = (
            f'<tr><th style="{th}">{_("Dump UUID")}</th>'
            f'<th style="{th}text-align:right;">{_("PID")}</th>'
            f'<th style="{th}text-align:right;">{_("Relationship")}</th></tr>'
        )
        rel_rows = []
        for rd in report.related_dumps:
            rel_rows.append(
                f'<tr>'
                f'<td style="padding:3px 10px;color:{cs.ACCENT_CYAN};'
                f'font-family:monospace;">{rd.related_dump_uuid}</td>'
                f'<td style="padding:3px 10px;color:{cs.TEXT_PRIMARY};'
                f'text-align:right;">{rd.related_pid}</td>'
                f'<td style="padding:3px 10px;color:{cs.TEXT_PRIMARY};'
                f'text-align:right;">{rd.relationship}</td></tr>'
            )
        sections.append(
            f'<div class="memdiver-header" style="margin-top:12px;">'
            + _("Related Dumps ({count})").format(count=len(report.related_dumps)) + '</div>'
            f'<table style="border-collapse:collapse;width:100%;">'
            f'<thead>{rel_hdr}</thead>'
            f'<tbody>{"".join(rel_rows)}</tbody></table>'
        )

    html = (
        f'{cs.BASE_CSS}'
        f'<div class="memdiver-panel">'
        + "".join(sections)
        + '</div>'
    )
    return mo.Html(html)
