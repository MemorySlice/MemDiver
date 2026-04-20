"""Session metadata navigator view."""

import logging
from typing import Any

from ui.components.html_builder import format_size as _format_size

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
        return mo.md("*No session data available.*")

    sections = []

    # -- Process Info --
    info_rows = [
        _info_row("Dump UUID", str(report.dump_uuid), cs),
        _info_row("PID", str(report.pid), cs),
        _info_row("OS", report.os_type, cs),
        _info_row("Architecture", report.arch_type, cs),
        _info_row("Timestamp", report.timestamp_iso, cs),
    ]
    if report.process_identity:
        pi = report.process_identity
        info_rows.extend([
            _info_row("Parent PID", str(pi.ppid), cs),
            _info_row("Session ID", str(pi.session_id), cs),
            _info_row("Executable", f"<code>{pi.exe_path}</code>", cs),
            _info_row("Command Line", f"<code>{pi.cmd_line}</code>", cs),
        ])
    sections.append(
        f'<div class="memdiver-header">Process Info</div>'
        f'<table style="border-collapse:collapse;">{"".join(info_rows)}</table>'
    )

    # -- Summary Stats --
    stats_rows = [
        _info_row("Memory Regions", str(report.region_count), cs),
        _info_row("Total Region Size", _format_size(report.total_region_size), cs),
        _info_row("Captured Pages", str(report.captured_page_count), cs),
        _info_row("Captured Size", _format_size(report.total_captured_bytes), cs),
        _info_row("Key Hints", str(report.key_hint_count), cs),
        _info_row("VAS Entries", str(len(report.vas_entries)), cs),
    ]
    sections.append(
        f'<div class="memdiver-header" style="margin-top:12px;">Summary</div>'
        f'<table style="border-collapse:collapse;">{"".join(stats_rows)}</table>'
    )

    # -- Module List --
    if report.modules:
        th = f'padding:4px 10px;color:{cs.TEXT_SECONDARY};text-align:left;'
        mod_hdr = (
            f'<tr><th style="{th}">Base Address</th>'
            f'<th style="{th}text-align:right;">Size</th>'
            f'<th style="{th}">Path</th>'
            f'<th style="{th}">Version</th></tr>'
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
            f'Modules ({len(report.modules)})</div>'
            f'<table style="border-collapse:collapse;width:100%;">'
            f'<thead>{mod_hdr}</thead>'
            f'<tbody>{"".join(mod_rows)}</tbody></table>'
        )

    # -- Related Dumps --
    if report.related_dumps:
        th = f'padding:4px 10px;color:{cs.TEXT_SECONDARY};text-align:left;'
        rel_hdr = (
            f'<tr><th style="{th}">Dump UUID</th>'
            f'<th style="{th}text-align:right;">PID</th>'
            f'<th style="{th}text-align:right;">Relationship</th></tr>'
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
            f'Related Dumps ({len(report.related_dumps)})</div>'
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
