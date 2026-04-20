"""MSL block navigator — grouped collapsible view of block types."""

import logging
from typing import Any, Dict, List

logger = logging.getLogger("memdiver.ui.views.block_navigator")


def render_block_navigator(mo, reader, selected_type: str = "") -> Any:
    """Render grouped block navigator for an MSL file.

    Args:
        mo: The marimo runtime module.
        reader: An opened MslReader instance.
        selected_type: Block type name to show details for.

    Returns:
        A marimo layout element with block tree and detail panel.
    """
    from msl.block_tree import list_blocks, group_blocks

    nodes = list_blocks(reader)
    if not nodes:
        return mo.callout(mo.md("No blocks found in MSL file."), kind="warn")

    groups = group_blocks(nodes)

    # Build summary HTML
    summary_parts = []
    total = len(nodes)
    summary_parts.append(f"<div style='font-size:13px; color:#808080; margin-bottom:8px;'>"
                         f"{total} blocks total</div>")

    for cat, cat_nodes in groups.items():
        type_counts: Dict[str, int] = {}
        for n in cat_nodes:
            type_counts[n.type_name] = type_counts.get(n.type_name, 0) + 1

        badge = "capture" if cat_nodes[0].is_capture_time else "structural"
        badge_color = "#4A90D9" if badge == "capture" else "#808080"

        lines = []
        for tname, count in type_counts.items():
            lines.append(f"  <div style='padding:2px 0 2px 16px; font-size:13px;'>"
                         f"{tname} ({count})</div>")

        summary_parts.append(
            f"<details open>"
            f"<summary style='cursor:pointer; font-weight:600; padding:4px 0;'>"
            f"{cat} "
            f"<span style='font-size:11px; color:{badge_color};'>[{badge}]</span>"
            f"</summary>"
            f"{''.join(lines)}"
            f"</details>"
        )

    tree_html = "<div style='font-family:monospace;'>" + "".join(summary_parts) + "</div>"

    # Build detail tables for each block type
    detail_sections = {}
    for cat, cat_nodes in groups.items():
        type_groups: Dict[str, list] = {}
        for n in cat_nodes:
            type_groups.setdefault(n.type_name, []).append(n)

        for tname, tnodes in type_groups.items():
            rows = []
            for n in tnodes:
                rows.append(
                    f"<tr><td style='font-family:monospace;'>0x{n.file_offset:08X}</td>"
                    f"<td>{n.payload_size:,} B</td>"
                    f"<td style='font-family:monospace; font-size:11px;'>"
                    f"{n.block_uuid[:12]}...</td></tr>"
                )
            table = (
                f"<table style='width:100%; border-collapse:collapse; font-size:13px;'>"
                f"<tr style='border-bottom:1px solid #ddd;'>"
                f"<th align='left'>Offset</th><th align='left'>Size</th>"
                f"<th align='left'>UUID</th></tr>"
                f"{''.join(rows)}</table>"
            )
            detail_sections[f"{tname} ({len(tnodes)})"] = mo.Html(table)

    # Render decoded block data for known types
    _add_decoded_sections(mo, reader, detail_sections)

    details_accordion = mo.accordion(detail_sections, lazy=True)

    return mo.vstack([
        mo.Html(tree_html),
        mo.md("---"),
        details_accordion,
    ])


def _add_decoded_sections(mo, reader, sections: dict) -> None:
    """Add decoded block content for specific types."""
    try:
        # Key hints
        hints = reader.collect_key_hints()
        if hints:
            rows = []
            for h in hints:
                from msl.enums import MslKeyType, MslProtocol
                try:
                    kt = MslKeyType(h.key_type).name
                except ValueError:
                    kt = str(h.key_type)
                try:
                    pr = MslProtocol(h.protocol).name
                except ValueError:
                    pr = str(h.protocol)
                rows.append(
                    f"<tr><td>0x{h.region_offset:X}</td><td>{h.key_length}</td>"
                    f"<td>{kt}</td><td>{pr}</td>"
                    f"<td>{h.confidence}</td></tr>"
                )
            html = (
                "<table style='width:100%; border-collapse:collapse; font-size:13px;'>"
                "<tr style='border-bottom:1px solid #ddd;'>"
                "<th align='left'>Offset</th><th align='left'>Length</th>"
                "<th align='left'>Type</th><th align='left'>Protocol</th>"
                "<th align='left'>Confidence</th></tr>"
                f"{''.join(rows)}</table>"
            )
            sections["Key Hints (decoded)"] = mo.Html(html)
    except Exception:
        pass

    try:
        # Modules
        modules = reader.collect_modules()
        if modules:
            rows = []
            for m in modules:
                rows.append(
                    f"<tr><td style='font-family:monospace;'>0x{m.base_addr:X}</td>"
                    f"<td>{m.module_size:,}</td>"
                    f"<td>{m.path}</td>"
                    f"<td>{m.version}</td></tr>"
                )
            html = (
                "<table style='width:100%; border-collapse:collapse; font-size:13px;'>"
                "<tr style='border-bottom:1px solid #ddd;'>"
                "<th align='left'>Base</th><th align='left'>Size</th>"
                "<th align='left'>Path</th><th align='left'>Version</th></tr>"
                f"{''.join(rows)}</table>"
            )
            sections["Modules (decoded)"] = mo.Html(html)
    except Exception:
        pass

    # -- MSL-Decoders-02: new spec-defined table decoders --
    try:
        mli_tables = reader.collect_module_list_index()
        mli_entries = [e for t in mli_tables for e in t.entries]
        if mli_entries:
            rows = [
                f"<tr><td style='font-family:monospace;'>{str(e.module_uuid)[:8]}</td>"
                f"<td style='font-family:monospace;'>0x{e.base_addr:X}</td>"
                f"<td>{e.module_size:,}</td><td>{e.path}</td></tr>"
                for e in mli_entries
            ]
            sections[f"Module Index ({len(mli_entries)})"] = mo.Html(
                "<table style='width:100%; border-collapse:collapse; font-size:13px;'>"
                "<tr style='border-bottom:1px solid #ddd;'>"
                "<th align='left'>UUID</th><th align='left'>Base</th>"
                "<th align='left'>Size</th><th align='left'>Path</th></tr>"
                f"{''.join(rows)}</table>"
            )
    except Exception:
        pass

    try:
        ptables = reader.collect_processes()
        procs = [e for t in ptables for e in t.entries]
        if procs:
            rows = [
                f"<tr><td>{p.pid}</td><td>{p.ppid}</td><td>{p.uid}</td>"
                f"<td>{'✓' if p.is_target else ''}</td>"
                f"<td style='font-family:monospace;'>{p.exe_name}</td>"
                f"<td>{p.cmd_line}</td><td>{p.user}</td></tr>"
                for p in procs
            ]
            sections[f"Processes ({len(procs)})"] = mo.Html(
                "<table style='width:100%; border-collapse:collapse; font-size:13px;'>"
                "<tr style='border-bottom:1px solid #ddd;'>"
                "<th align='left'>PID</th><th align='left'>PPID</th>"
                "<th align='left'>UID</th><th align='left'>Target</th>"
                "<th align='left'>Exe</th><th align='left'>Cmd</th>"
                "<th align='left'>User</th></tr>"
                f"{''.join(rows)}</table>"
            )
    except Exception:
        pass

    try:
        ctables = reader.collect_connections()
        conns = [e for t in ctables for e in t.entries]
        if conns:
            import ipaddress

            def _fmt_addr(family: int, raw: bytes) -> str:
                try:
                    if family == 0x02:
                        return str(ipaddress.IPv4Address(bytes(raw[:4])))
                    if family == 0x0A:
                        return str(ipaddress.IPv6Address(bytes(raw[:16])))
                except (ValueError, ipaddress.AddressValueError):
                    pass
                return raw[:16].hex()

            rows = [
                f"<tr><td>{c.pid}</td>"
                f"<td>{'v4' if c.family == 0x02 else 'v6' if c.family == 0x0A else hex(c.family)}</td>"
                f"<td>{'TCP' if c.protocol == 0x06 else 'UDP' if c.protocol == 0x11 else hex(c.protocol)}</td>"
                f"<td style='font-family:monospace;'>{_fmt_addr(c.family, c.local_addr)}:{c.local_port}</td>"
                f"<td style='font-family:monospace;'>{_fmt_addr(c.family, c.remote_addr)}:{c.remote_port}</td></tr>"
                for c in conns
            ]
            sections[f"Connections ({len(conns)})"] = mo.Html(
                "<table style='width:100%; border-collapse:collapse; font-size:13px;'>"
                "<tr style='border-bottom:1px solid #ddd;'>"
                "<th align='left'>PID</th><th align='left'>Family</th>"
                "<th align='left'>Protocol</th>"
                "<th align='left'>Local</th><th align='left'>Remote</th></tr>"
                f"{''.join(rows)}</table>"
            )
    except Exception:
        pass

    try:
        htables = reader.collect_handles()
        handles = [e for t in htables for e in t.entries]
        if handles:
            _HT = {0x00: "Unknown", 0x01: "File", 0x02: "Directory",
                   0x03: "Socket", 0x04: "Pipe", 0x05: "Device",
                   0x06: "Registry", 0xFF: "Other"}
            rows = [
                f"<tr><td>{h.pid}</td><td>{h.fd}</td>"
                f"<td>{_HT.get(h.handle_type, 'Unknown')}</td>"
                f"<td style='font-family:monospace;'>{h.path}</td></tr>"
                for h in handles
            ]
            sections[f"Handles ({len(handles)})"] = mo.Html(
                "<table style='width:100%; border-collapse:collapse; font-size:13px;'>"
                "<tr style='border-bottom:1px solid #ddd;'>"
                "<th align='left'>PID</th><th align='left'>FD</th>"
                "<th align='left'>Type</th><th align='left'>Path</th></tr>"
                f"{''.join(rows)}</table>"
            )
    except Exception:
        pass

    # -- Speculative/incomplete decoders (spec §4.3 reserved / §6.2 incomplete) --
    _RESERVED_BADGE = (
        "<span style='font-size:10px; padding:2px 6px; background:#D97706; "
        "color:white; border-radius:3px;'>SPEC RESERVED</span>"
    )
    _INCOMPLETE_BADGE = (
        "<span style='font-size:10px; padding:2px 6px; background:#DC2626; "
        "color:white; border-radius:3px;'>INCOMPLETE</span>"
    )
    _SPEC_BADGE = (
        "<span style='font-size:10px; padding:2px 6px; background:#16A34A; "
        "color:white; border-radius:3px;'>SPEC §6.2</span>"
    )

    _ext_specs = [
        ("collect_thread_contexts", "Thread Contexts", _RESERVED_BADGE),
        ("collect_file_descriptors", "File Descriptors", _RESERVED_BADGE),
        ("collect_network_connections", "Net Connections (0x0013)", _RESERVED_BADGE),
        ("collect_environment_blocks", "Environment Blocks", _RESERVED_BADGE),
        ("collect_security_tokens", "Security Tokens", _RESERVED_BADGE),
        ("collect_system_context", "System Context", _SPEC_BADGE),
    ]
    for method_name, title, badge in _ext_specs:
        try:
            blocks = getattr(reader, method_name)()
            if not blocks:
                continue
            sections[f"{title} [speculative]"] = mo.Html(
                f"<div>{badge}<p style='font-size:11px; color:#808080; margin:4px 0;'>"
                f"{len(blocks)} block(s). Layout is speculative — see decoders_ext.py warning."
                f"</p></div>"
            )
        except Exception:
            pass
