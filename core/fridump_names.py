"""Best-effort region names + protections for fridump chunks.

fridump writes only ``<base>_dump.data`` chunks: no names, no protections.
To build an honest ``.maps`` sidecar we look the target's mappings up
separately and annotate every chunk from the mapping(s) it lies in:

1. local Linux pid: read ``/proc/<pid>/maps`` directly (``proc_maps``);
2. otherwise (Android / remote / by name / macOS) attach a short Frida
   session to the same target and, inside the target, read
   ``/proc/self/maps`` (Linux/Android: ``proc_maps``) or fall back to
   ``Process.enumerateRanges`` file paths + protections (``frida_ranges``);
3. nothing available: chunks keep the conservative read-only perm, no name
   (``none``) -- the capture manifest records that so a preview can warn.
"""
from __future__ import annotations

import bisect
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from memdiver.core.capture_manifest import (NAMES_FRIDA_RANGES, NAMES_NONE,
                                            NAMES_PROC_MAPS)
from memdiver.core.capture_target import CaptureDevice, CaptureTarget
from memdiver.core.proc_maps_parser import parse_maps_text

logger = logging.getLogger("memdiver.core.fridump_names")


@dataclass(frozen=True, order=True)
class NamedSpan:
    """One target mapping: ``[start, end)`` with a 4-char perm and a name."""

    start: int
    end: int
    perm: str
    name: str = ""


_FRIDA_MAPS_SCRIPT = """\
function readMaps() {
    if (Process.platform !== 'linux') return '';
    try { return File.readAllText('/proc/self/maps'); } catch (e) {}
    try {
        var f = new File('/proc/self/maps', 'r'), out = '', chunk;
        if (typeof f.readText !== 'function') { f.close(); return ''; }
        while ((chunk = f.readText(65536)) !== '') out += chunk;
        f.close();
        return out;
    } catch (e) { return ''; }
}
rpc.exports = {
    readMaps: readMaps,
    ranges: function () {
        return Process.enumerateRanges('---').map(function (r) {
            return [r.base.toString(), r.size, r.protection,
                    r.file ? r.file.path : ''];
        });
    }
};
"""


def spans_from_maps_text(text: str) -> List[NamedSpan]:
    return sorted(NamedSpan(r.start, r.end, _perm4(r.perm), r.path)
                  for r in parse_maps_text(text))


def spans_from_frida_ranges(ranges: Sequence) -> List[NamedSpan]:
    """``[[base_str, size, 'rw-', path], ...]`` -> sorted spans."""
    spans = []
    for base, size, prot, path in ranges:
        start = int(str(base), 16) if str(base).startswith("0x") else int(base)
        spans.append(NamedSpan(start, start + int(size), _perm4(prot), path or ""))
    return sorted(spans)


def _perm4(prot: str) -> str:
    prot = (prot or "---")[:4].ljust(3, "-")
    return prot if len(prot) == 4 else prot + "p"


def read_local_proc_maps(pid: int) -> Optional[str]:
    """``/proc/<pid>/maps`` text on Linux, else ``None``."""
    if not sys.platform.startswith("linux"):
        return None
    try:
        return Path(f"/proc/{pid}/maps").read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.info("cannot read /proc/%d/maps: %s", pid, exc)
        return None


def frida_device(device: CaptureDevice):
    """The Frida device for *device* (mirrors memslicer's ``_get_frida_device``)."""
    import frida  # optional dependency

    if device.kind == "usb":
        if device.device_id:
            return frida.get_device(device.device_id, timeout=5)
        return frida.get_usb_device(timeout=5)
    if device.kind == "remote":
        addr = device.remote_addr
        if ":" not in addr:
            addr = f"{addr}:27042"
        return frida.get_device_manager().add_remote_device(addr)
    return frida.get_local_device()


def frida_target_spans(target: CaptureTarget) -> Tuple[List[NamedSpan], str]:
    """Attach briefly via Frida and return ``(spans, names_source)``."""
    session = frida_device(target.device).attach(
        target.pid if target.pid is not None else target.name)
    try:
        script = session.create_script(_FRIDA_MAPS_SCRIPT)
        script.load()
        text = script.exports_sync.read_maps()
        if text:
            return spans_from_maps_text(text), NAMES_PROC_MAPS
        return spans_from_frida_ranges(script.exports_sync.ranges()), NAMES_FRIDA_RANGES
    finally:
        session.detach()


def collect_target_spans(target: CaptureTarget) -> Tuple[List[NamedSpan], str]:
    """Best-effort mappings of *target*; ``([], "none")`` when unavailable."""
    if target.device.is_local and target.pid is not None:
        text = read_local_proc_maps(target.pid)
        if text:
            return spans_from_maps_text(text), NAMES_PROC_MAPS
    try:
        spans, source = frida_target_spans(target)
    except Exception as exc:  # noqa: BLE001 - frida missing / attach refused
        logger.info("fridump: no region names for %s (%s)", target.label, exc)
        return [], NAMES_NONE
    return (spans, source) if spans else ([], NAMES_NONE)


def annotate_chunk(base: int, size: int, spans: Sequence[NamedSpan],
                   default_perm: str) -> List[Tuple[int, int, str, str]]:
    """Split ``[base, base+size)`` at mapping boundaries -> ``(start, end, perm, name)``.

    Pieces outside every known mapping keep ``default_perm`` and no name, so
    the pieces always tile the chunk exactly (sum of sizes == chunk size).
    """
    end = base + size
    starts = [s.start for s in spans]
    idx = max(bisect.bisect_right(starts, base) - 1, 0)
    pieces, pos = [], base
    while pos < end:
        span = spans[idx] if idx < len(spans) else None
        if span is None or pos < span.start:
            stop = min(end, span.start) if span is not None else end
            pieces.append((pos, stop, default_perm, ""))
        elif pos >= span.end:
            idx += 1
            continue
        else:
            stop = min(end, span.end)
            pieces.append((pos, stop, span.perm, span.name))
            idx += 1
        pos = stop
    return pieces
