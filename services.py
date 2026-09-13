"""MemDiver structured services — the surface-agnostic producer layer.

Every user-facing MemDiver capability is backed by ONE producer function in the
``memdiver.app`` layer. The CLI, the FastAPI web app and the MCP server are all
thin *presenters* that route to these same functions, so the compute cannot
fork between surfaces. This module is the Python **library** surface: it
re-exports every ``app`` producer under a stable public name so a library user
reaches the whole feature set without importing deep internal modules.

Contract
--------
* The ``*_result`` producers (and :func:`get_cross_references_result` etc.)
  return a :class:`~memdiver.core.service_result.ServiceResult` — a payload plus
  a :class:`~memdiver.core.service_result.StatusBlock` that carries key/decrypt
  state. Read ``result.payload`` for the data and ``result.status`` for whether
  an encrypted dump was locked (missing/wrong key) rather than genuinely empty.
* The pipeline producers (:func:`consensus`, :func:`n_sweep`, …) and the
  dataset/analysis producers (:func:`scan_dataset`, …) return their native
  payloads (JSON-able dicts / artefact paths).
* Hard errors are RAISED as :class:`~memdiver.core.service_errors.CapabilityError`
  subclasses (e.g. ``FileNotFoundServiceError``, ``OffsetOutOfRangeError``,
  ``EncryptedDumpLockedError``) — never returned as ``{"error": ...}`` dicts.

Session
-------
The inspect / xref / dataset producers take a :class:`ToolSession` as their
first argument (it caches dataset scans across calls); construct one with
``memdiver.services.ToolSession()``. The pipeline / verify / experiment
producers are stateless and keyword-only.

Example::

    import memdiver

    session = memdiver.services.ToolSession()
    result = memdiver.services.session_info_result(session, "capture.msl")
    if result.status.key.decrypted:
        print(result.payload["region_count"])
    else:
        print(result.status.key.hint)  # neutral, surface-agnostic lock hint
"""

from __future__ import annotations

# Shared stateful context passed to the inspect/xref/dataset producers.
from memdiver.app.session import ToolSession

# --- inspect: hex / entropy / strings / byte-search / structured MSL --------
from memdiver.app.tools_inspect import (
    analyze_region_result,
    blocks_result,
    connections_result,
    detect_format_result,
    entropy_result,
    handles_result,
    modules_result,
    module_index_result,
    page_states_result,
    processes_result,
    read_hex_raw_result,
    read_hex_result,
    resolve_va_result,
    search_bytes_result,
    session_info_result,
    strings_result,
    vas_regions_result,
)

# --- xref / structure -------------------------------------------------------
from memdiver.app.tools_xref import (
    apply_structure_result,
    get_cross_references_result,
    identify_structure_result,
)

# --- pipeline stages + verify / experiment ----------------------------------
from memdiver.app.experiment_orchestration import experiment_result
from memdiver.app.tools_pipeline import (
    analyze_candidates,
    auto_floor,
    brute_force,
    consensus,
    emit_plugin,
    export_key_pattern,
    export_pattern,
    inspect_pcap,
    keylog_result,
    locate_field_across_pairs,
    locate_key,
    manual_export_pattern,
    n_sweep,
    scan_yara_rule,
    score_detector_matches,
    search_reduce,
    verify_key_result,
    verify_vol3_plugin,
)

# --- dataset / analysis -----------------------------------------------------
from memdiver.app.tools import (
    analyze_library,
    import_dump,
    list_phases,
    list_protocols,
    scan_dataset,
)

# --- consensus: the aligned window (the N-dump differential viewer) --------
from memdiver.app.tools_consensus import aligned_window_from_vector, aligned_window_result

# --- frontend-serving producers (field inference / algorithm availability) --
from memdiver.app.tools_algorithms import algorithm_availability
from memdiver.app.tools_fields import infer_fields_result

__all__ = [
    # session
    "ToolSession",
    # inspect
    "read_hex_result",
    "read_hex_raw_result",
    "resolve_va_result",
    "analyze_region_result",
    "search_bytes_result",
    "entropy_result",
    "strings_result",
    "detect_format_result",
    "session_info_result",
    "vas_regions_result",
    "page_states_result",
    "processes_result",
    "modules_result",
    "handles_result",
    "connections_result",
    "module_index_result",
    "blocks_result",
    # xref / structure
    "get_cross_references_result",
    "identify_structure_result",
    "apply_structure_result",
    # pipeline
    "consensus",
    "analyze_candidates",
    "search_reduce",
    "brute_force",
    "n_sweep",
    "auto_floor",
    "emit_plugin",
    "export_pattern",
    "manual_export_pattern",
    "locate_key",
    "export_key_pattern",
    # C3 — the paired field search (N (dump, capture) pairs, one needle each).
    "locate_field_across_pairs",
    # D1 — RUN an emitted YARA rule over N dumps. The other side of
    # ``export_pattern`` / ``export_key_pattern``, which only ever wrote one.
    "scan_yara_rule",
    # D2 — SCORE what D1 found. ``scan_yara_rule`` says the rule fired; this
    # says whether it was right, which is a different fact.
    "score_detector_matches",
    # D3 — RUN the Volatility3 plugin we emit, in BOTH of the ways a user runs
    # one: in-process against the framework MemDiver imports, and out-of-process
    # through the operator's own ``vol`` launcher. Every row names the runtime
    # and the RESOLVED framework version that produced it, because three
    # Volatility3 trees commonly coexist on one machine and they disagree.
    "verify_vol3_plugin",
    "keylog_result",
    "inspect_pcap",
    # consensus — one window, read in every dump at the address the consensus
    # aligned. ``aligned_window_from_vector`` is the same compute over a vector
    # the caller already has (no rebuild); ``aligned_window_result`` builds one.
    "aligned_window_result",
    "aligned_window_from_vector",
    # verify / experiment
    "verify_key_result",
    "experiment_result",
    # dataset / analysis
    "scan_dataset",
    "list_protocols",
    "list_phases",
    "analyze_library",
    "import_dump",
    # frontend-serving producers
    "infer_fields_result",
    "algorithm_availability",
]
