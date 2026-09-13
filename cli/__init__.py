"""memdiver.cli — command-line entry point (package facade).

The implementation is split across submodules (``_shared`` + the per-group
command modules ``dataset`` / ``consensus`` / ``experiment`` / ``pipeline`` /
``inspect``, plus ``main`` for parser construction and dispatch). This facade
re-exports the **complete** historical ``memdiver.cli.<symbol>`` surface — every
public function, private helper, and ``_cmd_*`` handler that lived on the old
monolithic ``cli`` module — so existing imports (in-tree tests AND out-of-tree
scripts) and the ``memdiver.cli:main`` console entry point keep working after
the P3.1 package split. Each symbol is imported from its owning submodule.
"""

from ._shared import (
    _CLI_EXIT,
    _KEY_FLAGS_HINT,
    _decrypt_parent_parser,
    _format_jsonl,
    _key_material_from_args,
    _print_missing_package,
    _resolve_dump_paths,
    _setup_logging,
    _warn_tag_status,
    _write_output,
    to_cli_exit,
)
from .consensus import (
    _cmd_consensus,
    _cmd_consensus_add,
    _cmd_consensus_begin,
    _cmd_consensus_finalize,
    _cmd_consensus_window,
    _consensus_state_paths,
    _load_welford_session,
)
from .dataset import (
    _cmd_analyze,
    _cmd_batch,
    _cmd_import,
    _cmd_mcp,
    _cmd_scan,
    _cmd_ui,
    _cmd_web,
)
from .experiment import (
    _cmd_experiment,
    _experiment_cli_progress,
    _print_experiment_table,
)
from .inspect import (
    _INSPECT_HANDLERS,
    _cmd_inspect,
    _cmd_inspect_byte_search,
    _cmd_inspect_entropy,
    _cmd_inspect_handles,
    _cmd_inspect_hex,
    _cmd_inspect_modules,
    _cmd_inspect_page_states,
    _cmd_inspect_processes,
    _cmd_inspect_region,
    _cmd_inspect_session_info,
    _cmd_inspect_strings,
    _cmd_inspect_structure,
    _cmd_inspect_vas,
    _cmd_inspect_xref,
    _emit_inspect,
    _inspect_key_kwargs,
    _new_tool_session,
    _present_inspect_cli_call,
    present_inspect_cli,
)
from .main import _build_parser, build_parser, main
from .pipeline import (
    _cmd_analyze_candidates,
    _cmd_auto_floor,
    _cmd_brute_force,
    _cmd_emit_plugin,
    _cmd_export,
    _cmd_export_key_pattern,
    _cmd_export_keylog,
    _cmd_gen_kem_key,
    _cmd_import_dir,
    _cmd_inspect_pcap,
    _cmd_locate_field_pairs,
    _cmd_locate_key,
    _cmd_n_sweep,
    _cmd_scan_yara,
    _cmd_score_detector,
    _cmd_search_reduce,
    _cmd_verify,
    _cmd_verify_plugin,
)

__all__ = [
    # main / parser
    "main",
    "build_parser",
    "_build_parser",
    # shared helpers
    "to_cli_exit",
    "_CLI_EXIT",
    "_KEY_FLAGS_HINT",
    "_decrypt_parent_parser",
    "_key_material_from_args",
    "_warn_tag_status",
    "_resolve_dump_paths",
    "_setup_logging",
    "_write_output",
    "_format_jsonl",
    "_print_missing_package",
    # dataset / analysis / servers
    "_cmd_ui",
    "_cmd_web",
    "_cmd_mcp",
    "_cmd_analyze",
    "_cmd_scan",
    "_cmd_batch",
    "_cmd_import",
    # consensus
    "_cmd_consensus",
    "_cmd_consensus_begin",
    "_cmd_consensus_add",
    "_cmd_consensus_finalize",
    "_cmd_consensus_window",
    "_consensus_state_paths",
    "_load_welford_session",
    # pipeline stages
    "_cmd_analyze_candidates",
    "_cmd_search_reduce",
    "_cmd_brute_force",
    "_cmd_n_sweep",
    "_cmd_auto_floor",
    "_cmd_emit_plugin",
    "_cmd_export",
    "_cmd_export_keylog",
    "_cmd_locate_key",
    "_cmd_locate_field_pairs",
    "_cmd_export_key_pattern",
    "_cmd_inspect_pcap",
    "_cmd_scan_yara",
    "_cmd_score_detector",
    "_cmd_verify_plugin",
    "_cmd_gen_kem_key",
    "_cmd_import_dir",
    "_cmd_verify",
    # experiment
    "_cmd_experiment",
    "_experiment_cli_progress",
    "_print_experiment_table",
    # inspect
    "present_inspect_cli",
    "_present_inspect_cli_call",
    "_INSPECT_HANDLERS",
    "_new_tool_session",
    "_emit_inspect",
    "_inspect_key_kwargs",
    "_cmd_inspect",
    "_cmd_inspect_hex",
    "_cmd_inspect_entropy",
    "_cmd_inspect_region",
    "_cmd_inspect_strings",
    "_cmd_inspect_byte_search",
    "_cmd_inspect_page_states",
    "_cmd_inspect_session_info",
    "_cmd_inspect_vas",
    "_cmd_inspect_processes",
    "_cmd_inspect_modules",
    "_cmd_inspect_handles",
    "_cmd_inspect_xref",
    "_cmd_inspect_structure",
]
