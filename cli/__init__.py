"""memdiver.cli — command-line entry point (package facade).

The implementation lives in submodules. Today everything sits in :mod:`.main`;
Phase 3 (P3.1) is decomposing it into per-group modules
(``inspect`` / ``pipeline`` / ``consensus`` / ``experiment`` / ``dataset`` /
``_shared``). This facade re-exports the historical ``memdiver.cli.<symbol>``
surface — including the private helpers and ``_cmd_*`` handlers that the test
suite imports directly — so existing imports and the ``memdiver.cli:main``
console entry point keep working while the module is split apart.

As groups are extracted, ``main`` re-imports the moved symbols, so this facade
only ever needs to import from ``.main``.
"""

from .main import (
    _KEY_FLAGS_HINT,
    _INSPECT_HANDLERS,
    _build_parser,
    _cmd_analyze,
    _cmd_batch,
    _cmd_brute_force,
    _cmd_consensus_add,
    _cmd_consensus_begin,
    _cmd_experiment,
    _cmd_gen_kem_key,
    _cmd_inspect,
    _cmd_inspect_byte_search,
    _cmd_inspect_entropy,
    _cmd_inspect_handles,
    _cmd_inspect_hex,
    _cmd_inspect_modules,
    _cmd_inspect_page_states,
    _cmd_inspect_processes,
    _cmd_inspect_session_info,
    _cmd_scan,
    _cmd_search_reduce,
    _cmd_verify,
    _key_material_from_args,
    _present_inspect_cli_call,
    _write_output,
    build_parser,
    main,
    present_inspect_cli,
    to_cli_exit,
)

__all__ = [
    "_KEY_FLAGS_HINT",
    "_INSPECT_HANDLERS",
    "_build_parser",
    "_cmd_analyze",
    "_cmd_batch",
    "_cmd_brute_force",
    "_cmd_consensus_add",
    "_cmd_consensus_begin",
    "_cmd_experiment",
    "_cmd_gen_kem_key",
    "_cmd_inspect",
    "_cmd_inspect_byte_search",
    "_cmd_inspect_entropy",
    "_cmd_inspect_handles",
    "_cmd_inspect_hex",
    "_cmd_inspect_modules",
    "_cmd_inspect_page_states",
    "_cmd_inspect_processes",
    "_cmd_inspect_session_info",
    "_cmd_scan",
    "_cmd_search_reduce",
    "_cmd_verify",
    "_key_material_from_args",
    "_present_inspect_cli_call",
    "_write_output",
    "build_parser",
    "main",
    "present_inspect_cli",
    "to_cli_exit",
]
