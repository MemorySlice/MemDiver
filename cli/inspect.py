"""Inspect CLI commands (hex/entropy/strings/byte-search/xref/etc), extracted from cli.main."""

import argparse
import sys

from ._shared import _KEY_FLAGS_HINT, _write_output


# ---------------------------------------------------------------------------
# inspect — low-level dump / structured-MSL inspection views
#
# Thin CLI adapters over the exact pure tool functions that the HTTP
# `/api/inspect` endpoints and the MCP server already expose
# (``mcp_server.tools_inspect`` / ``mcp_server.tools_xref``), so the three
# surfaces cannot drift. The stateless read functions take a ``ToolSession``
# only to share the MCP signature; a throwaway instance carries no state.
#
# These reuse the same pure tools_inspect / tools_xref functions behind the
# `/api/inspect` endpoints and the MCP server. The decryption flags
# (--key-file / --passphrase / --kem-key-file) are forwarded to the key-aware
# tools (hex, entropy, strings, byte-search, page-states, session-info), which
# open an uncached keyed reader, so an encrypted `.msl` is read transparently.
# ---------------------------------------------------------------------------


def _new_tool_session():
    """Construct a stateless ToolSession for reuse of the shared tool funcs."""
    from memdiver.app.composition import build_tool_session
    return build_tool_session()


def _emit_inspect(result: dict, output: str | None) -> int:
    """Write an inspect result as JSON; exit non-zero when it carries an error.

    When the error stems from an undecryptable encrypted container the tool
    layer tags it with ``tag_status`` (missing/wrong key). Surface that on
    stderr so an operator is not left staring at an empty-looking result and
    mistaking a key failure for a genuinely empty capture (O-3).
    """
    if isinstance(result, dict) and result.get("tag_status") in ("missing_key", "corrupted"):
        print(f"memdiver: ERROR — {result.get('error')}", file=sys.stderr)
    _write_output(result, output)
    return 1 if isinstance(result, dict) and "error" in result else 0


def _inspect_key_kwargs(args: argparse.Namespace) -> dict:
    """Decrypt flags → tools_inspect key kwargs, so `inspect` can read an
    encrypted .msl. Passed as keyword args (the underlying tools accept
    key_file / passphrase / kem_key_file)."""
    return {
        "key_file": getattr(args, "key_file", None),
        "passphrase": getattr(args, "passphrase", None),
        "kem_key_file": getattr(args, "kem_key_file", None),
    }


def present_inspect_cli(result) -> tuple[dict, int, str | None]:
    """Present an inspect ``ServiceResult`` as the CLI's observable triple.

    Returns ``(machine_payload, exit_code, stderr_msg)``:

    * **Locked** (``not result.status.key.decrypted``) — an encrypted container
      opened with a missing / wrong key. The neutral core hint is augmented HERE
      with the CLI-specific remedy (:data:`_KEY_FLAGS_HINT`), so the machine
      payload is ``{"error": <core hint>; <flags>, "tag_status": …}``, the exit
      code is ``1`` and the stderr message is that same augmented string.
    * **OK** — the producer's payload passes through untouched, exit code ``0``,
      no stderr message.

    This is the explicit CLI presenter that lets the handlers drop the
    ``report_key_status`` default: the producer always carries the key state in
    ``result.status`` and this function renders the CLI-flavoured guidance
    (the ``--key-file`` flags) that core deliberately no longer carries.
    """
    key = result.status.key
    if not key.decrypted:
        message = f"{key.hint}; {_KEY_FLAGS_HINT}"
        return {"error": message, "tag_status": key.tag_status.value}, 1, message
    return result.payload, 0, None


def _present_inspect_cli_call(produce) -> tuple[dict, int, str | None]:
    """Run a ServiceResult producer and present it for the CLI.

    Hard errors are RAISED by the producers as ``CapabilityError`` subclasses
    (missing file, wrong format, out-of-range offset, invalid pattern). Convert
    them back into the SAME error tuple the legacy ``{"error": …}`` dict path
    produced — the message plus any structured ``details`` — so the machine
    payload and exit code stay byte-for-byte unchanged.
    """
    from memdiver.core.service_errors import CapabilityError
    try:
        return present_inspect_cli(produce())
    except CapabilityError as e:
        return e.to_error_body(), 1, e.message


def _cmd_inspect_hex(args: argparse.Namespace) -> int:
    """Hex + ASCII dump of a byte range."""
    from memdiver.mcp_server.tools_inspect import read_hex_result
    machine_payload, _exit_code, _stderr_msg = _present_inspect_cli_call(
        lambda: read_hex_result(_new_tool_session(), args.dump_path,
                                args.offset, args.length, view=args.view,
                                **_inspect_key_kwargs(args)))
    return _emit_inspect(machine_payload, args.output)


def _cmd_inspect_entropy(args: argparse.Namespace) -> int:
    """Shannon entropy profile of a region."""
    from memdiver.mcp_server.tools_inspect import entropy_result
    machine_payload, _exit_code, _stderr_msg = _present_inspect_cli_call(
        lambda: entropy_result(_new_tool_session(), args.dump_path, args.offset,
                               args.length, args.window, args.step, args.threshold,
                               **_inspect_key_kwargs(args)))
    return _emit_inspect(machine_payload, args.output)


def _cmd_inspect_region(args: argparse.Namespace) -> int:
    """Investigate one offset: byte value, entropy band, neighbourhood strings."""
    from memdiver.mcp_server.tools_inspect import analyze_region_result
    machine_payload, _exit_code, _stderr_msg = _present_inspect_cli_call(
        lambda: analyze_region_result(_new_tool_session(), args.dump_path,
                                      args.offset, args.window, view=args.view,
                                      **_inspect_key_kwargs(args)))
    return _emit_inspect(machine_payload, args.output)


def _cmd_inspect_strings(args: argparse.Namespace) -> int:
    """Extract printable strings from a dump region."""
    from memdiver.mcp_server.tools_inspect import strings_result
    machine_payload, _exit_code, _stderr_msg = _present_inspect_cli_call(
        lambda: strings_result(_new_tool_session(), args.dump_path, args.offset,
                               args.length, args.min_length, args.encoding,
                               args.max_results, **_inspect_key_kwargs(args)))
    return _emit_inspect(machine_payload, args.output)


def _cmd_inspect_byte_search(args: argparse.Namespace) -> int:
    """Find every occurrence of a hex byte pattern."""
    from memdiver.mcp_server.tools_inspect import search_bytes_result
    machine_payload, _exit_code, _stderr_msg = _present_inspect_cli_call(
        lambda: search_bytes_result(_new_tool_session(), args.dump_path,
                                    args.pattern, view=args.view,
                                    max_results=args.max_results,
                                    **_inspect_key_kwargs(args)))
    return _emit_inspect(machine_payload, args.output)


def _cmd_inspect_page_states(args: argparse.Namespace) -> int:
    """Surface the MSL three-state page model (MSL only)."""
    from memdiver.mcp_server.tools_inspect import page_states_result
    machine_payload, _exit_code, _stderr_msg = _present_inspect_cli_call(
        lambda: page_states_result(_new_tool_session(), args.msl_path,
                                   **_inspect_key_kwargs(args)))
    return _emit_inspect(machine_payload, args.output)


def _cmd_inspect_session_info(args: argparse.Namespace) -> int:
    """Extract MSL session metadata (MSL only)."""
    from memdiver.mcp_server.tools_inspect import session_info_result
    machine_payload, _exit_code, _stderr_msg = _present_inspect_cli_call(
        lambda: session_info_result(_new_tool_session(), args.msl_path,
                                    **_inspect_key_kwargs(args)))
    return _emit_inspect(machine_payload, args.output)


def _cmd_inspect_vas(args: argparse.Namespace) -> int:
    """Extract the per-dump VAS region layout (MSL only)."""
    from memdiver.mcp_server.tools_inspect import vas_regions_result
    machine_payload, _exit_code, _stderr_msg = _present_inspect_cli_call(
        lambda: vas_regions_result(_new_tool_session(), args.msl_path,
                                   **_inspect_key_kwargs(args)))
    return _emit_inspect(machine_payload, args.output)


def _cmd_inspect_processes(args: argparse.Namespace) -> int:
    """List PROCESS_TABLE entries (MSL only)."""
    from memdiver.mcp_server.tools_inspect import processes_result
    machine_payload, _exit_code, _stderr_msg = _present_inspect_cli_call(
        lambda: processes_result(_new_tool_session(), args.msl_path,
                                 **_inspect_key_kwargs(args)))
    return _emit_inspect(machine_payload, args.output)


def _cmd_inspect_modules(args: argparse.Namespace) -> int:
    """List loaded modules from MSL metadata (MSL only)."""
    from memdiver.mcp_server.tools_inspect import modules_result
    machine_payload, _exit_code, _stderr_msg = _present_inspect_cli_call(
        lambda: modules_result(_new_tool_session(), args.msl_path,
                               **_inspect_key_kwargs(args)))
    return _emit_inspect(machine_payload, args.output)


def _cmd_inspect_handles(args: argparse.Namespace) -> int:
    """List HANDLE_TABLE entries (MSL only)."""
    from memdiver.mcp_server.tools_inspect import handles_result
    machine_payload, _exit_code, _stderr_msg = _present_inspect_cli_call(
        lambda: handles_result(_new_tool_session(), args.msl_path,
                               **_inspect_key_kwargs(args)))
    return _emit_inspect(machine_payload, args.output)


def _cmd_inspect_xref(args: argparse.Namespace) -> int:
    """Resolve cross-references for an MSL file (MSL only)."""
    from memdiver.mcp_server.tools_xref import get_cross_references_result
    machine_payload, _exit_code, _stderr_msg = _present_inspect_cli_call(
        lambda: get_cross_references_result(_new_tool_session(), args.msl_path))
    return _emit_inspect(machine_payload, args.output)


def _cmd_inspect_structure(args: argparse.Namespace) -> int:
    """Identify a data structure at the given offset."""
    from memdiver.mcp_server.tools_xref import identify_structure_result
    machine_payload, _exit_code, _stderr_msg = _present_inspect_cli_call(
        lambda: identify_structure_result(_new_tool_session(), args.dump_path,
                                          args.offset, args.protocol))
    return _emit_inspect(machine_payload, args.output)


_INSPECT_HANDLERS = {
    "hex": _cmd_inspect_hex,
    "entropy": _cmd_inspect_entropy,
    "region": _cmd_inspect_region,
    "strings": _cmd_inspect_strings,
    "byte-search": _cmd_inspect_byte_search,
    "page-states": _cmd_inspect_page_states,
    "session-info": _cmd_inspect_session_info,
    "vas": _cmd_inspect_vas,
    "processes": _cmd_inspect_processes,
    "modules": _cmd_inspect_modules,
    "handles": _cmd_inspect_handles,
    "xref": _cmd_inspect_xref,
    "structure": _cmd_inspect_structure,
}


def _cmd_inspect(args: argparse.Namespace) -> int:
    """Dispatch an ``inspect <action>`` subcommand to its handler."""
    handler = _INSPECT_HANDLERS.get(getattr(args, "inspect_action", None))
    if handler is None:
        print("memdiver inspect: pick an action: "
              + ", ".join(_INSPECT_HANDLERS), file=sys.stderr)
        return 1
    return handler(args)
