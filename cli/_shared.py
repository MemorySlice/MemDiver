"""Shared CLI helpers — error mapping, key material, argument parsing, output.

Leaf utilities used by the command handlers (``cli.dataset`` / ``cli.pipeline``
/ ``cli.consensus`` / ``cli.experiment`` / ``cli.inspect``) and by the parser
construction in ``cli.main``. Extracted from the monolithic ``cli`` module
(P3.1); depends only on ``memdiver.core`` and stdlib, never on the command
modules, so it sits at the bottom of the CLI package's import graph.
"""

import argparse
import json
import logging
import sys
from pathlib import Path

from memdiver.core.service_errors import CapabilityError, ErrorCategory

logger = logging.getLogger("memdiver.cli")


# Per-category process exit codes for the CLI backstop: NOT_FOUND is its own
# code (3) so scripts can distinguish "missing input" from a bad argument (2);
# caller-correctable input/precondition/unsupported errors share 2; anything
# INTERNAL is 1 (and additionally logs a traceback for the operator).
_CLI_EXIT = {
    ErrorCategory.NOT_FOUND: 3,
    ErrorCategory.INVALID_INPUT: 2,
    ErrorCategory.PRECONDITION: 2,
    ErrorCategory.UNSUPPORTED: 2,
    ErrorCategory.INTERNAL: 1,
}


def to_cli_exit(err: CapabilityError, *, stream=sys.stderr) -> int:
    """Translate a propagating ``CapabilityError`` into a CLI message + exit code.

    Prints a single ``memdiver: ERROR — <message>`` line to ``stream`` and maps
    the error's category to a process exit code via ``_CLI_EXIT``. Internal
    errors additionally log a full traceback under ``memdiver.cli`` so an
    operator can diagnose an unexpected failure.
    """
    print(f"memdiver: ERROR — {err.message}", file=stream)
    if err.category is ErrorCategory.INTERNAL:
        logging.getLogger("memdiver.cli").exception("internal error")
    return _CLI_EXIT[err.category]


def _decrypt_parent_parser() -> argparse.ArgumentParser:
    """Shared parent parser for encrypted-MSL decryption flags (spec §10).

    Attach via ``parents=[_decrypt_parent_parser()]`` to any subcommand that
    opens a dump, so it accepts a key for AES/XChaCha-encrypted .msl files.
    """
    p = argparse.ArgumentParser(add_help=False)
    g = p.add_argument_group("encrypted MSL (spec §10)")
    g.add_argument("--key-file", help="32-byte raw content-encryption key file "
                                      "(KeyEncap=None, KDF=None)")
    g.add_argument("--passphrase", help="Passphrase for Argon2id-derived key "
                                        "(KeyEncap=None, KDF=Argon2id)")
    g.add_argument("--kem-key-file", help="Recipient private key file for "
                                          "X25519/ML-KEM/hybrid key encapsulation")
    return p


def _key_material_from_args(args: argparse.Namespace) -> dict:
    """Build the open_dump() key-material kwargs from decryption CLI flags.

    Returns a dict with key/passphrase/kem_private_key (all None when no
    decryption flags were supplied), suitable for ``open_dump(path, **kw)``.

    Thin surface adapter over :func:`core.key_material.from_files`; the
    ``getattr`` guards let subcommands whose Namespace lacks the decryption
    attributes still resolve to the all-None dict.
    """
    from memdiver.core.key_material import from_files
    return from_files(
        getattr(args, "key_file", None),
        getattr(args, "passphrase", None),
        getattr(args, "kem_key_file", None),
    )


# CLI-surface remedy for a locked encrypted dump. The neutral core hint
# (``KeyStatus.hint``) never names a transport-specific remedy; the CLI owns
# the guidance that points its operator at the decryption FLAGS, so this string
# lives here in the CLI surface — never in core.
_KEY_FLAGS_HINT = "supply --key-file / --passphrase / --kem-key-file"


def _warn_tag_status(source) -> None:
    """Print a user-facing line about an encrypted dump's AEAD verification.

    Green = verified, red = failed/missing key. Plaintext dumps say nothing.
    """
    from memdiver.msl.enums import TagStatus
    status = getattr(source, "tag_status", TagStatus.NOT_ENCRYPTED)
    if status == TagStatus.VALID:
        print("memdiver: AEAD verified — encrypted dump decrypted successfully",
              file=sys.stderr)
    elif status == TagStatus.CORRUPTED:
        print("memdiver: ERROR — AEAD verification FAILED (wrong key or tampered file)",
              file=sys.stderr)
    elif status == TagStatus.MISSING_KEY:
        print(f"memdiver: ERROR — dump is encrypted; {_KEY_FLAGS_HINT}",
              file=sys.stderr)


def _resolve_dump_paths(raw_paths: list) -> list:
    """Expand directories to all supported dump flavours; pass through files.

    Recognised extensions inside a run directory:
      * ``.dump`` and ``.msl`` (legacy + Memory Slice)
      * ``.gcore.core`` and bare ``.core`` (Linux gcore/ELF core)
      * ``gdb_raw.bin`` / ``lldb_raw.bin`` (regioned raw dumps)
    """
    paths: list[Path] = []
    for p in raw_paths:
        path = Path(p)
        if path.is_dir():
            collected: list[Path] = []
            collected.extend(path.glob("*.dump"))
            collected.extend(path.glob("*.msl"))
            collected.extend(path.glob("*.gcore.core"))
            collected.extend(path.glob("*.core"))
            collected.extend(path.glob("*gdb_raw.bin"))
            collected.extend(path.glob("*lldb_raw.bin"))
            # De-duplicate (``*.gcore.core`` overlaps ``*.core``) and sort.
            paths.extend(sorted({c.resolve(): c for c in collected}.values()))
        elif path.is_file():
            paths.append(path)
        else:
            logger.warning("Skipping non-existent path: %s", p)
    return paths


def _setup_logging(verbose: bool) -> None:
    """Configure logging for CLI mode."""
    from memdiver.core.log import setup_logging
    setup_logging(level="DEBUG" if verbose else "WARNING")


def _write_output(
    data: dict,
    output_path: str | None,
    fmt: str = "json",
) -> None:
    """Write data to file or stdout as json or jsonl."""
    if fmt == "jsonl":
        text = _format_jsonl(data)
    else:
        text = json.dumps(data, indent=2)
    if output_path:
        try:
            Path(output_path).write_text(text)
        except OSError as exc:
            print(f"memdiver: cannot write output to {output_path}: {exc}",
                  file=sys.stderr)
            raise SystemExit(1)
        logger.info("Output written to %s", output_path)
    else:
        print(text)


def _format_jsonl(data: dict) -> str:
    """Serialize a BatchResult-shaped dict as newline-delimited JSON.

    One record per completed job + a trailing summary line tagged
    ``"_type": "summary"``. Non-batch shapes (no ``jobs`` list) fall
    back to a single-line JSON dump.
    """
    jobs = data.get("jobs")
    if not isinstance(jobs, list):
        return json.dumps(data)
    lines = [json.dumps(j) for j in jobs]
    summary = {k: v for k, v in data.items() if k != "jobs"}
    summary["_type"] = "summary"
    lines.append(json.dumps(summary))
    return "\n".join(lines) + "\n"


def _print_missing_package(package: str, extra: str | None = None) -> None:
    """Print a uniform 'package missing' install hint to stderr.

    ``extra`` names an optional-dependencies group (e.g. ``"experiment"``).
    When omitted, the hint points at a base-install reinstall.
    """
    if extra:
        message = (
            f"{package} is not available. Install the '{extra}' extras with:\n"
            f"    pip install memdiver[{extra}]"
        )
    else:
        message = (
            f"{package} is missing from your environment. It is part of the "
            f"base install; try: pip install --force-reinstall memdiver"
        )
    print(message, file=sys.stderr)
