"""Key material for ``import`` / ``import-dir`` of encrypted ``.msl`` sources.

Decryption flags come from the shared ``_decrypt_parent_parser``; this module
adds ``--decrypt-output`` and the TTY passphrase prompt. Key material is
request-scoped: it is never printed, logged or cached.
"""

import argparse
import getpass
import sys
from pathlib import Path
from typing import Iterable, Optional

from ._shared import _key_material_from_args
from .region_prompt import is_interactive

DECRYPT_OUTPUT_HELP = ("with --materialize on an encrypted .msl: write the "
                       "filtered copy as PLAINTEXT instead of re-encrypting it "
                       "with the source key (unprotected output)")


def decrypt_output_parent_parser() -> argparse.ArgumentParser:
    """Parent parser adding ``--decrypt-output`` to the import commands."""
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--decrypt-output", action="store_true",
                   help=DECRYPT_OUTPUT_HELP)
    return p


def is_encrypted_msl(path: Path) -> bool:
    """True when *path* is an ``.msl`` whose header has the ENCRYPTED flag."""
    from memdiver.msl.reader import MslReader

    try:
        with MslReader(Path(path)) as reader:
            return bool(reader.file_header.encrypted)
    except (OSError, ValueError):
        return False  # not an .msl (or unreadable): no key needed


def import_key_material(args: argparse.Namespace,
                        sources: Iterable[Path]) -> Optional[dict]:
    """Key material from the flags, or a TTY passphrase prompt, or ``None``.

    The prompt only fires when no flag was given, ``--materialize`` was
    requested, an input is an encrypted ``.msl`` and the session is
    interactive; otherwise a missing key surfaces later as a clear error.
    """
    km = _key_material_from_args(args)
    if any(v is not None for v in km.values()):
        return km
    if not getattr(args, "materialize", False) or not is_interactive():
        return None
    if not any(is_encrypted_msl(p) for p in sources):
        return None
    passphrase = getpass.getpass("memdiver: passphrase for encrypted .msl: ")
    if not passphrase:
        return None
    from memdiver.core.key_material import from_files
    return from_files(passphrase=passphrase)


def print_import_error(exc: Exception) -> int:
    """Render an import ``ValueError`` (e.g. missing/wrong key) on stderr."""
    print(f"memdiver: ERROR — {exc}", file=sys.stderr)
    if "key material" in str(exc) or "decryption failed" in str(exc):
        print("memdiver: hint — supply --key-file / --passphrase / "
              "--kem-key-file", file=sys.stderr)
    return 1
