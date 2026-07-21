"""Characterization tests pinning the CLI inspect surface's CURRENT behavior.

PHASE 0 (additive, test-only): these lock the observable contract of the
``inspect`` CLI handlers at the CLI boundary so a later refactor cannot
silently change it.

Each ``_cmd_inspect_*`` handler is invoked in-process with a hand-built
``argparse.Namespace`` (mirroring tests/test_cli.py's
``test_inspect_encrypted_msl_without_key_errors``) and its stdout/stderr are
captured via ``capsys``. On an encrypted .msl opened with NO key the current
contract is: rc == 1, the stdout machine payload carries
``tag_status == "missing_key"`` (and an ``error``), and stderr carries an
``encrypted``/"supply a key" style diagnostic.
"""

import argparse
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture
def encrypted_msl(tmp_path):
    """A raw-key AES-256-GCM encrypted .msl with one captured region.

    Reuses the same MslWriter + MslEncryptionConfig construction the existing
    CLI/MCP encrypted-msl tests use.
    """
    from memdiver.msl import crypto
    from memdiver.msl.enums import EncAlgo

    if not crypto.cipher_is_available(EncAlgo.AES_256_GCM):
        pytest.skip("AES-256-GCM backend not installed")

    from memdiver.msl.writer import MslEncryptionConfig, MslWriter

    key = os.urandom(32)
    msl_path = tmp_path / "encrypted.msl"
    cfg = MslEncryptionConfig(raw_key=key)
    w = MslWriter(msl_path, pid=7, encryption=cfg)
    w.add_memory_region(0x1000, b"\xCD" * 4096)
    w.add_end_of_capture()
    w.write()
    return str(msl_path)


def _msl_args(msl_path):
    """Namespace shape shared by the MSL-metadata inspect handlers."""
    return argparse.Namespace(
        msl_path=msl_path,
        key_file=None,
        passphrase=None,
        kem_key_file=None,
        output=None,
    )


def _hex_args(msl_path):
    """Namespace shape for the hex handler (decrypted vas view)."""
    return argparse.Namespace(
        dump_path=msl_path,
        offset=0,
        length=64,
        view="vas",
        key_file=None,
        passphrase=None,
        kem_key_file=None,
        output=None,
    )


def _run(handler_name, args_builder, msl_path):
    from memdiver import cli

    handler = getattr(cli, handler_name)
    return handler(args_builder(msl_path))


@pytest.mark.parametrize(
    "handler_name, args_builder",
    [
        ("_cmd_inspect_session_info", _msl_args),
        ("_cmd_inspect_page_states", _msl_args),
        ("_cmd_inspect_processes", _msl_args),
        ("_cmd_inspect_modules", _msl_args),
        ("_cmd_inspect_handles", _msl_args),
        ("_cmd_inspect_hex", _hex_args),
    ],
)
def test_cli_inspect_encrypted_msl_without_key_errors(
    encrypted_msl, capsys, handler_name, args_builder
):
    rc = _run(handler_name, args_builder, encrypted_msl)

    assert rc == 1
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result.get("tag_status") == "missing_key"
    assert "error" in result
    assert "encrypted" in captured.err
