"""Tests for cli module."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from memdiver.cli import _build_parser, _write_output

FIXTURES_DATASET = Path(__file__).parent / "fixtures" / "dataset"


def test_parser_no_args():
    parser = _build_parser()
    args = parser.parse_args([])
    assert args.command is None


def test_parser_ui_command():
    parser = _build_parser()
    args = parser.parse_args(["ui"])
    assert args.command == "ui"


def test_parser_analyze_command():
    parser = _build_parser()
    args = parser.parse_args([
        "analyze", "/tmp/lib1", "--phase", "pre_abort",
        "--protocol-version", "13", "-v",
    ])
    assert args.command == "analyze"
    assert args.phase == "pre_abort"
    assert args.protocol_version == "13"
    assert args.verbose is True
    assert args.library_dirs == ["/tmp/lib1"]


def test_parser_scan_command():
    parser = _build_parser()
    args = parser.parse_args(["scan", "--root", "/tmp/data"])
    assert args.command == "scan"
    assert args.root == "/tmp/data"


def test_parser_batch_command():
    parser = _build_parser()
    args = parser.parse_args(["batch", "--config", "batch.json", "-o", "out.json"])
    assert args.command == "batch"
    assert args.config == "batch.json"
    assert args.output == "out.json"


def test_write_output_to_file(tmp_path):
    out_file = tmp_path / "result.json"
    data = {"key": "value", "count": 42}
    _write_output(data, str(out_file))
    loaded = json.loads(out_file.read_text())
    assert loaded == data


def test_write_output_to_stdout(capsys):
    data = {"hello": "world"}
    _write_output(data, None)
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert parsed == data


def test_write_output_unwritable_path_exits_nonzero(tmp_path, capsys):
    """An unwritable -o path yields a clean stderr message and SystemExit(1),
    not a raw traceback."""
    import pytest

    # Writing into a path whose parent does not exist raises OSError.
    bad_path = tmp_path / "missing_dir" / "result.json"
    with pytest.raises(SystemExit) as exc_info:
        _write_output({"a": 1}, str(bad_path))
    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "cannot write output" in captured.err
    assert str(bad_path) in captured.err


def test_parser_import_command():
    parser = _build_parser()
    args = parser.parse_args(["import", "/tmp/test.dump", "-o", "/tmp/test.msl"])
    assert args.command == "import"
    assert args.dump_file == "/tmp/test.dump"
    assert args.output == "/tmp/test.msl"


def test_parser_import_dir_command():
    parser = _build_parser()
    args = parser.parse_args(["import-dir", "/tmp/run1", "-o", "/tmp/out"])
    assert args.command == "import-dir"
    assert args.run_dir == "/tmp/run1"
    assert args.output_dir == "/tmp/out"


# ---------------------------------------------------------------------------
# Integration tests — exercise actual CLI commands against fixture dataset
# ---------------------------------------------------------------------------


def test_cmd_scan_fixture_dataset(tmp_path):
    from memdiver.cli import _cmd_scan

    args = argparse.Namespace(
        root=str(FIXTURES_DATASET),
        keylog_filename="keylog.csv",
        protocols=None,
        output=str(tmp_path / "scan.json"),
        verbose=False,
    )
    rc = _cmd_scan(args)
    assert rc == 0
    data = json.loads((tmp_path / "scan.json").read_text())
    assert "protocol_versions" in data
    assert data["total_runs"] >= 4


def test_cmd_analyze_tls13(tmp_path):
    from memdiver.cli import _cmd_analyze

    lib_dir = FIXTURES_DATASET / "TLS13" / "scenario_a" / "boringssl"
    args = argparse.Namespace(
        library_dirs=[str(lib_dir)],
        phase="pre_abort",
        protocol_version="13",
        keylog_filename="keylog.csv",
        template="Auto-detect",
        max_runs=10,
        normalize=False,
        no_expand=False,
        output=str(tmp_path / "analyze.json"),
        verbose=False,
    )
    rc = _cmd_analyze(args)
    assert rc == 0
    data = json.loads((tmp_path / "analyze.json").read_text())
    lib_entry = data["libraries"][0]
    assert lib_entry["library"] == "boringssl"
    assert lib_entry["phase"] == "pre_abort"
    assert lib_entry["protocol_version"] == "13"


def test_cmd_analyze_tls12(tmp_path):
    from memdiver.cli import _cmd_analyze

    lib_dir = FIXTURES_DATASET / "TLS12" / "scenario_a" / "openssl"
    args = argparse.Namespace(
        library_dirs=[str(lib_dir)],
        phase="pre_abort",
        protocol_version="12",
        keylog_filename="keylog.csv",
        template="Auto-detect",
        max_runs=10,
        normalize=False,
        no_expand=False,
        output=str(tmp_path / "analyze.json"),
        verbose=False,
    )
    rc = _cmd_analyze(args)
    assert rc == 0
    data = json.loads((tmp_path / "analyze.json").read_text())
    lib_entry = data["libraries"][0]
    assert lib_entry["library"] == "openssl"


def test_cmd_batch_fixture(tmp_path):
    from memdiver.cli import _cmd_batch

    batch_config = {
        "jobs": [
            {
                "library_dirs": [str(FIXTURES_DATASET / "TLS13" / "scenario_a" / "boringssl")],
                "phase": "pre_abort",
                "protocol_version": "13",
            },
            {
                "library_dirs": [str(FIXTURES_DATASET / "TLS12" / "scenario_a" / "openssl")],
                "phase": "pre_abort",
                "protocol_version": "12",
            },
        ],
        "output_format": "json",
    }
    config_path = tmp_path / "batch.json"
    config_path.write_text(json.dumps(batch_config))
    args = argparse.Namespace(
        config=str(config_path),
        workers=1,
        output=str(tmp_path / "batch_result.json"),
        verbose=False,
    )
    rc = _cmd_batch(args)
    assert rc == 0
    data = json.loads((tmp_path / "batch_result.json").read_text())
    assert data["total_jobs"] == 2
    assert data["succeeded_count"] == 2


def test_parser_batch_output_format_flag():
    parser = _build_parser()
    args = parser.parse_args([
        "batch", "--config", "batch.json", "--output-format", "jsonl",
    ])
    assert args.output_format == "jsonl"

    args_default = parser.parse_args(["batch", "--config", "batch.json"])
    assert args_default.output_format is None

    import pytest
    with pytest.raises(SystemExit):
        parser.parse_args(["batch", "--config", "batch.json", "--output-format", "yaml"])


def test_write_output_jsonl_batch_shape(tmp_path):
    out = tmp_path / "result.jsonl"
    data = {
        "jobs": [
            {"job_index": 0, "succeeded": True, "duration_seconds": 1.0},
            {"job_index": 1, "succeeded": False, "error": "boom"},
        ],
        "total_jobs": 2,
        "succeeded_count": 1,
        "failed_count": 1,
        "total_duration_seconds": 2.0,
    }
    _write_output(data, str(out), fmt="jsonl")

    lines = out.read_text().rstrip("\n").split("\n")
    assert len(lines) == 3  # 2 jobs + 1 summary

    parsed = [json.loads(line) for line in lines]
    assert parsed[0]["job_index"] == 0
    assert parsed[1]["job_index"] == 1
    assert parsed[2]["_type"] == "summary"
    assert parsed[2]["total_jobs"] == 2
    assert "jobs" not in parsed[2]


def test_cmd_batch_jsonl_end_to_end(tmp_path):
    from memdiver.cli import _cmd_batch

    batch_config = {
        "jobs": [
            {
                "library_dirs": [str(FIXTURES_DATASET / "TLS13" / "scenario_a" / "boringssl")],
                "phase": "pre_abort",
                "protocol_version": "13",
            },
            {
                "library_dirs": [str(FIXTURES_DATASET / "TLS12" / "scenario_a" / "openssl")],
                "phase": "pre_abort",
                "protocol_version": "12",
            },
        ],
        "output_format": "jsonl",
    }
    config_path = tmp_path / "batch.json"
    config_path.write_text(json.dumps(batch_config))
    out_path = tmp_path / "batch_result.jsonl"
    args = argparse.Namespace(
        config=str(config_path),
        workers=1,
        output=str(out_path),
        output_format=None,
        verbose=False,
    )
    rc = _cmd_batch(args)
    assert rc == 0

    lines = out_path.read_text().rstrip("\n").split("\n")
    assert len(lines) == 3  # 2 jobs + 1 summary
    parsed = [json.loads(line) for line in lines]
    assert {p.get("job_index") for p in parsed[:2]} == {0, 1}
    assert parsed[-1]["_type"] == "summary"
    assert parsed[-1]["total_jobs"] == 2
    assert parsed[-1]["succeeded_count"] == 2


def test_cmd_analyze_nonexistent_dir():
    from memdiver.cli import _cmd_analyze

    args = argparse.Namespace(
        library_dirs=["/nonexistent/path"],
        phase="pre_abort",
        protocol_version="13",
        keylog_filename="keylog.csv",
        template="Auto-detect",
        max_runs=10,
        normalize=False,
        no_expand=False,
        output=None,
        verbose=False,
    )
    rc = _cmd_analyze(args)
    assert rc == 1


# ---------------------------------------------------------------------------
# Tests for verify command
# ---------------------------------------------------------------------------


class TestVerifyCommand:
    def test_verify_valid_key(self, tmp_path):
        """Verify a known key in a synthetic dump."""
        from memdiver.cli import _cmd_verify
        from memdiver.engine.verification import AesCbcVerifier, VERIFICATION_PLAINTEXT, VERIFICATION_IV

        # Create a dump with a known key at offset 0x100
        key = bytes(range(32))
        dump = bytearray(1024)
        dump[0x100:0x120] = key
        dump_path = tmp_path / "test.dump"
        dump_path.write_bytes(bytes(dump))

        # Create ciphertext
        verifier = AesCbcVerifier()
        ct = verifier.create_ciphertext(key, VERIFICATION_PLAINTEXT, VERIFICATION_IV)

        args = argparse.Namespace(
            dump=str(dump_path),
            offset=0x100,
            length=32,
            ciphertext_hex=ct.hex(),
            iv_hex=None,
            cipher="AES-256-CBC",
            output=None,
            verbose=False,
        )
        rc = _cmd_verify(args)
        assert rc == 0

    def test_verify_wrong_offset(self, tmp_path):
        """Wrong offset should show verified=false but command succeeds."""
        from memdiver.cli import _cmd_verify
        from memdiver.engine.verification import AesCbcVerifier, VERIFICATION_PLAINTEXT, VERIFICATION_IV

        key = bytes(range(32))
        dump = bytearray(1024)
        dump[0x100:0x120] = key
        dump_path = tmp_path / "test.dump"
        dump_path.write_bytes(bytes(dump))

        verifier = AesCbcVerifier()
        ct = verifier.create_ciphertext(key, VERIFICATION_PLAINTEXT, VERIFICATION_IV)

        args = argparse.Namespace(
            dump=str(dump_path),
            offset=0x200,
            length=32,
            ciphertext_hex=ct.hex(),
            iv_hex=None,
            cipher="AES-256-CBC",
            output=None,
            verbose=False,
        )
        rc = _cmd_verify(args)
        assert rc == 0  # Command succeeds but verified=false

    def test_verify_missing_dump(self):
        """Missing dump file should fail."""
        from memdiver.cli import _cmd_verify

        args = argparse.Namespace(
            dump="/nonexistent/dump.bin",
            offset=0x0,
            length=32,
            ciphertext_hex="aa" * 48,
            iv_hex=None,
            cipher="AES-256-CBC",
            output=None,
            verbose=False,
        )
        rc = _cmd_verify(args)
        assert rc == 1

    def test_verify_output_to_file(self, tmp_path):
        """Verify command writes JSON output to file."""
        from memdiver.cli import _cmd_verify
        from memdiver.engine.verification import AesCbcVerifier, VERIFICATION_PLAINTEXT, VERIFICATION_IV

        key = bytes(range(32))
        dump = bytearray(1024)
        dump[0x100:0x120] = key
        dump_path = tmp_path / "test.dump"
        dump_path.write_bytes(bytes(dump))

        verifier = AesCbcVerifier()
        ct = verifier.create_ciphertext(key, VERIFICATION_PLAINTEXT, VERIFICATION_IV)

        out_file = tmp_path / "result.json"
        args = argparse.Namespace(
            dump=str(dump_path),
            offset=0x100,
            length=32,
            ciphertext_hex=ct.hex(),
            iv_hex=None,
            cipher="AES-256-CBC",
            output=str(out_file),
            verbose=False,
        )
        rc = _cmd_verify(args)
        assert rc == 0
        result = json.loads(out_file.read_text())
        assert result["verified"] is True
        assert result["key_hex"] == key.hex()

    def test_verify_unknown_cipher(self, tmp_path):
        """Unknown cipher name should fail."""
        from memdiver.cli import _cmd_verify

        dump_path = tmp_path / "test.dump"
        dump_path.write_bytes(b"\x00" * 1024)

        args = argparse.Namespace(
            dump=str(dump_path),
            offset=0x0,
            length=32,
            ciphertext_hex="aa" * 48,
            iv_hex=None,
            cipher="UNKNOWN-CIPHER",
            output=None,
            verbose=False,
        )
        rc = _cmd_verify(args)
        assert rc == 1


# ---------------------------------------------------------------------------
# inspect — reading an encrypted .msl without a key must surface a diagnostic
# (non-zero exit + stderr message) instead of the old silent empty exit-0 (O-3).
# ---------------------------------------------------------------------------


def test_inspect_encrypted_msl_without_key_errors(tmp_path, capsys):
    """`inspect session-info` on an encrypted .msl with no key must fail loudly.

    Previously an undecryptable container looked like an empty capture and
    exited 0; O-3 now returns a non-zero rc and tags the result missing_key
    with an ``encrypted`` diagnostic on stderr.
    """
    import os

    import pytest

    from memdiver.msl import crypto
    from memdiver.msl.enums import EncAlgo

    if not crypto.cipher_is_available(EncAlgo.AES_256_GCM):
        pytest.skip("AES-256-GCM backend unavailable")

    from memdiver.cli import _cmd_inspect_session_info
    from memdiver.msl.writer import MslEncryptionConfig, MslWriter

    # Build an encrypted .msl with a random content-encryption key.
    key = os.urandom(32)
    msl_path = tmp_path / "encrypted.msl"
    cfg = MslEncryptionConfig(raw_key=key)
    w = MslWriter(msl_path, pid=7, encryption=cfg)
    w.add_memory_region(0x1000, b"\xCD" * 4096)
    w.add_end_of_capture()
    w.write()

    # Invoke `inspect session-info <path>` with NO decryption flags.
    args = argparse.Namespace(
        msl_path=str(msl_path),
        key_file=None,
        passphrase=None,
        kem_key_file=None,
        output=None,
    )
    rc = _cmd_inspect_session_info(args)

    # Non-zero exit + a diagnostic the operator can see.
    assert rc == 1
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result.get("tag_status") == "missing_key"
    assert "error" in result
    assert "encrypted" in captured.err


# ---------------------------------------------------------------------------
# Parser regression — emit-plugin and experiment subparsers must both build
# without one clobbering the other (formerly both bound to `ep`).
# ---------------------------------------------------------------------------


def test_parser_emit_plugin_and_experiment_independent():
    parser = _build_parser()

    emit = parser.parse_args([
        "emit-plugin", "--hit", "hits.json", "--reference", "ref.dump",
        "--name", "MyPlugin", "-o", "plugin.py",
    ])
    assert emit.command == "emit-plugin"
    assert emit.hit == "hits.json"
    assert emit.name == "MyPlugin"

    exp = parser.parse_args(["experiment", "--target", "sample.py"])
    assert exp.command == "experiment"
    assert exp.target == "sample.py"
    assert exp.num_runs == 30  # experiment-only default, proves no clobber


# ---------------------------------------------------------------------------
# gen-kem-key — private key must be written with owner-only perms and no
# partial keypair should survive a write failure.
# ---------------------------------------------------------------------------


def test_gen_kem_key_private_perms_and_atomicity(tmp_path):
    import stat
    import pytest

    from memdiver.cli import _cmd_gen_kem_key
    from memdiver.msl.crypto import kem_is_available
    from memdiver.msl.enums import KeyEncap

    if not kem_is_available(KeyEncap.X25519):
        pytest.skip("X25519 KEM unavailable in this environment")

    pub = tmp_path / "kem.pub"
    priv = tmp_path / "kem.key"
    args = argparse.Namespace(
        mechanism="X25519",
        public_out=str(pub),
        private_out=str(priv),
        verbose=False,
    )
    rc = _cmd_gen_kem_key(args)
    assert rc == 0
    assert pub.exists() and priv.exists()
    mode = stat.S_IMODE(priv.stat().st_mode)
    assert mode == 0o600, f"private key perms {oct(mode)} != 0o600"


def test_gen_kem_key_unwritable_private_no_partial(tmp_path):
    import pytest

    from memdiver.cli import _cmd_gen_kem_key
    from memdiver.msl.crypto import kem_is_available
    from memdiver.msl.enums import KeyEncap

    if not kem_is_available(KeyEncap.X25519):
        pytest.skip("X25519 KEM unavailable in this environment")

    pub = tmp_path / "kem.pub"
    # private_out points into a non-existent directory -> OSError on open.
    priv = tmp_path / "missing" / "kem.key"
    args = argparse.Namespace(
        mechanism="X25519",
        public_out=str(pub),
        private_out=str(priv),
        verbose=False,
    )
    rc = _cmd_gen_kem_key(args)
    assert rc == 1
    # No half-written keypair left behind.
    assert not priv.exists()
    assert not pub.exists()


# ---------------------------------------------------------------------------
# consensus-add — an all-zero folded dump should emit a warning.
# ---------------------------------------------------------------------------


def test_consensus_add_all_zero_dump_warns(tmp_path, caplog):
    import logging
    import numpy as np

    from memdiver.cli import _cmd_consensus_begin, _cmd_consensus_add

    state_path = tmp_path / "session.json"
    begin_args = argparse.Namespace(state=str(state_path), size=64)
    assert _cmd_consensus_begin(begin_args) == 0

    zero_dump = tmp_path / "zero.dump"
    zero_dump.write_bytes(b"\x00" * 64)
    add_args = argparse.Namespace(
        state=str(state_path),
        dump=str(zero_dump),
        key_file=None,
        passphrase=None,
        kem_key_file=None,
    )
    with caplog.at_level(logging.WARNING, logger="memdiver.cli"):
        rc = _cmd_consensus_add(add_args)
    assert rc == 0
    assert any("entirely zero bytes" in r.message for r in caplog.records)
