"""Tests for cli module."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from cli import _build_parser, _write_output

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
    from cli import _cmd_scan

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
    from cli import _cmd_analyze

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
    from cli import _cmd_analyze

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
    from cli import _cmd_batch

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
    from cli import _cmd_batch

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
    from cli import _cmd_analyze

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
        from cli import _cmd_verify
        from engine.verification import AesCbcVerifier, VERIFICATION_PLAINTEXT, VERIFICATION_IV

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
        from cli import _cmd_verify
        from engine.verification import AesCbcVerifier, VERIFICATION_PLAINTEXT, VERIFICATION_IV

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
        from cli import _cmd_verify

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
        from cli import _cmd_verify
        from engine.verification import AesCbcVerifier, VERIFICATION_PLAINTEXT, VERIFICATION_IV

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
        from cli import _cmd_verify

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
