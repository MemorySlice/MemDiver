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

    def test_verify_aead_key(self, tmp_path):
        """Verify a known AEAD (AES-256-GCM) key via nonce/tag against a record."""
        from memdiver.cli import _cmd_verify
        from memdiver.engine.verification import AesGcmVerifier

        key = bytes(range(32))
        dump = bytearray(1024)
        dump[0x100:0x120] = key
        dump_path = tmp_path / "test.dump"
        dump_path.write_bytes(bytes(dump))

        nonce = bytes(range(12))
        aad = b"header"
        # AEAD create_ciphertext returns ciphertext||tag (the on-record layout).
        verifier = AesGcmVerifier()
        ct = verifier.create_ciphertext(key, b"secret record", b"", nonce=nonce, aad=aad)

        args = argparse.Namespace(
            dump=str(dump_path),
            offset=0x100,
            length=32,
            ciphertext_hex=ct.hex(),
            iv_hex=None,
            nonce_hex=nonce.hex(),
            aad_hex=aad.hex(),
            tag_hex=None,
            cipher="AES-256-GCM",
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


# ---------------------------------------------------------------------------
# search-reduce — output carries the advisory recommended_floor (Phase 3).
# ---------------------------------------------------------------------------


def test_search_reduce_emits_recommended_floor(tmp_path):
    import json

    import numpy as np

    from memdiver.cli import (
        _cmd_consensus_add,
        _cmd_consensus_begin,
        _cmd_search_reduce,
    )

    size = 512
    state_path = tmp_path / "session.json"
    assert _cmd_consensus_begin(argparse.Namespace(state=str(state_path), size=size)) == 0

    rng = np.random.default_rng(5)
    base = rng.integers(0, 4, size, dtype=np.uint8)  # low-entropy shared background
    ref_dump = tmp_path / "d0.bin"
    for i in range(4):
        d = base.copy()
        d[256:288] = rng.integers(0, 256, 32, dtype=np.uint8)  # high-variance window
        p = tmp_path / f"d{i}.bin"
        p.write_bytes(d.tobytes())
        if i == 0:
            ref_dump = p
        assert _cmd_consensus_add(argparse.Namespace(
            state=str(state_path), dump=str(p),
            key_file=None, passphrase=None, kem_key_file=None)) == 0

    out_path = tmp_path / "candidates.json"
    rc = _cmd_search_reduce(argparse.Namespace(
        state=str(state_path), reference_dump=str(ref_dump),
        alignment=8, block_size=16, density_threshold=0.5,
        min_variance=100.0, entropy_window=16, entropy_threshold=3.5,
        min_region=8, output=str(out_path),
        key_file=None, passphrase=None, kem_key_file=None))
    assert rc == 0
    payload = json.loads(out_path.read_text())
    assert "recommended_floor" in payload
    assert payload["recommended_floor"] >= 0.0


# ---------------------------------------------------------------------------
# analyze-candidates — the exploratory path, reachable with no oracle (A4).
# ---------------------------------------------------------------------------


def test_parser_analyze_candidates_command():
    parser = _build_parser()
    args = parser.parse_args([
        "analyze-candidates", "/tmp/a.dump", "/tmp/b.dump",
        "--classes", "structural,pointer,key_candidate", "--min-region", "8",
    ])
    assert args.command == "analyze-candidates"
    assert args.dumps == ["/tmp/a.dump", "/tmp/b.dump"]
    assert args.classes == "structural,pointer,key_candidate"
    assert args.min_region == 8
    # Defaults that carry meaning: the floor is left to RESOLVE against
    # --classes (a wire default of 3000 would silently re-impose the
    # KEY_CANDIDATE cut the class query just widened), and the list comes back
    # best-first because an exploratory user reads the top of it.
    assert args.min_variance is None
    assert args.order == "rank"


def test_analyze_candidates_writes_a_ranked_payload(tmp_path, monkeypatch):
    """The handler routes through the shared producer and relays the full
    payload — regions, alignment provenance, resolved thresholds — to
    ``--output``."""
    import numpy as np

    from memdiver.cli import _cmd_analyze_candidates

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    rng = np.random.default_rng(3)
    background = rng.integers(0, 4, 8192, dtype=np.uint8)
    dumps = []
    for i in range(4):
        body = background.copy()
        body[2048:2096] = rng.integers(0, 256, 48, dtype=np.uint8)
        p = tmp_path / f"phase_{i}.dump"
        p.write_bytes(body.tobytes())
        dumps.append(str(p))

    out = tmp_path / "candidates.json"
    rc = _cmd_analyze_candidates(argparse.Namespace(
        dumps=dumps, classes="structural,pointer,key_candidate",
        min_variance=None, min_region=8, max_region=0,
        alignment=8, block_size=32, density_threshold=0.5,
        entropy_window=32, entropy_threshold=4.5,
        order="rank", max_returned=200, normalize=False, project_id="",
        output=str(out),
        key_file=None, passphrase=None, kem_key_file=None))

    assert rc == 0
    payload = json.loads(out.read_text())
    assert payload["num_dumps"] == 4
    assert payload["regions"][0]["offset"] == 2048
    assert payload["regions"][0]["rank"] == 1
    assert payload["alignment"]["method"] == "file_offset"
    assert payload["thresholds"]["min_variance"] == 0.0
    assert payload["warnings"] == []


# ---------------------------------------------------------------------------
# locate-key / export-key-pattern — the key-location spine (B1/B3).
# ---------------------------------------------------------------------------

#: 48 bytes, matching the real TLS 1.2 master-secret length.
_LK_SECRET = bytes(range(0x40, 0x40 + 48))


def _plant_locate_key_dumps(tmp_path, present: int = 2, total: int = 4) -> list:
    """``total`` dumps sharing one background; the secret in the first
    ``present`` of them at offset 2048 — the 2-of-N shape of real memory."""
    import numpy as np

    rng = np.random.default_rng(97)
    background = rng.integers(0, 4, 8192, dtype=np.uint8)
    paths = []
    for i in range(total):
        body = background.copy()
        if i < present:
            body[2048:2096] = np.frombuffer(_LK_SECRET, dtype=np.uint8)
        p = tmp_path / f"lk_{i}.dump"
        p.write_bytes(body.tobytes())
        paths.append(str(p))
    return paths


def _locate_key_args(dumps, output, **overrides):
    ns = dict(
        dumps=dumps, key_hex=_LK_SECRET.hex(), keylog_line=None,
        view=None, max_offsets=64, output=output,
        key_file=None, passphrase=None, kem_key_file=None,
    )
    ns.update(overrides)
    return argparse.Namespace(**ns)


def test_parser_locate_key_command():
    parser = _build_parser()
    args = parser.parse_args(
        ["locate-key", "/tmp/a.dump", "--key-hex", "aabbcc"])
    assert args.command == "locate-key"
    assert args.key_hex == "aabbcc"
    assert args.keylog_line is None
    assert args.max_offsets == 64
    assert args.view is None


def test_parser_locate_key_requires_exactly_one_input_form():
    """``--key-hex`` / ``--keylog-line`` are mutually exclusive AND required, so
    the CLI never reaches the producer's own check for these two cases."""
    import pytest

    parser = _build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["locate-key", "/tmp/a.dump"])
    with pytest.raises(SystemExit):
        parser.parse_args([
            "locate-key", "/tmp/a.dump", "--key-hex", "aa",
            "--keylog-line", "CLIENT_RANDOM 00 11"])


def test_parser_export_key_pattern_command():
    parser = _build_parser()
    args = parser.parse_args([
        "export-key-pattern", "/tmp/a.dump", "/tmp/b.dump",
        "--key-hex", "aabbcc", "--context", "32", "--include-window-hex",
    ])
    assert args.command == "export-key-pattern"
    assert args.context == 32
    assert args.include_window_hex is True
    # yara on the CLI, volatility3 in the producer — a documented per-surface
    # default divergence of the same kind as --order.
    assert args.format == "yara"
    assert args.name == "memdiver_key_pattern"
    assert args.min_static_ratio == 0.3


def test_locate_key_exits_zero_when_found(tmp_path, capsys):
    from memdiver.cli import _cmd_locate_key

    out = tmp_path / "located.json"
    rc = _cmd_locate_key(_locate_key_args(
        _plant_locate_key_dumps(tmp_path), str(out)))

    assert rc == 0
    payload = json.loads(out.read_text())
    assert payload["verdict"] == "found"
    assert (payload["dumps_present"], payload["dumps_absent"]) == (2, 2)
    # The verdict line and the diagnostics go to STDERR, so an operator piping
    # the JSON onward still sees the qualifications.
    err = capsys.readouterr().err
    assert "verdict=found" in err
    assert "Partial survival" in err


def test_locate_key_exits_three_when_absent(tmp_path, capsys):
    """``3`` is already ``_CLI_EXIT[NOT_FOUND]``, so this reuses the existing
    vocabulary instead of inventing a locate-key-specific code."""
    from memdiver.cli import _CLI_EXIT, _cmd_locate_key
    from memdiver.core.service_errors import ErrorCategory

    out = tmp_path / "absent.json"
    rc = _cmd_locate_key(_locate_key_args(
        _plant_locate_key_dumps(tmp_path, present=0), str(out)))

    assert rc == 3
    assert rc == _CLI_EXIT[ErrorCategory.NOT_FOUND]
    # The full payload is still written — a non-zero exit is a VERDICT, and the
    # census that produced it is exactly what the operator needs.
    payload = json.loads(out.read_text())
    assert payload["verdict"] == "absent"
    assert payload["dumps_searched"] == 4
    assert "verdict=absent" in capsys.readouterr().err


def test_locate_key_exits_two_when_nothing_was_searched(
    tmp_path, monkeypatch, capsys
):
    from memdiver.cli import _cmd_locate_key
    from memdiver.engine import key_location as key_location_module

    monkeypatch.setattr(
        key_location_module, "open_dump",
        lambda path, **kwargs: (_ for _ in ()).throw(OSError("unreadable")))

    out = tmp_path / "unknown.json"
    rc = _cmd_locate_key(_locate_key_args(
        _plant_locate_key_dumps(tmp_path), str(out)))

    assert rc == 2
    payload = json.loads(out.read_text())
    assert payload["verdict"] == "not_searched"
    # Never "absent": nothing was read, so nothing may be claimed.
    assert payload["verdict"] != "absent"
    assert payload["dumps_searched"] == 0
    assert "never searched" in capsys.readouterr().err


def test_locate_key_refuses_a_missing_dump_path(tmp_path, capsys):
    """A missing dump is INVALID_INPUT (exit 2), never a silent drop: answering
    ``absent`` over the remaining dumps would claim an absence nobody read."""
    import pytest

    from memdiver.cli import _CLI_EXIT, _cmd_locate_key
    from memdiver.core.service_errors import CapabilityError, ErrorCategory

    out = tmp_path / "never.json"
    dumps = _plant_locate_key_dumps(tmp_path, present=0)
    missing = str(tmp_path / "no_such.dump")
    with pytest.raises(CapabilityError) as excinfo:
        _cmd_locate_key(_locate_key_args(dumps + [missing], str(out)))

    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert _CLI_EXIT[excinfo.value.category] == 2
    assert missing in excinfo.value.message
    assert not out.exists()
    # No duplicate "skipping" warning: the error line is the only report.
    assert "skipping non-existent" not in capsys.readouterr().err


def test_locate_key_missing_dump_path_exits_two_through_main(
    tmp_path, monkeypatch, capsys
):
    import pytest

    from memdiver.cli import main

    out = tmp_path / "never.json"
    missing = str(tmp_path / "no_such.dump")
    monkeypatch.setattr(sys, "argv", [
        "memdiver", "locate-key", *_plant_locate_key_dumps(tmp_path), missing,
        "--key-hex", _LK_SECRET.hex(), "-o", str(out)])
    with pytest.raises(SystemExit) as excinfo:
        main()

    assert excinfo.value.code == 2
    assert not out.exists()
    assert (f"memdiver: ERROR — Dump path(s) not found: {missing}"
            in capsys.readouterr().err)


def test_locate_key_notes_unrecognised_files_and_still_searches(
    tmp_path, capsys
):
    """``x.bin`` matches no dump glob: noted on stderr, the ``.dump`` beside it
    is still searched; sidecars (``meta.json``) and dotfiles stay quiet."""
    from memdiver.cli import _cmd_locate_key

    run = tmp_path / "run"
    run.mkdir()
    _plant_locate_key_dumps(run, present=1, total=1)
    (run / "x.bin").write_bytes(b"\x00" * 16)
    (run / "meta.json").write_text("{}")
    (run / ".DS_Store").write_bytes(b"\x00")

    out = tmp_path / "located.json"
    rc = _cmd_locate_key(_locate_key_args([str(run)], str(out)))

    assert rc == 0
    assert json.loads(out.read_text())["dumps_searched"] == 1
    err = capsys.readouterr().err
    assert (f"memdiver: note — skipped 1 file(s) in {run} with unrecognised "
            f"extensions (e.g. x.bin)") in err
    assert "meta.json" not in err
    assert ".DS_Store" not in err


def test_scan_dump_inputs_classifies_without_printing(tmp_path, capsys):
    from memdiver.cli._shared import _scan_dump_inputs

    run = tmp_path / "run"
    run.mkdir()
    for name in ("a.dump", "b.gcore.core", "c.raw", "d.bin", "e.txt", ".hid"):
        (run / name).write_bytes(b"\x00")
    missing = str(tmp_path / "gone")

    inputs = _scan_dump_inputs([str(run), missing])

    # ``*.gcore.core`` overlaps ``*.core``: de-duplicated, as before.
    assert [p.name for p in inputs.paths] == ["a.dump", "b.gcore.core"]
    assert inputs.missing == [missing]
    assert [p.name for p in inputs.unrecognised[run]] == ["c.raw", "d.bin"]
    assert capsys.readouterr().err == ""


def test_resolve_dump_paths_warns_on_stderr_and_returns_paths(tmp_path, capsys):
    from memdiver.cli import _resolve_dump_paths

    dumps = _plant_locate_key_dumps(tmp_path, total=2)
    missing = str(tmp_path / "gone.dump")

    paths = _resolve_dump_paths([dumps[0], missing, dumps[1]])

    assert [str(p) for p in paths] == dumps
    err = capsys.readouterr().err
    assert f"memdiver: WARNING — skipping non-existent path: {missing}" in err


def test_locate_key_help_documents_exit_codes(capsys):
    import pytest

    with pytest.raises(SystemExit) as excinfo:
        _build_parser().parse_args(["locate-key", "--help"])

    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    assert "0  found — the secret is in at least one searched dump" in out
    assert "3  absent — every dump was searched, the secret is in none" in out
    assert "2  not searched — no dump could be searched" in out
    assert "missing dump path" in out
    assert "invalid input writes none." in out


def test_export_key_pattern_writes_the_pattern_and_warns(tmp_path, capsys):
    from memdiver.cli import _cmd_export_key_pattern

    out = tmp_path / "pattern.json"
    rc = _cmd_export_key_pattern(argparse.Namespace(
        dumps=_plant_locate_key_dumps(tmp_path),
        key_hex=_LK_SECRET.hex(), keylog_line=None,
        context=64, format="yara", name="lk_rule", min_static_ratio=0.3,
        view=None, output_dir=str(tmp_path / "rules"),
        include_window_hex=False, max_offsets=64, output=str(out),
        key_file=None, passphrase=None, kem_key_file=None))

    assert rc == 0
    payload = json.loads(out.read_text())
    assert payload["pattern"]["length"] == 176
    assert payload["region"]["key_offset_in_pattern"] == 64
    assert payload["key_wildcard_count"] == 48
    assert payload["mask_regions"] == 4
    assert (tmp_path / "rules" / "lk_rule.yar").is_file()
    err = capsys.readouterr().err
    assert "48/48 key bytes wildcarded" in err


def test_export_key_pattern_warns_when_the_rule_embeds_the_secret(
    tmp_path, capsys
):
    """Only the dumps that hold the key -> a 100 %-static rule. The operator
    must see that on stderr, because nothing in the payload's shape says it."""
    from memdiver.cli import _cmd_export_key_pattern

    out = tmp_path / "static.json"
    rc = _cmd_export_key_pattern(argparse.Namespace(
        dumps=_plant_locate_key_dumps(tmp_path, present=2, total=2),
        key_hex=_LK_SECRET.hex(), keylog_line=None,
        context=64, format="yara", name="static_rule", min_static_ratio=0.3,
        view=None, output_dir=None, include_window_hex=False,
        max_offsets=64, output=str(out),
        key_file=None, passphrase=None, kem_key_file=None))

    assert rc == 0
    payload = json.loads(out.read_text())
    assert payload["key_wildcard_count"] == 0
    err = capsys.readouterr().err
    assert "0/48 key bytes wildcarded" in err
    assert "verbatim" in err


# ---------------------------------------------------------------------------
# export — the --context knob applies to --auto ONLY (B4d).
# ---------------------------------------------------------------------------


def _export_args(dumps, **overrides):
    """A full ``export`` Namespace. ``context=None`` is the parser's default,
    i.e. "the flag was not supplied" — see ``_build_parser``."""
    ns = dict(
        dumps=dumps, offset=None, length=None, auto=False, context=None,
        format="json", name="ex_rule", min_static_ratio=0.3, align=False,
        output=None, key_file=None, passphrase=None, kem_key_file=None,
    )
    ns.update(overrides)
    return argparse.Namespace(**ns)


def test_parser_export_context_defaults_to_none_not_32():
    """The default MUST stay ``None``: with ``default=32`` the handler cannot
    tell an omitted flag from an explicit ``--context 32``, and the manual-path
    rejection would fire on every manual export."""
    from memdiver.cli.pipeline import DEFAULT_AUTO_EXPORT_CONTEXT

    parser = _build_parser()
    omitted = parser.parse_args(["export", "/tmp/a.dump", "/tmp/b.dump"])
    assert omitted.context is None
    supplied = parser.parse_args(
        ["export", "/tmp/a.dump", "/tmp/b.dump", "--context", "8"])
    assert supplied.context == 8
    # The 32 the flag used to carry now lives in the handler, unchanged.
    assert DEFAULT_AUTO_EXPORT_CONTEXT == 32


def test_export_manual_rejects_an_explicitly_supplied_context(tmp_path, capsys):
    """``manual_export_pattern`` has no ``context`` parameter and its contract is
    "the offset you gave me IS the key start", so the requested anchor bytes
    provably do not reach the pattern. Refuse, and name the command that does
    build a padded window."""
    from memdiver.cli import _cmd_export

    rc = _cmd_export(_export_args(
        _plant_locate_key_dumps(tmp_path), offset=0, length=64, context=32))

    assert rc == 1
    err = capsys.readouterr().err
    assert "export-key-pattern" in err
    assert "--context" in err
    # The message must point at the real alternative's input forms, not just
    # say "unsupported".
    assert "--key-hex" in err
    assert "--keylog-line" in err


def test_export_manual_never_claims_a_detection_or_a_context(tmp_path, capsys):
    """The manual path detects nothing and pads nothing. Before B4d it printed
    "Auto-detected region: ... context=32B" unconditionally — a knob it ignored
    and a detection that never happened."""
    from memdiver.cli import _cmd_export

    rc = _cmd_export(_export_args(
        _plant_locate_key_dumps(tmp_path), offset=0, length=64))

    assert rc == 0
    err = capsys.readouterr().err
    assert "Auto-detected" not in err
    assert "Auto-selected" not in err
    assert "context=" not in err
    # It says what actually happened instead.
    assert "Specified region: offset=0x0, 64 bytes" in err
    assert "pattern offset 0" in err


def test_export_manual_logs_without_the_auto_wording(tmp_path, caplog):
    """Same guarantee on the logger, which carried its own "Auto-selected"."""
    import logging

    from memdiver.cli import _cmd_export

    with caplog.at_level(logging.INFO, logger="memdiver.cli"):
        rc = _cmd_export(_export_args(
            _plant_locate_key_dumps(tmp_path), offset=0, length=64))

    assert rc == 0
    messages = "\n".join(r.getMessage() for r in caplog.records)
    assert "Auto-selected" not in messages
    assert "Specified region: offset=0x0 length=64" in messages


def _fake_auto_result():
    return {
        "format": "json",
        "content": "{}",
        "pattern": {"name": "ex_rule", "length": 128},
        "region": {"offset": 0x1000, "length": 128,
                   "key_start": 0x1020, "key_end": 0x1060},
    }


def test_export_auto_still_passes_the_default_32_and_the_auto_wording(
    tmp_path, monkeypatch, capsys
):
    """The --auto path is unchanged: an omitted --context still resolves to 32
    at the producer, and the auto wording still reports it."""
    from memdiver.app import tools_pipeline
    from memdiver.cli import _cmd_export

    seen = {}

    def _record(**kwargs):
        seen.update(kwargs)
        return _fake_auto_result()

    monkeypatch.setattr(tools_pipeline, "export_pattern", _record)

    rc = _cmd_export(_export_args(
        _plant_locate_key_dumps(tmp_path), auto=True))

    assert rc == 0
    assert seen["context"] == 32
    err = capsys.readouterr().err
    assert "Auto-detected region: offset=0x1000, 128 bytes" in err
    assert "context=32B" in err


def test_export_auto_forwards_an_explicit_context(tmp_path, monkeypatch, capsys):
    from memdiver.app import tools_pipeline
    from memdiver.cli import _cmd_export

    seen = {}
    monkeypatch.setattr(
        tools_pipeline, "export_pattern",
        lambda **kw: (seen.update(kw), _fake_auto_result())[1])

    rc = _cmd_export(_export_args(
        _plant_locate_key_dumps(tmp_path), auto=True, context=8))

    assert rc == 0
    assert seen["context"] == 8
    assert "context=8B" in capsys.readouterr().err


# --- import / import-dir region selection ----------------------------------


def _synth_core(path):
    from tests.fixtures import synth_elf_core
    from tests.test_region_select import _STACK_SP
    path.write_bytes(synth_elf_core.build_core_bytes(
        threads=[(101, _STACK_SP), (102, 0xDEAD0000)]))
    return path


def _run_import(argv, capsys):
    from memdiver.cli import _cmd_import, _cmd_import_dir
    args = _build_parser().parse_args(argv)
    handler = _cmd_import if args.command == "import" else _cmd_import_dir
    rc = handler(args)
    return rc, capsys.readouterr()


def test_parser_import_region_flags():
    args = _build_parser().parse_args([
        "import", "x.core", "--regions", "heap,stack", "--exclude-regions",
        "stack", "--list-regions", "--json", "--materialize", "-y"])
    assert (args.regions, args.exclude_regions) == ("heap,stack", "stack")
    assert args.list_regions and args.json and args.materialize and args.yes


def test_parser_import_region_flag_defaults():
    for argv in (["import", "x.core"], ["import-dir", "d", "-o", "o"]):
        args = _build_parser().parse_args(argv)
        assert args.regions is None and args.exclude_regions is None
        assert not (args.list_regions or args.json or args.materialize
                    or args.yes)


def test_import_non_tty_imports_everything(tmp_path, capsys):
    core = _synth_core(tmp_path / "t.core")
    rc, cap = _run_import(["import", str(core), "-o",
                           str(tmp_path / "o.msl")], capsys)
    assert rc == 0
    summary = json.loads(cap.out)
    assert summary["regions"] == 12
    assert "selection" not in summary  # unchanged shape
    assert cap.err == ""


def test_import_regions_heap_stack(tmp_path, capsys):
    core = _synth_core(tmp_path / "t.core")
    rc, cap = _run_import(["import", str(core), "-o", str(tmp_path / "o.msl"),
                           "--regions", "heap,stack"], capsys)
    assert rc == 0
    summary = json.loads(cap.out)
    assert summary["selection"] == "regions=heap,stack"
    assert summary["regions"] == 10
    assert summary["excluded_region_count"] == 2
    assert summary["excluded_bytes"] == 8192
    assert "excluded 2 region(s)" in cap.err


def test_import_bad_region_spec_exit_2(tmp_path, capsys):
    core = _synth_core(tmp_path / "t.core")
    rc, cap = _run_import(["import", str(core), "--regions", "bogus"], capsys)
    assert rc == 2
    assert "unknown region category" in cap.err
    assert not (tmp_path / "t.msl").exists()


def test_import_list_regions_table(tmp_path, capsys):
    core = _synth_core(tmp_path / "t.core")
    rc, cap = _run_import(["import", str(core), "--list-regions",
                           "--regions", "heap"], capsys)
    assert rc == 0
    assert "heap" in cap.out and "9 regions" in cap.out
    assert "excludes 3 region(s)" in cap.out
    assert "0x0000000000400000" not in cap.out  # region list needs -v
    assert not (tmp_path / "t.msl").exists()


def test_import_list_regions_verbose_and_json(tmp_path, capsys):
    core = _synth_core(tmp_path / "t.core")
    rc, cap = _run_import(["import", str(core), "--list-regions", "-v"],
                          capsys)
    assert rc == 0 and "0x0000000000400000" in cap.out
    rc, cap = _run_import(["import", str(core), "--list-regions", "--json",
                           "--regions", "heap,stack"], capsys)
    payload = json.loads(cap.out)
    assert payload["format"] == "elf_core"
    assert payload["totals"]["heap"]["count"] == 9
    assert payload["summary"]["excluded_count"] == 2


def test_import_interactive_prompt_used(tmp_path, capsys, monkeypatch):
    import memdiver.cli.import_selection as sel
    core = _synth_core(tmp_path / "t.core")
    monkeypatch.setattr(sel, "is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda: "")
    rc, cap = _run_import(["import", str(core), "-o", str(tmp_path / "o.msl")],
                          capsys)
    assert rc == 0
    summary = json.loads(cap.out)  # prompt text stays off stdout
    assert summary["selection"] == "regions=heap,stack,unclassified"
    assert "[x]" in cap.err


def test_import_yes_skips_prompt(tmp_path, capsys, monkeypatch):
    import memdiver.cli.import_selection as sel
    core = _synth_core(tmp_path / "t.core")
    monkeypatch.setattr(sel, "is_interactive", lambda: True)

    def _no_input():
        raise AssertionError("prompted despite --yes")
    monkeypatch.setattr("builtins.input", _no_input)
    rc, cap = _run_import(["import", str(core), "-o", str(tmp_path / "o.msl"),
                           "-y"], capsys)
    assert rc == 0 and json.loads(cap.out)["regions"] == 12


def test_import_interactive_cancel(tmp_path, capsys, monkeypatch):
    import memdiver.cli.import_selection as sel
    core = _synth_core(tmp_path / "t.core")
    monkeypatch.setattr(sel, "is_interactive", lambda: True)

    def _eof():
        raise EOFError
    monkeypatch.setattr("builtins.input", _eof)
    rc, cap = _run_import(["import", str(core), "-o", str(tmp_path / "o.msl")],
                          capsys)
    assert rc == 1 and "cancelled" in cap.err
    assert not (tmp_path / "o.msl").exists()


def test_import_dir_regions(tmp_path, capsys):
    run = tmp_path / "run"
    run.mkdir()
    _synth_core(run / "a.core")
    _synth_core(run / "b.core")
    out = tmp_path / "out"
    rc, cap = _run_import(["import-dir", str(run), "-o", str(out),
                           "--regions", "heap,stack"], capsys)
    assert rc == 0
    rows = json.loads(cap.out)
    assert len(rows) == 2
    assert all(r["selection"] == "regions=heap,stack" for r in rows)
    assert all(r["excluded_region_count"] == 2 for r in rows)
    assert cap.err.count("excluded 2 region(s)") == 2


def test_import_dir_default_shape_unchanged(tmp_path, capsys):
    run = tmp_path / "run"
    run.mkdir()
    _synth_core(run / "a.core")
    rc, cap = _run_import(["import-dir", str(run), "-o",
                           str(tmp_path / "out")], capsys)
    assert rc == 0
    (row,) = json.loads(cap.out)
    assert set(row) == {"source", "output", "key_hints"}


def test_import_dir_interactive_prompts_once(tmp_path, capsys, monkeypatch):
    import memdiver.cli.import_selection as sel
    run = tmp_path / "run"
    run.mkdir()
    _synth_core(run / "a.core")
    _synth_core(run / "b.core")
    calls = []
    monkeypatch.setattr(sel, "is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda: calls.append(1) or "heap")
    rc, cap = _run_import(["import-dir", str(run), "-o",
                           str(tmp_path / "out")], capsys)
    assert rc == 0 and len(calls) == 1
    assert "applied to all 2 dump(s)" in cap.err
    assert all(r["selection"] == "regions=heap" for r in json.loads(cap.out))


def test_import_dir_list_regions_json(tmp_path, capsys):
    run = tmp_path / "run"
    run.mkdir()
    _synth_core(run / "a.core")
    rc, cap = _run_import(["import-dir", str(run), "-o", str(tmp_path / "o"),
                           "--list-regions", "--json"], capsys)
    assert rc == 0
    (entry,) = json.loads(cap.out)
    assert entry["source"].endswith("a.core") and "totals" in entry
    assert not (tmp_path / "o").exists()
