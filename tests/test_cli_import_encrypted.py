"""CLI import / import-dir of an ENCRYPTED .msl: key flags, --decrypt-output,
TTY passphrase prompt, and a clear error when the key is missing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from memdiver.cli import _build_parser
from memdiver.msl.enums import KdfType, TagStatus
from memdiver.msl.importer import DECRYPTED_OUTPUT_WARNING
from memdiver.msl.reader import MslReader
from memdiver.msl.writer import MslEncryptionConfig

from tests.test_msl_materialize import _writer_built_msl

RAW_KEY = bytes(range(32))
KEPT = {0x10000000, 0x7FFF0000}  # heap + stack of _writer_built_msl


def _run(argv, capsys):
    from memdiver.cli import _cmd_import, _cmd_import_dir
    args = _build_parser().parse_args(argv)
    handler = _cmd_import if args.command == "import" else _cmd_import_dir
    rc = handler(args)
    return rc, capsys.readouterr()


@pytest.fixture
def raw_src(tmp_path):
    return _writer_built_msl(tmp_path, encryption=MslEncryptionConfig(
        raw_key=RAW_KEY))


@pytest.fixture
def key_file(tmp_path):
    path = tmp_path / "cek.bin"
    path.write_bytes(RAW_KEY)
    return path


def _bases(path, **km):
    with MslReader(Path(path), **km) as reader:
        assert reader.tag_status in (TagStatus.VALID, TagStatus.NOT_ENCRYPTED)
        return {r.base_addr for r in reader.collect_regions()}


def test_parser_accepts_key_flags_and_decrypt_output():
    for argv in (["import", "x.msl"], ["import-dir", "d", "-o", "o"]):
        args = _build_parser().parse_args(
            argv + ["--key-file", "k", "--passphrase", "p", "--kem-key-file",
                    "q", "--decrypt-output"])
        assert (args.key_file, args.passphrase, args.kem_key_file) == \
            ("k", "p", "q")
        assert args.decrypt_output
        assert not _build_parser().parse_args(argv).decrypt_output


def test_import_with_key_file_reencrypts(tmp_path, raw_src, key_file, capsys):
    out = tmp_path / "mat.msl"
    rc, cap = _run(["import", str(raw_src), "-o", str(out), "--regions",
                    "heap,stack", "--materialize", "-y", "--key-file",
                    str(key_file)], capsys)
    assert rc == 0
    summary = json.loads(cap.out)
    assert summary["reencrypted"] is True and summary["decrypted_output"] is False
    with MslReader(out) as locked:
        assert locked.tag_status is TagStatus.MISSING_KEY
    assert _bases(out, key=RAW_KEY) == KEPT
    assert RAW_KEY.hex() not in cap.out + cap.err


def test_import_decrypt_output_plaintext_warns(tmp_path, raw_src, key_file,
                                                capsys):
    out = tmp_path / "plain.msl"
    rc, cap = _run(["import", str(raw_src), "-o", str(out), "--regions",
                    "heap,stack", "--materialize", "-y", "--key-file",
                    str(key_file), "--decrypt-output"], capsys)
    assert rc == 0
    assert DECRYPTED_OUTPUT_WARNING in cap.err
    assert _bases(out) == KEPT


def test_import_missing_key_non_tty_errors(tmp_path, raw_src, capsys,
                                           monkeypatch):
    monkeypatch.setattr("memdiver.cli.import_keys.is_interactive",
                        lambda: False)
    out = tmp_path / "out.msl"
    rc, cap = _run(["import", str(raw_src), "-o", str(out), "--regions",
                    "heap,stack", "--materialize", "-y"], capsys)
    assert rc == 1
    assert "key material required" in cap.err and "--key-file" in cap.err
    assert not out.exists()


def test_import_wrong_key_errors(tmp_path, raw_src, capsys):
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"\x07" * 32)
    rc, cap = _run(["import", str(raw_src), "-o", str(tmp_path / "o.msl"),
                    "--regions", "heap,stack", "--materialize", "-y",
                    "--key-file", str(bad)], capsys)
    assert rc == 1 and "decryption failed" in cap.err


def test_import_prompts_for_passphrase_on_tty(tmp_path, capsys, monkeypatch):
    src = _writer_built_msl(tmp_path, encryption=MslEncryptionConfig(
        kdf_type=KdfType.ARGON2ID, passphrase=b"s3cret"))
    prompts = []
    monkeypatch.setattr("memdiver.cli.import_keys.is_interactive", lambda: True)
    monkeypatch.setattr("memdiver.cli.import_keys.getpass.getpass",
                        lambda prompt: prompts.append(prompt) or "s3cret")
    out = tmp_path / "mat.msl"
    rc, cap = _run(["import", str(src), "-o", str(out), "--regions",
                    "heap,stack", "--materialize", "-y"], capsys)
    assert rc == 0 and len(prompts) == 1
    assert "s3cret" not in cap.out + cap.err
    assert _bases(out, passphrase=b"s3cret") == KEPT


def test_no_prompt_without_materialize(tmp_path, raw_src, capsys, monkeypatch):
    monkeypatch.setattr("memdiver.cli.import_keys.is_interactive", lambda: True)
    monkeypatch.setattr("memdiver.cli.import_keys.getpass.getpass",
                        lambda prompt: pytest.fail("unexpected prompt"))
    out = tmp_path / "copy.msl"
    rc, _ = _run(["import", str(raw_src), "-o", str(out)], capsys)
    assert rc == 0 and out.read_bytes() == raw_src.read_bytes()


def test_list_regions_with_key(raw_src, key_file, capsys):
    rc, cap = _run(["import", str(raw_src), "--list-regions", "--json",
                    "--key-file", str(key_file)], capsys)
    assert rc == 0
    payload = json.loads(cap.out)
    assert payload["encrypted"] and payload["decrypted"]
    assert len(payload["regions"]) == 3


def test_import_dir_threads_key(tmp_path, raw_src, key_file, capsys):
    run = tmp_path / "run"
    run.mkdir()
    raw_src.rename(run / "a.dump")
    rc, cap = _run(["import-dir", str(run), "-o", str(tmp_path / "out"),
                    "--regions", "heap,stack", "--materialize", "-y",
                    "--key-file", str(key_file)], capsys)
    assert rc == 0
    (row,) = json.loads(cap.out)
    assert row["reencrypted"] is True
    assert _bases(row["output"], key=RAW_KEY) == KEPT
