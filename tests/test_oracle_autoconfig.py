"""Tests for ``app.oracle_autoconfig``.

Each test builds its own throwaway corpus (run dir + ``meta.json`` + a vault)
under ``tmp_path`` rather than reaching for the bundled example, so the rules
under test stay readable next to the assertion that exercises them.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from memdiver.app.oracle_autoconfig import (
    RESERVED_TABLE,
    VAULT_CONTENT_FILE,
    AutofillRule,
    ConfigSuggestion,
    ExampleAutomation,
    load_example_automation,
    split_reserved,
    suggest_example_config,
)

EXAMPLE_TOML = """\
sample_ciphertext = "/absolute/path/to/your/vault/<any-encrypted-file>"

[memdiver]
requires_cipher = "aes"

[memdiver.autofill.sample_ciphertext]
strategy = "vault_content_file"
exclude = ["gocryptfs.conf", "gocryptfs.diriv"]
"""


# -- Fixtures ------------------------------------------------------------------


def _write_example(tmp_path: Path, toml_text: str = EXAMPLE_TOML) -> Path:
    """An oracle example `.py` plus the sibling `.toml` the module reads."""
    example = tmp_path / "gocryptfs.py"
    example.write_text("def verify(candidate: bytes) -> bool:\n    return False\n")
    example.with_suffix(".toml").write_text(toml_text)
    return example


def _make_run(
    tmp_path: Path,
    run_id: str,
    *,
    cipher: str = "aes",
    content_names: tuple[str, ...] = ("jxSMOg-V7hYDb5UsGpxWxg",),
    declare_vault: bool = True,
    with_meta: bool = True,
    vault_declaration: str = "cipher",
) -> Path:
    """One corpus run directory; returns the dump inside it."""
    run_dir = tmp_path / run_id
    vault = run_dir / "cipher"
    vault.mkdir(parents=True)
    (vault / "gocryptfs.conf").write_text("{}")
    (vault / "gocryptfs.diriv").write_bytes(b"\x00" * 16)
    for name in content_names:
        (vault / name).write_bytes(b"ciphertext")

    dump = run_dir / "memslicer.msl"
    dump.write_bytes(b"\x00" * 64)

    if with_meta:
        payload = {
            "run_id": run_id,
            "cipher": cipher,
            "password": "hunter2",
            "master_key_hex": "00" * 32,
            "aslr_base": 0,
            "pid": 1234,
            "dumps": {},
        }
        if declare_vault:
            payload["vault_cipher_dir"] = vault_declaration
        (run_dir / "meta.json").write_text(json.dumps(payload))
    return dump


@pytest.fixture()
def example(tmp_path: Path) -> Path:
    return _write_example(tmp_path)


# -- split_reserved / load_example_automation ----------------------------------


def test_split_reserved_separates_template_from_reserved_table():
    config, reserved = split_reserved(
        {"sample_ciphertext": "/x", RESERVED_TABLE: {"requires_cipher": "aes"}}
    )
    assert config == {"sample_ciphertext": "/x"}
    assert reserved == {"requires_cipher": "aes"}


def test_split_reserved_without_reserved_table_returns_template_unchanged():
    config, reserved = split_reserved({"sample_ciphertext": "/x"})
    assert config == {"sample_ciphertext": "/x"}
    assert reserved == {}


def test_load_example_automation_parses_cipher_and_nested_rule(example: Path):
    automation = load_example_automation(example.with_suffix(".toml"))
    assert automation == ExampleAutomation(
        requires_cipher="aes",
        autofill={
            "sample_ciphertext": AutofillRule(
                strategy=VAULT_CONTENT_FILE,
                exclude=("gocryptfs.conf", "gocryptfs.diriv"),
            )
        },
    )


def test_load_example_automation_missing_file_is_empty(tmp_path: Path):
    assert load_example_automation(tmp_path / "nope.toml") == ExampleAutomation()


# -- The reference-run rule (fact 1) -------------------------------------------


def test_derives_from_first_source_not_a_later_one(tmp_path: Path, example: Path):
    """Only ``source_paths[0]`` is ever verified, so only its vault may be used."""
    first = _make_run(tmp_path, "run_0001", content_names=("first_file",))
    second = _make_run(tmp_path, "run_0002", content_names=("second_file",))

    suggestion = suggest_example_config(example, [str(first), str(second)])

    assert suggestion.config["sample_ciphertext"].endswith("run_0001/cipher/first_file")
    assert suggestion.reference_run == "run_0001"
    assert suggestion.reference_dump == str(first)
    assert "run_0001" in (suggestion.provenance or "")


def test_multi_run_selection_warns_and_names_the_reference_run(
    tmp_path: Path, example: Path
):
    first = _make_run(tmp_path, "run_0001", content_names=("first_file",))
    second = _make_run(tmp_path, "run_0002", content_names=("second_file",))

    suggestion = suggest_example_config(example, [str(first), str(second)])

    assert suggestion.config, "a multi-run selection is a warning, not a blocker"
    assert len(suggestion.warnings) == 1
    assert "run_0001" in suggestion.warnings[0]


def test_single_run_selection_is_not_warned_about(tmp_path: Path, example: Path):
    dump = _make_run(tmp_path, "run_0001")
    other_dump_same_run = dump.parent / "gcore.core"
    other_dump_same_run.write_bytes(b"\x00")

    suggestion = suggest_example_config(
        example, [str(dump), str(other_dump_same_run)]
    )

    assert suggestion.warnings == []
    assert suggestion.config


# -- Vault listing rules -------------------------------------------------------


def test_gocryptfs_metadata_files_are_excluded(tmp_path: Path, example: Path):
    dump = _make_run(tmp_path, "run_0001", content_names=("payload.bin",))

    suggestion = suggest_example_config(example, [str(dump)])

    filled = Path(suggestion.config["sample_ciphertext"])
    assert filled.name == "payload.bin"
    assert suggestion.warnings == []


def test_two_content_files_fill_nothing_and_warn(tmp_path: Path, example: Path):
    dump = _make_run(tmp_path, "run_0001", content_names=("file_a", "file_b"))

    suggestion = suggest_example_config(example, [str(dump)])

    assert suggestion.config == {}
    assert suggestion.provenance is None
    assert len(suggestion.warnings) == 1
    assert str(dump.parent / "cipher") in suggestion.warnings[0]


def test_empty_vault_fills_nothing_and_warns(tmp_path: Path, example: Path):
    dump = _make_run(tmp_path, "run_0001", content_names=())

    suggestion = suggest_example_config(example, [str(dump)])

    assert suggestion.config == {}
    assert len(suggestion.warnings) == 1


def test_dot_files_and_subdirectories_are_ignored(tmp_path: Path, example: Path):
    dump = _make_run(tmp_path, "run_0001", content_names=("payload.bin",))
    vault = dump.parent / "cipher"
    (vault / ".DS_Store").write_bytes(b"junk")
    (vault / "subdir").mkdir()

    suggestion = suggest_example_config(example, [str(dump)])

    assert Path(suggestion.config["sample_ciphertext"]).name == "payload.bin"


# -- Cipher mismatch (fact 2) --------------------------------------------------


def test_cipher_mismatch_blocks_and_names_both_ciphers(tmp_path: Path, example: Path):
    dump = _make_run(tmp_path, "run_0001", cipher="xchacha")

    suggestion = suggest_example_config(example, [str(dump)])

    assert suggestion.config == {}
    assert suggestion.blocked_reason is not None
    assert "xchacha" in suggestion.blocked_reason
    assert "aes" in suggestion.blocked_reason
    assert "run_0001" in suggestion.blocked_reason
    assert suggestion.reference_run == "run_0001"


def test_cipher_match_is_case_insensitive(tmp_path: Path, example: Path):
    dump = _make_run(tmp_path, "run_0001", cipher="AES")

    suggestion = suggest_example_config(example, [str(dump)])

    assert suggestion.blocked_reason is None
    assert suggestion.config


def test_example_without_requires_cipher_never_blocks(tmp_path: Path):
    example = _write_example(
        tmp_path,
        """\
sample_ciphertext = "/x"

[memdiver.autofill.sample_ciphertext]
strategy = "vault_content_file"
exclude = ["gocryptfs.conf", "gocryptfs.diriv"]
""",
    )
    dump = _make_run(tmp_path, "run_0001", cipher="xchacha")

    suggestion = suggest_example_config(example, [str(dump)])

    assert suggestion.blocked_reason is None
    assert suggestion.config


# -- Every underivable input is an empty suggestion, never an exception --------


def test_empty_source_paths_yields_empty_suggestion(example: Path):
    assert suggest_example_config(example, []) == ConfigSuggestion()


def test_missing_meta_json_yields_empty_suggestion(tmp_path: Path, example: Path):
    dump = _make_run(tmp_path, "run_0001", with_meta=False)

    suggestion = suggest_example_config(example, [str(dump)])

    assert suggestion.config == {}
    assert suggestion.blocked_reason is None
    assert suggestion.reference_run is None


def test_run_without_vault_declaration_yields_empty_suggestion(
    tmp_path: Path, example: Path
):
    dump = _make_run(tmp_path, "run_0001", declare_vault=False)

    suggestion = suggest_example_config(example, [str(dump)])

    assert suggestion.config == {}
    assert suggestion.blocked_reason is None
    assert suggestion.warnings == []
    assert suggestion.reference_run == "run_0001"


def test_declared_vault_that_does_not_exist_yields_empty_suggestion(
    tmp_path: Path, example: Path
):
    dump = _make_run(tmp_path, "run_0001")
    for entry in sorted((dump.parent / "cipher").iterdir()):
        entry.unlink()
    (dump.parent / "cipher").rmdir()

    suggestion = suggest_example_config(example, [str(dump)])

    assert suggestion.config == {}
    assert suggestion.blocked_reason is None


def test_dataset_root_relative_vault_declaration_is_derived(
    tmp_path: Path, example: Path
):
    """The shipped corpus writes ``"run_0001/cipher"`` -- relative to the DATASET ROOT.

    Regression guard for the defect this feature was one commit away from
    shipping with: ``vault_cipher_dir`` is written exactly like the ``dumps``
    entries beside it, so a run-dir-only resolver looks for
    ``run_0001/run_0001/cipher`` and derives nothing for EVERY run in the real
    dataset -- while every synthetic fixture using the bare ``cipher`` spelling
    stays green. Both spellings must work.
    """
    dump = _make_run(tmp_path, "run_0001", vault_declaration="run_0001/cipher")

    suggestion = suggest_example_config(example, [str(dump)])

    assert suggestion.config == {
        "sample_ciphertext": str(tmp_path / "run_0001" / "cipher" / "jxSMOg-V7hYDb5UsGpxWxg")
    }
    assert suggestion.blocked_reason is None


def test_vault_declaration_escaping_the_run_dir_yields_empty_suggestion(
    tmp_path: Path, example: Path
):
    """Corpus-authored data may not point the resolver outside the dataset.

    The traversal guard rejects it, so the analyst fills the field by hand
    rather than meeting a traceback -- or, worse, an oracle configured from a
    file the corpus never meant to name.
    """
    dump = _make_run(tmp_path, "run_0001", vault_declaration="../../elsewhere")

    suggestion = suggest_example_config(example, [str(dump)])

    assert suggestion.config == {}
    assert suggestion.blocked_reason is None


def test_missing_sibling_toml_yields_empty_suggestion(tmp_path: Path):
    example = tmp_path / "lonely.py"
    example.write_text("def verify(candidate):\n    return False\n")
    dump = _make_run(tmp_path, "run_0001")

    suggestion = suggest_example_config(example, [str(dump)])

    assert suggestion.config == {}
    assert suggestion.blocked_reason is None


def test_unknown_strategy_is_ignored(tmp_path: Path):
    example = _write_example(
        tmp_path,
        """\
sample_ciphertext = "/x"

[memdiver.autofill.sample_ciphertext]
strategy = "ask_the_oracle_nicely"
""",
    )
    dump = _make_run(tmp_path, "run_0001")

    suggestion = suggest_example_config(example, [str(dump)])

    assert suggestion.config == {}
    assert suggestion.blocked_reason is None
    assert suggestion.warnings == []


def test_malformed_toml_yields_empty_suggestion(tmp_path: Path):
    example = _write_example(tmp_path, "this is not = = valid toml\n")
    dump = _make_run(tmp_path, "run_0001")

    suggestion = suggest_example_config(example, [str(dump)])

    assert suggestion.config == {}
    assert suggestion.blocked_reason is None
