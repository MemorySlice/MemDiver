"""Guard against drift between the argparse CLI and the handwritten docs.

GitHub issue #27: the ``locate-key`` subcommand was missing from README.md and
the docs because the handwritten subcommand lists drifted from the parser in
``cli/main.py``. These tests derive the subcommand names from ``build_parser()``
and assert every one is documented, and that the auto-generated CLI reference
page still points at an importable parser factory.
"""
import argparse
import importlib
import re
import sys
from pathlib import Path

import pytest

from memdiver.cli import build_parser

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"
QUICKSTART_CLI = REPO_ROOT / "docs" / "quickstart" / "cli.md"
CLI_REFERENCE = REPO_ROOT / "docs" / "user_guide" / "cli_reference.md"
LOCATE_KEY_GUIDE = REPO_ROOT / "docs" / "user_guide" / "locate_key.md"
DOCS_INDEX = REPO_ROOT / "docs" / "index.md"

SUBCOMMAND_DOCS = [README, QUICKSTART_CLI]


def _top_level_subcommands() -> list[str]:
    parser = build_parser()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return sorted(action.choices)
    raise AssertionError("build_parser() defines no subcommands")


def _toctree_entries(markdown: str) -> set[str]:
    blocks = re.findall(r"```\{toctree\}(.*?)```", markdown, flags=re.DOTALL)
    return {
        line.strip()
        for block in blocks
        for line in block.splitlines()
        if line.strip() and not line.strip().startswith(":")
    }


def test_parser_exposes_subcommands():
    assert "locate-key" in _top_level_subcommands()


@pytest.mark.parametrize("doc_path", SUBCOMMAND_DOCS, ids=lambda p: p.name)
@pytest.mark.parametrize("subcommand", _top_level_subcommands())
def test_subcommand_is_documented(subcommand, doc_path):
    text = doc_path.read_text(encoding="utf-8")
    assert f"`{subcommand}`" in text, (
        f"`{subcommand}` is missing from {doc_path.relative_to(REPO_ROOT)}"
    )


def test_cli_reference_uses_argparse_directive():
    text = CLI_REFERENCE.read_text(encoding="utf-8")
    assert ".. argparse::" in text
    assert re.search(r"^\s*:func:\s*build_parser\s*$", text, flags=re.MULTILINE)


def test_cli_reference_module_exposes_build_parser(monkeypatch):
    text = CLI_REFERENCE.read_text(encoding="utf-8")
    match = re.search(r"^\s*:module:\s*(\S+)\s*$", text, flags=re.MULTILINE)
    assert match, "argparse directive has no :module: option"
    monkeypatch.setattr(sys, "path", [str(REPO_ROOT), *sys.path])
    module = importlib.import_module(match.group(1))
    assert callable(getattr(module, "build_parser", None))


def test_locate_key_guide_exists():
    assert LOCATE_KEY_GUIDE.is_file()


def test_locate_key_guide_is_in_toctree():
    entries = _toctree_entries(DOCS_INDEX.read_text(encoding="utf-8"))
    assert "user_guide/locate_key" in entries
