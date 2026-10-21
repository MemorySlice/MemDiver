"""Port resolution for ``memdiver web``.

The ``web`` subparser's ``--port`` used to default to 8080, which made the
documented ``MEMDIVER_PORT`` (and ``.env``) dead config: argparse always
supplied a value, so ``Settings.port`` was never consulted. The precedence is
now ``--port`` > ``MEMDIVER_PORT`` / ``.env`` > 8080.

``uvicorn.run`` and ``create_app`` are stubbed (same pattern as
tests/test_frontend_build.py) so nothing binds a socket; the port uvicorn
*would* have been given is captured instead.
"""

from __future__ import annotations

import argparse

import pytest

pytest.importorskip("uvicorn")

from memdiver.api.config import get_settings
from memdiver.cli import dataset as cli_dataset
from memdiver.cli.main import build_parser


@pytest.fixture
def served_port(tmp_path, monkeypatch):
    """Run ``_cmd_web`` against stubs and return the port uvicorn was given.

    CWD moves to ``tmp_path`` so a developer's real ``.env`` / ``config.json``
    cannot leak into ``Settings``; ``get_settings`` is cleared on both sides
    because ``_cmd_web`` writes the effective port onto the cached instance.
    """
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MEMDIVER_PORT", raising=False)
    monkeypatch.delenv("MEMDIVER_HOST", raising=False)
    get_settings.cache_clear()

    captured: dict = {}

    def fake_run(app, **kwargs):
        captured["port"] = kwargs["port"]

    monkeypatch.setattr("uvicorn.run", fake_run)
    monkeypatch.setattr("memdiver.api.main.create_app", lambda: object())
    # The prebuilt-bundle check is irrelevant here and reads the real tree.
    monkeypatch.setattr(
        "memdiver.api.frontend_build.frontend_build_warning", lambda: None
    )

    def run(args: argparse.Namespace) -> int:
        get_settings.cache_clear()  # pick up env set by the test body
        assert cli_dataset._cmd_web(args) == 0
        return captured["port"]

    yield run
    get_settings.cache_clear()


def test_explicit_port_beats_the_env_var(served_port, monkeypatch):
    monkeypatch.setenv("MEMDIVER_PORT", "9123")
    assert served_port(argparse.Namespace(port=9001)) == 9001


def test_env_var_applies_when_no_port_flag_is_given(served_port, monkeypatch):
    monkeypatch.setenv("MEMDIVER_PORT", "9123")
    assert served_port(argparse.Namespace(port=None)) == 9123


def test_falls_back_to_8080_with_neither(served_port):
    assert served_port(argparse.Namespace(port=None)) == 8080


def test_bare_memdiver_namespace_without_port_honours_env(served_port, monkeypatch):
    """Bare ``memdiver`` dispatches web with a Namespace that has no ``port``."""
    monkeypatch.setenv("MEMDIVER_PORT", "9123")
    assert served_port(argparse.Namespace()) == 9123


def test_dotenv_file_is_honoured(served_port, tmp_path):
    """``.env`` sits on the same rung as the env var (CWD is ``tmp_path``)."""
    (tmp_path / ".env").write_text("MEMDIVER_PORT=9234\n")
    assert served_port(argparse.Namespace(port=None)) == 9234


def test_effective_port_is_written_back_for_the_startup_log(served_port, monkeypatch):
    """api/main.py's lifespan logs ``settings.port`` -- it must match the bind."""
    monkeypatch.setenv("MEMDIVER_PORT", "9123")
    served_port(argparse.Namespace(port=9001))
    assert get_settings().port == 9001


def test_web_parser_leaves_port_unset_by_default():
    """The parser must not pre-fill 8080, or the env var is dead again."""
    args = build_parser().parse_args(["web"])
    assert args.port is None
    assert build_parser().parse_args(["web", "--port", "9001"]).port == 9001
