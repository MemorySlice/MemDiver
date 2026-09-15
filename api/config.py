"""Pydantic Settings for the MemDiver FastAPI backend."""

from __future__ import annotations

import json
import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import cast
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("memdiver.api.config")


def _cpu_workers() -> int:
    """Return sensible default worker count (1..4)."""
    return max(1, min(4, (os.cpu_count() or 2) - 1))


def _default_db_path() -> Path:
    from memdiver.engine.project_db import default_db_path
    return default_db_path()


def _default_session_dir() -> Path:
    from memdiver.engine.session_store import SessionStore
    return SessionStore.default_dir()


def _default_task_root() -> Path:
    return Path.home() / ".memdiver" / "tasks"


def _upload_dir_from_user_config() -> Path | None:
    """Return the upload dir the user chose previously, or ``None`` if unset."""
    from memdiver.api.upload_dir import read_user_upload_dir
    return read_user_upload_dir()


def _oracle_dir_from_user_config() -> Path | None:
    """Return the oracle dir the user consented to previously, else ``None``."""
    from memdiver.api.oracle_dir import read_user_oracle_dir
    return read_user_oracle_dir()


class Settings(BaseSettings):
    """MemDiver API configuration with env-var and .env support."""

    model_config = SettingsConfigDict(
        env_prefix="MEMDIVER_",
        env_file=".env",
        env_file_encoding="utf-8",
    )

    host: str = "127.0.0.1"
    port: int = 8080
    max_workers: int = _cpu_workers()
    max_rss_mb: int = 4096
    dataset_root: str = ""
    db_path: Path = Path("")
    # Configure-on-first-use (B0). ``upload_dir`` is not only where uploads land
    # — it is the containment root every write-path check measures against
    # (api/path_safety.ensure_within), so the unconfigured state must fail
    # CLOSED. It therefore gets ``None``, not the ``Path("")`` sentinel its
    # siblings below use: ``Path("") / "pcaps"`` is the *relative* path
    # ``pcaps``, so an unguarded consumer would silently write into the server's
    # CWD, whereas ``None / "pcaps"`` is a loud TypeError. In-class precedent:
    # ``oracle_dir`` below. The guarded entry point is
    # api.dependencies.upload_dir_or_409.
    upload_dir: Path | None = None
    session_dir: Path = Path("")
    config_path: Path = Path("config.json")
    cors_origins: list[str] = ["http://localhost:5173"]

    # API authentication (Phase 2.5). api_token stays None by default so the
    # API remains open — every existing test fixture and local single-user
    # workflow relies on that no-auth posture. allow_insecure is the explicit,
    # loud opt-out for the non-loopback bind guardrail (see api/security.py).
    api_token: str | None = None
    allow_insecure: bool = False

    # Phase 25 pipeline substrate
    oracle_dir: Path | None = None
    task_root: Path = Path("")
    task_quota_bytes: int = 5 * 2**30  # 5 GiB
    pipeline_max_workers: int = 2

    # Aggregate cap for the persisted pcap upload dir (upload_dir/pcaps). Unlike
    # task artifacts, captures are never GC'd by the task store, so without a cap
    # the dir is an unbounded disk-exhaustion vector. 5 GiB mirrors
    # ``task_quota_bytes`` — ~10 captures at the 512 MiB PCAP_UPLOAD_MAX_BYTES
    # ceiling. Override with ``MEMDIVER_PCAP_QUOTA_BYTES``; <=0 disables pruning.
    pcap_quota_bytes: int = 5 * 2**30  # 5 GiB

    # Aggregate cap for the imported-dump directory (``upload_dir/imports``, or
    # ``memdiver_home()/imports`` when no upload dir has been chosen). Imported
    # ``.msl`` containers are referenced by server path for the life of a
    # session and nothing else ever reclaims them, so the directory is capped
    # the same way the pcap one is. 5 GiB mirrors ``pcap_quota_bytes``.
    # Override with ``MEMDIVER_DUMP_QUOTA_BYTES``; <=0 disables pruning.
    dump_quota_bytes: int = 5 * 2**30  # 5 GiB

    @model_validator(mode="after")
    def _apply_defaults_and_config(self) -> "Settings":
        """Load config.json defaults and resolve factory paths."""
        if self.db_path == Path(""):
            self.db_path = _default_db_path()
        if self.session_dir == Path(""):
            self.session_dir = _default_session_dir()
        if self.task_root == Path(""):
            self.task_root = _default_task_root()
        # Merge dataset_root from config.json when not set via env
        if not self.dataset_root and self.config_path.is_file():
            try:
                data = json.loads(self.config_path.read_text())
                self.dataset_root = data.get("dataset_root", "")
                logger.info("Loaded dataset_root from %s", self.config_path)
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to read %s: %s", self.config_path, exc)
        # upload_dir resolution: MEMDIVER_UPLOAD_DIR / .env (already applied by
        # pydantic-settings above) always wins > the user-local config file >
        # unconfigured (None).
        #
        # Note the deliberate asymmetry with dataset_root just above:
        # dataset_root merges from ``self.config_path`` — the repo-root,
        # GIT-TRACKED config.json — while upload_dir merges from
        # ``memdiver_home()/config.json``, the user-local untracked file, and
        # never from the tracked one. upload_dir is the only field the *server*
        # writes (see api/routers/settings.py), and writing a tracked file would
        # dirty every clone.
        if self.upload_dir is not None and self.upload_dir == Path("."):
            # MEMDIVER_UPLOAD_DIR="" parses to Path(".") -- the server CWD --
            # because env_ignore_empty is False. Treat it as unset, loudly.
            logger.warning(
                "MEMDIVER_UPLOAD_DIR is empty; treating upload_dir as unconfigured"
            )
            self.upload_dir = None
        if self.upload_dir is None:
            self.upload_dir = _upload_dir_from_user_config()
        # oracle_dir resolves by exactly the same precedence, and for the same
        # reasons: MEMDIVER_ORACLE_DIR / .env wins > the user-local config file
        # > unconfigured (None, meaning oracle execution stays disabled).
        # Unlike upload_dir there is no legacy value to migrate — the setting
        # simply had no runtime affordance before, only the env var.
        if self.oracle_dir is not None and self.oracle_dir == Path("."):
            # MEMDIVER_ORACLE_DIR="" parses to Path(".") -- the server CWD --
            # because env_ignore_empty is False. Treating that as *enabled*
            # would drop executable oracles into whatever directory the server
            # happened to start in, so treat it as unset, loudly.
            logger.warning(
                "MEMDIVER_ORACLE_DIR is empty; treating oracle_dir as unconfigured"
            )
            self.oracle_dir = None
        if self.oracle_dir is None:
            self.oracle_dir = _oracle_dir_from_user_config()
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached singleton Settings instance."""
    return Settings()


def env_pinned(var_name: str) -> bool:
    """Return True if *var_name* pins a setting outside the UI's control.

    Checks the process environment *and* the ``.env`` file, because
    pydantic-settings applies both ahead of the user config file — persisting a
    value that would then be silently shadowed forever is worse than refusing.

    Lives here rather than in a router because it now has two callers with the
    same question about two different variables: the upload-dir settings router
    (``MEMDIVER_UPLOAD_DIR``) and the oracle router (``MEMDIVER_ORACLE_DIR``).
    """
    if os.environ.get(var_name, "").strip():
        return True
    # pydantic-settings types ``env_file`` as a path OR a sequence of them;
    # Settings pins it to the single string ".env", so one path is what comes
    # back. The cast documents that rather than widening the runtime handling.
    configured = get_settings().model_config.get("env_file") or ".env"
    env_file = Path(cast("str | os.PathLike[str]", configured))
    try:
        for line in env_file.read_text().splitlines():
            key, _, value = line.partition("=")
            if key.strip() == var_name and value.strip().strip("'\""):
                return True
    except OSError:
        pass
    return False
