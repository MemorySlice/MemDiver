"""Pydantic Settings for the MemDiver FastAPI backend."""

from __future__ import annotations

import json
import logging
import os
from functools import lru_cache
from pathlib import Path
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("memdiver.api.config")


def _cpu_workers() -> int:
    """Return sensible default worker count (1..4)."""
    return max(1, min(4, (os.cpu_count() or 2) - 1))


def _default_db_path() -> Path:
    from engine.project_db import default_db_path
    return default_db_path()


def _default_session_dir() -> Path:
    from engine.session_store import SessionStore
    return SessionStore.default_dir()


def _default_task_root() -> Path:
    return Path.home() / ".memdiver" / "tasks"


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
    upload_dir: Path = Path("/tmp/memdiver_uploads")
    session_dir: Path = Path("")
    config_path: Path = Path("config.json")
    cors_origins: list[str] = ["http://localhost:5173"]

    # Phase 25 pipeline substrate
    oracle_dir: Path | None = None
    task_root: Path = Path("")
    task_quota_bytes: int = 5 * 2**30  # 5 GiB
    pipeline_max_workers: int = 2

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
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached singleton Settings instance."""
    return Settings()
