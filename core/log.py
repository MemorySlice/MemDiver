"""Centralized logging configuration for MemDiver."""

import json
import logging
import sys
from pathlib import Path
from typing import Optional


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    config_path: Optional[Path] = None,
) -> logging.Logger:
    """Configure the memdiver logger hierarchy.

    Args:
        level: Logging level string (DEBUG, INFO, WARNING, ERROR).
        log_file: Optional path to a log file.
        config_path: Optional path to config.json to read settings from.

    Returns:
        The root 'memdiver' logger.
    """
    if config_path and config_path.exists():
        with open(config_path) as f:
            cfg = json.load(f)
        log_cfg = cfg.get("logging", {})
        level = log_cfg.get("level", level)
        log_file = log_cfg.get("file", log_file)

    root_logger = logging.getLogger("memdiver")
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    if not root_logger.handlers:
        fmt = logging.Formatter(
            "%(asctime)s %(name)s %(levelname)s %(message)s",
            datefmt="%H:%M:%S",
        )
        console = logging.StreamHandler(sys.stderr)
        console.setFormatter(fmt)
        root_logger.addHandler(console)

        if log_file:
            fh = logging.FileHandler(log_file)
            fh.setFormatter(fmt)
            root_logger.addHandler(fh)

    return root_logger
