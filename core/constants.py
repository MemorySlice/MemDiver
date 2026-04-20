"""Project-wide mode constants and type aliases."""

import os
from pathlib import Path
from typing import Literal


def memdiver_home() -> Path:
    """Return the MemDiver user data directory (~/.memdiver).

    Respects XDG_DATA_HOME on Linux.
    Creates the directory if it doesn't exist.
    """
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        base = Path(xdg) / "memdiver"
    else:
        base = Path.home() / ".memdiver"
    base.mkdir(parents=True, exist_ok=True)
    return base

# UI mode
TESTING: Literal["testing"] = "testing"
RESEARCH: Literal["research"] = "research"
UIMode = Literal["testing", "research"]
UI_MODES = (TESTING, RESEARCH)

# Input mode
INPUT_FILE: Literal["single_file"] = "single_file"
INPUT_DIRECTORY: Literal["run_directory"] = "run_directory"
INPUT_DATASET: Literal["dataset"] = "dataset"
InputMode = Literal["single_file", "run_directory", "dataset"]
INPUT_MODES = (INPUT_FILE, INPUT_DIRECTORY, INPUT_DATASET)

# Algorithm mode
KNOWN_KEY: Literal["known_key"] = "known_key"
UNKNOWN_KEY: Literal["unknown_key"] = "unknown_key"
AlgorithmMode = Literal["known_key", "unknown_key"]
ALGORITHM_MODES = (KNOWN_KEY, UNKNOWN_KEY)
