"""Tiny gettext-style lookup. Reads ui/locales/<lang>.json once at import time.

If LANG env var sets a known locale, use it; otherwise default to English.
Missing keys fall through to the key itself, so the app never crashes on lookup.
"""
from __future__ import annotations
import json
import logging
import os
from pathlib import Path
from typing import Final

_LOCALES_DIR: Final = Path(__file__).resolve().parent / "locales"
_DEFAULT_LANG: Final = "en"
logger = logging.getLogger(__name__)

def _load(lang: str) -> dict[str, str]:
    path = _LOCALES_DIR / f"{lang}.json"
    try:
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        if lang != _DEFAULT_LANG:
            logger.warning("Locale %s not found; falling back to %s", lang, _DEFAULT_LANG)
            return _load(_DEFAULT_LANG)
        logger.warning("Default locale %s missing at %s", _DEFAULT_LANG, path)
        return {}
    except json.JSONDecodeError as exc:
        logger.warning("Failed to parse locale %s: %s", path, exc)
        return {}

_lang = (os.environ.get("MEMDIVER_LANG") or _DEFAULT_LANG).split(".")[0].lower()
_table: dict[str, str] = _load(_lang)

def _(key: str) -> str:
    """Look up `key` in the active locale; fall through to `key` if missing."""
    return _table.get(key, key)
