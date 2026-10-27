"""Persistence of :class:`AgentSettings` through injected pref callables.

The API layer passes ``api.user_prefs.read_pref`` / ``write_pref``; this module never
imports ``api``. Invalid stored data falls back to defaults and raises a warning flag.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Mapping, Optional, Tuple

from .contracts import AgentSettings

logger = logging.getLogger(__name__)

PREF_KEY = "agent_chat"

ReadPref = Callable[[str, Any], Any]
WritePref = Callable[[str, Any], None]


def load_settings(read_pref: ReadPref) -> Tuple[AgentSettings, bool]:
    """``(settings, warning)``; warning is True when stored data was invalid."""
    stored = read_pref(PREF_KEY, None)
    if stored is None:
        return AgentSettings(), False
    try:
        if not isinstance(stored, dict):
            raise ValueError("stored agent_chat settings are not an object")
        return AgentSettings().merged(stored), False
    except (ValueError, TypeError) as exc:
        logger.warning("Ignoring invalid agent_chat settings: %s", exc)
        return AgentSettings(), True


def save_settings(write_pref: WritePref, changes: Mapping[str, Any],
                  current: Optional[AgentSettings] = None) -> AgentSettings:
    """Merge ``changes`` into ``current``, validate, persist, return the result.

    Raises ``ValueError`` (nothing written) for unknown or out-of-bounds values.
    """
    updated = (current or AgentSettings()).merged(changes)
    write_pref(PREF_KEY, updated.to_dict())
    return updated
