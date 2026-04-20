"""Mode manager for Testing vs Research mode switching."""

import logging
from typing import Dict, List

from core.constants import TESTING as _TESTING, RESEARCH as _RESEARCH

logger = logging.getLogger("memdiver.ui.mode")


class ModeManager:
    """Manage the Testing/Research mode toggle and its effects on the UI.

    Testing Mode: Validate known patterns against dumps.
        - Focused views: heatmap, hex viewer, match results
        - Quick feedback loop
        - Use case: 'Does this YARA rule match?'

    Research Mode: Discover unknown key patterns.
        - Full visualizations: consensus, entropy, variance, phase lifecycle
        - Pattern Architect sandbox
        - DerivedKeyExpander active
        - Use case: 'Where are TLS 1.3 keys in wolfssl?'
    """

    TESTING = _TESTING
    RESEARCH = _RESEARCH

    # Views available in each mode
    TESTING_VIEWS = [
        "heatmap",
        "hex_viewer",
    ]

    RESEARCH_VIEWS = [
        "heatmap",
        "hex_viewer",
        "entropy_chart",
        "variance_map",
        "phase_lifecycle",
        "cross_library",
        "differential_diff",
        "consensus_view",
        "architect_view",
    ]

    def __init__(self, initial_mode: str = TESTING):
        self._mode = initial_mode
        logger.info("Mode initialized: %s", self._mode)

    @property
    def mode(self) -> str:
        return self._mode

    @mode.setter
    def mode(self, value: str) -> None:
        if value not in (self.TESTING, self.RESEARCH):
            logger.warning("Invalid mode: %s, keeping %s", value, self._mode)
            return
        old = self._mode
        self._mode = value
        if old != value:
            logger.info("Mode changed: %s -> %s", old, value)

    @property
    def is_testing(self) -> bool:
        return self._mode == self.TESTING

    @property
    def is_research(self) -> bool:
        return self._mode == self.RESEARCH

    def available_views(self) -> List[str]:
        """Return view names available in the current mode."""
        if self.is_testing:
            return list(self.TESTING_VIEWS)
        return list(self.RESEARCH_VIEWS)

    def should_expand_keys(self) -> bool:
        """Whether to auto-expand derived keys (Research only)."""
        return self.is_research

    def should_show_view(self, view_name: str) -> bool:
        """Check if a view should be displayed in current mode."""
        return view_name in self.available_views()

    def get_algorithms(self) -> List[str]:
        """Suggested algorithm order for current mode."""
        if self.is_testing:
            return ["exact_match", "pattern_match", "user_regex"]
        return [
            "exact_match", "entropy_scan", "change_point",
            "differential", "constraint_validator", "pattern_match",
        ]

    def summary(self) -> Dict[str, str]:
        """Return mode summary for display."""
        if self.is_testing:
            return {
                "mode": "Testing",
                "icon": "🔍",
                "description": "Validate patterns against dumps",
            }
        return {
            "mode": "Research",
            "icon": "🔬",
            "description": "Discover unknown key patterns",
        }
