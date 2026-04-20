"""Color scheme constants for the MemDiver UI (VS Code dark theme)."""

# Background colors
BG_PRIMARY = "#1e1e1e"
BG_SECONDARY = "#252526"
BG_TERTIARY = "#2d2d30"
BG_HOVER = "#2a2d2e"
BG_SELECTED = "#094771"

# Text colors
TEXT_PRIMARY = "#d4d4d4"
TEXT_SECONDARY = "#808080"
TEXT_MUTED = "#6a737d"
TEXT_BRIGHT = "#ffffff"

# Accent colors
ACCENT_BLUE = "#569cd6"
ACCENT_GREEN = "#6a9955"
ACCENT_ORANGE = "#ce9178"
ACCENT_YELLOW = "#dcdcaa"
ACCENT_RED = "#f44747"
ACCENT_PURPLE = "#c586c0"
ACCENT_CYAN = "#4ec9b0"

# Byte classification colors (for hex viewer)
COLOR_KEY = "#ff6b6b"          # Key bytes - red/coral
COLOR_SAME = "#4ec9b0"         # Static/same across runs - teal
COLOR_DIFFERENT = "#ffd93d"    # Different across runs - yellow
COLOR_ZERO = "#3d3d3d"         # Zero bytes - dim gray
COLOR_ASCII = "#569cd6"        # Printable ASCII - blue
COLOR_HIGH_ENTROPY = "#c586c0" # High entropy regions - purple
COLOR_STRUCTURAL = "#6a9955"   # Structural patterns - green

# Heatmap colors
HEATMAP_PRESENT = "#4ec9b0"    # Key present
HEATMAP_ABSENT = "#f44747"     # Key absent
HEATMAP_PARTIAL = "#ffd93d"    # Partially present
HEATMAP_NA = "#3d3d3d"         # Not applicable

# Variance classification colors
VARIANCE_INVARIANT = "#3d3d3d"
VARIANCE_STRUCTURAL = "#6a9955"
VARIANCE_POINTER = "#569cd6"
VARIANCE_KEY_CANDIDATE = "#ff6b6b"

# Investigation mode colors
COLOR_BOOKMARK = "#ce9178"       # Bookmarked bytes - orange
COLOR_INSPECT = "#dcdcaa"        # Currently inspected byte - warm yellow
BG_INSPECT = "#3a3a00"           # Background for inspected byte
COLOR_SEARCH_HIT = "#c586c0"    # Search result highlight - purple
BG_SEARCH_HIT = "#3a1a3a"       # Background for search results

# VAS region type colors
VAS_HEAP = "#6a9955"
VAS_STACK = "#ce9178"
VAS_IMAGE = "#569cd6"
VAS_MAPPED = "#4ec9b0"
VAS_ANONYMOUS = "#808080"
VAS_SHARED = "#c586c0"

# CSS snippets
BASE_CSS = f"""
<style>
.memdiver {{ font-family: 'Cascadia Code', 'Fira Code', monospace; background: {BG_PRIMARY}; color: {TEXT_PRIMARY}; }}
.memdiver-panel {{ background: {BG_SECONDARY}; border: 1px solid {BG_TERTIARY}; border-radius: 4px; padding: 12px; margin: 8px 0; }}
.memdiver-header {{ color: {ACCENT_BLUE}; font-size: 14px; font-weight: 600; margin-bottom: 8px; }}
.memdiver-label {{ color: {TEXT_SECONDARY}; font-size: 12px; }}
.memdiver-value {{ color: {TEXT_PRIMARY}; font-size: 13px; }}
</style>
"""
