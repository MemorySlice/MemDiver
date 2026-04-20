"""Progress display helpers for marimo async operations."""

import asyncio
from typing import Optional


async def with_progress(output, message: str, coro):
    """Run a coroutine while showing a progress spinner.

    Args:
        output: marimo output object (mo.output).
        message: Progress message to display.
        coro: The coroutine to await.

    Returns:
        Result of the coroutine.
    """
    try:
        import marimo as mo
        output.replace(mo.md(f"**{message}...**"))
        await asyncio.sleep(0)  # Flush UI update
        result = await coro
        return result
    except ImportError:
        return await coro


def spinner_html(message: str = "Loading...") -> str:
    """Generate HTML for a loading spinner."""
    return (
        f'<div style="display:flex; align-items:center; gap:8px; padding:12px;">'
        f'<div style="width:20px; height:20px; border:2px solid #569cd6; '
        f'border-top-color:transparent; border-radius:50%; '
        f'animation:spin 1s linear infinite;"></div>'
        f'<span style="color:#808080">{message}</span>'
        f'</div>'
        f'<style>@keyframes spin {{ to {{ transform: rotate(360deg); }} }}</style>'
    )


def progress_bar(current: int, total: int, label: str = "") -> str:
    """Generate HTML for a progress bar."""
    pct = (current / total * 100) if total > 0 else 0
    bar_color = "#4ec9b0" if pct < 100 else "#6a9955"
    return (
        f'<div style="margin:4px 0;">'
        f'<div style="display:flex; justify-content:space-between; font-size:12px; '
        f'color:#808080;">'
        f'<span>{label}</span><span>{current}/{total}</span></div>'
        f'<div style="background:#2d2d30; border-radius:4px; height:6px; '
        f'overflow:hidden;">'
        f'<div style="background:{bar_color}; width:{pct:.1f}%; height:100%; '
        f'transition:width 0.3s;"></div></div></div>'
    )
