import { useEffect, useCallback, type RefObject } from "react";
import { useShallow } from "zustand/react/shallow";

import { useHexStore } from "@/stores/hex-store";
import { useVarianceRegionsStore } from "@/stores/variance-regions-store";

const BYTES_PER_ROW = 16;
const PAGE_ROWS = 32;

/**
 * Is the keystroke going into a text field?
 *
 * The listener is bound to the hex PANE, and the goto field, the search box and
 * the bookmark note all live inside it, so a bare letter shortcut would eat a
 * character the user was typing. Checked only for the letter keys: the cursor
 * keys predate this hook's inputs and changing their reach is a separate
 * question from adding `n` / `p`.
 */
function isTextEntry(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target.isContentEditable) return true;
  const tag = target.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
}

export function useHexKeyboard(
  containerRef: RefObject<HTMLDivElement | null>,
) {
  const {
    cursorOffset,
    fileSize,
    selection,
    focusColumn,
    setCursor,
    startSelection,
    extendSelection,
    clearSelection,
    setFocusColumn,
    scrollToOffset,
  } = useHexStore(
    useShallow((s) => ({
      cursorOffset: s.cursorOffset,
      fileSize: s.fileSize,
      selection: s.selection,
      focusColumn: s.focusColumn,
      setCursor: s.setCursor,
      startSelection: s.startSelection,
      extendSelection: s.extendSelection,
      clearSelection: s.clearSelection,
      setFocusColumn: s.setFocusColumn,
      scrollToOffset: s.scrollToOffset,
    })),
  );

  // The region browser's cursor, driven from the grid. Read as two separate
  // selectors so the hook subscribes to the actions and to nothing else --
  // `regions`, `activeIndex` and `loading` all churn while a page loads.
  const jumpNextRegion = useVarianceRegionsStore((s) => s.jumpNext);
  const jumpPrevRegion = useVarianceRegionsStore((s) => s.jumpPrev);

  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (fileSize <= 0) return;

      const cursor = cursorOffset ?? 0;
      const maxOffset = fileSize - 1;

      const clamp = (n: number) => Math.max(0, Math.min(n, maxOffset));

      const moveCursor = (delta: number, shift: boolean) => {
        const next = clamp(cursor + delta);
        if (shift) {
          if (!selection) startSelection(cursor);
          extendSelection(next);
        } else {
          clearSelection();
          setCursor(next);
        }
        scrollToOffset(next);
      };

      switch (e.key) {
        case "ArrowLeft":
          e.preventDefault();
          moveCursor(-1, e.shiftKey);
          break;
        case "ArrowRight":
          e.preventDefault();
          moveCursor(1, e.shiftKey);
          break;
        case "ArrowUp":
          e.preventDefault();
          moveCursor(-BYTES_PER_ROW, e.shiftKey);
          break;
        case "ArrowDown":
          e.preventDefault();
          moveCursor(BYTES_PER_ROW, e.shiftKey);
          break;
        case "PageUp":
          e.preventDefault();
          moveCursor(-PAGE_ROWS * BYTES_PER_ROW, false);
          break;
        case "PageDown":
          e.preventDefault();
          moveCursor(PAGE_ROWS * BYTES_PER_ROW, false);
          break;
        case "Home": {
          e.preventDefault();
          const next = e.ctrlKey || e.metaKey
            ? 0
            : cursor - (cursor % BYTES_PER_ROW);
          clearSelection();
          setCursor(next);
          scrollToOffset(next);
          break;
        }
        case "End": {
          e.preventDefault();
          const next = e.ctrlKey || e.metaKey
            ? maxOffset
            : clamp(cursor - (cursor % BYTES_PER_ROW) + BYTES_PER_ROW - 1);
          clearSelection();
          setCursor(next);
          scrollToOffset(next);
          break;
        }
        // Tab moves between the grid's HEX and ASCII columns — and must never
        // become a keyboard trap doing it (WCAG 2.1.2, Level A).
        //
        // This listener is bound to the PANE and `keydown` BUBBLES, so the
        // unconditional `preventDefault()` that used to live here swallowed
        // every Tab and Shift+Tab raised anywhere inside it: the toolbar, the
        // goto/find fields, the align and render-mode switches, the class
        // chips, the whole dump rail, the window-retry button and the status
        // bar's Prev/Next. A keyboard-only user who reached the pane could not
        // get to any of them, could not reach the tabs past the pane, and could
        // not get out again without a mouse.
        //
        // Two guards keep the column toggle and delete the trap:
        //
        //   1. SCOPE — it fires only when the event's target is the grid
        //      container ITSELF. The container is the grid's single focusable
        //      (the cells are not in the tab order), so `e.target === container`
        //      means "focus is on the byte grid", and anything focused inside
        //      the pane is a real control whose Tab belongs to the browser.
        //   2. ESCAPE — it fires only on the `hex` -> `ascii` step. Once the
        //      ASCII column is current, Tab falls through and focus leaves the
        //      pane, so Tab from the grid always exits after at most one extra
        //      press. Shift+Tab is never prevented and leaves immediately.
        case "Tab":
          if (e.target !== containerRef.current) break;
          if (e.shiftKey || focusColumn === "ascii") {
            // Leaving the grid: hand Tab back to the browser and reset the
            // column so the next entry starts on hex again.
            setFocusColumn("hex");
            break;
          }
          e.preventDefault();
          setFocusColumn("ascii");
          break;
        case "Escape":
          e.preventDefault();
          clearSelection();
          break;
        // Next / previous OCCURRENCE of the selected consensus class. The
        // viewer's cursor moves; focus does not, so a keyboard user walking the
        // list keeps their place. `g` is taken (ctrl/cmd-G, goto); `n` and `p`
        // were free, and they are the pager letters `less` and `vim` already
        // teach.
        case "n":
          if (e.ctrlKey || e.metaKey || e.altKey) break;
          if (isTextEntry(e.target)) break;
          e.preventDefault();
          jumpNextRegion();
          break;
        case "p":
          if (e.ctrlKey || e.metaKey || e.altKey) break;
          if (isTextEntry(e.target)) break;
          e.preventDefault();
          jumpPrevRegion();
          break;
        case "g":
          if (e.ctrlKey || e.metaKey) {
            e.preventDefault();
            containerRef.current?.dispatchEvent(
              new CustomEvent("goto-offset", { bubbles: true }),
            );
          }
          break;
        default:
          break;
      }
    },
    [
      cursorOffset, fileSize, selection, focusColumn, containerRef,
      setCursor, startSelection, extendSelection, clearSelection,
      setFocusColumn, scrollToOffset, jumpNextRegion, jumpPrevRegion,
    ],
  );

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    el.addEventListener("keydown", handleKeyDown);
    return () => el.removeEventListener("keydown", handleKeyDown);
  }, [containerRef, handleKeyDown]);
}
