import { useEffect, useCallback, type RefObject } from "react";
import { useHexStore } from "@/stores/hex-store";

const BYTES_PER_ROW = 16;
const PAGE_ROWS = 32;

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
  } = useHexStore();

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
        case "Tab":
          e.preventDefault();
          setFocusColumn(focusColumn === "hex" ? "ascii" : "hex");
          break;
        case "Escape":
          e.preventDefault();
          clearSelection();
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
      setFocusColumn, scrollToOffset,
    ],
  );

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    el.addEventListener("keydown", handleKeyDown);
    return () => el.removeEventListener("keydown", handleKeyDown);
  }, [containerRef, handleKeyDown]);
}
