import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { BookmarkList } from "@/components/investigation/BookmarkList";
import type { Bookmark } from "@/stores/hex-store";

describe("BookmarkList views", () => {
  const raw: Bookmark = { offset: 0x1b0, length: 1, label: "in raw", view: "raw" };
  const vas: Bookmark = { offset: 0x1b0, length: 1, label: "in vas", view: "vas" };

  it("lists the same offset in two views as two entries, tagged by view", () => {
    render(<BookmarkList bookmarks={[raw, vas]} onAdd={vi.fn()} onRemove={vi.fn()} onSelect={vi.fn()} showViews />);
    expect(screen.getAllByTestId("bookmark-entry")).toHaveLength(2);
    expect(screen.getByText("VAS")).toBeInTheDocument();
    expect(screen.getByText("Raw")).toBeInTheDocument();
  });

  it("hands the full entry (with its view) to select and remove", () => {
    const onSelect = vi.fn();
    const onRemove = vi.fn();
    render(<BookmarkList bookmarks={[vas]} onAdd={vi.fn()} onRemove={onRemove} onSelect={onSelect} />);
    fireEvent.click(screen.getByText("in vas"));
    expect(onSelect).toHaveBeenCalledWith(0x1b0, vas);
    fireEvent.click(screen.getByText("x"));
    expect(onRemove).toHaveBeenCalledWith(0x1b0, 1, vas);
  });

  it("does not tag views on a single-view dump", () => {
    render(<BookmarkList bookmarks={[raw]} onAdd={vi.fn()} onRemove={vi.fn()} onSelect={vi.fn()} />);
    expect(screen.queryByText("Raw")).not.toBeInTheDocument();
  });
});
