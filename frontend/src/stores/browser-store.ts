import { create } from "zustand";
import { persist } from "zustand/middleware";

const BROWSER_STORE_VERSION = 1;

export interface FolderBookmark {
  id: string;
  path: string;
  label: string;
  addedAt: number;
}

interface BrowserState {
  bookmarks: FolderBookmark[];
  addBookmark: (path: string, label?: string) => void;
  removeBookmark: (id: string) => void;
  renameBookmark: (id: string, label: string) => void;
  isBookmarked: (path: string) => boolean;
}

export function normalizePath(path: string): string {
  if (!path) return path;
  if (path.length > 1 && path.endsWith("/")) return path.slice(0, -1);
  return path;
}

function defaultLabel(path: string): string {
  const norm = normalizePath(path);
  if (norm === "" || norm === "/") return "/";
  const idx = norm.lastIndexOf("/");
  return idx === -1 ? norm : norm.slice(idx + 1) || "/";
}

function makeId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `bm-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

export const useBrowserStore = create<BrowserState>()(
  persist(
    (set, get) => ({
      bookmarks: [],

      addBookmark: (path, label) => {
        const norm = normalizePath(path);
        if (!norm) return;
        if (get().bookmarks.some((b) => b.path === norm)) return;
        const entry: FolderBookmark = {
          id: makeId(),
          path: norm,
          label: label?.trim() || defaultLabel(norm),
          addedAt: Date.now(),
        };
        set((state) => ({ bookmarks: [...state.bookmarks, entry] }));
      },

      removeBookmark: (id) =>
        set((state) => ({ bookmarks: state.bookmarks.filter((b) => b.id !== id) })),

      renameBookmark: (id, label) => {
        const next = label.trim();
        const current = get().bookmarks.find((b) => b.id === id);
        if (!current || !next || current.label === next) return;
        set((state) => ({
          bookmarks: state.bookmarks.map((b) => (b.id === id ? { ...b, label: next } : b)),
        }));
      },

      isBookmarked: (path) => {
        const norm = normalizePath(path);
        return get().bookmarks.some((b) => b.path === norm);
      },
    }),
    {
      name: "memdiver-browser",
      version: BROWSER_STORE_VERSION,
    },
  ),
);
