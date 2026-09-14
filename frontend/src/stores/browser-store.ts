import { create } from "zustand";

import {
  addFavourite as apiAddFavourite,
  getFavourites,
  getLastDir,
  removeFavourite as apiRemoveFavourite,
  setLastDir,
  type FavouriteDir,
} from "@/api/settings";

export type { FavouriteDir };

/**
 * The file browser's saved directories, and where it should reopen.
 *
 * ── Why this store has no `persist` ──────────────────────────────────────────
 * It used to. The list lived in `localStorage` under `memdiver-browser`, which
 * looked like persistence and mostly behaved like it — until the origin
 * changed. `localStorage` is keyed by scheme+host+port, so running
 * `memdiver web` on a different `--port`, clearing site data, or opening the
 * UI in a second browser each produced a silently empty list with no error and
 * nothing to recover. A forensic workspace's directories outlive all three, so
 * the server owns them now (`memdiver_home()/config.json`, via
 * `api/favourites.py`) and this store is the view of it.
 *
 * Every mutation adopts the full list the server answers with rather than
 * patching the local copy, so two tabs cannot drift apart.
 */

/** The `localStorage` key the favourites used to live under. */
const LEGACY_KEY = "memdiver-browser";

export function normalizePath(path: string): string {
  if (!path) return path;
  if (path.length > 1 && path.endsWith("/")) return path.slice(0, -1);
  return path;
}

/**
 * The label a favourite gets when the user supplies none: the directory's own
 * name, which is what a person recognises in a list.
 *
 * The backend derives the same thing (`api/favourites.default_label`) and its
 * answer is the one that gets stored. This copy exists for the legacy import
 * below, which has to name entries that predate the server ever seeing them.
 */
export function defaultLabel(path: string): string {
  const norm = normalizePath(path);
  if (norm === "" || norm === "/") return "/";
  const idx = norm.lastIndexOf("/");
  return idx === -1 ? norm : norm.slice(idx + 1) || "/";
}

/**
 * Any favourites still sitting in the old `localStorage` store, newest last.
 *
 * Tolerant to the point of paranoia: this reads a zustand-`persist` envelope
 * written by an older build, so every layer of it is untrusted. Anything
 * unreadable yields `[]` — a failed import must cost the user nothing they
 * still have.
 */
function readLegacyFavourites(): { path: string; label: string }[] {
  if (typeof localStorage === "undefined") return [];
  let raw: string | null = null;
  try {
    raw = localStorage.getItem(LEGACY_KEY);
  } catch {
    return [];
  }
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as { state?: { bookmarks?: unknown } };
    const entries = parsed?.state?.bookmarks;
    if (!Array.isArray(entries)) return [];
    return entries
      .filter((e): e is { path: string; label?: string } =>
        typeof (e as { path?: unknown })?.path === "string",
      )
      .map((e) => ({ path: e.path, label: e.label || defaultLabel(e.path) }));
  } catch {
    return [];
  }
}

function clearLegacyFavourites(): void {
  try {
    localStorage.removeItem(LEGACY_KEY);
  } catch {
    /* private mode, or storage disabled — the import simply runs again */
  }
}

interface BrowserState {
  favourites: FavouriteDir[];
  /** Where the browser should reopen; `null` means "the server has no answer". */
  lastDir: string | null;
  /** True once `load()` has completed, successfully or not. */
  loaded: boolean;
  loading: boolean;
  /** Why the last server call failed, for the UI to show. */
  error: string | null;

  load: () => Promise<void>;
  addFavourite: (path: string, label?: string) => Promise<void>;
  removeFavourite: (path: string) => Promise<void>;
  renameFavourite: (path: string, label: string) => Promise<void>;
  rememberLastDir: (path: string) => void;
  isFavourite: (path: string) => boolean;
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export const useBrowserStore = create<BrowserState>()((set, get) => ({
  favourites: [],
  lastDir: null,
  loaded: false,
  loading: false,
  error: null,

  load: async () => {
    if (get().loading) return;
    set({ loading: true, error: null });
    try {
      const [saved, lastDir] = await Promise.all([getFavourites(), getLastDir()]);
      let favourites = saved;

      // One-shot migration for anyone who curated a list under the old
      // localStorage store. Only when the server has none: a server list is
      // the newer truth, and re-importing over it would resurrect entries the
      // user has since deleted.
      if (favourites.length === 0) {
        const legacy = readLegacyFavourites();
        for (const entry of legacy) {
          try {
            favourites = await apiAddFavourite(entry.path, entry.label);
          } catch {
            // A directory that no longer exists is refused by the backend.
            // Skip it and keep the rest — a single dead entry must not abort
            // the whole import.
          }
        }
        if (legacy.length > 0) clearLegacyFavourites();
      }

      set({ favourites, lastDir, loaded: true, loading: false });
    } catch (err) {
      // The browser still navigates fine without favourites, so a failure here
      // is reported, never thrown: losing the dialog would be far worse than
      // losing the list.
      set({ loaded: true, loading: false, error: message(err) });
    }
  },

  addFavourite: async (path, label) => {
    const norm = normalizePath(path);
    if (!norm) return;
    try {
      set({ favourites: await apiAddFavourite(norm, label), error: null });
    } catch (err) {
      set({ error: message(err) });
    }
  },

  removeFavourite: async (path) => {
    try {
      set({ favourites: await apiRemoveFavourite(normalizePath(path)), error: null });
    } catch (err) {
      set({ error: message(err) });
    }
  },

  // Relabelling goes through the same upsert-by-path POST the backend already
  // exposes, so there is no second endpoint and no second rule about identity.
  renameFavourite: async (path, label) => {
    const next = label.trim();
    if (!next) return;
    await get().addFavourite(path, next);
  },

  rememberLastDir: (path) => {
    const norm = normalizePath(path);
    if (!norm || norm === get().lastDir) return;
    set({ lastDir: norm });
    // Fire and forget: failing to remember where you were is not worth
    // interrupting anything for.
    void setLastDir(norm).catch(() => undefined);
  },

  isFavourite: (path) => {
    const norm = normalizePath(path);
    return get().favourites.some((f) => f.path === norm);
  },
}));
