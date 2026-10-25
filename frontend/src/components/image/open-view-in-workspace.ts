import { getPathInfo } from "@/api/client";
import { useAppStore } from "@/stores/app-store";
import { useDumpStore } from "@/stores/dump-store";

/**
 * Open a `.mdview` descriptor in the hex workspace the way a dump is opened:
 * a dump-store entry, activated. A `.mdview` is registered as a plain "raw" entry and
 * NEVER imported — the backend resolves it to the image view
 * (see apply-region-selection's image-view guard).
 */
export async function openViewInWorkspace(viewPath: string): Promise<void> {
  ensureFileWorkspace(viewPath);
  const store = useDumpStore.getState();
  const existing = store.dumps.find((d) => d.path === viewPath);
  if (existing) {
    store.setActiveDump(existing.id);
    return;
  }
  const name = viewPath.split("/").pop() ?? viewPath;
  let size = 0;
  try {
    size = (await getPathInfo(viewPath)).file_size ?? 0;
  } catch {
    // The size is cosmetic; the view opens regardless.
  }
  const id = store.addDump({ path: viewPath, name, size, format: /\.msl$/i.test(name) ? "msl" : "raw" });
  useDumpStore.getState().setActiveDump(id);
}

/**
 * The hex workspace renders only in "file" mode with a non-empty input path; an
 * image entered from the wizard starts with neither, so the first view opened
 * becomes the input. An existing file workspace is left alone.
 */
function ensureFileWorkspace(viewPath: string): void {
  const app = useAppStore.getState();
  if (app.inputMode === "file" && app.inputPath) return;
  app.setInputMode("file");
  app.setInputPath(viewPath);
}

export const isMdview = (path: string): boolean => /\.mdview$/i.test(path);
