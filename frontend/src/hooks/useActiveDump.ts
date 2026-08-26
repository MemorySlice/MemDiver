import { useShallow } from "zustand/react/shallow";

import { useAppStore } from "@/stores/app-store";
import { useDumpStore } from "@/stores/dump-store";

export interface ActiveDump {
  path: string;
  format: "raw" | "msl";
  fileSize: number;
}

export function useActiveDump(): ActiveDump | null {
  const { inputMode, inputPath, pathInfo } = useAppStore(
    useShallow((s) => ({
      inputMode: s.inputMode,
      inputPath: s.inputPath,
      pathInfo: s.pathInfo,
    })),
  );
  const dumps = useDumpStore((s) => s.dumps);
  const activeDumpId = useDumpStore((s) => s.activeDumpId);

  if (inputMode !== "file") return null;

  const activeDump = dumps.find((d) => d.id === activeDumpId);
  if (activeDump) {
    return { path: activeDump.path, format: activeDump.format, fileSize: activeDump.size };
  }

  if (!inputPath) return null;
  const ext = inputPath.split(".").pop()?.toLowerCase();
  return { path: inputPath, format: ext === "msl" ? "msl" : "raw", fileSize: pathInfo?.file_size ?? 0 };
}
