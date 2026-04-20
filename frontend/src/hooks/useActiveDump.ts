import { useAppStore } from "@/stores/app-store";
import { useDumpStore } from "@/stores/dump-store";

export interface ActiveDump {
  path: string;
  format: "raw" | "msl";
  fileSize: number;
}

export function useActiveDump(): ActiveDump | null {
  const { inputMode, inputPath, pathInfo } = useAppStore();
  const { dumps, activeDumpId } = useDumpStore();

  if (inputMode !== "file") return null;

  const activeDump = dumps.find((d) => d.id === activeDumpId);
  if (activeDump) {
    return { path: activeDump.path, format: activeDump.format, fileSize: activeDump.size };
  }

  if (!inputPath) return null;
  const ext = inputPath.split(".").pop()?.toLowerCase();
  return { path: inputPath, format: ext === "msl" ? "msl" : "raw", fileSize: pathInfo?.file_size ?? 0 };
}
