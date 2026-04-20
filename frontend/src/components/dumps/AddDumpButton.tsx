import { useState } from "react";
import { useDumpStore } from "../../stores/dump-store";
import { getPathInfo } from "@/api/client";

export function AddDumpButton() {
  const [path, setPath] = useState("");
  const [loading, setLoading] = useState(false);
  const addDump = useDumpStore((s) => s.addDump);

  const handleAdd = async () => {
    const trimmed = path.trim();
    if (!trimmed) return;
    const name = trimmed.split("/").pop() ?? trimmed;
    const format = name.endsWith(".msl") ? "msl" : "raw";
    setLoading(true);
    try {
      const info = await getPathInfo(trimmed);
      addDump({ path: trimmed, name, size: info.file_size ?? 0, format });
    } catch {
      addDump({ path: trimmed, name, size: 0, format });
    } finally {
      setLoading(false);
      setPath("");
    }
  };

  return (
    <div className="flex gap-1">
      <input
        value={path}
        onChange={(e) => setPath(e.target.value)}
        onKeyDown={(e) => e.key === "Enter" && handleAdd()}
        placeholder="Server path to dump file"
        className="flex-1 px-2 py-1 text-xs rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)]"
      />
      <button
        onClick={handleAdd}
        disabled={!path.trim() || loading}
        className="px-3 py-1 text-xs font-medium rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40"
      >
        {loading ? "..." : "Add"}
      </button>
    </div>
  );
}
