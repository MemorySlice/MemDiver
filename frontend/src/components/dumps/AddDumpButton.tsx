import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useDumpStore } from "../../stores/dump-store";
import { getPathInfo } from "@/api/client";

export function AddDumpButton() {
  const { t } = useTranslation("dumps");
  const [path, setPath] = useState("");
  const [loading, setLoading] = useState(false);
  const addDump = useDumpStore((s) => s.addDump);
  const fetchTagStatus = useDumpStore((s) => s.fetchTagStatus);

  const handleAdd = async () => {
    const trimmed = path.trim();
    if (!trimmed) return;
    const name = trimmed.split("/").pop() ?? trimmed;
    // Format detection is extension-based only (case-insensitive .msl).
    // A misnamed/extensionless MSL file is treated as "raw" and its
    // tag-status fetch is skipped; reliable detection would require
    // backend content sniffing, which is intentionally not done here.
    const format = name.toLowerCase().endsWith(".msl") ? "msl" : "raw";
    setLoading(true);
    try {
      const info = await getPathInfo(trimmed);
      const id = addDump({ path: trimmed, name, size: info.file_size ?? 0, format });
      if (format === "msl") void fetchTagStatus(id);
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
        placeholder={t("add.placeholder")}
        className="flex-1 px-2 py-1 text-xs rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)]"
      />
      <button
        onClick={handleAdd}
        disabled={!path.trim() || loading}
        className="px-3 py-1 text-xs font-medium rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40"
      >
        {loading ? t("add.adding") : t("common:add")}
      </button>
    </div>
  );
}
