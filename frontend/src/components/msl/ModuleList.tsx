import { useEffect, useState } from "react";
import { useHexStore } from "../../stores/hex-store";

interface Module {
  path: string;
  base_addr: number;
  size: number;
  version: string;
}

interface Props {
  mslPath: string;
}

async function resolveVa(
  mslPath: string,
  va: number,
): Promise<{ file_offset: number | null; vas_offset: number | null } | null> {
  const url =
    `/api/inspect/resolve-va?dump_path=${encodeURIComponent(mslPath)}` +
    `&va=${va}`;
  try {
    const res = await fetch(url);
    if (!res.ok) return null;
    const json = await res.json();
    if (json.error) return null;
    return { file_offset: json.file_offset, vas_offset: json.vas_offset };
  } catch {
    return null;
  }
}

export function ModuleList({ mslPath }: Props) {
  const [modules, setModules] = useState<Module[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const scrollToOffset = useHexStore((s) => s.scrollToOffset);

  useEffect(() => {
    if (!mslPath) return;
    setError(null);
    fetch(`/api/inspect/modules?msl_path=${encodeURIComponent(mslPath)}`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((data: Module[]) => setModules(data))
      .catch((e) => setError(String(e)));
  }, [mslPath]);

  const handleModuleClick = async (m: Module) => {
    setNotice(null);
    const result = await resolveVa(mslPath, m.base_addr);
    if (!result) {
      setNotice(`Could not resolve ${m.path.split("/").pop()}`);
      return;
    }
    const viewMode = useHexStore.getState().viewMode;
    const target =
      viewMode === "raw" ? result.file_offset : result.vas_offset;
    if (target === null || target === undefined) {
      setNotice(
        viewMode === "raw"
          ? `No block header for this module in raw view`
          : `Module not captured in VAS view`,
      );
      return;
    }
    scrollToOffset(target);
  };

  if (error) return <p className="p-3 text-xs md-text-error">{error}</p>;
  if (!modules.length) return <p className="p-3 text-xs md-text-muted">No modules</p>;

  const truncate = (p: string) => (p.length > 40 ? "..." + p.slice(-37) : p);
  const toKB = (n: number) => (n / 1024).toFixed(1);

  return (
    <div className="p-3 text-xs space-y-1">
      <h3 className="text-sm font-semibold md-text-accent">Modules</h3>
      {notice && (
        <p className="text-[11px] md-text-warning">{notice}</p>
      )}
      {modules.map((m, i) => (
        <button
          key={i}
          onClick={() => handleModuleClick(m)}
          className="block w-full text-left py-1 px-1 hover:bg-[var(--md-bg-hover)] rounded cursor-pointer"
          title={m.path}
        >
          <span className="font-mono md-text-secondary">{truncate(m.path)}</span>
          <span className="ml-2 md-text-muted">
            0x{m.base_addr.toString(16)} &middot; {toKB(m.size)}KB
            {m.version ? ` (${m.version})` : ""}
          </span>
        </button>
      ))}
    </div>
  );
}
