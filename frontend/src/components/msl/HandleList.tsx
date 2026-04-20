import { useEffect, useMemo, useState } from "react";

interface Handle {
  pid: number;
  fd: number;
  handle_type: number;
  handle_type_name: string;
  path: string;
}

interface Props {
  mslPath: string;
}

const TYPE_COLORS: Record<string, string> = {
  File: "var(--md-accent-blue)",
  Directory: "var(--md-accent-blue)",
  Socket: "var(--md-accent-purple)",
  Pipe: "var(--md-accent-green)",
  Device: "var(--md-accent-orange)",
  Registry: "var(--md-accent-red)",
  Other: "var(--md-text-muted)",
  Unknown: "var(--md-text-muted)",
};

export function HandleList({ mslPath }: Props) {
  const [handles, setHandles] = useState<Handle[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!mslPath) return;
    setError(null);
    fetch(`/api/inspect/handles?msl_path=${encodeURIComponent(mslPath)}`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((data: Handle[]) => setHandles(data))
      .catch((e) => setError(String(e)));
  }, [mslPath]);

  const grouped = useMemo(() => {
    const out: Record<string, Handle[]> = {};
    for (const h of handles) {
      const key = h.handle_type_name || "Unknown";
      if (!out[key]) out[key] = [];
      out[key].push(h);
    }
    return out;
  }, [handles]);

  if (error) return <p className="p-3 text-xs text-red-500">{error}</p>;
  if (!handles.length) return <p className="p-3 text-xs md-text-muted">No handle table blocks</p>;

  return (
    <div className="p-3 text-xs space-y-2">
      <h3 className="text-sm font-semibold md-text-accent">Handles ({handles.length})</h3>
      {Object.entries(grouped).map(([type, items]) => (
        <div key={type} className="md-panel p-2">
          <div className="flex items-center gap-2 mb-1">
            <span
              className="inline-block w-2 h-2 rounded-full"
              style={{ background: TYPE_COLORS[type] || "var(--md-text-muted)" }}
            />
            <span className="font-medium">{type}</span>
            <span className="md-text-muted text-[10px]">({items.length})</span>
          </div>
          <div className="space-y-0.5 max-h-32 overflow-auto">
            {items.map((h, i) => (
              <div key={i} className="font-mono md-text-secondary truncate" title={h.path || `<no path>`}>
                <span className="md-text-muted text-[10px] mr-1">pid={h.pid}</span>
                <span className="md-text-muted text-[10px] mr-2">fd={h.fd}</span>
                <span>{h.path || <em className="md-text-muted">(no path)</em>}</span>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
