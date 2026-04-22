import { useEffect, useState } from "react";

interface Process {
  pid: number;
  ppid: number;
  uid: number;
  is_target: boolean;
  start_time_ns: number;
  rss: number;
  exe_name: string;
  cmd_line: string;
  user: string;
}

interface Props {
  mslPath: string;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

function shortPath(path: string): string {
  if (!path) return "";
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] || path;
}

export function ProcessList({ mslPath }: Props) {
  const [processes, setProcesses] = useState<Process[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!mslPath) return;
    setError(null);
    fetch(`/api/inspect/processes?msl_path=${encodeURIComponent(mslPath)}`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((data: Process[]) => setProcesses(data))
      .catch((e) => setError(String(e)));
  }, [mslPath]);

  if (error) return <p className="p-3 text-xs md-text-error">{error}</p>;
  if (!processes.length) return <p className="p-3 text-xs md-text-muted">No process table blocks</p>;

  return (
    <div className="p-3 text-xs space-y-1">
      <h3 className="text-sm font-semibold md-text-accent">Processes ({processes.length})</h3>
      <div className="md-panel p-2 space-y-1 max-h-64 overflow-auto">
        {processes.map((p, i) => (
          <div
            key={i}
            className={`px-1 py-1 rounded ${p.is_target ? "bg-[var(--md-accent-purple)]/10 border-l-2 border-[var(--md-accent-purple)]" : ""}`}
            title={p.cmd_line || p.exe_name}
          >
            <div className="flex items-baseline gap-2">
              <span className="font-mono font-medium">{p.pid}</span>
              <span className="md-text-muted text-[10px]">ppid={p.ppid}</span>
              {p.is_target && (
                <span className="text-[10px] px-1 rounded bg-[var(--md-accent-purple)] text-white">TARGET</span>
              )}
              {p.user && <span className="ml-auto md-text-muted text-[10px]">{p.user}</span>}
            </div>
            <div className="font-mono md-text-secondary truncate">{shortPath(p.exe_name)}</div>
            {p.cmd_line && (
              <div className="md-text-muted text-[10px] truncate">{p.cmd_line}</div>
            )}
            {p.rss > 0 && (
              <div className="md-text-muted text-[10px]">RSS {formatSize(p.rss)}</div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
