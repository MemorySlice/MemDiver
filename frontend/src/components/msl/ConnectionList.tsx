import { useEffect, useState } from "react";

interface Connection {
  pid: number;
  family: number;
  protocol: number;
  state: number;
  local_addr: string;
  local_port: number;
  remote_addr: string;
  remote_port: number;
}

interface Props {
  mslPath: string;
}

const FAMILY_NAMES: Record<number, string> = { 0x02: "v4", 0x0a: "v6" };
const PROTOCOL_NAMES: Record<number, string> = { 0x06: "TCP", 0x11: "UDP" };

function familyLabel(f: number): string {
  return FAMILY_NAMES[f] || `0x${f.toString(16)}`;
}

function protocolLabel(p: number): string {
  return PROTOCOL_NAMES[p] || `0x${p.toString(16)}`;
}

function formatEndpoint(addr: string, port: number, family: number): string {
  if (port === 0 && addr === "0.0.0.0") return "—";
  const bracketed = family === 0x0a ? `[${addr}]` : addr;
  return `${bracketed}:${port}`;
}

export function ConnectionList({ mslPath }: Props) {
  const [connections, setConnections] = useState<Connection[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!mslPath) return;
    setError(null);
    fetch(`/api/inspect/connections?msl_path=${encodeURIComponent(mslPath)}`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((data: Connection[]) => setConnections(data))
      .catch((e) => setError(String(e)));
  }, [mslPath]);

  if (error) return <p className="p-3 text-xs text-red-500">{error}</p>;
  if (!connections.length) return <p className="p-3 text-xs md-text-muted">No connection table blocks</p>;

  return (
    <div className="p-3 text-xs space-y-1">
      <h3 className="text-sm font-semibold md-text-accent">Connections ({connections.length})</h3>
      <div className="md-panel p-2 space-y-1 max-h-64 overflow-auto">
        {connections.map((c, i) => (
          <div key={i} className="font-mono md-text-secondary">
            <span className="md-text-muted text-[10px] mr-1">
              {familyLabel(c.family)}/{protocolLabel(c.protocol)}
            </span>
            <span className="md-text-muted text-[10px] mr-2">pid={c.pid}</span>
            <span>{formatEndpoint(c.local_addr, c.local_port, c.family)}</span>
            <span className="md-text-muted mx-1">→</span>
            <span>{formatEndpoint(c.remote_addr, c.remote_port, c.family)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
