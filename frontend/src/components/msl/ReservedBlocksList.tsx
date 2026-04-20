import { useEffect, useState } from "react";

interface Props {
  mslPath: string;
  /** One of: thread-contexts, file-descriptors, network-connections,
   *  env-blocks, security-tokens, system-context */
  endpoint: string;
  title: string;
}

interface ReservedResponse {
  spec_reserved?: boolean;
  incomplete?: boolean;
  note: string;
  entries: Array<Record<string, unknown>>;
}

export function ReservedBlocksList({ mslPath, endpoint, title }: Props) {
  const [data, setData] = useState<ReservedResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!mslPath) return;
    setError(null);
    setData(null);
    fetch(`/api/inspect/${endpoint}?msl_path=${encodeURIComponent(mslPath)}`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((body: ReservedResponse) => setData(body))
      .catch((e) => setError(String(e)));
  }, [mslPath, endpoint]);

  if (error) return <p className="p-3 text-xs text-red-500">{error}</p>;
  if (!data) return null;
  if (!data.entries.length) return null;

  const badgeLabel = data.spec_reserved ? "SPEC RESERVED" : "INCOMPLETE";
  const badgeColor = data.spec_reserved
    ? "var(--md-accent-orange)"
    : "var(--md-accent-red)";

  return (
    <div className="p-3 text-xs space-y-1">
      <div className="flex items-center gap-2">
        <h3 className="text-sm font-semibold md-text-accent">{title}</h3>
        <span
          className="text-[9px] px-1.5 py-0.5 rounded"
          style={{ background: badgeColor, color: "white" }}
          title={data.note}
        >
          {badgeLabel}
        </span>
      </div>
      <p className="md-text-muted text-[10px] italic">{data.note}</p>
      <div className="md-panel p-2 space-y-0.5 max-h-40 overflow-auto">
        {data.entries.map((entry, i) => (
          <pre key={i} className="font-mono md-text-secondary text-[10px] whitespace-pre-wrap break-all">
            {JSON.stringify(entry, null, 1)}
          </pre>
        ))}
      </div>
    </div>
  );
}
