/**
 * Side-by-side method comparison table matching the CLI output format.
 */

interface ToolResult {
  tool: string;
  format: string;
  precision?: number;
  false_positives?: number;
  recall?: number;
  decryption_verified?: boolean;
  plugin_saved?: string | null;
}

interface MethodComparisonTableProps {
  results: ToolResult[];
}

export function MethodComparisonTable({ results }: MethodComparisonTableProps) {
  if (results.length === 0) {
    return (
      <div className="flex items-center justify-center h-24 text-zinc-500 text-sm">
        No experiment results available.
      </div>
    );
  }

  const metrics = [
    { key: 'format', label: 'Format', fmt: (v: unknown) => String(v) },
    { key: 'precision', label: 'Precision', fmt: (v: unknown) => typeof v === 'number' ? `${(v * 100).toFixed(2)}%` : 'N/A' },
    { key: 'false_positives', label: 'False positives', fmt: (v: unknown) => typeof v === 'number' ? v.toLocaleString() : 'N/A' },
    { key: 'recall', label: 'Recall', fmt: (v: unknown) => typeof v === 'number' ? `${(v * 100).toFixed(1)}%` : 'N/A' },
    { key: 'decryption_verified', label: 'Decryption', fmt: (v: unknown) => v === true ? 'YES' : v === false ? 'NO' : 'N/A' },
    { key: 'plugin_saved', label: 'Plugin', fmt: (v: unknown) => v ? 'Saved' : '-' },
  ];

  return (
    <div className="p-4">
      <h3 className="text-sm font-semibold text-zinc-300 mb-3">
        Tool Comparison
      </h3>
      <table className="w-full text-xs font-mono">
        <thead>
          <tr className="border-b border-zinc-700">
            <th className="text-left py-1.5 px-2 text-zinc-400 font-medium">Metric</th>
            {results.map(r => (
              <th key={r.tool} className="text-center py-1.5 px-2 text-zinc-300 font-semibold">
                {r.tool}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {metrics.map(m => (
            <tr key={m.key} className="border-b border-zinc-800 hover:bg-zinc-800/50">
              <td className="py-1.5 px-2 text-zinc-400">{m.label}</td>
              {results.map(r => (
                <td key={r.tool} className="text-center py-1.5 px-2 text-zinc-300">
                  {m.fmt((r as unknown as Record<string, unknown>)[m.key])}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
