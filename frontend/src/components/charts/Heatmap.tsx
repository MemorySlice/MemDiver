import { memo } from "react";

interface Props {
  libraries: string[];
  secretTypes: string[];
  presenceData: Record<string, Record<string, boolean>>;
}

export const Heatmap = memo(function Heatmap({ libraries, secretTypes, presenceData }: Props) {
  if (!libraries.length || !secretTypes.length) {
    return <p className="md-text-muted text-sm p-4">No heatmap data available.</p>;
  }
  return (
    <div className="overflow-auto">
      <table className="text-xs border-collapse w-full">
        <thead>
          <tr>
            <th className="p-2 text-left md-text-secondary border-b border-[var(--md-border)]">Library</th>
            {secretTypes.map((st) => (
              <th key={st} className="p-2 text-center md-text-secondary border-b border-[var(--md-border)] whitespace-nowrap">
                {st.replace(/_/g, " ").slice(0, 20)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {libraries.map((lib) => (
            <tr key={lib} className="hover:bg-[var(--md-bg-hover)]">
              <td className="p-2 font-medium border-b border-[var(--md-border)]">{lib}</td>
              {secretTypes.map((st) => {
                const present = presenceData[lib]?.[st];
                return (
                  <td
                    key={st}
                    className="p-2 text-center border-b border-[var(--md-border)]"
                    style={{ color: present ? "var(--md-heatmap-present)" : "var(--md-heatmap-absent)" }}
                  >
                    {present === undefined ? "\u2014" : present ? "\u2713" : "\u2717"}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
});
