import { memo } from "react";

interface Props {
  library: string;
  phases: string[];
  secretTypes: string[];
  /** { phaseName: { secretType: true/false } } */
  phasePresence: Record<string, Record<string, boolean>>;
}

export const PhaseLifecycleGrid = memo(function PhaseLifecycleGrid({
  library,
  phases,
  secretTypes,
  phasePresence,
}: Props) {
  if (!phases.length || !secretTypes.length) {
    return <p className="p-4 text-sm md-text-muted">No lifecycle data available.</p>;
  }

  return (
    <div className="p-3 text-xs overflow-auto">
      <h3 className="text-sm font-semibold md-text-accent mb-2">
        Phase Lifecycle: {library}
      </h3>
      <table className="border-collapse">
        <thead>
          <tr>
            <th className="p-1" />
            {phases.map((p) => (
              <th
                key={p}
                className="p-1 md-text-muted text-[10px] text-center"
                style={{
                  writingMode: "vertical-lr",
                  transform: "rotate(180deg)",
                  minWidth: 32,
                  height: 72,
                }}
              >
                {p}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {secretTypes.map((st) => (
            <tr key={st}>
              <td className="p-1 pr-2 whitespace-nowrap font-medium">{st}</td>
              {phases.map((phase) => {
                const present = phasePresence[phase]?.[st] ?? false;
                return (
                  <td
                    key={phase}
                    className="text-center p-1"
                    style={{
                      minWidth: 32,
                      background: present
                        ? "var(--md-accent-green, #4ec9b0)"
                        : "var(--md-bg-tertiary, #2d2d2d)",
                      color: present ? "white" : "transparent",
                      fontSize: 11,
                    }}
                  >
                    {present ? "\u2713" : ""}
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
