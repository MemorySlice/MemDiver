import { useAppStore } from "@/stores/app-store";

const MODE_DESCRIPTIONS: Record<string, string> = {
  verification:
    "Validate known patterns with focused algorithms and quick feedback.",
  exploration:
    "Full discovery toolkit — all algorithms, entropy visualization, cross-dump consensus.",
};

export function ModeBanner() {
  const { mode, setMode } = useAppStore();

  return (
    <div className="flex items-center gap-2 px-3 py-1.5 text-xs border-b border-[var(--md-border)]">
      <span className="md-text-secondary">Mode:</span>
      {(["verification", "exploration"] as const).map((m) => (
        <button
          key={m}
          onClick={() => setMode(m)}
          className={`px-2 py-0.5 rounded capitalize transition-colors ${
            mode === m ? "text-white" : "md-text-muted hover:bg-[var(--md-bg-hover)]"
          }`}
          style={mode === m ? { background: m === "verification" ? "var(--md-accent-blue)" : "var(--md-accent-purple)" } : undefined}
        >
          {m}
        </button>
      ))}
      <span className="text-[10px] md-text-muted ml-1 flex-1 truncate">
        {MODE_DESCRIPTIONS[mode]}
      </span>
    </div>
  );
}
