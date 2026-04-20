import { useTheme } from "@/providers/ThemeProvider";

const LABELS: Record<string, string> = {
  light: "Light",
  dark: "Dark",
};

const ICONS: Record<string, string> = {
  light: "\u2600",   // sun
  dark: "\u263E",     // moon
};

export function ThemeToggle() {
  const { theme, setTheme, highContrast, toggleHighContrast } = useTheme();
  const next = theme === "light" ? "dark" : "light";

  return (
    <div className="flex items-center gap-1">
      <button
        onClick={() => setTheme(next)}
        className="px-2 py-1 rounded text-sm hover:bg-[var(--md-bg-hover)] transition-colors"
        title={`Theme: ${LABELS[theme]} (click for ${LABELS[next]})`}
      >
        {ICONS[theme]} {LABELS[theme]}
      </button>
      <button
        onClick={toggleHighContrast}
        className={`px-1.5 py-1 rounded text-xs font-bold transition-colors ${
          highContrast
            ? "bg-[var(--md-accent-blue)] text-white"
            : "hover:bg-[var(--md-bg-hover)] text-[var(--md-text-secondary)]"
        }`}
        title={`High contrast: ${highContrast ? "ON" : "OFF"}`}
      >
        HC
      </button>
    </div>
  );
}
