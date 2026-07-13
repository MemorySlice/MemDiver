import { useTranslation } from "react-i18next";
import { useTheme } from "@/providers/ThemeProvider";

const LABEL_KEYS: Record<string, string> = {
  light: "app.themeLabelLight",
  dark: "app.themeLabelDark",
};

const ICONS: Record<string, string> = {
  light: "\u2600",   // sun
  dark: "\u263E",     // moon
};

export function ThemeToggle() {
  const { t } = useTranslation("misc");
  const { theme, setTheme, highContrast, toggleHighContrast } = useTheme();
  const next = theme === "light" ? "dark" : "light";

  return (
    <div className="flex items-center gap-1">
      <button
        onClick={() => setTheme(next)}
        className="px-2 py-1 rounded text-sm hover:bg-[var(--md-bg-hover)] transition-colors"
        title={t("app.themeToggleTitle", {
          current: t(LABEL_KEYS[theme]),
          next: t(LABEL_KEYS[next]),
        })}
      >
        {ICONS[theme]} {t(LABEL_KEYS[theme])}
      </button>
      <button
        onClick={toggleHighContrast}
        className={`px-1.5 py-1 rounded text-xs font-bold transition-colors ${
          highContrast
            ? "bg-[var(--md-accent-blue)] text-white"
            : "hover:bg-[var(--md-bg-hover)] text-[var(--md-text-secondary)]"
        }`}
        title={t("app.highContrastTitle", {
          state: highContrast ? t("app.highContrastOn") : t("app.highContrastOff"),
        })}
      >
        {t("app.highContrastAbbr")}
      </button>
    </div>
  );
}
