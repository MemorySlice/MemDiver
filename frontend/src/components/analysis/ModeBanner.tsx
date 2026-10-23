import { useTranslation } from "react-i18next";
import { APP_MODES, useAppStore } from "@/stores/app-store";
import { MODE_ACCENT } from "./mode-accent";

export function ModeBanner() {
  const { t } = useTranslation("analysis");
  const mode = useAppStore((s) => s.mode);
  const setMode = useAppStore((s) => s.setMode);

  return (
    <div className="flex items-center gap-2 px-3 py-1.5 text-xs border-b border-[var(--md-border)]">
      <span className="md-text-secondary">{t("modeBanner.modeLabel")}</span>
      {APP_MODES.map((m) => (
        <button
          key={m}
          onClick={() => setMode(m)}
          data-testid={`mode-${m}`}
          aria-pressed={mode === m}
          className={`px-2 py-0.5 rounded capitalize transition-colors ${
            mode === m ? "md-text-on-accent" : "md-text-muted hover:bg-[var(--md-bg-hover)]"
          }`}
          style={mode === m ? { background: MODE_ACCENT[m] } : undefined}
        >
          {t(`modeBanner.${m}Name`)}
        </button>
      ))}
      <span className="text-[10px] md-text-muted ml-1 flex-1 truncate">
        {t(`modeBanner.${mode}`)}
      </span>
    </div>
  );
}
