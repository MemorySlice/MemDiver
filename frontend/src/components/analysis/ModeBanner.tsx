import { useTranslation } from "react-i18next";
import { useAppStore } from "@/stores/app-store";

export function ModeBanner() {
  const { t } = useTranslation("analysis");
  const mode = useAppStore((s) => s.mode);
  const setMode = useAppStore((s) => s.setMode);

  return (
    <div className="flex items-center gap-2 px-3 py-1.5 text-xs border-b border-[var(--md-border)]">
      <span className="md-text-secondary">{t("modeBanner.modeLabel")}</span>
      {(["verification", "exploration"] as const).map((m) => (
        <button
          key={m}
          onClick={() => setMode(m)}
          className={`px-2 py-0.5 rounded capitalize transition-colors ${
            mode === m ? "md-text-on-accent" : "md-text-muted hover:bg-[var(--md-bg-hover)]"
          }`}
          style={mode === m ? { background: m === "verification" ? "var(--md-accent-blue)" : "var(--md-accent-purple)" } : undefined}
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
