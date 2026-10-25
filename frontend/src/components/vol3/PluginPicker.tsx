import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import type { Vol3Plugin } from "@/api/vol3";

/** Searchable list of the bundled plugins (name + one-line description). */
export function PluginPicker({ plugins, selected, onSelect }: {
  plugins: readonly Vol3Plugin[];
  selected: string;
  onSelect: (name: string) => void;
}) {
  const { t } = useTranslation("vol3");
  const [query, setQuery] = useState("");
  const shown = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return plugins;
    return plugins.filter((p) =>
      p.name.toLowerCase().includes(needle) || p.description.toLowerCase().includes(needle));
  }, [plugins, query]);

  return (
    <div className="space-y-1" data-testid="plugin-picker">
      <input type="text" value={query} onChange={(e) => setQuery(e.target.value)}
        aria-label={t("plugin.search")} placeholder={t("plugin.search")}
        className="w-full px-2 py-1 text-xs rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)]" />
      <div className="text-xs md-text-muted">
        {t("plugin.count", { shown: shown.length, total: plugins.length })}
      </div>
      <ul className="max-h-40 overflow-auto rounded border border-[var(--md-border)]">
        {shown.map((p) => (
          <li key={p.name}>
            <button type="button" onClick={() => onSelect(p.name)} data-testid="plugin-option"
              aria-pressed={p.name === selected} title={p.description}
              className={`w-full text-left px-2 py-1 text-xs hover:bg-[var(--md-bg-hover)] ${
                p.name === selected ? "bg-[var(--md-bg-hover)] md-text-accent" : ""}`}>
              <span className="font-mono">{p.name}</span>
              {p.description && <span className="block truncate md-text-muted">{p.description}</span>}
            </button>
          </li>
        ))}
        {shown.length === 0 && <li className="px-2 py-1 text-xs md-text-muted">{t("plugin.none")}</li>}
      </ul>
    </div>
  );
}
