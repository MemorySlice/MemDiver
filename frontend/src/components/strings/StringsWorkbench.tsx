import { useState } from "react";
import { useTranslation } from "react-i18next";
import { StringsPanel } from "./StringsPanel";
import { StringsTable } from "./StringsTable";

type Mode = "stream" | "table";

interface Props {
  dumpPath: string;
}

/** The Strings tab: the streaming extractor, or the table with IOC badges. */
export function StringsWorkbench({ dumpPath }: Props) {
  const { t } = useTranslation("misc");
  const [mode, setMode] = useState<Mode>("stream");
  const modes: Mode[] = ["stream", "table"];
  return (
    <div className="h-full flex flex-col">
      <div role="tablist" aria-label={t("strings.table.modeLabel")}
           className="flex gap-1 px-2 py-1 border-b border-[var(--md-border)] text-xs">
        {modes.map((m) => (
          <button
            key={m}
            role="tab"
            aria-selected={mode === m}
            onClick={() => setMode(m)}
            className={`px-2 py-0.5 rounded border border-[var(--md-border)] ${mode === m ? "bg-[var(--md-bg-selected)]" : "hover:bg-[var(--md-bg-hover)]"}`}
          >
            {t(`strings.table.mode.${m}`)}
          </button>
        ))}
      </div>
      <div className="flex-1 min-h-0">
        {mode === "stream" ? <StringsPanel dumpPath={dumpPath} /> : <StringsTable dumpPath={dumpPath} />}
      </div>
    </div>
  );
}
