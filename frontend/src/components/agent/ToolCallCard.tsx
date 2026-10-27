import { useState } from "react";
import { useTranslation } from "react-i18next";

import type { TranscriptItem } from "@/stores/agent-reducer";
import { describeLocation, isDumpOpen, isLocationNavigable, openLocationInHex } from "./open-location";

type ToolItem = Extract<TranscriptItem, { kind: "tool" }>;

function Badge({ children, color, testId }: { children: string; color: string; testId?: string }) {
  return (
    <span data-testid={testId} className="px-1 rounded border text-[10px] uppercase"
      style={{ color, borderColor: color }}>{children}</span>
  );
}

export function ToolCallCard({ item }: { item: ToolItem }) {
  const { t } = useTranslation("agent");
  const [open, setOpen] = useState(false);
  const r = item.result;
  const accessColor = item.access === "write" ? "var(--md-accent-orange)" : "var(--md-accent-blue)";
  return (
    <div data-testid="tool-card" className="rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)] p-2 text-xs space-y-1">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="font-mono">{item.name}</span>
        <Badge color={accessColor} testId="tool-access">{t(`tool.access.${item.access === "write" ? "write" : "read"}`)}</Badge>
        {r === null && <span className="md-text-muted">{t("tool.running")}</span>}
        {r && <Badge color={r.ok ? "var(--md-accent-green)" : "var(--md-accent-red)"}>{t(r.ok ? "tool.ok" : "tool.failed")}</Badge>}
        {r && <span className="md-text-muted">{t("tool.bytes", { n: r.bytes })}</span>}
        {r?.truncated && <Badge color="var(--md-accent-orange)" testId="tool-truncated">{t("tool.truncated")}</Badge>}
        <button type="button" aria-expanded={open} onClick={() => setOpen((o) => !o)}
          className="ml-auto md-text-secondary hover:underline">
          {t(open ? "tool.hideInput" : "tool.showInput")}
        </button>
      </div>
      {open && (
        <pre aria-label={t("tool.input")} className="font-mono text-[11px] overflow-auto max-h-40 whitespace-pre-wrap break-all">
          {JSON.stringify(item.input, null, 2)}
        </pre>
      )}
      {r && <p className="md-text-secondary whitespace-pre-wrap break-words">{r.summary}</p>}
      {r && r.locations.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {r.locations.map((loc, i) => {
            const navigable = isLocationNavigable(loc);
            const enabled = navigable && isDumpOpen(loc.dump_path);
            return (
              <button key={i} type="button" disabled={!enabled}
                title={enabled ? undefined : t(navigable ? "tool.dumpNotOpen" : "tool.vaOnly")}
                aria-label={t("tool.openInHexAt", { where: describeLocation(loc) })}
                onClick={() => openLocationInHex(loc)}
                className="px-1.5 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-50">
                {t("tool.openInHex")}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
