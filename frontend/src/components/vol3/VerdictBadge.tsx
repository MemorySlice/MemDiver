import { useTranslation } from "react-i18next";

import type { Vol3Verdict } from "@/api/vol3";

const STYLE: Record<Vol3Verdict, { icon: string; colour: string }> = {
  pass: { icon: "✓", colour: "var(--md-accent-green)" },
  fail: { icon: "✗", colour: "var(--md-accent-red)" },
  indeterminate: { icon: "?", colour: "var(--md-accent-orange)" },
};

/**
 * Verdict as icon + word + colour: colour is never the only cue. `label`
 * replaces the fixture word for another verdict vocabulary (e.g. a synthesized
 * plugin's "proven" / "not proven").
 */
export function VerdictBadge({ verdict, label }: { verdict: Vol3Verdict; label?: string }) {
  const { t } = useTranslation("vol3");
  const { icon, colour } = STYLE[verdict];
  return (
    <span data-testid="verdict-badge" data-verdict={verdict}
      className="inline-flex items-center gap-1 px-1.5 rounded border font-medium"
      style={{ color: colour, borderColor: colour }}>
      <span aria-hidden="true">{icon}</span>{label ?? t(`editor.fixtures.verdict.${verdict}`)}
    </span>
  );
}
