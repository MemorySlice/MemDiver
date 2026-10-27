import { Fragment, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { parseInline } from "@/utils/markdown";

const TAG = /\[(seen|inferred|unknown)\]/g;
const TAG_COLOR: Record<string, string> = {
  seen: "var(--md-accent-green)",
  inferred: "var(--md-accent-blue)",
  unknown: "var(--md-text-muted)",
};

/** Assistant text: inline markdown (as React nodes, never HTML) with [seen]/[inferred]/[unknown] as badges. */
export function EvidenceText({ text }: { text: string }) {
  const { t } = useTranslation("agent");
  const renderLine = (line: string): ReactNode[] => {
    const out: ReactNode[] = [];
    let last = 0;
    for (const m of line.matchAll(TAG)) {
      const at = m.index ?? 0;
      if (at > last) out.push(...parseInline(line.slice(last, at)));
      out.push(
        <span
          key={`tag-${at}`}
          data-testid={`evidence-${m[1]}`}
          className="mx-0.5 px-1 rounded border text-[10px] uppercase align-middle"
          style={{ color: TAG_COLOR[m[1]], borderColor: TAG_COLOR[m[1]] }}
        >
          {t(`evidence.${m[1]}`)}
        </span>,
      );
      last = at + m[0].length;
    }
    if (last < line.length) out.push(...parseInline(line.slice(last)));
    return out;
  };
  return (
    <div className="text-xs whitespace-pre-wrap break-words">
      {text.split("\n").map((line, i) => (
        <Fragment key={i}>
          {i > 0 && <br />}
          {renderLine(line)}
        </Fragment>
      ))}
    </div>
  );
}
