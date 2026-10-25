import { useRef } from "react";
import { useTranslation } from "react-i18next";

const TAB = "    ";

/** Number of lines in `text` (an empty text still has line 1). */
const lineCount = (text: string) => text.split("\n").length;

/**
 * A plain textarea with a line-number gutter (no editor dependency).
 * The gutter scrolls with the textarea; `errorLine` (1-based) is marked in it,
 * and Tab inserts four spaces instead of leaving the field.
 */
export function SourceEditor({ value, onChange, errorLine = null }: {
  value: string;
  onChange: (next: string) => void;
  errorLine?: number | null;
}) {
  const { t } = useTranslation("vol3");
  const gutter = useRef<HTMLDivElement>(null);
  const total = lineCount(value);

  const onKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key !== "Tab" || e.shiftKey) return;
    e.preventDefault();
    const el = e.currentTarget;
    const { selectionStart: from, selectionEnd: to } = el;
    onChange(value.slice(0, from) + TAB + value.slice(to));
    // Restore the caret after React re-renders the controlled value.
    requestAnimationFrame(() => el.setSelectionRange(from + TAB.length, from + TAB.length));
  };

  return (
    <div className="flex rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)] overflow-hidden"
      data-testid="source-editor" style={{ height: "18rem" }}>
      <div ref={gutter} aria-hidden="true" data-testid="editor-gutter"
        className="select-none overflow-hidden text-right font-mono md-text-muted border-r border-[var(--md-border)] py-1"
        style={{ lineHeight: "1.25rem", minWidth: "3rem" }}>
        {Array.from({ length: total }, (_, i) => {
          const n = i + 1;
          const bad = n === errorLine;
          return (
            <div key={n} data-testid="gutter-line" data-error={bad ? "true" : undefined} className="px-1"
              title={bad ? t("editor.errorLine", { n }) : undefined}
              style={bad ? { color: "var(--md-accent-red)", background: "var(--md-bg-active)", fontWeight: 700 } : undefined}>
              {bad ? `! ${n}` : n}
            </div>
          );
        })}
      </div>
      <textarea value={value} spellCheck={false} wrap="off" data-testid="editor-textarea"
        aria-label={t("editor.sourceLabel")}
        onChange={(e) => onChange(e.target.value)} onKeyDown={onKeyDown}
        onScroll={(e) => { if (gutter.current) gutter.current.scrollTop = e.currentTarget.scrollTop; }}
        className="flex-1 min-w-0 resize-none bg-transparent font-mono outline-none py-1 px-2"
        style={{ lineHeight: "1.25rem", whiteSpace: "pre", overflow: "auto" }} />
    </div>
  );
}
