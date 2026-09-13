/**
 * In-app documentation slide-over.
 *
 * Fetches one `docs/`-relative markdown page from `GET /api/docs/{path}` and
 * renders it with `@/utils/markdown` — a React node tree, never an HTML
 * string, so nothing in a doc can execute.
 *
 * This replaces four dead `/docs/<path>.md` links: no environment has ever
 * served that path (FastAPI's Swagger UI owns `/docs`, and the Vite dev
 * server's `server.fs.allow` excludes the repo-root `docs/` tree), so every
 * click returned `Not Found`.
 *
 * Relative `.md` links between docs navigate INSIDE the panel via `docPath`
 * state, which is why the panel owns the path rather than taking it as a
 * fixed prop.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { fallbackDocUrl, getDoc } from "@/api/docs";
import { renderMarkdown } from "@/utils/markdown";

export interface DocPanelProps {
  /** `docs/`-relative page to open, e.g. `visualizations/consensus.md`. */
  doc: string;
  onClose: () => void;
}

/** The settled outcome of one fetch, tagged with the path it answers for. */
interface FetchedDoc {
  path: string;
  content: string | null;
  error: unknown;
}

export function DocPanel({ doc, onClose }: DocPanelProps) {
  const { t } = useTranslation("misc");
  // `doc` seeds the panel; in-panel links move it from here on. Callers that
  // need to swap the page from outside remount with a `key` (see EmptyState),
  // which is why there is no prop -> state sync effect.
  const [docPath, setDocPath] = useState(doc);
  const [fetched, setFetched] = useState<FetchedDoc | null>(null);
  const closeRef = useRef<HTMLButtonElement | null>(null);
  const bodyRef = useRef<HTMLDivElement | null>(null);
  const titleId = "doc-panel-title";

  // Loading is DERIVED from "the settled result is not for the page we want"
  // rather than held in its own flag. A flag would have to be raised
  // synchronously inside the fetch effect, which is the cascading-render
  // pattern `react-hooks/set-state-in-effect` rejects; this cannot go stale.
  const loading = fetched === null || fetched.path !== docPath;
  const content = loading ? null : fetched.content;
  const error = loading ? null : fetched.error;

  useEffect(() => {
    let cancelled = false;
    getDoc(docPath)
      .then((page) => {
        if (!cancelled) setFetched({ path: docPath, content: page.content, error: null });
      })
      .catch((err: unknown) => {
        if (!cancelled) setFetched({ path: docPath, content: null, error: err });
      });
    return () => {
      cancelled = true;
    };
  }, [docPath]);

  // Focus on open, restore on close. Captured as the element that was focused
  // when the panel mounted, so the empty state's trigger gets focus back.
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    closeRef.current?.focus();
    return () => previous?.focus?.();
  }, []);

  // Escape closes from anywhere, not just from inside the dialog subtree: a
  // click on the backdrop moves focus to <body>, and a reader who lands there
  // still expects Escape to work.
  useEffect(() => {
    const onEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onEscape);
    return () => document.removeEventListener("keydown", onEscape);
  }, [onClose]);

  const handleKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLDivElement>) => {
      if (event.key !== "Tab") return;
      // Minimal focus trap: cycle within the dialog's own tabbables.
      const focusable = event.currentTarget.querySelectorAll<HTMLElement>(
        'a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])',
      );
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    },
    [],
  );

  // A new page means a new document: send the reader back to the top. The
  // scroll lives in an effect rather than in `navigate` because `navigate` is
  // handed to the renderer DURING render, and reading a ref there is exactly
  // what the React Compiler's "Cannot access refs during render" rule forbids.
  useEffect(() => {
    bodyRef.current?.scrollTo?.({ top: 0 });
  }, [docPath]);

  const navigate = useCallback((next: string) => setDocPath(next), []);

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-black/50"
      onClick={onClose}
      onKeyDown={handleKeyDown}
      data-testid="doc-panel-overlay"
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        data-testid="doc-panel"
        onClick={(event) => event.stopPropagation()}
        className="flex h-full w-full max-w-2xl flex-col border-l shadow-xl text-[var(--text-sm)]"
        style={{
          background: "var(--md-bg-primary)",
          borderColor: "var(--md-border)",
          color: "var(--md-text-primary)",
        }}
      >
        <header
          className="flex items-center justify-between gap-[var(--space-3)] px-[var(--space-4)] py-[var(--space-3)] border-b"
          style={{ borderColor: "var(--md-border)" }}
        >
          <h2
            id={titleId}
            className="text-[var(--text-sm)] font-semibold truncate"
            style={{ color: "var(--md-text-bright)" }}
          >
            {t("docs.title", { path: docPath })}
          </h2>
          <button
            ref={closeRef}
            type="button"
            onClick={onClose}
            aria-label={t("docs.close")}
            className="px-[var(--space-2)] py-[var(--space-1)] rounded-[var(--radius-sm)] text-[var(--text-xs)] border"
            style={{ borderColor: "var(--md-border)", color: "var(--md-text-secondary)" }}
          >
            {t("docs.close")}
          </button>
        </header>

        <div
          ref={bodyRef}
          className="flex-1 overflow-y-auto px-[var(--space-4)] py-[var(--space-3)]"
          data-testid="doc-panel-body"
        >
          {loading && (
            <p role="status" style={{ color: "var(--md-text-muted)" }}>
              {t("docs.loading")}
            </p>
          )}

          {!loading && error !== null && (
            <div role="alert" className="space-y-[var(--space-2)]">
              <p style={{ color: "var(--md-text-primary)" }}>{t("docs.errorTitle")}</p>
              <p style={{ color: "var(--md-text-secondary)" }}>
                {t("docs.errorFallback")}
              </p>
              <a
                href={fallbackDocUrl(docPath, error)}
                target="_blank"
                rel="noreferrer noopener"
                className="underline underline-offset-2"
                style={{ color: "var(--md-accent-blue)" }}
              >
                {fallbackDocUrl(docPath, error)}
              </a>
            </div>
          )}

          {!loading && error === null && content !== null && (
            <article data-testid="doc-panel-content">
              {renderMarkdown(content, {
                basePath: docPath,
                onDocLink: navigate,
                labels: {
                  note: t("docs.admonitionNote"),
                  tip: t("docs.admonitionTip"),
                  warning: t("docs.admonitionWarning"),
                  caution: t("docs.admonitionCaution"),
                  important: t("docs.admonitionImportant"),
                  figure: t("docs.figure"),
                },
              })}
            </article>
          )}
        </div>
      </div>
    </div>
  );
}
