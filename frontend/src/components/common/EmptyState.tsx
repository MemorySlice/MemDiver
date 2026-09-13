import { useState, type ReactNode } from "react";
import { DocPanel } from "@/components/common/DocPanel";

/** An ordinary link out of the empty state. Unchanged, byte for byte. */
export interface EmptyStateHrefLink {
  label: string;
  href: string;
}

/**
 * A link into the in-app documentation panel.
 *
 * `doc` is a `docs/`-relative markdown path (`visualizations/consensus.md`),
 * NOT a URL. The four call sites that used to pass `href: "/docs/..."` pass
 * this instead: no environment has ever served `/docs/<path>.md` — FastAPI's
 * Swagger UI owns `/docs`, and the Vite dev server's `server.fs.allow`
 * excludes the repo-root `docs/` tree — so every one of those links 404'd.
 */
export interface EmptyStateDocLink {
  label: string;
  doc: string;
}

export type EmptyStateSecondary = EmptyStateHrefLink | EmptyStateDocLink;

export interface EmptyStateProps {
  icon?: ReactNode;
  title: string;
  description?: ReactNode;
  primaryCta?: { label: string; onClick: () => void; disabled?: boolean };
  secondary?: EmptyStateSecondary;
  className?: string;
  children?: ReactNode;
  "data-testid"?: string;
}

function isDocLink(link: EmptyStateSecondary): link is EmptyStateDocLink {
  return "doc" in link;
}

export function EmptyState(props: EmptyStateProps) {
  const { icon, title, description, primaryCta, secondary, className, children } = props;
  const [openDoc, setOpenDoc] = useState<string | null>(null);
  const isExternal =
    secondary !== undefined && !isDocLink(secondary) && secondary.href.startsWith("http");
  return (
    <div
      role="status"
      data-testid={props["data-testid"] ?? "empty-state"}
      className={`flex flex-col items-center text-center mx-auto max-w-md px-[var(--space-5)] py-[var(--space-5)] gap-[var(--space-3)] text-xs ${className ?? ""}`}
    >
      {icon && (
        <div
          aria-hidden="true"
          className="flex items-center justify-center h-8 w-8 rounded-[var(--radius-md)] border border-[var(--md-border)] bg-[var(--md-bg-secondary)] md-text-muted"
        >
          {icon}
        </div>
      )}
      <h3
        className="text-[var(--text-md)] font-semibold"
        style={{ color: "var(--md-text-primary)" }}
      >
        {title}
      </h3>
      {description && (
        <p
          className="text-[var(--text-sm)] leading-relaxed max-w-[52ch]"
          style={{ color: "var(--md-text-secondary)" }}
        >
          {description}
        </p>
      )}
      {(primaryCta || secondary) && (
        <div className="flex items-center gap-[var(--space-3)] mt-[var(--space-2)]">
          {primaryCta && (
            <button
              type="button"
              onClick={primaryCta.onClick}
              disabled={primaryCta.disabled}
              className="px-3 py-1.5 rounded md-text-on-accent text-xs disabled:opacity-40 transition-opacity"
              style={{ background: "var(--md-accent-blue)" }}
            >
              {primaryCta.label}
            </button>
          )}
          {secondary &&
            (isDocLink(secondary) ? (
              <button
                type="button"
                onClick={() => setOpenDoc(secondary.doc)}
                className="text-[var(--text-xs)] underline-offset-2 hover:underline bg-transparent p-0"
                style={{ color: "var(--md-accent-blue)" }}
              >
                {secondary.label}
              </button>
            ) : (
              <a
                href={secondary.href}
                {...(isExternal ? { target: "_blank", rel: "noreferrer" } : {})}
                className="text-[var(--text-xs)] underline-offset-2 hover:underline"
                style={{ color: "var(--md-accent-blue)" }}
              >
                {secondary.label}
              </a>
            ))}
        </div>
      )}
      {children}
      {openDoc !== null && (
        // `key` so a different page always gets a fresh panel: DocPanel seeds
        // its own path state from this prop and then owns it.
        <DocPanel key={openDoc} doc={openDoc} onClose={() => setOpenDoc(null)} />
      )}
    </div>
  );
}
