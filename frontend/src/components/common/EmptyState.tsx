import type { ReactNode } from "react";

export interface EmptyStateProps {
  icon?: ReactNode;
  title: string;
  description?: ReactNode;
  primaryCta?: { label: string; onClick: () => void; disabled?: boolean };
  secondary?: { label: string; href: string };
  className?: string;
  children?: ReactNode;
  "data-testid"?: string;
}

export function EmptyState(props: EmptyStateProps) {
  const { icon, title, description, primaryCta, secondary, className, children } = props;
  const isExternal = secondary?.href?.startsWith("http");
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
              className="px-3 py-1.5 rounded text-white text-xs disabled:opacity-40 transition-opacity"
              style={{ background: "var(--md-accent-blue)" }}
            >
              {primaryCta.label}
            </button>
          )}
          {secondary && (
            <a
              href={secondary.href}
              {...(isExternal ? { target: "_blank", rel: "noreferrer" } : {})}
              className="text-[var(--text-xs)] underline-offset-2 hover:underline"
              style={{ color: "var(--md-accent-blue)" }}
            >
              {secondary.label}
            </a>
          )}
        </div>
      )}
      {children}
    </div>
  );
}
