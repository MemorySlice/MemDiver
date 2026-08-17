import { Component, type ReactNode, type ErrorInfo } from "react";
import { useTranslation } from "react-i18next";

/**
 * A fallback can be a plain node (rendered as-is, unchanged from the
 * original API) or a function that receives a `retry` callback so it can
 * render its own "try again" control.
 */
export type ErrorBoundaryFallback = ReactNode | ((retry: () => void) => ReactNode);

interface Props {
  children: ReactNode;
  fallback?: ErrorBoundaryFallback;
  /**
   * Invoked right before the boundary clears its error state, i.e. as
   * part of `retry()`. Lets a parent recreate anything that needs a fresh
   * attempt (e.g. a fresh `lazy()` import whose promise already rejected
   * once) so a transient chunk-load/render failure gets a genuine second
   * try instead of immediately re-throwing the same cached error.
   */
  onReset?: () => void;
}

function DefaultErrorFallback({
  message,
  onRetry,
}: {
  message?: string;
  onRetry: () => void;
}) {
  const { t } = useTranslation("misc");
  return (
    <div className="p-4 text-sm md-text-muted">
      <p className="font-semibold">{t("app.errorBoundaryTitle")}</p>
      <p className="mt-1 opacity-70">{message}</p>
      <button
        type="button"
        className="mt-2 px-2 py-1 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]"
        onClick={onRetry}
      >
        {t("app.errorBoundaryRetry")}
      </button>
    </div>
  );
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, error: null };

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("[ErrorBoundary]", error, info.componentStack);
  }

  private retry = () => {
    this.props.onReset?.();
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError) {
      const { fallback } = this.props;
      if (typeof fallback === "function") {
        return fallback(this.retry);
      }
      return fallback ?? (
        <DefaultErrorFallback message={this.state.error?.message} onRetry={this.retry} />
      );
    }
    return this.props.children;
  }
}
