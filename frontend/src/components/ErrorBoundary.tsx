import { Component, type ReactNode, type ErrorInfo } from "react";
import { useTranslation } from "react-i18next";

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

function DefaultErrorFallback({ message }: { message?: string }) {
  const { t } = useTranslation("misc");
  return (
    <div className="p-4 text-sm md-text-muted">
      <p className="font-semibold">{t("app.errorBoundaryTitle")}</p>
      <p className="mt-1 opacity-70">{message}</p>
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

  render() {
    if (this.state.hasError) {
      return this.props.fallback ?? (
        <DefaultErrorFallback message={this.state.error?.message} />
      );
    }
    return this.props.children;
  }
}
