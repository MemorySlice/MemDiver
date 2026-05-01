import { useEffect, useState } from "react";
import {
  dismiss,
  subscribe,
  type ErrorNotification,
  type Severity,
} from "@/utils/errorNotifier";

const SEVERITY_STYLES: Record<
  Severity,
  { container: string; text: string; borderStyle?: React.CSSProperties }
> = {
  info: {
    container: "md-bg-secondary",
    text: "md-text-accent",
    borderStyle: { borderColor: "var(--md-accent-blue)" },
  },
  warning: {
    container: "md-bg-warning-subtle md-border-warning",
    text: "md-text-warning",
  },
  error: {
    container: "md-bg-error-subtle md-border-error",
    text: "md-text-error",
  },
};

function Toast({ notif }: { notif: ErrorNotification }) {
  const styles = SEVERITY_STYLES[notif.severity] ?? SEVERITY_STYLES.error;
  return (
    <div
      role="alert"
      data-severity={notif.severity}
      className={`pointer-events-auto flex items-start gap-2 px-3 py-2 rounded shadow-md border ${styles.container}`}
      style={{ minWidth: "240px", maxWidth: "360px", ...(styles.borderStyle ?? {}) }}
    >
      <div className="flex-1 text-xs">
        <p className={`font-semibold uppercase tracking-wider ${styles.text}`}>
          {notif.severity}
        </p>
        <p className="md-text-primary mt-0.5 break-words">{notif.message}</p>
        {notif.context && (
          <p className="md-text-muted mt-0.5 text-[10px]">{notif.context}</p>
        )}
      </div>
      <button
        type="button"
        onClick={() => dismiss(notif.id)}
        aria-label="Dismiss notification"
        className="md-text-muted hover:md-text-primary text-sm leading-none px-1"
      >
        &times;
      </button>
    </div>
  );
}

export function NotificationStack() {
  const [notifs, setNotifs] = useState<ErrorNotification[]>([]);

  useEffect(() => {
    return subscribe(setNotifs);
  }, []);

  if (notifs.length === 0) return null;

  return (
    <div
      className="fixed top-3 right-3 z-50 flex flex-col gap-2 pointer-events-none"
      data-testid="notification-stack"
    >
      {notifs.map((n) => (
        <Toast key={n.id} notif={n} />
      ))}
    </div>
  );
}
