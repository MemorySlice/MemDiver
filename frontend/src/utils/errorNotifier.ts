/**
 * Lightweight in-process notifier used by the top-right toast stack.
 *
 * Components publish messages via `notifyError(...)`; the
 * `NotificationStack` subscribes via `subscribe(...)` and re-renders.
 * Errors are sticky by default; info / warning auto-dismiss after 5s.
 */

export type Severity = "info" | "warning" | "error";

export interface ErrorNotification {
  id: string;
  message: string;
  context: string;
  severity: Severity;
  timestamp: number;
}

export interface NotifyOptions {
  severity?: Severity;
  /** 0 means sticky. Defaults: error => 0, info/warning => 5000. */
  autoDismissMs?: number;
}

type Listener = (notifs: ErrorNotification[]) => void;

let counter = 0;
const notifications = new Map<string, ErrorNotification>();
const listeners = new Set<Listener>();

function broadcast(): void {
  const arr = Array.from(notifications.values());
  listeners.forEach((cb) => cb(arr));
}

export function notifyError(
  message: string,
  context: string,
  options?: NotifyOptions,
): string {
  const severity = options?.severity ?? "error";
  const autoDismissMs =
    options?.autoDismissMs ?? (severity === "error" ? 0 : 5000);
  const id = `${context}-${Date.now()}-${++counter}`;
  notifications.set(id, {
    id,
    message,
    context,
    severity,
    timestamp: Date.now(),
  });
  broadcast();
  if (autoDismissMs > 0) {
    setTimeout(() => dismiss(id), autoDismissMs);
  }
  return id;
}

export function dismiss(id: string): void {
  if (notifications.delete(id)) broadcast();
}

export function subscribe(cb: Listener): () => void {
  listeners.add(cb);
  cb(Array.from(notifications.values()));
  return () => {
    listeners.delete(cb);
  };
}
