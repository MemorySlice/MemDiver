/**
 * Task progress WebSocket client.
 *
 * Matches the backend ProgressBus.Event schema from
 * api/services/progress_bus.py. Events are plain JSON objects with a
 * monotonically-increasing per-task ``seq``. The client:
 *
 *  - Connects to ``/ws/tasks/{taskId}?since=<seq>`` so a reconnect
 *    only receives events newer than whatever it last processed.
 *  - Auto-reconnects with exponential backoff (capped) when the
 *    server closes unexpectedly and the client has NOT seen a
 *    terminal ``done`` / ``error`` event yet.
 *  - Falls back to the HTTP backfill endpoint
 *    ``/api/tasks/{taskId}/events?since=<seq>`` before re-opening the
 *    socket, because the 512-event ring buffer on the server may
 *    have rolled past the client's last-seen seq.
 *
 * ``TaskProgressEvent`` is the superset discriminated union the backend
 * can emit; consumers pick out the fields they care about.
 */

export type TaskProgressEventType =
  | "stage_start"
  | "progress"
  | "stage_end"
  | "funnel"
  | "nsweep_point"
  | "oracle_tick"
  | "oracle_hit"
  | "artifact"
  | "done"
  | "error";

export interface ProgressArtifact {
  name: string;
  relpath?: string;
  path?: string;
  size?: number;
  sha256?: string;
  media_type?: string;
}

export interface TaskProgressEvent {
  task_id: string;
  type: TaskProgressEventType;
  seq: number;
  ts: number;
  stage?: string | null;
  pct?: number | null;
  msg?: string | null;
  extra?: Record<string, unknown> | null;
  artifact?: ProgressArtifact | null;
  error?: string | null;
}

export type ProgressHandler = (msg: TaskProgressEvent) => void;

const TERMINAL_TYPES: ReadonlySet<TaskProgressEventType> = new Set([
  "done",
  "error",
]);

const RECONNECT_DELAYS_MS = [500, 1000, 2000, 4000, 8000, 15000] as const;

export interface TaskWebSocketOptions {
  /** Seq the caller has already processed; replay starts after this. */
  since?: number;
  /** Auto-reconnect until a terminal event arrives. Default: true. */
  autoReconnect?: boolean;
  /** Optional override for testing. Default: derived from location. */
  baseUrl?: string;
}

/**
 * Reconnecting WebSocket client for ``/ws/tasks/{taskId}``.
 *
 * Usage:
 *
 *     const ws = new TaskWebSocket();
 *     const unsubscribe = ws.onProgress((ev) => { ... });
 *     ws.connect(taskId, { since: lastSeq });
 *     // later
 *     unsubscribe();
 *     ws.close();
 */
export class TaskWebSocket {
  private ws: WebSocket | null = null;
  private handlers: Set<ProgressHandler> = new Set();
  private taskId: string | null = null;
  private lastSeq = 0;
  private autoReconnect = true;
  private reconnectAttempt = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private closedByCaller = false;
  private terminated = false;
  private baseUrl: string | null = null;

  connect(taskId: string, options: TaskWebSocketOptions = {}): void {
    this.taskId = taskId;
    this.lastSeq = Math.max(this.lastSeq, options.since ?? 0);
    this.autoReconnect = options.autoReconnect !== false;
    this.baseUrl = options.baseUrl ?? null;
    this.closedByCaller = false;
    this.terminated = false;
    this.reconnectAttempt = 0;
    void this.openSocket();
  }

  onProgress(handler: ProgressHandler): () => void {
    this.handlers.add(handler);
    return () => {
      this.handlers.delete(handler);
    };
  }

  close(): void {
    this.closedByCaller = true;
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.ws?.close();
    this.ws = null;
    this.handlers.clear();
    this.taskId = null;
  }

  /** Most recent seq this client has observed (0 if nothing yet). */
  getLastSeq(): number {
    return this.lastSeq;
  }

  // ---- internals --------------------------------------------------------

  private buildWsUrl(taskId: string): string {
    if (this.baseUrl) {
      const sep = this.baseUrl.includes("?") ? "&" : "?";
      return `${this.baseUrl}${sep}since=${this.lastSeq}`;
    }
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    return `${proto}//${location.host}/ws/tasks/${taskId}?since=${this.lastSeq}`;
  }

  private buildBackfillUrl(taskId: string): string {
    return `/api/tasks/${encodeURIComponent(taskId)}/events?since=${this.lastSeq}`;
  }

  private async openSocket(): Promise<void> {
    if (this.taskId === null || this.closedByCaller || this.terminated) return;

    // Before opening the live socket, ask the HTTP backfill endpoint
    // for any events the ring buffer may still have that sit beyond
    // whatever the socket will replay. On first connect this is a
    // no-op (since=0 returns the same events). On reconnect it
    // catches races where new events arrived while we were offline.
    try {
      const resp = await fetch(this.buildBackfillUrl(this.taskId));
      if (resp.ok) {
        const data: { events?: TaskProgressEvent[] } = await resp.json();
        for (const ev of data.events ?? []) {
          this.handleEvent(ev);
          if (this.terminated) return;
        }
      }
    } catch {
      // HTTP backfill is best-effort; the WS replay covers the common case.
    }

    if (this.taskId === null || this.closedByCaller || this.terminated) return;
    const url = this.buildWsUrl(this.taskId);
    let ws: WebSocket;
    try {
      ws = new WebSocket(url);
    } catch {
      this.scheduleReconnect();
      return;
    }
    this.ws = ws;
    ws.onmessage = (evt) => {
      try {
        const ev = JSON.parse(evt.data) as TaskProgressEvent;
        this.handleEvent(ev);
      } catch {
        this.dispatch({
          task_id: this.taskId ?? "",
          type: "error",
          seq: this.lastSeq,
          ts: Date.now() / 1000,
          error: "Invalid message from server",
        });
      }
    };
    ws.onerror = () => {
      // Don't emit here — onclose will follow and handle reconnect.
    };
    ws.onclose = () => {
      this.ws = null;
      if (this.terminated || this.closedByCaller) return;
      this.scheduleReconnect();
    };
  }

  private handleEvent(event: TaskProgressEvent): void {
    if (typeof event.seq === "number" && event.seq > this.lastSeq) {
      this.lastSeq = event.seq;
    }
    this.reconnectAttempt = 0;
    this.dispatch(event);
    if (TERMINAL_TYPES.has(event.type)) {
      this.terminated = true;
      if (this.reconnectTimer !== null) {
        clearTimeout(this.reconnectTimer);
        this.reconnectTimer = null;
      }
      this.ws?.close();
    }
  }

  private dispatch(event: TaskProgressEvent): void {
    for (const h of this.handlers) {
      h(event);
    }
  }

  private scheduleReconnect(): void {
    if (!this.autoReconnect || this.closedByCaller || this.terminated) return;
    const delay =
      RECONNECT_DELAYS_MS[
        Math.min(this.reconnectAttempt, RECONNECT_DELAYS_MS.length - 1)
      ];
    this.reconnectAttempt += 1;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      void this.openSocket();
    }, delay);
  }
}
