/**
 * Pure display helpers for pcap TLS sessions. Kept free of React + i18n so the
 * version mapping and summary interpolation values can be unit-tested in
 * isolation; the components apply ``t()`` to the returned fields.
 */
import type { PcapField, PcapSession } from "@/api/pipeline";

/** Map the wire-format version code ("12"/"13") to a human "1.2"/"1.3". */
export function pcapVersionLabel(version: PcapSession["version"]): string {
  return version === "13" ? "1.3" : "1.2";
}

/** Shorten a client_random hex for compact display (e.g. dropdown options). */
export function shortClientRandom(clientRandom: string): string {
  return clientRandom.length > 16 ? `${clientRandom.slice(0, 16)}…` : clientRandom;
}

/** Interpolation values for the ``stages.oracle.pcap.sessionRow`` i18n string. */
export interface PcapSessionSummary {
  version: string;
  cipher: string;
  clientRecords: number;
  serverRecords: number;
}

/** Build the summary interpolation values for one session row. */
export function pcapSessionSummary(session: PcapSession): PcapSessionSummary {
  return {
    version: pcapVersionLabel(session.version),
    cipher: session.cipher_name,
    clientRecords: session.client_app_records,
    serverRecords: session.server_app_records,
  };
}

/**
 * Whether the oracle can actually use this session. It needs at least one
 * application_data record to decrypt — a handshake-only session yields a
 * misleading "no session matched" error if selected. The backend always emits
 * ``has_app_records``, so it is the single source of truth here.
 */
export function sessionHasAppRecords(session: PcapSession): boolean {
  return session.has_app_records;
}

/**
 * Hex characters shown inline for a field value before it is elided; the full
 * run stays in the row's ``title`` so nothing is actually hidden.
 */
const HEX_PREVIEW_CHARS = 32;

/**
 * The value to show for one protocol field: its decoded form when there is a
 * more useful one than hex (the hostname for ``sni``, the int for
 * ``cipher_suite``, the list for ``cipher_suites``), else the possibly-elided
 * wire bytes.
 */
export function pcapFieldPreview(field: PcapField): string {
  if (typeof field.value === "string" && field.value) return field.value;
  if (typeof field.value === "number") return String(field.value);
  if (Array.isArray(field.value)) return field.value.join(", ");
  if (!field.value_hex) return "";
  return field.value_hex.length > HEX_PREVIEW_CHARS
    ? `${field.value_hex.slice(0, HEX_PREVIEW_CHARS)}…`
    : field.value_hex;
}

/**
 * Which session's protocol fields to show, or ``undefined`` when the honest
 * answer is "ask".
 *
 * Mirrors the backend rule in ``app.tools_pipeline._select_pcap_field_session``
 * and for the same reason: with several sessions parsed and none picked,
 * defaulting to the first would offer a perfectly valid-looking needle from the
 * WRONG handshake. A selection the capture does not hold (one left over from a
 * previous file) is likewise "ask", never a silent fallback.
 */
export function selectFieldSession(
  sessions: PcapSession[],
  clientRandom: string | null,
): PcapSession | undefined {
  if (clientRandom) {
    return sessions.find((session) => session.client_random === clientRandom);
  }
  return sessions.length === 1 ? sessions[0] : undefined;
}
