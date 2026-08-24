/**
 * Pure display helpers for pcap TLS sessions. Kept free of React + i18n so the
 * version mapping and summary interpolation values can be unit-tested in
 * isolation; the components apply ``t()`` to the returned fields.
 */
import type { PcapSession } from "@/api/pipeline";

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
