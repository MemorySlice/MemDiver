/**
 * Canonical Wireshark NSS key-log secret labels.
 *
 * Mirrored from the backend so the composer offers exactly the labels the
 * exporter understands:
 *   - core/protocols.py  TLS_DESCRIPTOR.secret_types (lines 83-90)
 *   - core/keylog_templates.py  TLS12_TEMPLATE (line 27) + TLS13_TEMPLATE (lines 36-41)
 *
 * Each NSS key-log line has the shape: "<LABEL> <client_random> <secret>".
 *
 * NOTE: this list mirrors the backend's TLS labels only (the composer is
 * TLS-focused). The backend ``keylog_result`` accepts the wider
 * ``ALL_SECRET_TYPES`` superset (TLS ∪ SSH2 ∪ AES), so this is intentionally a
 * strict subset — kept honest by ``tests/test_keylog_label_parity.py``.
 */
export const NSS_KEYLOG_LABELS = [
  "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
  "SERVER_HANDSHAKE_TRAFFIC_SECRET",
  "CLIENT_TRAFFIC_SECRET_0",
  "SERVER_TRAFFIC_SECRET_0",
  "EXPORTER_SECRET",
  "CLIENT_RANDOM",
] as const;

export type NssKeylogLabel = (typeof NSS_KEYLOG_LABELS)[number];

/**
 * The TLS ClientHello random is 32 bytes → 64 hex characters. Every canonical
 * label above keys its secret by this full client random, so Wireshark can
 * only match a key-log line whose client_random is exactly this length.
 */
export const CLIENT_RANDOM_HEX_LEN = 64;

/** Default label used when seeding an entry from a verified recovered key. */
export const DEFAULT_SECRET_TYPE: NssKeylogLabel = "CLIENT_TRAFFIC_SECRET_0";
