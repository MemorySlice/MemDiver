/**
 * Typed client for `POST /api/disasm` — decode the CAPTURED bytes at an address of one dump.
 *
 * `address` is in the view's own space and a kernel VA exceeds 2^53, so it is sent as an
 * exact decimal literal spliced into the body (never through a JS number).
 */

import { requestLossless, type WireInt } from "./lossless-json";

export interface DisasmRow {
  addr: string;
  bytes: string;
  mnemonic: string;
  op_str: string;
  size: number;
  stop_reason?: string | null;
}
/** `start` is exact (a decimal string past 2^53); `start_hex` is the server's own `0x` text. */
export interface DisasmGap { start: WireInt; start_hex?: string; length: number; reason: string }
export interface DisasmStop { addr: string; addr_hex?: string; offset: number; stop_reason: string }
export interface DisasmResult {
  dump_path: string;
  arch: string;
  space: string;
  address: string;
  length: number;
  rows: DisasmRow[];
  row_count: number;
  max_insns: number;
  truncated: boolean;
  stops: DisasmStop[];
  coverage: { requested: number; captured: number; gaps: DisasmGap[]; complete: boolean };
}

const ADDRESS_SLOT = "__ADDRESS__";

export const disassemble = (
  dumpPath: string, address: bigint, length: number, opts: { arch?: string; view?: string } = {},
) => {
  const body = JSON.stringify({
    dump_path: dumpPath, address: ADDRESS_SLOT, length, arch: opts.arch ?? "auto",
    ...(opts.view ? { view: opts.view } : {}),
  }).replace(`"${ADDRESS_SLOT}"`, address.toString());
  return requestLossless<DisasmResult>("/api/disasm", { method: "POST", body });
};
