import path from "node:path";
import { existsSync } from "node:fs";

const DEFAULT =
  "/Users/danielbaier/research/projects/github/issues/2024 fritap issues/2026_success/mempdumps/dataset_memory_slice";

export const DATASET_ROOT = process.env.MEMDIVER_DATASET ?? DEFAULT;
export const RUN_0001 = path.join(
  DATASET_ROOT,
  "gocryptfs/dataset_gocryptfs/run_0001",
);
export const MSL = path.join(RUN_0001, "memslicer.msl");
export const GDB_RAW = path.join(RUN_0001, "gdb_raw.bin");
export const LLDB_RAW = path.join(RUN_0001, "lldb_raw.bin");
export const GCORE = path.join(RUN_0001, "gcore.core");
export const datasetAvailable = existsSync(MSL);
