import path from "node:path";
import { existsSync } from "node:fs";

/**
 * Two fixture tiers gate the e2e specs:
 *
 *  - SMOKE specs (load an MSL + assert inspect/blocks/tabs render) should
 *    gate on `syntheticMslAvailable` and load `syntheticMslPath`. The
 *    synthetic fixture is committed (see tests/e2e/fixtures/synthetic_msl/
 *    sample.msl, regenerated via generate.py), so `syntheticMslAvailable`
 *    is effectively always true and these flows run on any machine / CI.
 *
 *  - DEEP / analysis specs that need the large real capture keep gating on
 *    `datasetAvailable` and load `MSL` (the private run_0001 dataset). They
 *    skip automatically when the dataset is absent.
 *
 * Both flags coexist; nothing below removes the real-dataset path.
 */
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

// Synthetic, committed MSL fixture for smoke flows (no private dataset needed).
// Regenerate with: python tests/e2e/fixtures/synthetic_msl/generate.py
export const syntheticMslPath = path.join(
  __dirname,
  "synthetic_msl",
  "sample.msl",
);
export const syntheticMslAvailable = existsSync(syntheticMslPath);
