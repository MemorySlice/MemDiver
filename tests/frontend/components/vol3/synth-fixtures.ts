/** Shapes of a REAL synthesize / exec answer (gocryptfs run_0001 + run_0002, keys replaced). */
import type { Vol3ExecResult, Vol3SynthesizeResult } from "@/api/vol3";

export const REPO_PLUGINS = "/repo dir/MemDiver/vol3plugins";
export const CASE_PLUGINS = "/cases/my case/vol3/plugins";
export const RUN1 = "/data/run_0001/memslicer.msl";
export const RUN2 = "/data/run_0002/memslicer.msl";
export const CIPHER2 = "/data/run_0002/cipher";
export const PLUGIN = "memdiver_gocryptfs.MemDiverSynthGocryptfs";
export const KEY1 = "ee2813d66e00112233445566778899aabbccddeeff00112233445566778899aa";
export const KEY2 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const cmd = (image: string, extra = "") =>
  `vol -p '${REPO_PLUGINS};${CASE_PLUGINS}' -f '${image}' ${PLUGIN}${extra}`;

export const SYNTH: Vol3SynthesizeResult = {
  source: "# plugin\nclass MemDiverSynthGocryptfs: pass\n",
  recipe: { name: "memdiver_gocryptfs", class_name: "MemDiverSynthGocryptfs" },
  oracle: { kind: "gocryptfs-gcm", sample_bytes: 344, sample_sha256: "d98a" },
  self_test: { error: null, found: true, proven: 2, rows: 2, expected_offset: 32768, expected_offset_reported: true },
  verdicts: [
    { target: "msl", dump_path: RUN1, name: "memslicer.msl", status: "proven", proven: true,
      proven_hits: [{ key_offset: 824634491424, pattern_offset: 824634491360, proven: "oracle:gocryptfs-gcm" },
        { key_offset: 824634492064, pattern_offset: 824634492000, proven: "oracle:gocryptfs-gcm" }],
      rows: 2, oracle_sample_override: false, vol_command: cmd(RUN1), matched_dump_index: 0, error: null, error_code: null },
    { target: "msl", dump_path: RUN2, name: "memslicer.msl", status: "proven", proven: true,
      proven_hits: [{ key_offset: 824633836192, pattern_offset: 824633836128, proven: "oracle:gocryptfs-gcm" },
        { key_offset: 824633836832, pattern_offset: 824633836768, proven: "oracle:gocryptfs-gcm" }],
      rows: 2, oracle_sample_override: true, vol_command: cmd(RUN2, ` --oracle-sample '${CIPHER2}'`),
      matched_dump_index: 1, error: null, error_code: null },
  ],
  proven: true,
  proven_hits: 4,
  export_files: [`${CASE_PLUGINS}/memdiver_gocryptfs.py`],
  stored: { path: `${CASE_PLUGINS}/memdiver_gocryptfs.py`, recipe_path: `${CASE_PLUGINS}/memdiver_gocryptfs.recipe.json`,
    history_dir: "/cases/my case/vol3/history", sha256: "0401", versions_archived: 0 },
  vol_command: cmd(RUN1),
  plugin_dir: CASE_PLUGINS,
  diagnostics: [{ code: "vol3_recipe.high_entropy_constant", message: "program constant", severity: "info" }],
};

export const EXEC: Vol3ExecResult = {
  ok: true, returncode: 0, plugin: PLUGIN, image_path: RUN2, plugin_dirs: [REPO_PLUGINS, CASE_PLUGINS],
  symbol_dirs: [], args: ["--oracle-sample", CIPHER2],
  rows: [
    { Detail: "via anchor", KeyHex: KEY2, KeyOffset: 824633836192, Proven: "oracle:gocryptfs-gcm", Scope: "msl:1", __children: [] },
    { Detail: "via anchor", KeyHex: KEY2, KeyOffset: 824633836832, Proven: "oracle:gocryptfs-gcm", Scope: "msl:1", __children: [] },
  ],
  row_count: 2, truncated: false, stderr_tail: "Volatility 3 Framework 2.27.0\n", framework: "Volatility 3 Framework 2.27.0",
  vol_command: "vol -q -r json ...", launcher: "vol", elapsed_s: 2.95, out_dir: null, output_files: [],
};
