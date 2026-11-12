/**
 * Pure helpers of the "Export as Volatility 3 plugin" flow: secret masking,
 * request building and turning a verdict into an exec request (its `exec`, or
 * for an older stored verdict its parsed `vol_command`).
 * Kept out of the components so each rule is unit-tested on its own.
 */

import type {
  Vol3ExecRequest, Vol3ExecRow, Vol3SynthesizeRequest, Vol3SynthesizeResult, Vol3SynthVerdict,
} from "@/api/vol3";
import { isEvenHex, normalizeHex } from "@/utils/hex";
import { useDumpStore } from "@/stores/dump-store";

const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** Hex digits of a secret as typed: whitespace and an optional `0x` dropped. */
export const isHexSecret = (text: string) => isEvenHex(normalizeHex(text));

export const isPluginName = (name: string) => IDENTIFIER.test(name);

/**
 * A secret as it may be SHOWN: its length only. No byte of the key is ever
 * rendered (not even a prefix, nor in a tooltip); an input holding it is a
 * password field.
 */
export function maskSecret(text: string): string {
  const hex = normalizeHex(text);
  if (hex === "") return "";
  return `•••• (${Math.floor(hex.length / 2)} B)`;
}

/** A plugin output column that carries key material (`KeyHex`, `secret`, `MasterKey`…). */
export const isSecretColumn = (name: string) => /key.?hex|secret|master.?key|^key$/i.test(name);

/** A default plugin name for an oracle kind: `gocryptfs-gcm` -> `memdiver_gocryptfs`. */
export function defaultPluginName(oracleKind: string): string {
  const stem = oracleKind.split(/[^A-Za-z0-9]/)[0]?.toLowerCase() ?? "";
  return stem ? `memdiver_${stem}` : "memdiver_plugin";
}

/** One dump of the dialog: its path, its own secret and its own oracle sample. */
export interface SynthDumpDraft {
  path: string;
  secretHex: string;
  samplePath: string;
}

export interface SynthDraft {
  dumps: SynthDumpDraft[];
  name: string;
  oracleKind: string;
  caseDir: string;
  context: string;
  verifyOnMsl: boolean;
  allowHighEntropy: boolean;
  fullImage: string;
  pid: string;
  fullImageSample: string;
  fullImageSecretHex: string;
  symbolDirs: string;
}

/** Error KEYS (vol3 namespace) of a draft; empty when it can be sent. */
export function validateDraft(d: SynthDraft): string[] {
  const errors: string[] = [];
  const dumps = d.dumps.filter((x) => x.path.trim() !== "");
  if (dumps.length === 0) errors.push("synth.error.noDumps");
  if (!isPluginName(d.name.trim())) errors.push("synth.error.name");
  if (d.oracleKind.trim() === "") errors.push("synth.error.oracle");
  const secrets = dumps.map((x) => x.secretHex.trim());
  if (secrets.some((s) => s !== "" && !isHexSecret(s))) errors.push("synth.error.secretHex");
  else if (secretForm(secrets) === null) errors.push("synth.error.secretPerDump");
  if (d.context.trim() !== "" && !/^\d+$/.test(d.context.trim())) errors.push("synth.error.context");
  if (d.pid.trim() !== "" && !/^\d+$/.test(d.pid.trim())) errors.push("synth.error.pid");
  if (d.fullImageSecretHex.trim() !== "" && !isHexSecret(d.fullImageSecretHex)) {
    errors.push("synth.error.imageSecretHex");
  }
  return errors;
}

/**
 * The `secret_hex` wire form: one key per dump, or the first dump's key for all
 * of them (the other rows left blank). `null` when neither shape fits.
 */
function secretForm(secrets: string[]): string | string[] | null {
  const filled = secrets.filter((s) => s !== "");
  if (filled.length === 0) return null;
  if (filled.length === secrets.length) return secrets.length === 1 ? normalizeHex(secrets[0]) : secrets.map(normalizeHex);
  if (filled.length === 1 && secrets[0] !== "") return normalizeHex(secrets[0]);
  return null;
}

/** `oracle_sample_path`: one for all, one per dump (blank = none), or omitted. */
function sampleForm(samples: string[]): string | (string | null)[] | undefined {
  if (samples.every((s) => s === "")) return undefined;
  if (samples.length === 1) return samples[0];
  return samples.map((s) => (s === "" ? null : s));
}

export const lines = (text: string) => text.split("\n").map((s) => s.trim()).filter(Boolean);

/** The synthesize request of a VALID draft (see {@link validateDraft}). */
export function buildSynthRequest(
  d: SynthDraft, containerKey: Pick<Vol3SynthesizeRequest, "passphrase" | "key_hex" | "kem_key_hex"> = {},
): Vol3SynthesizeRequest {
  const dumps = d.dumps.filter((x) => x.path.trim() !== "");
  const fullImage = d.fullImage.trim();
  return {
    ...containerKey,
    dump_paths: dumps.map((x) => x.path.trim()),
    name: d.name.trim(),
    oracle_kind: d.oracleKind.trim(),
    secret_hex: secretForm(dumps.map((x) => x.secretHex.trim())) ?? undefined,
    oracle_sample_path: sampleForm(dumps.map((x) => x.samplePath.trim())),
    context: d.context.trim() === "" ? undefined : Number(d.context.trim()),
    case_dir: d.caseDir.trim() || undefined,
    verify_on: d.verifyOnMsl ? ["msl"] : [],
    allow_high_entropy_context: d.allowHighEntropy || undefined,
    ...(fullImage ? {
      full_image: fullImage,
      pid: d.pid.trim() === "" ? undefined : Number(d.pid.trim()),
      full_image_sample: d.fullImageSample.trim() || undefined,
      full_image_secret_hex: d.fullImageSecretHex.trim() ? normalizeHex(d.fullImageSecretHex) : undefined,
      symbol_dirs: lines(d.symbolDirs).length ? lines(d.symbolDirs) : undefined,
    } : {}),
  };
}

/**
 * POSIX shell words of a command line (the backend quotes with `shlex.quote`):
 * single quotes are literal, double quotes honour `\"` / `\\`, a bare backslash
 * escapes the next character.
 */
export function shellSplit(command: string): string[] {
  const words: string[] = [];
  let word = "";
  let inWord = false;
  let quote: "'" | '"' | null = null;
  for (let i = 0; i < command.length; i++) {
    const c = command[i];
    if (quote === "'") {
      if (c === "'") quote = null; else word += c;
    } else if (quote === '"') {
      if (c === '"') quote = null;
      else if (c === "\\" && (command[i + 1] === '"' || command[i + 1] === "\\")) word += command[++i];
      else word += c;
    } else if (c === "'" || c === '"') {
      quote = c; inWord = true;
    } else if (c === "\\" && i + 1 < command.length) {
      word += command[++i]; inWord = true;
    } else if (/\s/.test(c)) {
      if (inWord) { words.push(word); word = ""; inWord = false; }
    } else {
      word += c; inWord = true;
    }
  }
  if (inWord) words.push(word);
  return words;
}

/** `vol` options that take a value (anything else before the plugin is a flag). */
const VALUE_OPTIONS = new Set(["-p", "--plugin-dirs", "-f", "--file", "-s", "--symbol-dirs", "-r", "--renderer",
  "-c", "--config", "--cache-path", "-o", "--output-dir"]);

/**
 * The exec request that reruns a verdict's `vol_command` under stock vol:
 * `-f` is the image, the token after it the plugin, everything after the plugin
 * its args, `-p` (`;`-separated) the plugin dirs minus the installed MemDiver
 * dir (exec adds that itself), `-s` the symbol dirs. `null` for a command with
 * no image or no plugin.
 */
export function execRequestFromVolCommand(
  command: string, memdiverPluginDir: string | null,
): Vol3ExecRequest | null {
  const words = shellSplit(command);
  if (words.length === 0) return null;
  const pluginDirs: string[] = [];
  const symbolDirs: string[] = [];
  let image = "";
  let i = 1; // words[0] is the launcher
  for (; i < words.length; i++) {
    const w = words[i];
    if (!w.startsWith("-")) break;
    if (!VALUE_OPTIONS.has(w)) continue;
    const value = words[++i] ?? "";
    if (w === "-p" || w === "--plugin-dirs") pluginDirs.push(...value.split(";").filter(Boolean));
    else if (w === "-f" || w === "--file") image = value;
    else if (w === "-s" || w === "--symbol-dirs") symbolDirs.push(...value.split(";").filter(Boolean));
  }
  const plugin = words[i] ?? "";
  if (!image || !plugin) return null;
  return {
    plugin,
    image_path: image,
    plugin_dirs: withoutMemdiverDir(pluginDirs, memdiverPluginDir),
    symbol_dirs: symbolDirs,
    args: words.slice(i + 1),
  };
}

/** *dirs* minus the installed MemDiver plugin dir (exec adds that one itself); trailing `/` ignored. */
export function withoutMemdiverDir(dirs: readonly string[], memdiverPluginDir: string | null): string[] {
  const bare = (d: string) => d.replace(/\/+$/, "");
  return dirs.filter((d) => memdiverPluginDir === null || bare(d) !== bare(memdiverPluginDir));
}

/** `<module>.<Class>` of a synthesized plugin, from its recipe. */
export const pluginNameOf = (r: Pick<Vol3SynthesizeResult, "recipe">) =>
  `${r.recipe.name}.${r.recipe.class_name}`;

/**
 * The exec request for one verdict. The backend's own `exec` comes first (the
 * same spec its `vol_command` is rendered from: a later dump's
 * `--oracle-sample`, a full image's `--pid` and `-s`); a verdict stored before
 * that field existed has its `vol_command` parsed instead; the last fallback is
 * the synthesized plugin over the verdict's dump.
 */
export function execRequestForVerdict(
  result: Vol3SynthesizeResult, verdict: Vol3SynthVerdict, memdiverPluginDir: string | null,
): Vol3ExecRequest {
  if (verdict.exec) {
    return {
      ...verdict.exec,
      plugin_dirs: withoutMemdiverDir(verdict.exec.plugin_dirs ?? [], memdiverPluginDir),
      symbol_dirs: verdict.exec.symbol_dirs ?? [],
      args: verdict.exec.args ?? [],
    };
  }
  return execRequestFromVolCommand(verdict.vol_command, memdiverPluginDir) ?? {
    plugin: pluginNameOf(result),
    image_path: verdict.dump_path,
    plugin_dirs: [result.plugin_dir],
    args: [],
  };
}

/** The column names of exec rows, in first-seen order, without the tree's `__children`. */
export function execColumns(rows: readonly Vol3ExecRow[]): string[] {
  const seen: string[] = [];
  for (const row of rows) {
    for (const key of Object.keys(row)) if (key !== "__children" && !seen.includes(key)) seen.push(key);
  }
  return seen;
}

/** A `Proven` cell that names the oracle that proved the row (`oracle:<kind>`). */
export const isProvenCell = (value: unknown) => typeof value === "string" && value.startsWith("oracle:");

/** A cell as text: a secret column is masked, `null` is a dash. */
export function cellText(column: string, value: unknown): string {
  if (value === null || value === undefined) return "—";
  const text = typeof value === "object" ? JSON.stringify(value) : String(value);
  return isSecretColumn(column) ? maskSecret(text) || "—" : text;
}

/** The dumps of the current context: the active dump, else every loaded dump. */
export function contextDumpPaths(): string[] {
  const { dumps, activeDumpId } = useDumpStore.getState();
  const active = dumps.find((d) => d.id === activeDumpId);
  return active ? [active.path] : dumps.map((d) => d.path);
}
