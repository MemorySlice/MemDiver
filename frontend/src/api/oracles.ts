/**
 * Typed client for the BYO oracle registry endpoints.
 *
 * Mirrors the Pydantic + dataclass models in api/routers/oracles.py
 * and api/services/oracle_registry.py. Upload uses multipart/form-data
 * so it bypasses the shared JSON request() helper.
 */

import { ApiError, request } from "./client";

/**
 * Repo-relative directory the bundled example oracles are served from.
 *
 * Single source of truth for the UI copy that tells an analyst where to find
 * the templates. It mirrors the `examples_dir` the backend builds in
 * `api/main.py` (`<repo>/docs/oracle/examples`); the two drifted once already,
 * with the UI naming a directory that has never existed on disk, so the literal
 * lives here rather than being retyped in each component.
 */
export const ORACLE_EXAMPLES_DIR = "docs/oracle/examples/";

/** Bundled example oracle from docs/oracle/examples/ served read-only. */
export interface OracleExample {
  filename: string;
  path: string;
  sha256: string;
  size: number;
  shape: 1 | 2;
  summary: string;
  head_lines: string[];
  /**
   * The example's sibling ``.toml``, parsed — or ``null`` when it ships without
   * one. The reserved ``memdiver`` table is stripped server-side, so every key
   * here is a key ``build_oracle(cfg)`` actually reads.
   *
   * Values are hints, NOT defaults to submit blind: the bundled gocryptfs
   * template carries a path that names no real file. The UI seeds its config
   * form from these and makes the user answer the ones listed in
   * ``config_placeholders``.
   */
  config_template: Record<string, unknown> | null;
  /**
   * Which ``config_template`` keys are questions rather than answers.
   *
   * The server decides this — the union of keys whose value is a ``${VAR}``
   * and keys the example declares under its reserved ``[memdiver.autofill]``
   * table — because the shape of the value cannot be trusted to give it away:
   * ``/absolute/path/to/your/vault/cipher/<any-encrypted-file>`` is every bit
   * as fake as ``${MEMDIVER_FIXTURE_ROOT}/...`` and looks like a real path.
   *
   * Optional only so a response from an older server cannot break the picker;
   * the current API always sends it (``[]`` when nothing is a placeholder).
   */
  config_placeholders?: string[];
}

/** Uploaded oracle tracked in the in-memory OracleRegistry. */
export interface OracleEntry {
  id: string;
  filename: string;
  sha256: string;
  size: number;
  shape: 1 | 2;
  head_lines: string[];
  uploaded_at: number;
  armed: boolean;
  description: string | null;
  /**
   * The config this oracle was registered with, echoed back by the server.
   *
   * Always present on the wire (``OracleRecord.to_dict``); optional here so a
   * fixture can describe an entry without restating an empty object.
   */
  config?: Record<string, unknown>;
}

/**
 * Where oracle files are stored, and who decided that.
 *
 * Mirrors `_status()` in api/routers/oracles.py. `enabled: false` is a normal
 * state the UI renders as a consent panel — the endpoint answers 200 for it,
 * so it is never an ApiError. `source` says whether the directory came from
 * `MEMDIVER_ORACLE_DIR` (`"env"`) or the user's own opt-in (`"user_config"`),
 * and `env_pinned` means the UI must not offer to change it: the server
 * answers 409 to `POST /api/oracles/enable` in that case.
 */
export interface OracleStatus {
  enabled: boolean;
  path: string | null;
  source: "env" | "user_config" | null;
  env_pinned: boolean;
  default_path: string;
}

export interface DryRunResult {
  oracle_id: string;
  samples: number;
  passes: number;
  fails: number;
  errors: number;
  per_call_us_avg: number;
  results: Array<{
    index: number;
    ok: boolean;
    duration_us?: number;
    error?: string;
  }>;
}

// ---- endpoints ----

export const listOracleExamples = () =>
  request<{ examples: OracleExample[] }>("/api/oracles/examples");

export const listOracles = () =>
  request<{ oracles: OracleEntry[] }>("/api/oracles");

/** Read the oracle-directory status. Always 200, including when disabled. */
export const getOracleStatus = () => request<OracleStatus>("/api/oracles/status");

/**
 * Record the user's consent to store and execute oracle code.
 *
 * `path` defaults server-side to the reported `default_path`, so the common
 * case sends an empty body. Rejects with 409 when the env var pins the value
 * and 400 when the directory is refused.
 */
export const enableOracles = (path?: string) =>
  request<OracleStatus>("/api/oracles/enable", {
    method: "POST",
    body: JSON.stringify(path === undefined ? {} : { path }),
  });

export async function uploadOracle(
  file: File,
  description?: string,
): Promise<OracleEntry> {
  const form = new FormData();
  form.append("file", file);
  if (description !== undefined) {
    form.append("description", description);
  }
  const res = await fetch("/api/oracles/upload", {
    method: "POST",
    body: form,
  });
  if (!res.ok) {
    throw new ApiError(res.status, await res.text());
  }
  return (await res.json()) as OracleEntry;
}

/**
 * Register a bundled example as a real, runnable oracle, server-side.
 *
 * The file is never uploaded: the server copies it out of its own read-only
 * examples directory, so what runs is byte-for-byte the template the card
 * showed. ``config`` is what a Shape 2 example's ``build_oracle(cfg)`` receives
 * — omitted for Shape 1, which takes no configuration. Rejects with 503 when
 * oracle execution is disabled, 404 for an unknown filename and 400 when the
 * file will not load.
 */
export const loadOracleExample = (
  filename: string,
  config?: Record<string, unknown>,
  description?: string,
) =>
  request<OracleEntry>(
    `/api/oracles/examples/${encodeURIComponent(filename)}/load`,
    {
      method: "POST",
      body: JSON.stringify({
        ...(config === undefined ? {} : { config }),
        ...(description === undefined ? {} : { description }),
      }),
    },
  );

/**
 * What the server can work out about a Shape 2 example's config on its own.
 *
 * Mirrors ``ConfigSuggestion`` in app/oracle_autoconfig.py. The config an
 * example such as ``gocryptfs.py`` needs is a *sibling of the dump the user
 * already picked* on the dumps step, so the server derives it from
 * ``source_paths`` rather than asking the analyst to go find it: the bundled
 * template can only name a placeholder, and a placeholder is not an answer.
 *
 * Every field is advisory except ``blocked_reason``:
 *
 *  - ``config`` — values to prefill, keyed exactly as the template's keys.
 *    ``{}`` means nothing was derivable, which is a normal 200, not an error.
 *  - ``provenance`` — one sentence saying where the values came from, so a
 *    value that appeared by itself is never mysterious.
 *  - ``blocked_reason`` — the oracle cannot verify this run at all (a cipher
 *    mismatch, say). Arming anyway would sweep every candidate to ``False``
 *    and read as "the key is not in the dump", so the UI refuses to load.
 *  - ``reference_run`` / ``reference_dump`` — which run ``source_paths[0]``
 *    belongs to. Only that dump is ever verified by the sweep and every run
 *    has its own master key, so a config derived against another run yields
 *    silent zero hits; the UI compares these before arming.
 */
export interface ConfigSuggestion {
  config: Record<string, unknown>;
  provenance: string | null;
  blocked_reason: string | null;
  warnings: string[];
  reference_run: string | null;
  reference_dump: string | null;
}

/**
 * Ask the server to derive a bundled example's config from the picked dumps.
 *
 * Answers 200 with an empty ``config`` when nothing could be derived — an
 * example without an autofill rule, a dump with no run metadata beside it, a
 * vault directory that is not there any more — because "I could not work this
 * out" is an answer, not a failure. 404 is the same rule as ``.../load``: no
 * such bundled example.
 */
export const suggestExampleConfig = (filename: string, sourcePaths: string[]) =>
  request<ConfigSuggestion>(
    `/api/oracles/examples/${encodeURIComponent(filename)}/suggest-config`,
    { method: "POST", body: JSON.stringify({ source_paths: sourcePaths }) },
  );

/**
 * Flip the ``armed`` flag after the server re-hashes the file on disk.
 *
 * ``config`` is re-sent for a Shape 2 oracle because arming actually BUILDS it:
 * a wrong value is rejected here, with 400 and a readable detail naming the
 * offending key, not at run time.
 */
export const armOracle = (
  oracleId: string,
  sha256: string,
  config?: Record<string, unknown>,
) =>
  request<OracleEntry>(
    `/api/oracles/${encodeURIComponent(oracleId)}/arm`,
    {
      method: "POST",
      body: JSON.stringify({
        sha256,
        ...(config === undefined ? {} : { config }),
      }),
    },
  );

/**
 * Dry-run the oracle against a list of sample bytes (base64-encoded).
 * The registry does NOT require the oracle to be armed first so the
 * user can smoke-test before committing.
 */
export const dryRunOracle = (oracleId: string, samplesB64: string[]) =>
  request<DryRunResult>(
    `/api/oracles/${encodeURIComponent(oracleId)}/dry-run`,
    { method: "POST", body: JSON.stringify({ samples_b64: samplesB64 }) },
  );

export const deleteOracle = (oracleId: string) =>
  request<{ oracle_id: string; deleted: boolean }>(
    `/api/oracles/${encodeURIComponent(oracleId)}`,
    { method: "DELETE" },
  );
