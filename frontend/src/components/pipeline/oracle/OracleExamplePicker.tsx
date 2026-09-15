/**
 * Example oracle picker.
 *
 * Fetches the bundled oracles from ``docs/oracle/examples/`` via
 * ``GET /api/oracles/examples`` and renders them as selectable cards.
 *
 * Each card offers two routes, because analysts want both:
 *
 *  - **Copy it yourself** — clicking the card reports the example to the
 *    parent stage via {@link Props.onSelect}, which surfaces the "copy it from
 *    ``docs/oracle/examples/``, edit it, upload it" hint. This is the right
 *    path when the example is a starting point rather than an answer.
 *  - **Use this example** — registers the bundled file server-side through
 *    ``POST /api/oracles/examples/{filename}/load``, so it becomes a real,
 *    runnable oracle without a round trip through the file system. The card
 *    used to offer only the first route, which read as a dead end: the user
 *    asked for the example and got directions to it.
 *
 * A Shape 1 example takes no configuration and is registered immediately. A
 * Shape 2 example is built from a config, so it reveals a small editor seeded
 * from the example's ``config_template`` first. Those seeds are hints, not
 * defaults: the bundled gocryptfs template names
 * ``${MEMDIVER_FIXTURE_ROOT}/...``, which is a placeholder and not a path that
 * exists, so the value is never submitted without the user confirming it.
 */

import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import {
  ORACLE_EXAMPLES_DIR,
  type OracleEntry,
  type OracleExample,
} from "@/api/oracles";
import { FileBrowser } from "@/components/wizard/FileBrowser";
import { useOracleStore } from "@/stores/oracle-store";

interface Props {
  selected: string | null;
  onSelect: (example: OracleExample) => void;
  /**
   * Reports an example that is now registered server-side, armed or not.
   *
   * The parent stage owns the wizard form, so it is what turns this entry into
   * ``form.oracleId`` / ``form.oracleSha256`` and thereby into a reachable
   * "Next". ``entry.armed`` says which of the two the caller may set.
   */
  onLoaded?: (entry: OracleEntry) => void;
}

/** One editable row of a Shape 2 oracle's ``build_oracle(cfg)`` config. */
interface ConfigField {
  key: string;
  value: string;
  /**
   * The template's own value for this key, kept so a number or boolean seed
   * survives the round trip through a text input. ``undefined`` for a row the
   * user added by hand, which is always sent as a string.
   */
  seed?: unknown;
}

/** Seed the editor from the example's sibling ``.toml``, in template order. */
function templateFields(example: OracleExample): ConfigField[] {
  return Object.entries(example.config_template ?? {}).map(([key, seed]) => ({
    key,
    value: typeof seed === "string" ? seed : JSON.stringify(seed),
    seed,
  }));
}

/**
 * Text back to the type the template used.
 *
 * A text input can only hand back a string, but a template value of ``0.5`` or
 * ``true`` means the oracle expects a number or a boolean. Anything the user
 * retyped into a different shape stays a string — guessing further would be
 * how a path like ``/1`` becomes the number 1.
 */
function coerce(text: string, seed: unknown): string | number | boolean {
  if (typeof seed === "number" && text.trim() !== "" && Number.isFinite(Number(text))) {
    return Number(text);
  }
  if (typeof seed === "boolean" && (text === "true" || text === "false")) {
    return text === "true";
  }
  return text;
}

/** The filled-in rows as the object the load + arm endpoints receive. */
function buildConfig(fields: ConfigField[]): Record<string, unknown> {
  const config: Record<string, unknown> = {};
  for (const field of fields) {
    const key = field.key.trim();
    if (key === "") continue;
    config[key] = coerce(field.value, field.seed);
  }
  return config;
}

/**
 * Whether this row should offer the file browser.
 *
 * Keyed off the name as well as the value because a placeholder seed such as
 * ``${MEMDIVER_FIXTURE_ROOT}/...`` is not itself a valid path — the row that
 * most needs the browser is exactly the one whose value is unusable.
 */
function looksLikePath(field: ConfigField): boolean {
  if (/(path|file|dir|ciphertext|keyfile|sample)/i.test(field.key)) return true;
  return field.value.startsWith("/") || field.value.includes("${");
}

export function OracleExamplePicker({ selected, onSelect, onLoaded }: Props) {
  const { t } = useTranslation("pipeline");
  const examples = useOracleStore((s) => s.examples);
  const loading = useOracleStore((s) => s.loading);
  const error = useOracleStore((s) => s.error);
  const refresh = useOracleStore((s) => s.refresh);
  const loadExample = useOracleStore((s) => s.loadExample);
  const arm = useOracleStore((s) => s.arm);

  /** Filename of the example whose config editor is open, if any. */
  const [configFor, setConfigFor] = useState<string | null>(null);
  const [fields, setFields] = useState<ConfigField[]>([]);
  const [busy, setBusy] = useState(false);
  const [inlineError, setInlineError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  /** Index of the row the file browser is filling in, if it is open. */
  const [browseRow, setBrowseRow] = useState<number | null>(null);
  /**
   * Which card the notice / error below belongs to.
   *
   * Tracked separately from the parent's ``selected`` so the outcome is
   * reported under the card that produced it even if the parent stage keeps a
   * different card highlighted.
   */
  const [feedbackFor, setFeedbackFor] = useState<string | null>(null);

  useEffect(() => {
    if (examples.length === 0) {
      void refresh();
    }
  }, [examples.length, refresh]);

  /**
   * Why the last call failed, in the words the server used.
   *
   * ``guarded`` already ran the body through ``readableFailure``, so this is
   * the decoded detail (e.g. "oracle gocryptfs.py could not be loaded with the
   * supplied configuration (sample_ciphertext): ...") rather than a JSON blob.
   */
  const storeFailure = (): string =>
    useOracleStore.getState().error ?? t("oracle.examples.unknownError");

  function resetFeedback(filename: string | null): void {
    setFeedbackFor(filename);
    setInlineError(null);
    setNotice(null);
  }

  /** Register the example; returns the new entry, or null once it has failed. */
  async function register(
    example: OracleExample,
    config?: Record<string, unknown>,
  ): Promise<OracleEntry | null> {
    const entry = await loadExample(example.filename, config);
    if (entry === null) {
      setInlineError(storeFailure());
      return null;
    }
    onLoaded?.(entry);
    return entry;
  }

  async function handleUse(example: OracleExample): Promise<void> {
    resetFeedback(example.filename);
    onSelect(example);
    if (example.shape === 2) {
      // Configured before it is registered: arming REPLAYS build_oracle(cfg)
      // strictly, so a Shape 2 example loaded blind is an entry that can never
      // be armed from here.
      setConfigFor(example.filename);
      setFields(templateFields(example));
      return;
    }
    setBusy(true);
    const entry = await register(example);
    setBusy(false);
    if (entry !== null) {
      setNotice(t("oracle.examples.loaded", { filename: example.filename }));
    }
  }

  async function handleLoadUnarmed(example: OracleExample): Promise<void> {
    resetFeedback(example.filename);
    setBusy(true);
    const entry = await register(example, buildConfig(fields));
    setBusy(false);
    if (entry !== null) {
      setNotice(t("oracle.examples.loadedUnarmed", { filename: example.filename }));
    }
  }

  async function handleLoadAndArm(example: OracleExample): Promise<void> {
    resetFeedback(example.filename);
    setBusy(true);
    const config = buildConfig(fields);
    const entry = await register(example, config);
    if (entry === null) {
      setBusy(false);
      return;
    }
    const armed = await arm(entry.id, entry.sha256, config);
    setBusy(false);
    if (!armed) {
      // The entry exists and is selected; only the config was refused, so the
      // editor stays open with the values that failed still in it.
      setInlineError(storeFailure());
      return;
    }
    onLoaded?.({ ...entry, armed: true });
    setNotice(t("oracle.examples.armed", { filename: example.filename }));
  }

  function updateField(index: number, patch: Partial<ConfigField>): void {
    setFields((prev) =>
      prev.map((field, i) => (i === index ? { ...field, ...patch } : field)),
    );
  }

  if (loading && examples.length === 0) {
    return (
      <p className="p-3 text-xs md-text-muted">{t("oracle.examples.loading")}</p>
    );
  }

  if (error && examples.length === 0) {
    return (
      <p className="p-3 text-xs md-text-error">
        {t("oracle.examples.loadError", { error })}
      </p>
    );
  }

  if (examples.length === 0) {
    return (
      <p className="p-3 text-xs md-text-muted">
        {t("oracle.examples.noneBundledPrefix")} <code>{ORACLE_EXAMPLES_DIR}</code>.
      </p>
    );
  }

  return (
    <div className="space-y-2">
      <p className="text-xs md-text-muted">
        {t("oracle.examples.intro")} <code>.py</code>{" "}
        {t("oracle.examples.introMid")}{" "}
        <em>{t("oracle.examples.introUpload")}</em>{" "}
        {t("oracle.examples.introTail")}
      </p>
      <p className="text-xs md-text-muted">{t("oracle.examples.useIntro")}</p>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
        {examples.map((ex) => {
          const isSelected = selected === ex.filename;
          const isConfiguring = configFor === ex.filename;
          return (
            /*
              The card and its action are SIBLINGS inside this panel. The card
              used to be the <button> itself, so putting "Use this example"
              inside it would nest one button in another -- invalid DOM, and an
              axe violation the a11y baseline would fail on.
            */
            <div
              key={ex.filename}
              data-testid={`oracle-example-${ex.filename}`}
              className={`md-panel p-3 space-y-2 transition-colors ${
                isSelected ? "border-2 border-[var(--md-accent-blue)]" : ""
              }`}
            >
              <button
                type="button"
                onClick={() => onSelect(ex)}
                aria-pressed={isSelected}
                className={`w-full text-left space-y-1 transition-colors ${
                  isSelected ? "" : "hover:bg-[var(--md-bg-hover)]"
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="md-text-accent font-mono text-xs">
                    {ex.filename}
                  </span>
                  <span className="inline-block text-[10px] uppercase tracking-wide md-text-on-accent rounded px-1.5 py-0.5 bg-[var(--md-accent-purple)]">
                    {t("oracle.examples.shape", { shape: ex.shape })}
                  </span>
                </div>
                <div className="text-xs md-text-muted truncate">
                  {ex.summary || t("oracle.examples.noSummary")}
                </div>
                <div className="text-[10px] md-text-muted font-mono">
                  {t("oracle.examples.shaMeta", { sha: ex.sha256.slice(0, 12), size: ex.size })}
                </div>
              </button>

              <button
                type="button"
                data-testid={`oracle-example-use-${ex.filename}`}
                disabled={busy}
                aria-busy={busy}
                onClick={() => void handleUse(ex)}
                className="text-xs px-3 py-1 rounded bg-[var(--md-accent-blue)] md-text-on-accent disabled:opacity-50 hover:opacity-90"
              >
                {t("oracle.examples.use")}
              </button>

              {isConfiguring && (
                <div
                  data-testid={`oracle-example-config-${ex.filename}`}
                  className="space-y-2 pt-1 border-t border-[var(--md-border)]"
                >
                  <p className="text-[10px] md-text-muted">
                    {ex.config_template
                      ? t("oracle.examples.configHint")
                      : t("oracle.examples.configEmptyHint")}
                  </p>
                  {fields.map((field, index) => {
                    const keyId = `oracle-cfg-key-${ex.filename}-${index}`;
                    const valueId = `oracle-cfg-value-${ex.filename}-${index}`;
                    return (
                      <div key={index} className="space-y-1">
                        <label
                          htmlFor={keyId}
                          className="block text-[10px] md-text-muted"
                        >
                          {t("oracle.examples.fieldKeyLabel")}
                        </label>
                        <input
                          id={keyId}
                          type="text"
                          value={field.key}
                          onChange={(e) => updateField(index, { key: e.target.value })}
                          className="w-full text-xs px-2 py-1 rounded bg-[var(--md-bg-hover)] md-text-primary border border-[var(--md-border)]"
                        />
                        <label
                          htmlFor={valueId}
                          className="block text-[10px] md-text-muted"
                        >
                          {t("oracle.examples.fieldValueLabel", { key: field.key })}
                        </label>
                        <div className="flex gap-1 items-start">
                          <input
                            id={valueId}
                            type="text"
                            value={field.value}
                            onChange={(e) =>
                              updateField(index, { value: e.target.value })
                            }
                            className="flex-1 min-w-0 text-xs px-2 py-1 rounded bg-[var(--md-bg-hover)] md-text-primary border border-[var(--md-border)]"
                          />
                          {looksLikePath(field) && (
                            <button
                              type="button"
                              onClick={() => setBrowseRow(index)}
                              aria-label={t("oracle.examples.browseFor", {
                                key: field.key,
                              })}
                              className="shrink-0 text-xs px-2 py-1 rounded bg-[var(--md-bg-hover)] md-text-secondary hover:bg-[var(--md-border)]"
                            >
                              {t("oracle.examples.browse")}
                            </button>
                          )}
                        </div>
                      </div>
                    );
                  })}
                  <button
                    type="button"
                    onClick={() =>
                      setFields((prev) => [...prev, { key: "", value: "" }])
                    }
                    className="text-xs px-2 py-1 rounded bg-[var(--md-bg-hover)] md-text-secondary hover:bg-[var(--md-border)]"
                  >
                    {t("oracle.examples.addField")}
                  </button>
                  <div className="flex flex-wrap gap-2 pt-1">
                    <button
                      type="button"
                      data-testid={`oracle-example-arm-${ex.filename}`}
                      disabled={busy}
                      aria-busy={busy}
                      onClick={() => void handleLoadAndArm(ex)}
                      className="text-xs px-3 py-1 rounded bg-[var(--md-accent-blue)] md-text-on-accent disabled:opacity-50 hover:opacity-90"
                    >
                      {busy
                        ? t("oracle.examples.working")
                        : t("oracle.examples.loadAndArm")}
                    </button>
                    <button
                      type="button"
                      data-testid={`oracle-example-load-${ex.filename}`}
                      disabled={busy}
                      aria-busy={busy}
                      onClick={() => void handleLoadUnarmed(ex)}
                      className="text-xs px-3 py-1 rounded bg-[var(--md-bg-hover)] md-text-secondary disabled:opacity-50 hover:bg-[var(--md-border)]"
                    >
                      {t("oracle.examples.loadUnarmed")}
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setConfigFor(null);
                        resetFeedback(null);
                      }}
                      className="text-xs px-3 py-1 rounded bg-[var(--md-bg-hover)] md-text-secondary hover:bg-[var(--md-border)]"
                    >
                      {t("oracle.examples.cancelConfig")}
                    </button>
                  </div>
                </div>
              )}

              {feedbackFor === ex.filename && notice && (
                <p data-testid="oracle-example-notice" className="text-[10px] md-text-muted">
                  {notice}
                </p>
              )}
              {feedbackFor === ex.filename && inlineError && (
                <p data-testid="oracle-example-error" className="text-xs md-text-error">
                  {t("oracle.examples.useError", { error: inlineError })}
                </p>
              )}
            </div>
          );
        })}
      </div>

      {browseRow !== null && (
        /*
          ``allFiles`` is not optional here: the file a gocryptfs oracle is
          configured with has no extension at all, and the endpoint's default
          listing shows only .dump / .msl -- the dialog would be empty of the
          one file the user came to pick.
        */
        <FileBrowser
          allFiles
          onSelect={(path) => {
            updateField(browseRow, { value: path });
            setBrowseRow(null);
          }}
          onClose={() => setBrowseRow(null)}
        />
      )}
    </div>
  );
}
