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
 * from the example's ``config_template`` first.
 *
 * A template seed is a hint, not an answer, and the editor now says so with
 * the only thing a form can say it with — emptiness. The bundled gocryptfs
 * template names ``${MEMDIVER_FIXTURE_ROOT}/...``: nothing in the product ever
 * expands that, and the file it names exists on nobody's machine. Seeded into
 * the input's *value* it read as a real answer and was submitted verbatim, so
 * every "Load + arm" on a fresh install failed on the server. Such a value now
 * seeds the input's ``placeholder`` instead, and the load buttons stay
 * disabled until the row is answered.
 *
 * The answer itself is rarely something the analyst has to go find: the file a
 * gocryptfs oracle needs is a sibling of the dump they already picked on the
 * dumps step. ``suggestExampleConfig`` derives it from ``sourcePaths`` and the
 * result is prefilled here, with its provenance shown beside it.
 */

import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import {
  ORACLE_EXAMPLES_DIR,
  type ConfigSuggestion,
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
  /**
   * The dumps the wizard is already pointed at, newest selection first.
   *
   * Passed in rather than read from the pipeline store so this stays a dumb
   * component: the picker never decides what a dump selection is, it only asks
   * the server what config those dumps imply. ``sourcePaths[0]`` is the one the
   * sweep actually verifies, which is why it alone is the reference run.
   */
  sourcePaths: string[];
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

/**
 * A ``${NAME}`` placeholder, which is a question the template is asking.
 *
 * Mirrors ``_PLACEHOLDER_RE`` in api/services/oracle_registry.py, which now
 * rejects such a value by key name. Two guards, on purpose: the server one is
 * what makes a bad config impossible, this one is what makes the form honest
 * before the user has spent a round trip finding out.
 *
 * It is a fallback, not the rule. ``example.config_placeholders`` is the
 * server's own list of which keys are questions, and it catches the ones this
 * pattern cannot: a template that says ``/absolute/path/to/your/vault/...`` is
 * just as fake and looks exactly like an answer. The regex stays for a
 * third-party example that ships a ``${VAR}`` and no reserved table.
 */
const PLACEHOLDER_RE = /\$\{[A-Za-z_][A-Za-z0-9_]*\}/;

/** Whether a template key is a question, by either signal. */
function isPlaceholderKey(
  key: string,
  seed: unknown,
  placeholders: string[],
): boolean {
  if (typeof seed !== "string" || seed === "") return false;
  return placeholders.includes(key) || PLACEHOLDER_RE.test(seed);
}

/** A template value as the single line of text an <input> can carry. */
function asText(value: unknown): string {
  return typeof value === "string" ? value : JSON.stringify(value);
}

/**
 * Seed the editor from the example's sibling ``.toml``, in template order.
 *
 * A placeholder seeds an EMPTY value: the template string survives in ``seed``
 * and is rendered as the input's ``placeholder`` attribute, where it reads as
 * the shape of the expected answer instead of as the answer itself. Keeping it
 * in ``seed`` rather than copying it into a second field keeps one source of
 * truth for what the template said.
 */
function templateFields(example: OracleExample): ConfigField[] {
  const placeholders = example.config_placeholders ?? [];
  return Object.entries(example.config_template ?? {}).map(([key, seed]) => ({
    key,
    value: isPlaceholderKey(key, seed, placeholders) ? "" : asText(seed),
    seed,
  }));
}

/**
 * The template string this row is still asking for, or ``null``.
 *
 * ``seed === undefined`` is a row the user added by hand: it was never asking
 * anything, so it can never be unanswered. ``placeholders`` is the owning
 * example's ``config_placeholders``, threaded down from the render rather than
 * fetched from a store, so these stay pure functions of their arguments.
 */
function templateHint(field: ConfigField, placeholders: string[]): string | null {
  return isPlaceholderKey(field.key, field.seed, placeholders)
    ? String(field.seed)
    : null;
}

/** Nothing the server could use: an empty or whitespace-only value. */
function isBlank(field: ConfigField): boolean {
  return field.value.trim() === "";
}

/** A placeholder row the user has not answered yet. */
function isUnfilled(field: ConfigField, placeholders: string[]): boolean {
  return templateHint(field, placeholders) !== null && isBlank(field);
}

/** The keys still to answer, in template order, for the blocking message. */
function unfilledKeys(fields: ConfigField[], placeholders: string[]): string[] {
  return fields
    .filter((field) => isUnfilled(field, placeholders))
    .map((field) => field.key);
}

/**
 * Write the server's derived values into the rows that are still blank.
 *
 * Never clobbers: a row with anything typed in it is the user's answer, and a
 * suggestion arriving a second later must not overwrite it. Returns the same
 * array when it changed nothing, so the caller can tell whether the values on
 * screen are now the suggestion's or still the ones already there.
 */
function prefilled(
  fields: ConfigField[],
  config: Record<string, unknown>,
): ConfigField[] {
  let changed = false;
  const next = fields.map((field) => {
    const derived = config[field.key];
    if (derived === undefined || !isBlank(field)) return field;
    changed = true;
    return { ...field, value: asText(derived) };
  });
  return changed ? next : fields;
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
 * Keyed off the name and the TEMPLATE as well as the value, because the row
 * that most needs the browser is the one with nothing in it: a placeholder
 * such as ``${MEMDIVER_FIXTURE_ROOT}/...`` never reaches the value any more,
 * so asking the value whether it contains ``${`` would be asking a question
 * that can no longer be true and would quietly drop the Browse… button from
 * exactly the rows it exists for.
 */
function looksLikePath(field: ConfigField, placeholders: string[]): boolean {
  if (/(path|file|dir|ciphertext|keyfile|sample)/i.test(field.key)) return true;
  return field.value.startsWith("/") || templateHint(field, placeholders) !== null;
}

export function OracleExamplePicker({
  selected,
  onSelect,
  onLoaded,
  sourcePaths,
}: Props) {
  const { t } = useTranslation("pipeline");
  const examples = useOracleStore((s) => s.examples);
  const loading = useOracleStore((s) => s.loading);
  const error = useOracleStore((s) => s.error);
  const refresh = useOracleStore((s) => s.refresh);
  const loadExample = useOracleStore((s) => s.loadExample);
  const suggest = useOracleStore((s) => s.suggest);
  const arm = useOracleStore((s) => s.arm);

  /** Filename of the example whose config editor is open, if any. */
  const [configFor, setConfigFor] = useState<string | null>(null);
  const [fields, setFields] = useState<ConfigField[]>([]);
  const [busy, setBusy] = useState(false);
  const [inlineError, setInlineError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  /**
   * Whether {@link notice} reports the armed state, or only a load.
   *
   * Three outcomes share one notice element, and only ONE of them lets the
   * wizard move on: loading without arming leaves ``oracleSha256`` null, so
   * "Next" stays disabled. Painting that in the success token would tell the
   * analyst they are done standing in front of a button they cannot press.
   */
  const [noticeIsArmed, setNoticeIsArmed] = useState(false);
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
  /** What the server derived for the open editor, if it answered at all. */
  const [suggestion, setSuggestion] = useState<ConfigSuggestion | null>(null);
  /**
   * The run whose derived values are sitting in the editor right now.
   *
   * Not the same question as ``suggestion.reference_run``, which is the run the
   * LAST derivation was about. They part company exactly when they matter: the
   * user changes the dump selection, the re-derivation declines to overwrite
   * the values already on screen, and the config in the form is now a config
   * for a run nobody is going to sweep.
   */
  const [configRun, setConfigRun] = useState<string | null>(null);

  /**
   * The rows and dumps as they are right now, readable from an async effect.
   *
   * The re-derivation writes rows, so listing them as dependencies would make
   * it re-run forever, and reading them from the effect's own closure would
   * read them as they were before the request went out — the two things the
   * "never clobber what the user typed" rule is about.
   */
  const latest = useRef({ fields, sourcePaths });
  // Declared BEFORE the derivation below so that effect always reads the rows
  // this render drew, not the ones the previous one did.
  useEffect(() => {
    latest.current = { fields, sourcePaths };
  });

  /** The only dump the sweep verifies, and therefore the only one to derive from. */
  const referenceDump = sourcePaths[0] ?? null;

  useEffect(() => {
    if (examples.length === 0) {
      void refresh();
    }
  }, [examples.length, refresh]);

  /**
   * Ask the server for this example's config, and again if the dumps change.
   *
   * Runs off ``configFor`` rather than being called from ``handleUse`` so that
   * opening the editor and re-pointing the wizard at another dump take the
   * same path — one derivation per (example, reference dump) pair, and no
   * double request on open.
   */
  useEffect(() => {
    if (configFor === null || referenceDump === null) return;
    let cancelled = false;
    void (async () => {
      const derived = await suggest(configFor, latest.current.sourcePaths);
      // A failed derivation is not a failed workflow: the user can still fill
      // the form in by hand, so it leaves the rows exactly as they were.
      if (cancelled || derived === null) return;
      setSuggestion(derived);
      const next = prefilled(latest.current.fields, derived.config);
      if (next === latest.current.fields) return;
      setFields(next);
      setConfigRun(derived.reference_run);
    })();
    return () => {
      cancelled = true;
    };
  }, [configFor, referenceDump, suggest]);

  /**
   * The values on screen came from a run that is no longer the reference.
   *
   * Every run has its own master key, so a config derived against run X tests
   * candidates from run Y against a file only run X's key can open: the sweep
   * ends with zero hits and nothing says why.
   */
  const referenceChanged =
    configRun !== null &&
    suggestion !== null &&
    suggestion.reference_run !== null &&
    suggestion.reference_run !== configRun;

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
    setNoticeIsArmed(false);
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
      //
      // The rows start as the template says, with every placeholder blank; the
      // effect above then asks the server to fill what it can from the picked
      // dumps. Dropping the previous example's suggestion is the point of
      // doing it here: it was derived for a different oracle.
      setSuggestion(null);
      setConfigRun(null);
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
    setNoticeIsArmed(true);
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
          /*
            Everything below is about the ONE open editor, so it is all scoped
            to this card: the blocking ids have to be unique in the document
            for aria-describedby to resolve, and only a card that is being
            configured may claim them.
          */
          const placeholders = ex.config_placeholders ?? [];
          const unfilled = isConfiguring ? unfilledKeys(fields, placeholders) : [];
          const blockedReason = isConfiguring
            ? (suggestion?.blocked_reason ?? null)
            : null;
          const unfilledId = `oracle-cfg-unfilled-${ex.filename}`;
          const blockedId = `oracle-cfg-blocked-${ex.filename}`;
          /*
            A disabled button explains itself in TEXT. `title` is not announced
            by a screen reader and never appears on touch, so the reason is a
            real element the buttons point at with aria-describedby; the title
            below is a convenience for a mouse, not the explanation.
          */
          const blockedBy = [
            blockedReason !== null ? blockedId : null,
            unfilled.length > 0 ? unfilledId : null,
          ].filter((id): id is string => id !== null);
          const blockTitle =
            blockedReason !== null
              ? t("oracle.examples.cipherMismatch", { reason: blockedReason })
              : unfilled.length > 0
                ? t("oracle.examples.unfilledBlock", { keys: unfilled.join(", ") })
                : undefined;
          const cannotLoad = busy || blockedBy.length > 0;
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
                className="text-xs px-3 py-1 rounded bg-[var(--md-accent-blue)] md-text-on-accent disabled:opacity-50 disabled:grayscale disabled:cursor-not-allowed hover:opacity-90"
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
                            placeholder={templateHint(field, placeholders) ?? undefined}
                            /*
                              A derived vault path runs to ~1200px inside a
                              ~390px input, so the visible head is the part
                              every run shares and the tail that says WHICH run
                              is the part clipped off. The full value is the
                              hover text rather than only the provenance line,
                              which names the run but not the file.
                            */
                            title={field.value || undefined}
                            onChange={(e) =>
                              updateField(index, { value: e.target.value })
                            }
                            className="flex-1 min-w-0 text-xs px-2 py-1 rounded bg-[var(--md-bg-hover)] md-text-primary border border-[var(--md-border)]"
                          />
                          {looksLikePath(field, placeholders) && (
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
                        {/*
                          The template string goes in a <code> rather than only
                          in the input's placeholder: a 90-character path is
                          truncated invisibly inside a narrow input, and text
                          on the page can be read in full and selected.
                        */}
                        {isUnfilled(field, placeholders) && (
                          <p
                            data-testid={`oracle-cfg-note-${field.key}`}
                            className="text-[10px] md-text-muted"
                          >
                            {t("oracle.examples.unfilledNote")}{" "}
                            <code className="break-words">
                              {templateHint(field, placeholders)}
                            </code>
                          </p>
                        )}
                        {/*
                          A value that appeared on its own is worse than an
                          empty field unless it says where it came from.
                        */}
                        {suggestion?.provenance &&
                          suggestion.config[field.key] !== undefined && (
                            <p
                              data-testid={`oracle-cfg-provenance-${field.key}`}
                              className="text-[10px] md-text-muted"
                            >
                              {t("oracle.examples.derivedFrom", {
                                provenance: suggestion.provenance,
                              })}
                            </p>
                          )}
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
                  {/*
                    Warnings are the server's own sentences about a derivation
                    it could only half make; they inform, they do not block.
                  */}
                  {(suggestion?.warnings ?? []).map((warning) => (
                    <p
                      key={warning}
                      data-testid="oracle-example-suggest-warning"
                      className="text-[10px] md-text-muted"
                    >
                      {t("oracle.examples.suggestWarning", { warning })}
                    </p>
                  ))}
                  {referenceChanged && (
                    <p
                      data-testid="oracle-example-reference-changed"
                      className="text-[10px] md-text-error"
                    >
                      {t("oracle.examples.referenceChanged", { run: configRun })}
                    </p>
                  )}
                  {blockedReason !== null && (
                    <p
                      id={blockedId}
                      data-testid="oracle-example-blocked"
                      className="text-xs md-text-error"
                    >
                      {t("oracle.examples.cipherMismatch", {
                        reason: blockedReason,
                      })}
                    </p>
                  )}
                  {unfilled.length > 0 && (
                    <p
                      id={unfilledId}
                      data-testid="oracle-example-unfilled"
                      className="text-[10px] md-text-error"
                    >
                      {t("oracle.examples.unfilledBlock", {
                        keys: unfilled.join(", "),
                      })}
                    </p>
                  )}
                  <div className="flex flex-wrap gap-2 pt-1">
                    <button
                      type="button"
                      data-testid={`oracle-example-arm-${ex.filename}`}
                      disabled={cannotLoad}
                      aria-busy={busy}
                      aria-describedby={
                        blockedBy.length > 0 ? blockedBy.join(" ") : undefined
                      }
                      title={blockTitle}
                      onClick={() => void handleLoadAndArm(ex)}
                      className="text-xs px-3 py-1 rounded bg-[var(--md-accent-blue)] md-text-on-accent disabled:opacity-50 disabled:grayscale disabled:cursor-not-allowed hover:opacity-90"
                    >
                      {busy
                        ? t("oracle.examples.working")
                        : t("oracle.examples.loadAndArm")}
                    </button>
                    <button
                      type="button"
                      data-testid={`oracle-example-load-${ex.filename}`}
                      disabled={cannotLoad}
                      aria-busy={busy}
                      aria-describedby={
                        blockedBy.length > 0 ? blockedBy.join(" ") : undefined
                      }
                      title={blockTitle}
                      onClick={() => void handleLoadUnarmed(ex)}
                      className="text-xs px-3 py-1 rounded bg-[var(--md-bg-hover)] md-text-secondary disabled:opacity-50 disabled:cursor-not-allowed hover:bg-[var(--md-border)]"
                    >
                      {t("oracle.examples.loadUnarmed")}
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setConfigFor(null);
                        setSuggestion(null);
                        setConfigRun(null);
                        resetFeedback(null);
                      }}
                      className="text-xs px-3 py-1 rounded bg-[var(--md-bg-hover)] md-text-secondary hover:bg-[var(--md-border)]"
                    >
                      {t("oracle.examples.cancelConfig")}
                    </button>
                  </div>
                </div>
              )}

              {/*
                Weighted like a result, not like a footnote: "armed" is the
                one state this whole stage exists to reach, and it was the
                only signal of it — at 10px muted grey it read as fine print
                next to the buttons it was reporting on. The success token
                carries the meaning; the size makes it survive a glance.
              */}
              {feedbackFor === ex.filename && notice && (
                <p
                  data-testid="oracle-example-notice"
                  className={
                    noticeIsArmed
                      ? "text-xs font-semibold md-text-success px-2 py-1 rounded border md-border-success md-bg-success-subtle"
                      : "text-xs md-text-secondary"
                  }
                >
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
