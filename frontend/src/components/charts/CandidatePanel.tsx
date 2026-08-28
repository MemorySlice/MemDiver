import { useCallback, useEffect, useRef, useState } from "react";
import { useShallow } from "zustand/react/shallow";
import { useTranslation } from "react-i18next";
import {
  analyzeCandidates,
  buildCandidatesRequest,
  BYTE_CLASSES,
  DEFAULT_CANDIDATE_FILTERS,
  offsetsAreDumpOffsets,
  type AnalysisCandidatesResponse,
  type CandidateFilterState,
} from "@/api/candidates";
import { useDumpStore } from "@/stores/dump-store";
import { useConsensusStore } from "@/stores/consensus-store";
import { useHexStore } from "@/stores/hex-store";
import { CandidateAlignmentBanner } from "./CandidateAlignmentBanner";
import { CandidateFilters } from "./CandidateFilters";
import { CandidateTable } from "./CandidateTable";

/**
 * The exploratory differential workflow, made visible.
 *
 * Before this, an analyst who loaded N dumps and clicked "Run Consensus" got a
 * four-bar histogram and nothing else: the store received `staticRegions` /
 * `volatileRegions` and no component rendered them, and the only filter form
 * in the app lived inside the Pipeline wizard, which refuses to run without an
 * oracle or a pcap. This panel calls `POST /api/analysis/candidates` — the one
 * route that takes N dumps and returns a ranked list with neither — so the
 * exploratory user reaches candidates at all.
 *
 * Filter state is component-local on purpose. These are the terms of one
 * query; nothing else in the app reads them, so a store slice would only add a
 * second place for them to go stale.
 */
export function CandidatePanel() {
  const { t } = useTranslation("candidates");

  const dumpPaths = useDumpStore(useShallow((s) => s.dumps.map((d) => d.path)));
  const normalize = useDumpStore((s) => s.aslrNormalize);
  const consensusAvailable = useConsensusStore((s) => s.available);
  const scrollToOffset = useHexStore((s) => s.scrollToOffset);

  const [filters, setFilters] = useState<CandidateFilterState>(DEFAULT_CANDIDATE_FILTERS);
  const [result, setResult] = useState<AnalysisCandidatesResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // The auto-run effect must fire on "consensus finished", never on "the user
  // is halfway through editing a threshold" — so it reads the filters through
  // a ref instead of listing them as dependencies.
  const filtersRef = useRef(filters);
  filtersRef.current = filters;

  const enoughDumps = dumpPaths.length >= 2;

  const runQuery = useCallback(
    async (next: CandidateFilterState) => {
      if (dumpPaths.length < 2) return;
      setLoading(true);
      setError(null);
      try {
        const body = buildCandidatesRequest(dumpPaths, next, { normalize });
        setResult(await analyzeCandidates(body));
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
        setResult(null);
      } finally {
        setLoading(false);
      }
    },
    [dumpPaths, normalize],
  );

  // "Run Consensus" is the gesture the analyst already makes; landing a ranked
  // table under the histogram it produces is the whole point of A6.
  useEffect(() => {
    if (!consensusAvailable) return;
    void runQuery(filtersRef.current);
  }, [consensusAvailable, runQuery]);

  const handleJump = useCallback(
    (offset: number) => scrollToOffset(offset),
    [scrollToOffset],
  );

  return (
    <section className="p-3 space-y-2 text-xs" data-testid="candidate-panel">
      <header className="space-y-0.5">
        <h3 className="text-sm font-semibold md-text-accent">{t("title")}</h3>
        <p className="md-text-muted">{t("subtitle")}</p>
      </header>

      {!enoughDumps ? (
        <p className="md-text-muted" data-testid="candidate-need-dumps">
          {t("needDumps")}
        </p>
      ) : (
        <>
          <CandidateFilters value={filters} onChange={setFilters} disabled={loading} />

          <div className="flex items-center gap-2">
            <button
              type="button"
              data-testid="candidate-apply"
              disabled={loading}
              onClick={() => void runQuery(filters)}
              className="px-3 py-1 font-medium rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40"
            >
              {loading ? t("applying") : t("apply")}
            </button>
            {loading && (
              <span className="md-text-muted" role="status">
                {t("running")}
              </span>
            )}
          </div>

          {error && (
            <p className="md-text-error" data-testid="candidate-error">
              {t("errorTitle")}: {error}
            </p>
          )}

          {!result && !loading && !error && (
            <p className="md-text-muted" data-testid="candidate-idle">
              {t("idle")}
            </p>
          )}

          {result && <CandidateResult result={result} onJump={handleJump} />}
        </>
      )}
    </section>
  );
}

/** The rendered half of one query's answer: banner, counts, rows, legend. */
function CandidateResult({
  result,
  onJump,
}: {
  result: AnalysisCandidatesResponse;
  onJump: (offset: number) => void;
}) {
  const { t } = useTranslation("candidates");

  return (
    <div className="space-y-2" aria-live="polite">
      <CandidateAlignmentBanner report={result.alignment} />

      <p className="md-text-muted" data-testid="candidate-summary">
        {t("summary", {
          returned: result.regions_returned.toLocaleString(),
          total: result.num_regions.toLocaleString(),
          dumps: result.num_dumps,
        })}
        {result.regions_truncated && (
          <>
            {" "}
            <span className="md-text-warning">
              {t("truncated", { max: result.max_returned.toLocaleString() })}
            </span>
          </>
        )}
      </p>

      {result.fallback_entropy_only && (
        <p className="md-text-warning" data-testid="candidate-entropy-only">
          {t("fallbackEntropyOnly")}
        </p>
      )}

      {result.regions.length === 0 ? (
        <div data-testid="candidate-empty" className="space-y-1">
          <p className="font-medium">{t("empty.title")}</p>
          <p className="md-text-muted">{t("empty.description")}</p>
          {result.diagnostics.map((d) => (
            <p key={d.code} className="md-text-muted" data-testid="candidate-diagnostic">
              {d.message}
            </p>
          ))}
        </div>
      ) : (
        <CandidateTable
          regions={result.regions}
          onJump={onJump}
          jumpable={offsetsAreDumpOffsets(result.alignment)}
        />
      )}

      <CandidateLegend />
    </div>
  );
}

/**
 * The projection, made honest.
 *
 * A ranked list invites being read as a list of keys. It is not one: ranking
 * says which regions are worth looking at first, and nothing on this screen
 * has decrypted anything.
 */
function CandidateLegend() {
  const { t } = useTranslation("candidates");
  return (
    <details className="text-[11px]" data-testid="candidate-legend">
      <summary className="cursor-pointer md-text-muted">{t("legend.summary")}</summary>
      <div className="mt-1 space-y-1.5 md-text-muted">
        <p>{t("legend.honesty")}</p>
        <ul className="space-y-0.5">
          {BYTE_CLASSES.map((name) => (
            <li key={name}>{t(`legend.class.${name}`)}</li>
          ))}
        </ul>
        <p>{t("legend.ranking")}</p>
        <p>{t("legend.coordinate")}</p>
      </div>
    </details>
  );
}
