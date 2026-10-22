import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { getImportProvenance } from "@/api/client";
import type { ImportProvenanceRecord } from "@/api/types";
import { useDumpStore } from "@/stores/dump-store";
import { formatBytes } from "@/utils/format-bytes";

interface Props {
  mslPath: string;
}

/**
 * IMPORT_PROVENANCE of the open .msl: where it came from, which region
 * categories the import kept, what it excluded, and whether the file is a
 * materialized (filtered) copy of another .msl. Renders nothing for a dump
 * without provenance (live captures, non-.msl inputs).
 */
export function ImportProvenancePanel({ mslPath }: Props) {
  const { t } = useTranslation("session");
  const [records, setRecords] = useState<ImportProvenanceRecord[]>([]);
  const [error, setError] = useState<string | null>(null);
  const keyMaterial = useDumpStore((s) => s.getKeyMaterialByPath(mslPath));
  const [prevSource, setPrevSource] = useState({ mslPath, keyMaterial });

  if (prevSource.mslPath !== mslPath || prevSource.keyMaterial !== keyMaterial) {
    setPrevSource({ mslPath, keyMaterial });
    setRecords([]);
    setError(null);
  }

  useEffect(() => {
    if (!mslPath) return;
    let cancelled = false;
    getImportProvenance(mslPath, keyMaterial)
      .then((res) => {
        if (!cancelled) setRecords(res.provenance ?? []);
      })
      .catch((e) => {
        if (!cancelled) setError(String(e));
      });
    return () => {
      cancelled = true;
    };
  }, [mslPath, keyMaterial]);

  if (error) {
    return (
      <p className="px-3 text-xs md-text-error" data-testid="import-provenance-error">
        {t("provenance.loadFailed", { error })}
      </p>
    );
  }
  if (!records.length) return null;

  return (
    <div className="px-3 pb-3 space-y-2 text-xs" data-testid="import-provenance">
      <h3 className="text-sm font-semibold md-text-accent">{t("provenance.title")}</h3>
      {records.map((record, i) => (
        <ProvenanceRecord key={i} record={record} />
      ))}
    </div>
  );
}

function ProvenanceRecord({ record }: { record: ImportProvenanceRecord }) {
  const { t } = useTranslation("session");
  const kept = useKeptText(record);
  return (
    <div className="md-panel p-2 space-y-1" data-testid="import-provenance-record">
      <Row label={t("provenance.sourceFormat")} value={record.source_format_name} testId="source-format" />
      <Row label={t("provenance.tool")} value={record.tool_name} />
      <Row label={t("provenance.originalSize")} value={formatBytes(record.orig_file_size)} />
      <Row label={t("provenance.kept")} value={kept} testId="kept" />
      {record.excluded_regions !== null && (
        <Row
          label={t("provenance.excluded")}
          value={t("provenance.excludedValue", {
            count: record.excluded_regions,
            size: formatBytes(record.excluded_bytes ?? 0),
          })}
          testId="excluded"
        />
      )}
      {record.fallback_all && (
        <p className="md-text-warning">{t("provenance.fallbackAll")}</p>
      )}
      {record.materialized && <MaterializedRows record={record} />}
      {record.region_names && (
        <Row label={t("provenance.regionNames")} value={t("provenance.regionNamesYes")} testId="region-names" />
      )}
      <Row label={t("provenance.rawNote")} value={record.note} />
    </div>
  );
}

function MaterializedRows({ record }: { record: ImportProvenanceRecord }) {
  const { t } = useTranslation("session");
  return (
    <>
      <Row
        label={t("provenance.materialized")}
        value={t("provenance.materializedValue")}
        testId="materialized"
      />
      <Row
        label={t("provenance.originalHash")}
        value={record.orig_eoc_hash ?? t("provenance.hashUnknown")}
        testId="orig-hash"
      />
      {record.dropped_key_hints !== null && (
        <Row label={t("provenance.droppedKeyHints")} value={String(record.dropped_key_hints)} />
      )}
    </>
  );
}

/** "Heap, Stack (writable only) + modules libssl*" in the active language. */
function useKeptText(record: ImportProvenanceRecord): string {
  const { t } = useTranslation(["session", "import"]);
  if (record.selected_categories === null) return t("provenance.noSelection");
  let text = record.selection_all
    ? t("provenance.keptAll")
    : record.selected_categories
        .map((c) => t(`import:category.${c}.label`, { defaultValue: c }))
        .join(", ");
  if (record.writable_only) text += ` (${t("provenance.writableOnly")})`;
  if (record.module_globs.length) {
    text += ` + ${t("provenance.modules", { globs: record.module_globs.join("|") })}`;
  }
  return text;
}

function Row({ label, value, testId }: { label: string; value: string; testId?: string }) {
  return (
    <div className="flex" data-testid={testId ? `import-provenance-${testId}` : undefined}>
      <span className="w-28 md-text-secondary shrink-0">{label}</span>
      <span className="font-mono truncate" title={value}>{value}</span>
    </div>
  );
}
