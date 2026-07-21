interface SessionData {
  dump_uuid: string;
  pid: number;
  os_type: string;
  arch_type: string;
  timestamp_iso: string;
  exe_path?: string;
  modules: { path: string; base_addr: number; size: number }[];
  region_count: number;
  total_region_size: number;
  captured_page_count: number;
  key_hint_count: number;
}

import { memo } from "react";
import { useTranslation } from "react-i18next";

interface Props {
  data: SessionData;
  /** Fractional page-capture coverage (0..1); rendered as a percentage. */
  coverage?: number;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

export const SessionView = memo(function SessionView({ data, coverage }: Props) {
  const { t } = useTranslation("session");
  return (
    <div className="p-3 space-y-3 text-xs">
      <h3 className="text-sm font-semibold md-text-accent">{t("info.title")}</h3>

      <div className="md-panel p-2 space-y-1">
        <Row label={t("info.uuid")} value={data.dump_uuid} />
        <Row label={t("info.pid")} value={String(data.pid)} />
        <Row label={t("info.osArch")} value={`${data.os_type} / ${data.arch_type}`} />
        <Row label={t("info.timestamp")} value={data.timestamp_iso} />
        {data.exe_path && <Row label={t("info.executable")} value={data.exe_path} />}
      </div>

      <div className="md-panel p-2 space-y-1">
        <Row label={t("info.regions")} value={String(data.region_count)} />
        <Row label={t("info.totalSize")} value={formatSize(data.total_region_size)} />
        <Row label={t("info.capturedPages")} value={String(data.captured_page_count)} />
        {coverage !== undefined && (
          <Row label={t("info.coverage")} value={`${Math.round(coverage * 100)}%`} />
        )}
        <Row label={t("info.keyHints")} value={String(data.key_hint_count)} />
      </div>

      {data.modules.length > 0 && (
        <div className="md-panel p-2">
          <div className="font-medium mb-1 md-text-secondary">{t("info.modules", { n: data.modules.length })}</div>
          <div className="max-h-32 overflow-auto space-y-0.5">
            {data.modules.map((m, i) => (
              <div key={i} className="font-mono md-text-muted truncate" title={m.path}>
                0x{m.base_addr.toString(16)} ({formatSize(m.size)}) {m.path.split(/[\\/]/).pop()}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
});

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex">
      <span className="w-28 md-text-secondary shrink-0">{label}</span>
      <span className="font-mono truncate" title={value}>{value}</span>
    </div>
  );
}
