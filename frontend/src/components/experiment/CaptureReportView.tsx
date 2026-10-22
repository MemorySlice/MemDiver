/**
 * Read-only rendering of one `POST /api/experiment/capture` report:
 * outcome, output path, region/byte totals, where region names came from,
 * summary warnings, skipped regions and the error text.
 */
import { useTranslation } from 'react-i18next';
import {
  CAPTURE_NAME_SOURCES,
  KNOWN_SKIP_REASONS,
  type CaptureNameSource,
  type CaptureReport,
  type CaptureSkippedRegion,
} from '@/api/capture';
import { formatBytes } from '@/utils/format-bytes';

const isKnown = <T extends string>(list: readonly T[], value: string): value is T =>
  (list as readonly string[]).includes(value);

function NamesSourceLine({ names }: { names: CaptureNameSource | null }) {
  const { t } = useTranslation('misc');
  const source = names && isKnown(CAPTURE_NAME_SOURCES, names) ? names : null;
  return (
    <div className="flex flex-col gap-1" data-testid="capture-names-source">
      <span className="text-xs md-text-secondary">
        {t('capture.namesSource', {
          source: source ? t(`capture.names.${source}`) : t('capture.names.unknown'),
        })}
      </span>
      {source === 'none' && (
        <span className="text-xs text-[var(--md-accent-orange)]" role="alert">
          {t('capture.namesNoneWarning')}
        </span>
      )}
    </div>
  );
}

function SkippedTable({ skipped, skippedBytes }: { skipped: CaptureSkippedRegion[]; skippedBytes: number }) {
  const { t } = useTranslation('misc');
  const reasonLabel = (reason: string) =>
    isKnown(KNOWN_SKIP_REASONS, reason) ? t(`capture.skipReason.${reason}`) : reason;
  return (
    <div className="flex flex-col gap-1" data-testid="capture-skipped">
      <span className="text-xs md-text-secondary">
        {t('capture.skippedCount', { count: skipped.length, bytes: formatBytes(skippedBytes) })}
      </span>
      {skipped.length > 0 && (
        <table className="text-xs border border-[var(--md-border)]">
          <thead>
            <tr className="md-text-secondary text-left">
              <th className="px-2">{t('capture.colBase')}</th>
              <th className="px-2">{t('capture.colSize')}</th>
              <th className="px-2">{t('capture.colReason')}</th>
            </tr>
          </thead>
          <tbody>
            {skipped.map(region => (
              <tr key={region.base} className="text-[var(--md-text-primary)]">
                <td className="px-2 font-mono">{region.base_hex}</td>
                <td className="px-2">{formatBytes(region.size)}</td>
                <td className="px-2">{reasonLabel(region.reason)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export function CaptureReportView({ report }: { report: CaptureReport }) {
  const { t } = useTranslation('misc');
  return (
    <div className="flex flex-col gap-2 border border-[var(--md-border)] rounded p-2" data-testid="capture-report">
      <span
        className={`text-xs font-medium ${report.ok ? 'text-[var(--md-accent-green)]' : 'text-[var(--md-accent-red)]'}`}
        data-testid="capture-outcome"
      >
        {report.ok ? t('capture.succeeded') : t('capture.failed')}
      </span>
      <span className="text-xs md-text-secondary break-all">
        {t('capture.outputPathLabel', { path: report.output_path })}
      </span>
      <span className="text-xs md-text-secondary">
        {t('capture.capturedTotals', {
          regions: report.regions_captured,
          bytes: formatBytes(report.bytes_captured),
        })}
      </span>
      <NamesSourceLine names={report.names} />
      {report.summary_warnings.length > 0 && (
        <ul className="list-disc pl-4 text-xs text-[var(--md-accent-orange)]" data-testid="capture-warnings">
          {report.summary_warnings.map(warning => <li key={warning}>{warning}</li>)}
        </ul>
      )}
      <SkippedTable skipped={report.skipped} skippedBytes={report.skipped_bytes} />
      {report.error && (
        <span className="text-xs text-[var(--md-accent-red)] break-all" data-testid="capture-report-error">
          {t('capture.errorLabel', { error: report.error })}
        </span>
      )}
    </div>
  );
}
