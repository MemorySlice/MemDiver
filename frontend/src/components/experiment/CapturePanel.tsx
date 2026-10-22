/**
 * "Capture a running process" -- dump ONE live process via
 * `POST /api/experiment/capture` (synchronous) and render the returned report.
 *
 * The device string is composed from a kind select (Local / USB / Remote) plus
 * a detail input by `composeDeviceString`; HTTP refusals (400 / 412 capability
 * errors) surface inline via `readableFailure` and through `notifyError`.
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  CAPTURE_TOOLS,
  DEVICE_KINDS,
  INITIAL_CAPTURE_FORM,
  buildCaptureRequest,
  captureProcess,
  type CaptureForm,
  type CaptureReport,
  type CaptureTool,
  type DeviceKind,
} from '@/api/capture';
import { readableFailure } from '@/api/client';
import { notifyError } from '@/utils/errorNotifier';
import { CaptureReportView } from './CaptureReportView';

const NOTIFY_CONTEXT = 'capture-panel';
const INPUT_CLASS =
  'bg-[var(--md-bg-tertiary)] border border-[var(--md-border)] rounded px-2 py-1 text-xs text-[var(--md-text-primary)]';

function DeviceFields({ form, update }: { form: CaptureForm; update: (patch: Partial<CaptureForm>) => void }) {
  const { t } = useTranslation('misc');
  return (
    <div className="flex gap-2 items-center">
      <select
        value={form.deviceKind}
        onChange={e => update({ deviceKind: e.target.value as DeviceKind, deviceDetail: '' })}
        className={INPUT_CLASS}
        aria-label={t('capture.deviceKind')}
        data-testid="capture-device-kind"
      >
        {DEVICE_KINDS.map(kind => (
          <option key={kind} value={kind}>{t(`capture.device.${kind}`)}</option>
        ))}
      </select>
      {form.deviceKind !== 'local' && (
        <input
          type="text"
          value={form.deviceDetail}
          onChange={e => update({ deviceDetail: e.target.value })}
          className={`${INPUT_CLASS} flex-1`}
          aria-label={form.deviceKind === 'usb' ? t('capture.usbDeviceId') : t('capture.remoteHost')}
          placeholder={form.deviceKind === 'usb' ? t('capture.usbDeviceIdPlaceholder') : t('capture.remoteHostPlaceholder')}
          data-testid="capture-device-detail"
        />
      )}
    </div>
  );
}

function OptionalFields({ form, update }: { form: CaptureForm; update: (patch: Partial<CaptureForm>) => void }) {
  const { t } = useTranslation('misc');
  return (
    <>
      <input
        type="text"
        value={form.output}
        onChange={e => update({ output: e.target.value })}
        className={INPUT_CLASS}
        aria-label={t('capture.outputPath')}
        placeholder={t('capture.outputPathPlaceholder')}
        data-testid="capture-output"
      />
      <input
        type="text"
        inputMode="numeric"
        value={form.maxRegionSize}
        onChange={e => update({ maxRegionSize: e.target.value })}
        className={INPUT_CLASS}
        aria-label={t('capture.maxRegionSize')}
        placeholder={t('capture.maxRegionSizePlaceholder')}
        data-testid="capture-max-region-size"
      />
      <label className="flex items-center gap-1 text-xs cursor-pointer" title={t('capture.includeLargeReadonlyHint')}>
        <input
          type="checkbox"
          checked={form.includeLargeReadonly}
          disabled={form.tool !== 'lldb'}
          onChange={e => update({ includeLargeReadonly: e.target.checked })}
          className="w-3 h-3"
          data-testid="capture-include-large-readonly"
        />
        <span className={form.tool === 'lldb' ? 'md-text-secondary' : 'md-text-muted'}>
          {t('capture.includeLargeReadonly')}
        </span>
      </label>
    </>
  );
}

export function CapturePanel() {
  const { t } = useTranslation('misc');
  const [form, setForm] = useState<CaptureForm>(INITIAL_CAPTURE_FORM);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<CaptureReport | null>(null);
  const update = (patch: Partial<CaptureForm>) => setForm(prev => ({ ...prev, ...patch }));

  const handleCapture = async () => {
    const body = buildCaptureRequest(form);
    if ('invalid' in body) {
      setError(t(body.invalid));
      return;
    }
    setBusy(true);
    setError(null);
    setReport(null);
    try {
      setReport(await captureProcess(body));
    } catch (err) {
      const message = t('capture.requestFailed', { msg: readableFailure(err) });
      setError(message);
      notifyError(message, NOTIFY_CONTEXT);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="flex flex-col gap-2" data-testid="capture-panel">
      <h2 className="text-sm font-semibold text-[var(--md-text-primary)]">{t('capture.heading')}</h2>
      <input
        type="text"
        value={form.target}
        onChange={e => update({ target: e.target.value })}
        className={INPUT_CLASS}
        aria-label={t('capture.target')}
        placeholder={t('capture.targetPlaceholder')}
        data-testid="capture-target"
      />
      <select
        value={form.tool}
        onChange={e => update({ tool: e.target.value as CaptureTool })}
        className={INPUT_CLASS}
        aria-label={t('capture.tool')}
        data-testid="capture-tool"
      >
        {CAPTURE_TOOLS.map(tool => <option key={tool} value={tool}>{tool}</option>)}
      </select>
      <DeviceFields form={form} update={update} />
      <OptionalFields form={form} update={update} />
      <button
        onClick={handleCapture}
        disabled={busy}
        className="px-4 py-2 bg-[var(--md-accent-blue)] hover:opacity-90 disabled:bg-[var(--md-bg-hover)]
                   disabled:text-[var(--md-text-muted)] rounded text-xs font-medium md-text-on-accent"
        data-testid="capture-submit"
      >
        {busy ? t('capture.capturing') : t('capture.captureButton')}
      </button>
      {error && (
        <p className="text-xs text-[var(--md-accent-red)] break-all" role="alert" data-testid="capture-error">
          {error}
        </p>
      )}
      {report && <CaptureReportView report={report} />}
    </section>
  );
}
