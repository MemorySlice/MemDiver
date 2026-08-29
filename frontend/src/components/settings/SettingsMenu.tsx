import { useState, useRef, useEffect, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { useSettingsStore } from "@/stores/settings-store";
import { useTheme } from "@/providers/ThemeProvider";
import { downloadJsonFile } from "@/utils/download";
import { useTourController } from "@/ftue/useTourController";
import type { ChartBackend } from "@/components/charts/types";
import { UploadDirPrompt } from "./UploadDirPrompt";
import { useUploadDir } from "./useUploadDir";

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="px-3 py-2 border-b border-[var(--md-border)]">
      <div className="text-[10px] uppercase tracking-wider font-semibold md-text-muted mb-1.5">
        {title}
      </div>
      <div className="space-y-1.5">{children}</div>
    </div>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="flex items-center justify-between gap-2 text-xs md-text-secondary">
      <span>{label}</span>
      {children}
    </label>
  );
}

function CheckboxRow({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <Row label={label}>
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="accent-[var(--md-accent-blue)] cursor-pointer"
      />
    </Row>
  );
}

function SelectRow<T extends string | number>({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: T;
  options: { value: T; label: string }[];
  onChange: (v: T) => void;
}) {
  return (
    <Row label={label}>
      <select
        value={value}
        onChange={(e) => {
          const raw = e.target.value;
          const parsed = typeof value === "number" ? (Number(raw) as T) : (raw as T);
          onChange(parsed);
        }}
        className="bg-[var(--md-bg-primary)] border border-[var(--md-border)] rounded px-1.5 py-0.5 text-xs md-text-secondary cursor-pointer"
      >
        {options.map((o) => (
          <option key={String(o.value)} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </Row>
  );
}

/**
 * Where uploads land. Unlike every other row in this menu, this one is *server*
 * state: it comes from ``GET /api/settings/upload-dir``, never from the zustand
 * ``persist`` store, because a localStorage copy could claim a path the backend
 * never accepted.
 *
 * The picker is ``UploadDirPrompt`` -- the same modal the 409-on-upload path
 * opens -- so there is exactly one place that POSTs the directory.
 */
function StorageSection() {
  const { t } = useTranslation("misc");
  const { status, refresh } = useUploadDir();
  const [choosing, setChoosing] = useState(false);

  const pinned = status?.env_pinned ?? false;

  return (
    <Section title={t("settings.sectionStorage")}>
      <div className="space-y-1.5" data-testid="settings-storage">
        <div className="md-text-secondary">{t("settings.uploadDir")}</div>
        {status?.path ? (
          <div
            data-testid="settings-upload-dir-path"
            className="font-mono text-[10px] break-all md-text-muted"
          >
            {status.path}
          </div>
        ) : (
          <div data-testid="settings-upload-dir-unset" className="md-text-error">
            {t("settings.uploadDirNotConfigured")}
          </div>
        )}
        {pinned ? (
          // Read-only: a POST would be rejected with 409, so do not offer one.
          <div data-testid="settings-upload-dir-pinned" className="md-text-muted">
            {t("settings.uploadDirEnvPinned")}
          </div>
        ) : (
          <button
            type="button"
            data-testid="settings-upload-dir-choose"
            onClick={() => setChoosing(true)}
            className="w-full text-left px-2 py-1 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] transition-colors md-text-secondary"
          >
            {t("settings.uploadDirChoose")}
          </button>
        )}
      </div>
      {choosing && (
        <UploadDirPrompt
          onSaved={() => {
            setChoosing(false);
            void refresh();
          }}
          onClose={() => setChoosing(false)}
        />
      )}
    </Section>
  );
}

export function SettingsMenu() {
  const { t } = useTranslation("misc");
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  // intentional: whole-store read. This menu renders every settings field,
  // so there is nothing to narrow — a useShallow wrapper over the full state
  // is a no-op that only adds a per-render object allocation and comparison.
  const settings = useSettingsStore();
  const { setTheme, toggleHighContrast: toggleHC } = useTheme();
  const { startTour } = useTourController();

  const handleStartOnboardingTour = () => {
    setOpen(false);
    startTour("structure-overlay-101");
  };

  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [open]);

  const handleExport = () => {
    const json = settings.exportSettings();
    downloadJsonFile(JSON.parse(json), "memdiver-settings.json");
  };

  const handleReset = () => {
    if (settings.general.confirmBeforeReset) {
      if (!window.confirm(t("settings.resetConfirm"))) return;
    }
    settings.resetToDefaults();
  };

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen((prev) => !prev)}
        className="text-xs px-2 py-1 rounded hover:bg-[var(--md-bg-hover)] transition-colors md-text-secondary"
        title={t("common:settings")}
        aria-label={t("common:settings")}
      >
        <svg
          xmlns="http://www.w3.org/2000/svg"
          width="14"
          height="14"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" />
          <circle cx="12" cy="12" r="3" />
        </svg>
      </button>
      {open && (
        <div className="absolute right-0 top-full mt-1 w-72 max-h-[70vh] overflow-auto rounded border border-[var(--md-border)] bg-[var(--md-bg-primary)] shadow-lg z-50 text-xs">
          <div className="px-3 py-2 border-b border-[var(--md-border)]">
            <span className="text-xs font-semibold md-text-secondary">{t("settings.title")}</span>
          </div>

          <Section title={t("settings.sectionDisplay")}>
            <SelectRow
              label={t("settings.theme")}
              value={settings.display.theme}
              options={[
                { value: "dark", label: t("settings.themeDark") },
                { value: "light", label: t("settings.themeLight") },
              ]}
              onChange={(v) => {
                const t = v as "light" | "dark";
                settings.updateDisplay({ theme: t });
                setTheme(t);
              }}
            />
            <CheckboxRow
              label={t("settings.highContrast")}
              checked={settings.display.highContrast}
              onChange={(v) => {
                settings.updateDisplay({ highContrast: v });
                toggleHC();
              }}
            />
            <SelectRow
              label={t("settings.hexBytesPerRow")}
              value={settings.display.hexBytesPerRow}
              options={[
                { value: 16, label: "16" },
                { value: 32, label: "32" },
              ]}
              onChange={(v) => settings.updateDisplay({ hexBytesPerRow: v as 16 | 32 })}
            />
            <CheckboxRow
              label={t("settings.uppercaseHex")}
              checked={settings.display.hexUpperCase}
              onChange={(v) => settings.updateDisplay({ hexUpperCase: v })}
            />
            <CheckboxRow
              label={t("settings.showAsciiColumn")}
              checked={settings.display.showAsciiColumn}
              onChange={(v) => settings.updateDisplay({ showAsciiColumn: v })}
            />
            <SelectRow
              label={t("settings.fontSize")}
              value={settings.display.fontSize}
              options={[
                { value: "xs", label: t("settings.fontSizeExtraSmall") },
                { value: "sm", label: t("settings.fontSizeSmall") },
                { value: "base", label: t("settings.fontSizeNormal") },
              ]}
              onChange={(v) => settings.updateDisplay({ fontSize: v as "xs" | "sm" | "base" })}
            />
            <SelectRow
              label={t("settings.chartBackend")}
              value={settings.display.chartBackend}
              options={[
                { value: "plotly", label: t("settings.chartBackendPlotly") },
                { value: "svg", label: t("settings.chartBackendSvg") },
              ]}
              onChange={(v) =>
                settings.updateDisplay({ chartBackend: v as ChartBackend })
              }
            />
          </Section>

          <Section title={t("settings.sectionAnalysis")}>
            <Row label={t("settings.entropyThreshold")}>
              <input
                type="number"
                step="0.1"
                min="0"
                max="8"
                value={settings.analysis.entropyThreshold}
                onChange={(e) => {
                  const v = parseFloat(e.target.value);
                  settings.updateAnalysis({
                    entropyThreshold: Number.isNaN(v) ? 4.5 : v,
                  });
                }}
                className="w-16 bg-[var(--md-bg-primary)] border border-[var(--md-border)] rounded px-1.5 py-0.5 text-xs md-text-secondary text-right"
              />
            </Row>
            <CheckboxRow
              label={t("settings.autoRunOnLoad")}
              checked={settings.analysis.autoRunOnLoad}
              onChange={(v) => settings.updateAnalysis({ autoRunOnLoad: v })}
            />
          </Section>

          <Section title={t("settings.sectionGeneral")}>
            <CheckboxRow
              label={t("settings.autoSaveSession")}
              checked={settings.general.autoSaveSession}
              onChange={(v) => settings.updateGeneral({ autoSaveSession: v })}
            />
            <CheckboxRow
              label={t("settings.keyboardShortcuts")}
              checked={settings.general.keyboardShortcutsEnabled}
              onChange={(v) => settings.updateGeneral({ keyboardShortcutsEnabled: v })}
            />
            <CheckboxRow
              label={t("settings.confirmBeforeReset")}
              checked={settings.general.confirmBeforeReset}
              onChange={(v) => settings.updateGeneral({ confirmBeforeReset: v })}
            />
          </Section>

          <StorageSection />

          <Section title={t("settings.sectionHelp")}>
            <button
              onClick={handleStartOnboardingTour}
              className="w-full text-left px-2 py-1 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] transition-colors md-text-secondary"
            >
              {t("settings.runOnboardingTour")}
            </button>
          </Section>

          <div className="flex items-center gap-2 px-3 py-2">
            <button
              onClick={handleExport}
              className="flex-1 px-2 py-1 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] transition-colors md-text-secondary"
            >
              {t("settings.export")}
            </button>
            <button
              onClick={handleReset}
              className="flex-1 px-2 py-1 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] transition-colors md-text-error"
            >
              {t("settings.reset")}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
