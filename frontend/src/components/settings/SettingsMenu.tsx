import { useState, useRef, useEffect, type ReactNode } from "react";
import { useSettingsStore } from "@/stores/settings-store";
import { useTheme } from "@/providers/ThemeProvider";
import { downloadJsonFile } from "@/utils/download";
import { useTourController } from "@/ftue/useTourController";

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

export function SettingsMenu() {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
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
      if (!window.confirm("Reset all settings to defaults?")) return;
    }
    settings.resetToDefaults();
  };

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen((prev) => !prev)}
        className="text-xs px-2 py-1 rounded hover:bg-[var(--md-bg-hover)] transition-colors md-text-secondary"
        title="Settings"
        aria-label="Settings"
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
            <span className="text-xs font-semibold md-text-secondary">Settings</span>
          </div>

          <Section title="Display">
            <SelectRow
              label="Theme"
              value={settings.display.theme}
              options={[
                { value: "dark", label: "Dark" },
                { value: "light", label: "Light" },
              ]}
              onChange={(v) => {
                const t = v as "light" | "dark";
                settings.updateDisplay({ theme: t });
                setTheme(t);
              }}
            />
            <CheckboxRow
              label="High Contrast"
              checked={settings.display.highContrast}
              onChange={(v) => {
                settings.updateDisplay({ highContrast: v });
                toggleHC();
              }}
            />
            <SelectRow
              label="Hex Bytes/Row"
              value={settings.display.hexBytesPerRow}
              options={[
                { value: 16, label: "16" },
                { value: 32, label: "32" },
              ]}
              onChange={(v) => settings.updateDisplay({ hexBytesPerRow: v as 16 | 32 })}
            />
            <CheckboxRow
              label="Uppercase Hex"
              checked={settings.display.hexUpperCase}
              onChange={(v) => settings.updateDisplay({ hexUpperCase: v })}
            />
            <CheckboxRow
              label="Show ASCII Column"
              checked={settings.display.showAsciiColumn}
              onChange={(v) => settings.updateDisplay({ showAsciiColumn: v })}
            />
            <SelectRow
              label="Font Size"
              value={settings.display.fontSize}
              options={[
                { value: "xs", label: "Extra Small" },
                { value: "sm", label: "Small" },
                { value: "base", label: "Normal" },
              ]}
              onChange={(v) => settings.updateDisplay({ fontSize: v as "xs" | "sm" | "base" })}
            />
          </Section>

          <Section title="Analysis">
            <Row label="Entropy Threshold">
              <input
                type="number"
                step="0.1"
                min="0"
                max="8"
                value={settings.analysis.entropyThreshold}
                onChange={(e) =>
                  settings.updateAnalysis({
                    entropyThreshold: parseFloat(e.target.value) || 4.5,
                  })
                }
                className="w-16 bg-[var(--md-bg-primary)] border border-[var(--md-border)] rounded px-1.5 py-0.5 text-xs md-text-secondary text-right"
              />
            </Row>
            <CheckboxRow
              label="Auto-run on Load"
              checked={settings.analysis.autoRunOnLoad}
              onChange={(v) => settings.updateAnalysis({ autoRunOnLoad: v })}
            />
          </Section>

          <Section title="General">
            <CheckboxRow
              label="Auto-save Session"
              checked={settings.general.autoSaveSession}
              onChange={(v) => settings.updateGeneral({ autoSaveSession: v })}
            />
            <CheckboxRow
              label="Keyboard Shortcuts"
              checked={settings.general.keyboardShortcutsEnabled}
              onChange={(v) => settings.updateGeneral({ keyboardShortcutsEnabled: v })}
            />
            <CheckboxRow
              label="Confirm Before Reset"
              checked={settings.general.confirmBeforeReset}
              onChange={(v) => settings.updateGeneral({ confirmBeforeReset: v })}
            />
          </Section>

          <Section title="Help">
            <button
              onClick={handleStartOnboardingTour}
              className="w-full text-left px-2 py-1 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] transition-colors md-text-secondary"
            >
              Run onboarding tour
            </button>
          </Section>

          <div className="flex items-center gap-2 px-3 py-2">
            <button
              onClick={handleExport}
              className="flex-1 px-2 py-1 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] transition-colors md-text-secondary"
            >
              Export
            </button>
            <button
              onClick={handleReset}
              className="flex-1 px-2 py-1 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] transition-colors md-text-error"
            >
              Reset
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
