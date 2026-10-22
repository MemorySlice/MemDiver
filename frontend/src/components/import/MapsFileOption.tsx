import { useState } from "react";
import { useTranslation } from "react-i18next";
import { FileBrowser } from "@/components/wizard/FileBrowser";

export interface MapsFileOptionProps {
  /** Memory map the current preview used (`null` = the dump has no layout). */
  activeMapsPath: string | null;
  /** True when `activeMapsPath` is the user's choice rather than an auto-detected sidecar. */
  chosen: boolean;
  /** Pre-filled path when no map is active (e.g. a chosen map the server rejected). */
  initialPath?: string;
  /** Re-preview the dump with this memory map. */
  onApply: (mapsPath: string) => void;
}

function baseName(path: string): string {
  return path.split(/[\\/]/).pop() || path;
}

/**
 * Raw dump: point the import at a `/proc/<pid>/maps`-style memory map.
 *
 * Without a layout it offers a path input (typed or browsed) and "Apply",
 * which re-runs the preview with that map. With a map in use it names the
 * file (auto-detected or chosen) and offers "change" to pick another.
 */
export function MapsFileOption({ activeMapsPath, chosen, initialPath = "", onApply }: MapsFileOptionProps) {
  const { t } = useTranslation("import");
  const [editing, setEditing] = useState(false);

  if (activeMapsPath && !editing) {
    return (
      <p className="text-xs flex items-center gap-2" data-testid="region-maps-active">
        <span>
          {t(chosen ? "maps.activeChosen" : "maps.activeDetected", { name: baseName(activeMapsPath) })}
        </span>
        <button
          type="button"
          onClick={() => setEditing(true)}
          className="underline md-text-accent"
          data-testid="region-maps-change"
        >
          {t("maps.change")}
        </button>
      </p>
    );
  }
  return (
    <MapsPathForm
      initialPath={activeMapsPath ?? initialPath}
      onApply={(path) => {
        setEditing(false);
        onApply(path);
      }}
      onCancel={activeMapsPath ? () => setEditing(false) : undefined}
    />
  );
}

interface MapsPathFormProps {
  initialPath: string;
  onApply: (mapsPath: string) => void;
  /** Shown only when there is an active map to go back to. */
  onCancel?: () => void;
}

function MapsPathForm({ initialPath, onApply, onCancel }: MapsPathFormProps) {
  const { t } = useTranslation("import");
  const [path, setPath] = useState(initialPath);
  const [browsing, setBrowsing] = useState(false);
  const trimmed = path.trim();
  const buttonClass =
    "text-xs px-2 py-1 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40";

  return (
    <div className="space-y-1" data-testid="region-maps-form">
      <label htmlFor="region-maps-input" className="text-xs font-medium block">
        {t("maps.label")}
      </label>
      <div className="flex items-center gap-2">
        <input
          id="region-maps-input"
          type="text"
          value={path}
          onChange={(e) => setPath(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && trimmed) onApply(trimmed);
          }}
          placeholder={t("maps.placeholder")}
          className="flex-1 text-xs px-2 py-1 rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)] text-[var(--md-text-primary)]"
          data-testid="region-maps-input"
        />
        <button type="button" onClick={() => setBrowsing(true)} className={buttonClass} data-testid="region-maps-browse">
          {t("maps.browse")}
        </button>
        <button
          type="button"
          onClick={() => onApply(trimmed)}
          disabled={!trimmed}
          className={buttonClass}
          data-testid="region-maps-apply"
        >
          {t("maps.apply")}
        </button>
        {onCancel && (
          <button type="button" onClick={onCancel} className={buttonClass} data-testid="region-maps-cancel">
            {t("maps.cancel")}
          </button>
        )}
      </div>
      <p className="text-xs md-text-muted">{t("maps.hint")}</p>
      {browsing && (
        <FileBrowser
          allFiles
          onSelect={(selected) => {
            setPath(selected);
            setBrowsing(false);
          }}
          onClose={() => setBrowsing(false)}
        />
      )}
    </div>
  );
}
