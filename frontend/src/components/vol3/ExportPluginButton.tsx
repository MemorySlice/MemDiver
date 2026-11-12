import { useState } from "react";
import { useTranslation } from "react-i18next";

import { useImageStore } from "@/stores/image-store";
import { SynthesizeDialog, type SynthesizeDialogProps } from "./SynthesizeDialog";
import { contextDumpPaths } from "./synth-utils";

const defaultButtonClass =
  "px-2 py-1 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40";

/**
 * The "Export as Volatility 3 plugin" button: opens {@link SynthesizeDialog}
 * prefilled from where it sits (a located-key hit row, the plugin editor). The
 * case defaults to the workspace's case. `dumps` / `secretHex` are read when
 * the dialog OPENS, so a row's latest values are used.
 */
export function ExportPluginButton({
  dumps, secretHex, caseDir, onSynthesized, className, testId = "export-vol3-plugin", ariaLabel, disabled,
}: {
  dumps?: () => readonly string[];
  secretHex?: () => string | undefined;
  caseDir?: string;
  onSynthesized?: SynthesizeDialogProps["onSynthesized"];
  className?: string;
  testId?: string;
  ariaLabel?: string;
  disabled?: boolean;
}) {
  const { t } = useTranslation("vol3");
  const workspaceCase = useImageStore((s) => s.caseDir);
  const [open, setOpen] = useState<{ dumps: readonly string[]; secret?: string } | null>(null);
  return (
    <>
      <button type="button" className={className ?? defaultButtonClass} data-testid={testId}
        aria-label={ariaLabel} disabled={disabled}
        onClick={(e) => { e.stopPropagation(); setOpen({ dumps: (dumps ?? contextDumpPaths)(), secret: secretHex?.() }); }}>
        {t("synth.button")}
      </button>
      {open && (
        // A click inside the dialog must not reach a host row's own click handler.
        <span role="presentation" onClick={(e) => e.stopPropagation()}>
          <SynthesizeDialog initialDumps={open.dumps} initialSecretHex={open.secret}
            initialCaseDir={caseDir ?? workspaceCase} onSynthesized={onSynthesized}
            onClose={() => setOpen(null)} />
        </span>
      )}
    </>
  );
}
