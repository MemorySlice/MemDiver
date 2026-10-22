import { useEffect, useState } from "react";
import { useShallow } from "zustand/react/shallow";
import { listDatasetRuns } from "@/api/client";
import type { ImportPreview, KeyMaterial } from "@/api/types";
import { RegionSelectStep } from "@/components/import/RegionSelectStep";
import { useAppStore } from "@/stores/app-store";
import { useRegionSelectionStore } from "@/stores/region-selection-store";

/** First dump path under a directory input, for the preview (null = none found). */
function useFirstDirectoryDump(root: string | null): string | null {
  const [found, setFound] = useState<{ root: string; path: string | null } | null>(null);
  useEffect(() => {
    if (!root) return;
    let cancelled = false;
    listDatasetRuns(root, 1)
      .then((res) => {
        if (!cancelled) setFound({ root, path: res.runs[0]?.dumps[0]?.path ?? null });
      })
      .catch(() => {
        if (!cancelled) setFound({ root, path: null });
      });
    return () => { cancelled = true; };
  }, [root]);
  return found && found.root === root ? found.path : null;
}

/** Encrypted-`.msl` inputs, held in the Wizard's component state (never a store). */
export interface WizardDecryption {
  keyMaterial: KeyMaterial;
  decryptOutput: boolean;
}

export interface StepRegionsProps {
  onPreviewChange: (p: ImportPreview | null) => void;
  decryption?: WizardDecryption;
  onDecryptionChange?: (next: WizardDecryption) => void;
}

/** Wizard "Regions" step: binds `RegionSelectStep` to the wizard's stores. */
export function StepRegions({ onPreviewChange, decryption, onDecryptionChange }: StepRegionsProps) {
  const { inputPath, pathInfo } = useAppStore(
    useShallow((s) => ({ inputPath: s.inputPath, pathInfo: s.pathInfo })),
  );
  const { categories, materialize, setCategories, setMaterialize, maps, setMaps } = useRegionSelectionStore(
    useShallow((s) => ({
      categories: s.wizardCategories,
      materialize: s.wizardMaterialize,
      setCategories: s.setWizardCategories,
      setMaterialize: s.setWizardMaterialize,
      maps: s.wizardMaps,
      setMaps: s.setWizardMaps,
    })),
  );
  const isDirectory = pathInfo?.is_directory ?? false;
  const firstDirectoryDump = useFirstDirectoryDump(isDirectory ? inputPath : null);
  const paths = isDirectory
    ? (firstDirectoryDump ? [firstDirectoryDump] : [])
    : [inputPath];
  const dumpCount = isDirectory ? (pathInfo?.dump_count || null) : 1;
  // A map chosen for another input does not describe this one.
  const mapsPath = !isDirectory && maps?.input === inputPath ? maps.mapsPath : null;

  return (
    <RegionSelectStep
      paths={paths}
      dumpCount={dumpCount}
      selected={categories}
      onSelectedChange={setCategories}
      materialize={materialize}
      onMaterializeChange={setMaterialize}
      onPreviewChange={onPreviewChange}
      keyMaterial={decryption?.keyMaterial}
      onKeyMaterialChange={(keyMaterial) =>
        onDecryptionChange?.({ decryptOutput: decryption?.decryptOutput ?? false, keyMaterial })}
      decryptOutput={decryption?.decryptOutput}
      onDecryptOutputChange={(decryptOutput) =>
        onDecryptionChange?.({ keyMaterial: decryption?.keyMaterial ?? {}, decryptOutput })}
      allowMapsFile={!isDirectory}
      mapsPath={mapsPath}
      onMapsPathChange={(next) => setMaps(next ? { input: inputPath, mapsPath: next } : null)}
    />
  );
}
