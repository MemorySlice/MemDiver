/**
 * Memory-image panel state: which full image the user is working on, the
 * optional case directory / ISF, and the kernel view the process table reads.
 * `wizardImageMode` is the wizard's "Memory image" choice.
 */
import { create } from "zustand";

import type { ImageProbe } from "@/api/image";

interface ImageState {
  imagePath: string;
  isfPath: string;
  caseDir: string;
  kernelViewPath: string;
  wizardImageMode: boolean;
  /** Last probe per image path, so a reopened tab keeps its scanned banners. */
  probes: Record<string, ImageProbe>;
  /** Whether each opened `.mdview` carries a kernel profile (from its descriptor). */
  viewHasProfile: Record<string, boolean>;
  setViewHasProfile: (viewPath: string, has: boolean) => void;
  setImagePath: (path: string) => void;
  setIsfPath: (path: string) => void;
  setCaseDir: (dir: string) => void;
  setKernelViewPath: (path: string) => void;
  setWizardImageMode: (on: boolean) => void;
  setProbe: (path: string, probe: ImageProbe | null) => void;
  reset: () => void;
}

const INITIAL = {
  imagePath: "",
  isfPath: "",
  caseDir: "",
  kernelViewPath: "",
  wizardImageMode: false,
  probes: {} as Record<string, ImageProbe>,
  viewHasProfile: {} as Record<string, boolean>,
};

export const useImageStore = create<ImageState>((set) => ({
  ...INITIAL,
  setImagePath: (imagePath) => set({ imagePath, kernelViewPath: "" }),
  setIsfPath: (isfPath) => set({ isfPath }),
  setCaseDir: (caseDir) => set({ caseDir }),
  setKernelViewPath: (kernelViewPath) => set({ kernelViewPath }),
  setWizardImageMode: (wizardImageMode) => set({ wizardImageMode }),
  setViewHasProfile: (viewPath, has) =>
    set((state) => ({ viewHasProfile: { ...state.viewHasProfile, [viewPath]: has } })),
  setProbe: (path, probe) =>
    set((state) => {
      const { [path]: _dropped, ...rest } = state.probes;
      return { probes: probe ? { ...rest, [path]: probe } : rest };
    }),
  reset: () => set(INITIAL),
}));
