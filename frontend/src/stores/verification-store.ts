import { create } from "zustand";
import type { VerifyKeyResult } from "@/api/types";

interface VerificationState {
  ciphertextHex: string;
  ivHex: string;
  nonceHex: string;
  aadHex: string;
  tagHex: string;
  cipher: string;
  isVerifying: boolean;
  result: VerifyKeyResult | null;
  error: string | null;

  setCiphertextHex: (value: string) => void;
  setIvHex: (value: string) => void;
  setNonceHex: (value: string) => void;
  setAadHex: (value: string) => void;
  setTagHex: (value: string) => void;
  setCipher: (value: string) => void;
  startVerify: () => void;
  setResult: (result: VerifyKeyResult) => void;
  setError: (error: string) => void;
  reset: () => void;
}

export const useVerificationStore = create<VerificationState>((set) => ({
  ciphertextHex: "",
  ivHex: "",
  nonceHex: "",
  aadHex: "",
  tagHex: "",
  cipher: "AES-256-CBC",
  isVerifying: false,
  result: null,
  error: null,

  setCiphertextHex: (value) => set({ ciphertextHex: value }),
  setIvHex: (value) => set({ ivHex: value }),
  setNonceHex: (value) => set({ nonceHex: value }),
  setAadHex: (value) => set({ aadHex: value }),
  setTagHex: (value) => set({ tagHex: value }),
  setCipher: (value) => set({ cipher: value }),
  startVerify: () => set({ isVerifying: true, result: null, error: null }),
  setResult: (result) => set({ isVerifying: false, result }),
  setError: (error) => set({ isVerifying: false, error }),
  reset: () =>
    set({
      ciphertextHex: "",
      ivHex: "",
      nonceHex: "",
      aadHex: "",
      tagHex: "",
      cipher: "AES-256-CBC",
      isVerifying: false,
      result: null,
      error: null,
    }),
}));
