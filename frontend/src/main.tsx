import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "@/styles/globals.css";
import "@/styles/hex.css";
import App from "./App";
import { usePipelineStore } from "@/stores/pipeline-store";
import { useConsensusStore } from "@/stores/consensus-store";

// Dev-only store hooks for Playwright / browser-console experiments.
// Gated on import.meta.env.DEV so these globals never leak into a
// production bundle. Enables fixture-driven tests by allowing
// `page.evaluate` to call e.g. `window.__useConsensusStore.setState(...)`
// without spinning up a real backend run of `consensus` or the pipeline.
if (import.meta.env.DEV) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (window as any).__usePipelineStore = usePipelineStore;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (window as any).__useConsensusStore = useConsensusStore;
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>
);
