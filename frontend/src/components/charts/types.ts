/**
 * Shared prop types for the backend-switchable chart components.
 *
 * Each chart has two implementations (Plotly and SVG) behind a dispatcher
 * that reads `settings.display.chartBackend`. Both implementations accept
 * the same props; these interfaces are the source of truth.
 */
import type { EntropyData } from "@/api/types";

export type ChartBackend = "plotly" | "svg";

export interface EntropyChartProps {
  data: EntropyData;
  threshold?: number;
  title?: string;
}

export interface VarianceMapProps {
  variance: number[];
  classifications?: number[];
  step?: number;
  title?: string;
}

export interface VasEntry {
  base_addr: number;
  region_size: number;
  region_type: number;
  protection: number;
  mapped_path?: string;
}

export interface VasChartProps {
  entries: VasEntry[];
  title?: string;
}
