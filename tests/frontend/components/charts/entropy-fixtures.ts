import type { EntropyData } from "@/api/types";

/** A full-resolution window-32 response with one single-window spike (bucket 2). */
export const ENVELOPE_DATA: EntropyData = {
  overall_entropy: 3.1,
  high_entropy_regions: [
    { start: 64, end: 96, mean_entropy: 4.8, byte_end: 128 },
    { start: 160, end: 192, mean_entropy: 4.6, byte_end: 224 },
  ],
  profile_sample: [{ offset: 0, entropy: 2 }, { offset: 128, entropy: 3 }],
  stats: { min: 1, max: 4.97, mean: 3 },
  step: 1,
  window: 32,
  view: "raw",
  resolution: "full",
  full_resolution_available: false,
  envelope: {
    starts: [0, 64, 128, 192],
    stops: [64, 128, 192, 256],
    min: [1, 2, 2.5, 1.5],
    max: [3, 4, 4.97, 3.5],
    mean: [2, 3, 3.2, 2.5],
  },
  threshold: 4.5,
  threshold_source: "default",
  max_entropy: 5,
  threshold_reachable: true,
  warnings: [],
  region_count: 2,
  regions_truncated: false,
  min_region_bytes: 32,
};

/** A legacy response: no envelope, no threshold metadata. */
export const LEGACY_DATA: EntropyData = {
  overall_entropy: 3,
  high_entropy_regions: [{ start: 64, end: 128, mean_entropy: 7.6 }],
  profile_sample: [
    { offset: 0, entropy: 2 },
    { offset: 64, entropy: 7.7 },
    { offset: 128, entropy: 3 },
  ],
  stats: { min: 2, max: 7.7, mean: 4 },
  step: 64,
};
