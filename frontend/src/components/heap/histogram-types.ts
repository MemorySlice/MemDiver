import type { HeapSizeBucket } from "@/api/types";

export interface HeapSizeHistogramProps {
  buckets: HeapSizeBucket[];
}

/** Bucket label: an exact size when the bucket is one value wide. */
export function bucketLabel(b: HeapSizeBucket): string {
  return b.min_size === b.max_size ? String(b.min_size) : `${b.min_size}–${b.max_size}`;
}
