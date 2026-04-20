/**
 * Client-side port of PatternGenerator.infer_fields() — segments a
 * neighborhood variance array into contiguous static / dynamic / key_material
 * fields.
 */

export interface InferredField {
  offset: number;
  length: number;
  type: "static" | "key_material" | "dynamic";
  label: string;
  mean_variance: number;
}

/** Default variance threshold matching PLUGIN_STATIC_THRESHOLD on the backend. */
export const DEFAULT_VARIANCE_THRESHOLD = 2000.0;

export function inferNeighborhoodFields(
  variance: number[],
  keyOffset: number,
  keyLength: number,
  threshold: number = DEFAULT_VARIANCE_THRESHOLD,
): InferredField[] {
  if (variance.length === 0) return [];

  const n = variance.length;
  const keyEnd = keyOffset + keyLength;

  // Assign per-byte role: key region overrides variance classification.
  const roles: string[] = [];
  for (let i = 0; i < n; i++) {
    if (i >= keyOffset && i < keyEnd) {
      roles.push("key_material");
    } else if (variance[i] <= threshold) {
      roles.push("static");
    } else {
      roles.push("dynamic");
    }
  }

  // Merge contiguous runs of the same role into fields.
  const fields: InferredField[] = [];
  let runStart = 0;
  for (let i = 1; i < n; i++) {
    if (roles[i] !== roles[runStart]) {
      fields.push(makeField(variance, runStart, i, roles[runStart], fields));
      runStart = i;
    }
  }
  fields.push(makeField(variance, runStart, n, roles[runStart], fields));
  return fields;
}

function makeField(
  variance: number[],
  start: number,
  end: number,
  role: string,
  existing: InferredField[],
): InferredField {
  const length = end - start;
  let sum = 0;
  for (let i = start; i < end; i++) sum += variance[i];
  const meanVar = sum / length;

  let label: string;
  if (role === "key_material") {
    label = "key";
  } else {
    const seq = existing.filter((f) => f.type === role).length;
    label = `${role}_${seq}`;
  }

  return {
    offset: start,
    length,
    type: role as InferredField["type"],
    label,
    mean_variance: Math.round(meanVar * 100) / 100,
  };
}
