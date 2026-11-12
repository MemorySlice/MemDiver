/**
 * The backend's `VolSpec` and the UI's `execRequestFromVolCommand` must agree:
 * for every case of the golden file pytest generates from real specs
 * (`tests/test_vol_spec.py`), parsing its `display_command` gives exactly its
 * `exec_request`.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import type { Vol3ExecRequest } from "@/api/vol3";
import { execRequestFromVolCommand } from "@/components/vol3/synth-utils";

const GOLDEN: Record<string, { display_command: string; exec_request: Vol3ExecRequest }> = JSON.parse(
  readFileSync(
    resolve(dirname(fileURLToPath(import.meta.url)), "../../../fixtures/vol3_spec/exec_request_golden.json"),
    "utf-8",
  ),
);

describe("VolSpec golden cross-check", () => {
  it("has cases", () => {
    expect(Object.keys(GOLDEN).length).toBeGreaterThanOrEqual(5);
  });

  it.each(Object.entries(GOLDEN))("%s: display_command parses back into exec_request", (_name, golden) => {
    expect(execRequestFromVolCommand(golden.display_command, null)).toEqual(golden.exec_request);
  });
});
