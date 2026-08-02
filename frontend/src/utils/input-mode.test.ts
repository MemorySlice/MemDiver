import { describe, it, expect } from "vitest";

import { uiToApiInputMode, apiToUiInputMode } from "./input-mode";

describe("uiToApiInputMode", () => {
  it("maps each UI mode to its API counterpart", () => {
    expect(uiToApiInputMode("file")).toBe("single_file");
    expect(uiToApiInputMode("directory")).toBe("run_directory");
    expect(uiToApiInputMode("dataset")).toBe("dataset");
  });
});

describe("apiToUiInputMode", () => {
  it("maps each API mode to its UI counterpart", () => {
    expect(apiToUiInputMode("single_file")).toBe("file");
    expect(apiToUiInputMode("run_directory")).toBe("directory");
    expect(apiToUiInputMode("dataset")).toBe("dataset");
  });

  it("falls back to 'dataset' for unknown API values", () => {
    expect(apiToUiInputMode("")).toBe("dataset");
    expect(apiToUiInputMode("bogus")).toBe("dataset");
    expect(apiToUiInputMode("single_file ")).toBe("dataset");
  });

  it("round-trips every UI mode through the API representation", () => {
    for (const mode of ["file", "directory", "dataset"] as const) {
      expect(apiToUiInputMode(uiToApiInputMode(mode))).toBe(mode);
    }
  });
});
