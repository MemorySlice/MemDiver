import { describe, it, expect } from "vitest";

import { artifactDownloadUrl } from "@/api/pipeline";

describe("artifactDownloadUrl", () => {
  it("builds the runs/artifacts path", () => {
    expect(artifactDownloadUrl("abc123", "keys.json")).toBe(
      "/api/pipeline/runs/abc123/artifacts/keys.json",
    );
  });

  it("percent-encodes both the task id and the artifact name", () => {
    expect(artifactDownloadUrl("a b/c", "my file.bin")).toBe(
      "/api/pipeline/runs/a%20b%2Fc/artifacts/my%20file.bin",
    );
  });
});
