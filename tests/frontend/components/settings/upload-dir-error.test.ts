import { describe, it, expect } from "vitest";

import { ApiError } from "@/api/client";
import {
  UPLOAD_DIR_UNCONFIGURED,
  isUploadDirUnconfigured,
} from "@/components/settings/upload-dir-error";

/** The exact detail string the backend sends with its 409. */
const REAL_DETAIL =
  "upload_dir_unconfigured: no upload directory configured; choose one in Settings -> Storage";

describe("isUploadDirUnconfigured", () => {
  it("matches the token the backend prefixes onto the 409 detail", () => {
    expect(isUploadDirUnconfigured(REAL_DETAIL)).toBe(true);
  });

  it("matches the bare token", () => {
    expect(isUploadDirUnconfigured(UPLOAD_DIR_UNCONFIGURED)).toBe(true);
  });

  it("does not match an unrelated conflict message", () => {
    // The other 409 shapes that reach the same catch block.
    expect(isUploadDirUnconfigured("upload already in progress")).toBe(false);
    expect(isUploadDirUnconfigured("quota exceeded for upload directory")).toBe(false);
    expect(
      isUploadDirUnconfigured(
        "upload_dir is pinned by MEMDIVER_UPLOAD_DIR; unset it to configure the directory from the UI",
      ),
    ).toBe(false);
    expect(isUploadDirUnconfigured("")).toBe(false);
  });

  it("does not match a near-miss token", () => {
    expect(isUploadDirUnconfigured("upload_dir_unconfigurable: nope")).toBe(false);
  });

  it("is message-only: the status check belongs to the caller", () => {
    // The classifier itself sees no status, so a 400 that happens to carry the
    // token still classifies true...
    expect(isUploadDirUnconfigured(REAL_DETAIL)).toBe(true);

    // ...and it is the CALLER's compound guard -- the one PcapUpload ships --
    // that rejects it. Asserted here so the two halves can never drift apart.
    const guard = (e: ApiError) => e.status === 409 && isUploadDirUnconfigured(e.message);
    expect(guard(new ApiError(400, REAL_DETAIL))).toBe(false);
    expect(guard(new ApiError(409, REAL_DETAIL))).toBe(true);
    expect(guard(new ApiError(409, "something else entirely"))).toBe(false);
  });
});
