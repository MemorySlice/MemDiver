import { describe, expect, it } from "vitest";

import {
  RECOVERY_SESSION_NAME,
  isRecoverySession,
  suggestSessionName,
} from "@/utils/session-names";

const AT = new Date(2026, 8, 14, 9, 5); // 2026-09-14 09:05 local

describe("RECOVERY_SESSION_NAME", () => {
  it("is a bare filename", () => {
    // The server resolves a session name through `safe_filename`, which rejects
    // anything addressing a subdirectory or escaping the session directory.
    expect(RECOVERY_SESSION_NAME).not.toMatch(/[/\\]/);
    expect(RECOVERY_SESSION_NAME).not.toBe(".");
    expect(RECOVERY_SESSION_NAME).not.toBe("..");
  });

  it("recognises only itself", () => {
    expect(isRecoverySession(RECOVERY_SESSION_NAME)).toBe(true);
    expect(isRecoverySession("recovery")).toBe(false);
    expect(isRecoverySession("")).toBe(false);
  });
});

describe("suggestSessionName", () => {
  it("names the session after the dump the user was looking at", () => {
    expect(suggestSessionName("/dumps/openssl/pre_key.msl", AT)).toBe(
      "pre_key.msl-2026-09-14-0905",
    );
  });

  it("zero-pads so names sort chronologically as text", () => {
    expect(suggestSessionName("/d/a.msl", new Date(2026, 0, 2, 3, 4))).toBe(
      "a.msl-2026-01-02-0304",
    );
  });

  it("tolerates a trailing slash on a dataset root", () => {
    expect(suggestSessionName("/data/tls_dumps/", AT)).toBe("tls_dumps-2026-09-14-0905");
  });

  it("folds characters safe_filename would reject", () => {
    const name = suggestSessionName("/dumps/we ird:name?.msl", AT);

    expect(name).toMatch(/^[A-Za-z0-9._-]+$/);
    expect(name).toContain("2026-09-14-0905");
  });

  it("still produces a usable name when there is nothing to name it after", () => {
    expect(suggestSessionName("", AT)).toBe("session-2026-09-14-0905");
  });

  it("never collides with the reserved recovery name", () => {
    for (const subject of ["", "/", "__recovery__", "///"]) {
      expect(suggestSessionName(subject, AT)).not.toBe(RECOVERY_SESSION_NAME);
    }
  });
});
