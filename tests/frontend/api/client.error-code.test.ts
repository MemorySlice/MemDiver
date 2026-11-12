/**
 * `apiErrorCode`: the machine-readable `code` of a failed request.
 *
 * A path denial answers `{detail, error, code: "path.outside_sandbox", category}`,
 * a FastAPI `detail` may be a `{code, message}` object, and everything else (a
 * network error, a proxy page, a 422 list) has no code. It must never throw.
 */

import { describe, expect, it } from "vitest";

import { ApiError, apiErrorCode } from "@/api/client";

const DENIAL = JSON.stringify({
  detail: "read path '/x' is outside the read sandbox",
  error: "read path '/x' is outside the read sandbox",
  code: "path.outside_sandbox",
  category: "PRECONDITION",
});

describe("apiErrorCode", () => {
  it("reads the top-level code of the CapabilityError envelope", () => {
    expect(apiErrorCode(new ApiError(403, DENIAL))).toBe("path.outside_sandbox");
  });

  it("reads detail.code when detail is an object", () => {
    const body = JSON.stringify({ detail: { code: "agent.no_key", message: "no key" } });
    expect(apiErrorCode(new ApiError(400, body))).toBe("agent.no_key");
  });

  it("prefers the top-level code over detail.code", () => {
    const body = JSON.stringify({ code: "top.level", detail: { code: "nested.one" } });
    expect(apiErrorCode(new ApiError(400, body))).toBe("top.level");
  });

  it("has no code for a plain-string detail, a 422 list or a body without one", () => {
    expect(apiErrorCode(new ApiError(404, JSON.stringify({ detail: "No consensus computed yet" })))).toBeUndefined();
    expect(apiErrorCode(new ApiError(422, JSON.stringify({ detail: [{ type: "missing", loc: ["body", "x"] }] })))).toBeUndefined();
    expect(apiErrorCode(new ApiError(400, JSON.stringify({ error: "boom" })))).toBeUndefined();
  });

  it("ignores a code that is not a non-empty string", () => {
    expect(apiErrorCode(new ApiError(400, JSON.stringify({ code: 403 })))).toBeUndefined();
    expect(apiErrorCode(new ApiError(400, JSON.stringify({ code: "" })))).toBeUndefined();
    expect(apiErrorCode(new ApiError(400, JSON.stringify({ code: null, detail: null })))).toBeUndefined();
  });

  it("never throws on a non-JSON or non-object body", () => {
    expect(apiErrorCode(new ApiError(502, "<html>Bad Gateway</html>"))).toBeUndefined();
    expect(apiErrorCode(new ApiError(500, ""))).toBeUndefined();
    expect(apiErrorCode(new ApiError(500, "null"))).toBeUndefined();
    expect(apiErrorCode(new ApiError(500, "42"))).toBeUndefined();
    expect(apiErrorCode(new ApiError(500, '"path.outside_sandbox"'))).toBeUndefined();
  });

  it("has no code for anything that is not an ApiError", () => {
    expect(apiErrorCode(new Error(DENIAL))).toBeUndefined();
    expect(apiErrorCode(DENIAL)).toBeUndefined();
    expect(apiErrorCode(undefined)).toBeUndefined();
    expect(apiErrorCode(null)).toBeUndefined();
    expect(apiErrorCode({ body: DENIAL })).toBeUndefined();
  });
});
