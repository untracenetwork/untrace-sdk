import { describe, expect, it } from "vitest"

import {
  errorFromResponse,
  redactSecrets,
  UntraceAbortError,
  UntraceAuthError,
  UntraceConflictError,
  UntraceError,
  UntraceIntegrityError,
  UntraceNotFoundError,
  UntracePaymentRequiredError,
  UntracePlannedError,
  UntraceRateLimitError,
  UntraceRoleError,
  UntraceScopeError,
  UntraceServerError,
  UntraceTimeoutError,
  UntraceTooLargeError,
  UntraceUnavailableError,
} from "../src/errors"

describe("errorFromResponse maps every contract code", () => {
  it.each([
    [401, { error: "invalid_client" }, UntraceAuthError, false],
    [401, { error: "token_expired" }, UntraceAuthError, false],
    [403, { error: "insufficient_scope", required: "upload" }, UntraceScopeError, false],
    [400, { error: "invalid_scope" }, UntraceScopeError, false],
    [403, { error: "insufficient_role" }, UntraceRoleError, false],
    [404, { error: "not_found" }, UntraceNotFoundError, false],
    [402, { error: "payment_required", code: "no_subscription" }, UntracePaymentRequiredError, false],
    [503, { error: "payment_required" }, UntraceUnavailableError, true],
    [409, { error: "conflict" }, UntraceConflictError, false],
    [409, { error: "owner_immutable" }, UntraceConflictError, false],
    [409, { error: "unsupported_format" }, UntraceConflictError, false],
    [413, { error: "payload_too_large" }, UntraceTooLargeError, false],
    [429, { error: "rate_limited" }, UntraceRateLimitError, true],
    [503, { error: "unavailable" }, UntraceUnavailableError, true],
    [503, {}, UntraceUnavailableError, true],
    [500, {}, UntraceServerError, false],
    [502, { error: "weird" }, UntraceServerError, false],
    [400, {}, UntraceError, false],
  ])("%i %j", (status, body, cls, retryable) => {
    const e = errorFromResponse(status, body as Record<string, unknown>, null)
    expect(e).toBeInstanceOf(cls)
    expect(e.status).toBe(status)
    expect(e.retryable).toBe(retryable)
  })

  it.each([
    [400, "invalid_request"],
    [401, "invalid_client"],
    [402, "payment_required"],
    [403, "insufficient_role"],
    [404, "not_found"],
    [409, "conflict"],
    [413, "payload_too_large"],
    [429, "rate_limited"],
    [503, "unavailable"],
    [500, "server_error"],
  ])("falls back to a code for a bare %i", (status, code) => {
    expect(errorFromResponse(status, {}, null).code).toBe(code)
  })

  it("reads message, OAuth error_description, required, plan code and Retry-After", () => {
    expect(errorFromResponse(401, { error: "invalid_client", error_description: "nope" }, null).message).toBe("nope")
    expect((errorFromResponse(403, { error: "insufficient_scope", required: "upload" }, null) as UntraceScopeError).required).toBe("upload")
    expect((errorFromResponse(402, { error: "payment_required", code: "quota_exceeded" }, null) as UntracePaymentRequiredError).planCode).toBe("quota_exceeded")
    expect((errorFromResponse(429, { error: "rate_limited" }, "7") as UntraceRateLimitError).retryAfterSeconds).toBe(7)
    expect((errorFromResponse(429, { error: "rate_limited" }, "soon") as UntraceRateLimitError).retryAfterSeconds).toBeNull()
  })
})

describe("redaction", () => {
  it.each([
    ["untrace_sk_v1_AAAAAAAAAAAAAAAAAAAAAAAA leaked", "untrace_sk_v1_[redacted]"],
    ["Authorization: Bearer abc.def.ghi", "Bearer [redacted]"],
    ["Basic dXNlcjpwYXNz", "Basic [redacted]"],
    ['{"access_token":"abcdefghijkl"}', "[redacted]"],
    ["client_secret=WKQRlxMXONoje8EKnsUlmRVYZPCChszN0DyBKhj52gk", "[redacted]"],
  ])("%s", (input, expected) => {
    const out = redactSecrets(input)
    expect(out).toContain(expected)
    expect(out).not.toMatch(/AAAAAAAAAAAA|abc\.def|dXNlcjpwYXNz|abcdefghijkl|WKQRlx/)
  })

  it("redacts error messages and secret-looking body fields", () => {
    const e = new UntraceError({ status: 400, code: "x", message: "bad untrace_sk_v1_abcdefabcdef", body: { token: "t", wrappedKey: "k", note: "Bearer zzzz" } })
    expect(e.message).not.toContain("abcdef")
    expect(e.body).toEqual({ token: "[redacted]", wrappedKey: "[redacted]", note: "Bearer [redacted]" })
  })
})

describe("local errors", () => {
  it("have stable codes", () => {
    expect(new UntraceTimeoutError("t").code).toBe("timeout")
    expect(new UntraceTimeoutError("t").retryable).toBe(true)
    expect(new UntraceAbortError().code).toBe("aborted")
    expect(new UntraceAbortError().retryable).toBe(false)
    expect(new UntraceIntegrityError("i").code).toBe("integrity")
    const p = new UntracePlannedError("listFolders")
    expect(p).toMatchObject({ status: 404, code: "planned", operationId: "listFolders", retryable: false })
  })
})
