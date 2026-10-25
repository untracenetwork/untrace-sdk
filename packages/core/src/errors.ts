/**
 * Typed errors. Every error the SDK throws for an API answer or a local
 * refusal is an `UntraceError`. Codes follow the contract's error bodies:
 * `{ "error": "<code>", "message": "<text>" }`, and for the token endpoint the
 * OAuth form `{ "error": "<code>", "error_description": "<text>" }`.
 */

export type UntraceErrorCode =
  | "invalid_request"
  | "invalid_client"
  | "invalid_scope"
  | "unsupported_grant_type"
  | "token_expired"
  | "payment_required"
  | "insufficient_scope"
  | "insufficient_role"
  | "folder_access_required"
  | "not_found"
  | "conflict"
  | "owner_immutable"
  | "unsupported_format"
  | "payload_too_large"
  | "rate_limited"
  | "unavailable"
  | "server_error"
  | "planned"
  | "integrity"
  | "network"
  | "timeout"
  | "aborted"
  | (string & {})

export interface UntraceErrorInit {
  status: number
  code: UntraceErrorCode
  message: string
  body?: Record<string, unknown>
}

const SECRET_PATTERNS: RegExp[] = [
  /untrace_sk_v1_[A-Za-z0-9_\-+/=]*/g,
  /(bearer\s+)[A-Za-z0-9._\-+/=]+/gi,
  /(basic\s+)[A-Za-z0-9+/=]+/gi,
  /("?(?:accessToken|access_token|token|client_secret|clientSecret|sealedKey|wrappedKey)"?\s*[:=]\s*"?)[A-Za-z0-9._\-+/=%]{8,}/gi,
]

/** Remove client secrets, OAuth values, tokens and sealed keys from a string before it is shown or logged. */
export function redactSecrets(text: string): string {
  let out = text
  out = out.replace(SECRET_PATTERNS[0]!, "untrace_sk_v1_[redacted]")
  out = out.replace(SECRET_PATTERNS[1]!, "$1[redacted]")
  out = out.replace(SECRET_PATTERNS[2]!, "$1[redacted]")
  out = out.replace(SECRET_PATTERNS[3]!, "$1[redacted]")
  return out
}

function redactBody(body: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(body)) {
    if (/token|secret|sealedkey|wrappedkey/i.test(k)) out[k] = "[redacted]"
    else out[k] = typeof v === "string" ? redactSecrets(v) : v
  }
  return out
}

export class UntraceError extends Error {
  readonly status: number
  readonly code: UntraceErrorCode
  readonly body: Record<string, unknown>
  /** True when the same call may succeed later (503, 429, network, timeout). */
  readonly retryable: boolean

  constructor(init: UntraceErrorInit, retryable = false) {
    super(redactSecrets(init.message))
    this.name = "UntraceError"
    this.status = init.status
    this.code = init.code
    this.body = redactBody(init.body ?? {})
    this.retryable = retryable
  }
}

/** 401 `invalid_client` (unknown, revoked or wrong credentials) or `token_expired`. */
export class UntraceAuthError extends UntraceError {
  constructor(init: UntraceErrorInit) {
    super(init)
    this.name = "UntraceAuthError"
  }
}

/** 403 `insufficient_scope` or 400 `invalid_scope`. `required` names the missing scope when Drive says it. */
export class UntraceScopeError extends UntraceError {
  readonly required: string | null
  constructor(init: UntraceErrorInit) {
    super(init)
    this.name = "UntraceScopeError"
    this.required = typeof init.body?.required === "string" ? init.body.required : null
  }
}

/** 403 `insufficient_role`: the key's role on this file does not allow it. */
export class UntraceRoleError extends UntraceError {
  constructor(init: UntraceErrorInit) {
    super(init)
    this.name = "UntraceRoleError"
  }
}

/**
 * 403 `folder_access_required`: a key uploads only into a folder it has been
 * added to (role editor or above, scope `upload`). Also the answer for a
 * folder that does not exist.
 */
export class UntraceFolderAccessError extends UntraceError {
  constructor(init: UntraceErrorInit) {
    super(init)
    this.name = "UntraceFolderAccessError"
  }
}

/** 404 `not_found`. A file that does not exist and one your key cannot reach answer the same way. */
export class UntraceNotFoundError extends UntraceError {
  constructor(init: UntraceErrorInit) {
    super(init)
    this.name = "UntraceNotFoundError"
  }
}

/** 402 `payment_required`: the owner's plan does not allow this. `planCode` says why. */
export class UntracePaymentRequiredError extends UntraceError {
  readonly planCode: string | null
  constructor(init: UntraceErrorInit) {
    super(init)
    this.name = "UntracePaymentRequiredError"
    this.planCode = typeof init.body?.code === "string" ? init.body.code : null
  }
}

/** 409 `conflict`, `owner_immutable` or `unsupported_format`. */
export class UntraceConflictError extends UntraceError {
  constructor(init: UntraceErrorInit) {
    super(init)
    this.name = "UntraceConflictError"
  }
}

/** 413 `payload_too_large`, or refused locally before sending. */
export class UntraceTooLargeError extends UntraceError {
  constructor(init: UntraceErrorInit) {
    super(init)
    this.name = "UntraceTooLargeError"
  }
}

/** 429 `rate_limited`. `retryAfterSeconds` comes from Retry-After. */
export class UntraceRateLimitError extends UntraceError {
  readonly retryAfterSeconds: number | null
  constructor(init: UntraceErrorInit & { retryAfterSeconds?: number | null }) {
    super(init, true)
    this.name = "UntraceRateLimitError"
    this.retryAfterSeconds = init.retryAfterSeconds ?? null
  }
}

/** 503 `unavailable` or a network failure. Retry with backoff. Never a denial. */
export class UntraceUnavailableError extends UntraceError {
  constructor(init: UntraceErrorInit) {
    super(init, true)
    this.name = "UntraceUnavailableError"
  }
}

/** No answer within `timeoutMs`. Retryable. */
export class UntraceTimeoutError extends UntraceUnavailableError {
  constructor(message: string) {
    super({ status: 0, code: "timeout", message })
    this.name = "UntraceTimeoutError"
  }
}

/** The caller's AbortSignal fired. Never retried. */
export class UntraceAbortError extends UntraceError {
  constructor(message = "untrace: the request was aborted") {
    super({ status: 0, code: "aborted", message })
    this.name = "UntraceAbortError"
  }
}

/** Any other 5xx. Not retried. */
export class UntraceServerError extends UntraceError {
  constructor(init: UntraceErrorInit) {
    super(init)
    this.name = "UntraceServerError"
  }
}

/** A sealed key, a signature or a UTE1 body failed a local check. Nothing was trusted. */
export class UntraceIntegrityError extends UntraceError {
  constructor(message: string) {
    super({ status: 0, code: "integrity", message })
    this.name = "UntraceIntegrityError"
  }
}

/**
 * The operation is `planned` in the contract and this Drive does not serve it
 * yet (it answered 404). Not retryable: upgrade the SDK once Drive ships it.
 */
export class UntracePlannedError extends UntraceError {
  readonly operationId: string
  constructor(operationId: string) {
    super({ status: 404, code: "planned", message: `untrace: ${operationId} is planned and not available on this Drive yet` })
    this.name = "UntracePlannedError"
    this.operationId = operationId
  }
}

export function errorFromResponse(status: number, body: Record<string, unknown>, retryAfter: string | null): UntraceError {
  const code = (typeof body.error === "string" ? body.error : null) ?? fallbackCode(status)
  const text = typeof body.message === "string" ? body.message : typeof body.error_description === "string" ? body.error_description : null
  const message = text ?? `untrace: HTTP ${status} ${code}`
  const init: UntraceErrorInit = { status, code, message, body }
  switch (code) {
    case "invalid_client":
    case "token_expired":
      return new UntraceAuthError(init)
    case "insufficient_scope":
    case "invalid_scope":
      return new UntraceScopeError(init)
    case "insufficient_role":
      return new UntraceRoleError(init)
    case "folder_access_required":
      return new UntraceFolderAccessError(init)
    case "not_found":
      return new UntraceNotFoundError(init)
    case "payment_required":
      // Drive answers 503 with payment_required when billing cannot be checked: retryable.
      return status === 503 ? new UntraceUnavailableError(init) : new UntracePaymentRequiredError(init)
    case "conflict":
    case "owner_immutable":
    case "unsupported_format":
      return new UntraceConflictError(init)
    case "payload_too_large":
      return new UntraceTooLargeError(init)
    case "rate_limited": {
      const n = retryAfter == null ? NaN : Number(retryAfter)
      return new UntraceRateLimitError({ ...init, retryAfterSeconds: Number.isFinite(n) ? n : null })
    }
    case "unavailable":
      return new UntraceUnavailableError(init)
    default:
      if (status === 503) return new UntraceUnavailableError(init)
      if (status >= 500) return new UntraceServerError(init)
      return new UntraceError(init)
  }
}

function fallbackCode(status: number): UntraceErrorCode {
  if (status === 400) return "invalid_request"
  if (status === 401) return "invalid_client"
  if (status === 402) return "payment_required"
  if (status === 403) return "insufficient_role"
  if (status === 404) return "not_found"
  if (status === 409) return "conflict"
  if (status === 413) return "payload_too_large"
  if (status === 429) return "rate_limited"
  if (status === 503) return "unavailable"
  return "server_error"
}
