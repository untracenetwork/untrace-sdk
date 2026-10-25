/**
 * UntraceClient: a thin, typed client for the Untrace Drive API v1.
 * Contract: contract/openapi.yaml (copied from untrace-drive, see contract/SOURCE.json).
 *
 * What runs on your machine, and nothing else:
 *   1. OAuth 2.0 client credentials. The `client_secret` sent to the token
 *      endpoint is DERIVED from your `untrace_sk_v1_` secret. The secret itself
 *      never leaves this process.
 *   2. One encryption step (UTE1, AES-256-GCM) before upload and after download.
 *      The file key is sealed to your key and to the owner's sharing key.
 *
 * Everything else (storage, redundancy, access checks, billing) is Drive's job.
 */

import type { components } from "./generated/openapi"
import { OPERATIONS, type OperationId } from "./generated/operations"
import {
  deriveClientKeys,
  deriveFolderBoxKeys,
  openKeyPath,
  openSealed,
  parseClientSecret,
  randomBytes,
  sealToPublicKey,
  verifyShareKey,
  type ClientKeys,
} from "./crypto"
import { fromBase64, toBase64 } from "./encoding"
import {
  errorFromResponse,
  redactSecrets,
  UntraceAbortError,
  UntraceAuthError,
  UntraceError,
  UntraceIntegrityError,
  UntracePlannedError,
  UntraceRateLimitError,
  UntraceTimeoutError,
  UntraceTooLargeError,
  UntraceUnavailableError,
} from "./errors"
import { decryptUte1, encryptUte1, newFileKey, UTE1_DEFAULT_CHUNK_BYTES, ute1SealedLength } from "./ute1"

export const DEFAULT_BASE_URL = "https://drive.untrace.network"
/** Largest UTE1 body Drive accepts in one upload (contract: 16 MiB). */
export const MAX_UPLOAD_BODY_BYTES = 16 * 1024 * 1024

export type Scope = components["schemas"]["Scope"]
export type FileSummary = components["schemas"]["File"]
export type FileWithKey = components["schemas"]["FileWithKey"]
export type OwnerShareKey = components["schemas"]["OwnerShareKey"]
export type TokenResponse = components["schemas"]["TokenResponse"]
export type Folder = components["schemas"]["Folder"]
export type KeyEntry = components["schemas"]["KeyEntry"]
/** `passkey` (an account's passkey) or `client` (a developer client credential). */
export type KeyType = components["schemas"]["KeyType"]
/** A role that can be granted or offered: admin, editor or viewer. */
export type GrantRole = components["schemas"]["Role"]
/** A key entry role: a grant, or `none` for an explicit block. */
export type EntryRole = GrantRole | "none"
export type Share = components["schemas"]["Share"]
export type ResourceType = "folder" | "file"
/** A folder or a file, for the key and sharing calls. */
export interface ResourceRef {
  type: ResourceType
  id: string
}

export const CLIENT_ID_RE = /^utc_[1-9A-HJ-NP-Za-km-z]{22}$/
export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
export const USERNAME_RE = /^[a-z0-9-]{6,32}$/
export const KEY_TYPES: readonly KeyType[] = ["passkey", "client"]
export const GRANT_ROLES: readonly GrantRole[] = ["admin", "editor", "viewer"]
export const ENTRY_ROLES: readonly EntryRole[] = ["admin", "editor", "viewer", "none"]
export const SCOPES: readonly Scope[] = ["download", "upload", "manage-sharing", "delete"]

export interface UntraceClientOptions {
  /** `utc_...`. Defaults to process.env.UNTRACE_CLIENT_ID. */
  clientId?: string
  /** `untrace_sk_v1_...`. Defaults to process.env.UNTRACE_CLIENT_SECRET. Server only. */
  clientSecret?: string
  /** Drive origin. Defaults to UNTRACE_BASE_URL or https://drive.untrace.network. */
  baseUrl?: string
  /** Ask for fewer scopes than the key holds (space separated, or an array). */
  scope?: string | readonly Scope[]
  fetch?: typeof fetch
  /** Per-request timeout in ms. Default 30000. */
  timeoutMs?: number
  /** Extra attempts after 503, 429 or a network error. Never after another 4xx. Default 2. */
  maxRetries?: number
  /** First backoff delay in ms, doubled per attempt with jitter, capped at 10 s. Default 250. */
  retryBaseMs?: number
  /** Allow running in a browser. Never do this with a real secret. Default false. */
  dangerouslyAllowBrowser?: boolean
}

/** Per-call options. */
export interface CallOptions {
  signal?: AbortSignal
  timeoutMs?: number
}

export interface TokenInfo {
  accessToken: string
  expiresAt: number
  scopes: string[]
}

/** Billing headers on an upload. */
export interface Metering {
  billedTo: string | null
  meteredBytes: number | null
  usageBytes: number | null
  /** `-1` means unlimited. */
  quotaBytes: number | null
}

export interface UploadInput {
  data: Uint8Array | ArrayBuffer | Blob
  name: string
  /**
   * REQUIRED. The folder to put the file in. Your key must have been added to
   * it (role editor or above, scope `upload`); Drive answers 403
   * `folder_access_required` otherwise. Create one with `client.folders.create`.
   */
  folderId: string
  /** Media type of the plaintext. Default application/octet-stream. */
  mime?: string
  /** UTE1 chunk size in plaintext bytes. Default 1 MiB. */
  chunkBytes?: number
}

export interface UploadResult {
  file: FileSummary
  metering: Metering
}

export interface DownloadResult {
  bytes: Uint8Array
  name: string
  mime: string
}

export interface FileList {
  files: FileSummary[]
  nextCursor: string | null
}

export interface FolderList {
  folders: Folder[]
  nextCursor: string | null
}

export interface ListOptions extends CallOptions {
  cursor?: string | null
  /** 1 to 200. */
  limit?: number
}

const TOKEN_SKEW_MS = 30_000
const MAX_BACKOFF_MS = 10_000
const MAX_RETRY_AFTER_MS = 30_000

/** Only 503, 429 and network or timeout failures are retried. Never another 4xx, never an abort. */
export function isRetryable(err: unknown): boolean {
  if (err instanceof UntraceAbortError) return false
  return err instanceof UntraceError && err.retryable
}

/** Exponential backoff with full jitter; honours Retry-After on 429. */
export function backoffDelay(attempt: number, baseMs: number, err?: unknown): number {
  if (err instanceof UntraceRateLimitError && err.retryAfterSeconds != null && err.retryAfterSeconds >= 0) {
    return Math.min(err.retryAfterSeconds * 1000, MAX_RETRY_AFTER_MS)
  }
  const cap = Math.min(baseMs * 2 ** attempt, MAX_BACKOFF_MS)
  return Math.round(cap / 2 + Math.random() * (cap / 2))
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new UntraceAbortError())
    const onAbort = () => {
      clearTimeout(t)
      reject(new UntraceAbortError())
    }
    const t = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort)
      resolve()
    }, ms)
    signal?.addEventListener("abort", onAbort, { once: true })
  })
}

/** Let one caller stop waiting on a shared promise (the token request) without cancelling it for others. */
function withSignal<T>(p: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return p
  if (signal.aborted) return Promise.reject(new UntraceAbortError())
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(new UntraceAbortError())
    signal.addEventListener("abort", onAbort, { once: true })
    p.then(resolve, reject).finally(() => signal.removeEventListener("abort", onAbort))
  })
}

function invalid(message: string): UntraceError {
  return new UntraceError({ status: 0, code: "invalid_request", message })
}

function env(name: string): string | undefined {
  const p = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process
  return p?.env?.[name]
}

function positiveOr(v: number | undefined, d: number): number {
  return typeof v === "number" && Number.isFinite(v) && v > 0 ? v : d
}

function hostOf(url: string): string {
  try {
    return new URL(url).host
  } catch {
    return "the server"
  }
}

function num(h: Headers, name: string): number | null {
  const v = h.get(name)
  if (v == null || v === "") return null
  const n = Number(v)
  return Number.isFinite(n) ? n : null
}

export function parseMetering(h: Headers): Metering {
  return {
    billedTo: h.get("x-untrace-billed-to"),
    meteredBytes: num(h, "x-untrace-metered-bytes"),
    usageBytes: num(h, "x-untrace-usage-bytes"),
    quotaBytes: num(h, "x-untrace-quota-bytes"),
  }
}

export function assertUuid(value: unknown, what: string): asserts value is string {
  if (typeof value !== "string" || !UUID_RE.test(value)) {
    throw new UntraceError({ status: 400, code: "invalid_request", message: `untrace: ${what} must be a UUID` })
  }
}

export function assertFileId(fileId: string): void {
  assertUuid(fileId, "fileId")
}

function assertListOptions(opts: ListOptions): void {
  if (opts.limit !== undefined && (!Number.isInteger(opts.limit) || opts.limit < 1 || opts.limit > 200)) {
    throw new UntraceError({ status: 400, code: "invalid_request", message: "untrace: limit must be an integer from 1 to 200" })
  }
  if (opts.cursor != null && !UUID_RE.test(String(opts.cursor))) {
    throw new UntraceError({ status: 400, code: "invalid_request", message: "untrace: cursor must be the nextCursor of a previous page" })
  }
}

function assertResource(r: ResourceRef): void {
  if (!r || (r.type !== "folder" && r.type !== "file")) throw invalid('untrace: resource type must be "folder" or "file"')
  assertUuid(r.id, `${r.type}Id`)
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let d = 0
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!
  return d === 0
}

function publicKeyBytes(b64: string, what: string): Uint8Array {
  let pk: Uint8Array
  try {
    pk = fromBase64(b64)
  } catch {
    throw invalid(`untrace: ${what} is not base64`)
  }
  if (pk.length !== 32) throw invalid(`untrace: ${what} must be a 32-byte X25519 public key`)
  return pk
}

export function assertFileName(name: unknown): string {
  const clean = typeof name === "string" ? name.trim() : ""
  if (!clean || clean.length > 256) throw new UntraceError({ status: 400, code: "invalid_request", message: "untrace: the file name must be 1 to 256 characters" })
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(clean)) throw new UntraceError({ status: 400, code: "invalid_request", message: "untrace: the file name contains control characters" })
  return clean
}

async function toBytes(data: UploadInput["data"]): Promise<Uint8Array> {
  if (data instanceof Uint8Array) return data
  if (data instanceof ArrayBuffer) return new Uint8Array(data)
  if (data && typeof (data as Blob).arrayBuffer === "function") return new Uint8Array(await (data as Blob).arrayBuffer())
  throw invalid("untrace: upload data must be a Uint8Array, an ArrayBuffer or a Blob")
}

interface RequestOptions extends CallOptions {
  query?: Record<string, string | number | null | undefined>
  json?: unknown
  body?: Uint8Array
  headers?: Record<string, string>
  /** Default true. */
  auth?: boolean
  /** May a transport failure be retried? Default: every method but POST. */
  idempotent?: boolean
  /** For planned operations: a 404 becomes UntracePlannedError. */
  operationId?: OperationId
}

interface Answer {
  res: Response
  bytes: Uint8Array
}

class ExpiredToken extends Error {
  constructor(
    readonly accessToken: string,
    readonly original: UntraceError
  ) {
    super("token expired")
  }
}

export class UntraceClient {
  readonly clientId: string
  readonly baseUrl: string
  // ES private fields: never enumerable, never printed by console.log or util.inspect.
  readonly #secret: Uint8Array
  #keys: Promise<ClientKeys> | null = null
  #token: TokenInfo | null = null
  #pending: Promise<TokenInfo> | null = null
  #shareKey: Promise<Uint8Array> | null = null
  /** Folder public keys this client checked against a folder key it opened itself. */
  #folderBox = new Map<string, Uint8Array>()
  private readonly fetchImpl: typeof fetch
  private readonly scope: string | null
  private readonly timeoutMs: number
  private readonly maxRetries: number
  private readonly retryBaseMs: number

  readonly files: FilesApi
  readonly folders: FoldersApi
  readonly keys: KeysApi
  readonly shares: SharesApi

  constructor(opts: UntraceClientOptions = {}) {
    if (typeof window !== "undefined" && typeof document !== "undefined" && !opts.dangerouslyAllowBrowser) {
      throw invalid("untrace: UntraceClient holds a client secret and must run on a server. Use @untracenetwork/react or @untracenetwork/vue in the browser.")
    }
    const clientId = (opts.clientId ?? env("UNTRACE_CLIENT_ID") ?? "").trim()
    const secret = opts.clientSecret ?? env("UNTRACE_CLIENT_SECRET") ?? ""
    if (!CLIENT_ID_RE.test(clientId)) throw invalid("untrace: clientId must be utc_ followed by 22 base58 characters (set UNTRACE_CLIENT_ID)")
    if (!secret) throw invalid("untrace: clientSecret is missing (set UNTRACE_CLIENT_SECRET)")
    try {
      this.#secret = parseClientSecret(secret)
    } catch (e) {
      throw invalid(redactSecrets((e as Error).message))
    }
    const base = (opts.baseUrl ?? env("UNTRACE_BASE_URL") ?? DEFAULT_BASE_URL).replace(/\/+$/, "")
    let u: URL
    try {
      u = new URL(base)
    } catch {
      throw invalid("untrace: baseUrl is not a valid URL")
    }
    if (u.protocol !== "https:" && u.protocol !== "http:") throw invalid("untrace: baseUrl must be http or https")
    if (u.username || u.password) throw invalid("untrace: baseUrl must not contain credentials")
    this.clientId = clientId
    this.baseUrl = base
    this.scope = opts.scope == null ? null : Array.isArray(opts.scope) ? opts.scope.join(" ") : String(opts.scope)
    const f = opts.fetch ?? globalThis.fetch
    if (typeof f !== "function") throw invalid("untrace: no fetch available (Node 20+ is required)")
    this.fetchImpl = (input, init) => f(input, init)
    this.timeoutMs = positiveOr(opts.timeoutMs, 30_000)
    this.maxRetries = Number.isInteger(opts.maxRetries) && opts.maxRetries! >= 0 ? opts.maxRetries! : 2
    this.retryBaseMs = positiveOr(opts.retryBaseMs, 250)
    this.files = new FilesApi(this)
    this.folders = new FoldersApi(this)
    this.keys = new KeysApi(this)
    this.shares = new SharesApi(this)
  }

  /** Never print key material. */
  toJSON(): Record<string, string> {
    return { clientId: this.clientId, baseUrl: this.baseUrl }
  }

  private clientKeys(): Promise<ClientKeys> {
    return (this.#keys ??= deriveClientKeys(this.#secret))
  }

  /** This key's X25519 box public key (standard base64). Share it so others can seal file keys to you. */
  async boxPublicKey(): Promise<string> {
    return toBase64((await this.clientKeys()).boxPublicKey)
  }

  /**
   * A valid Bearer token, from cache or a fresh client credentials grant.
   * Concurrent callers share ONE in-flight token request.
   */
  async getToken(force = false, call: CallOptions = {}): Promise<TokenInfo> {
    const t = this.#token
    if (!force && t && t.expiresAt - TOKEN_SKEW_MS > Date.now()) return t
    if (!this.#pending) {
      this.#pending = this.fetchToken({ timeoutMs: call.timeoutMs }).finally(() => {
        this.#pending = null
      })
    }
    return withSignal(this.#pending, call.signal)
  }

  private async fetchToken(call: CallOptions): Promise<TokenInfo> {
    const { oauthSecret } = await this.clientKeys()
    const form = new URLSearchParams({ grant_type: "client_credentials", client_id: this.clientId, client_secret: oauthSecret })
    if (this.scope) form.set("scope", this.scope)
    const { res, bytes } = await this.request("POST", OPERATIONS.createToken.path, {
      auth: false,
      idempotent: true,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new TextEncoder().encode(form.toString()),
      timeoutMs: call.timeoutMs,
    })
    const body = parseJson(bytes) as Partial<TokenResponse> | null
    if (!body || typeof body.access_token !== "string" || !body.access_token || String(body.token_type).toLowerCase() !== "bearer") {
      throw new UntraceError({ status: res.status, code: "server_error", message: "untrace: malformed token response" })
    }
    const ttl = Number(body.expires_in)
    this.#token = {
      accessToken: body.access_token,
      expiresAt: Date.now() + (Number.isFinite(ttl) && ttl > 0 ? ttl : 900) * 1000,
      scopes: typeof body.scope === "string" ? body.scope.split(" ").filter(Boolean) : [],
    }
    return this.#token
  }

  private invalidate(accessToken: string): void {
    if (this.#token?.accessToken === accessToken) this.#token = null
  }

  /** One fetch with a timeout and the caller's AbortSignal. Transport failures become typed errors. */
  private async send(url: string, init: RequestInit, call: CallOptions): Promise<Answer> {
    if (call.signal?.aborted) throw new UntraceAbortError()
    const ctl = new AbortController()
    const timeoutMs = positiveOr(call.timeoutMs, this.timeoutMs)
    let timedOut = false
    const timer = setTimeout(() => {
      timedOut = true
      ctl.abort()
    }, timeoutMs)
    const onAbort = () => ctl.abort()
    call.signal?.addEventListener("abort", onAbort, { once: true })
    try {
      const res = await this.fetchImpl(url, { ...init, signal: ctl.signal })
      const bytes = new Uint8Array(await res.arrayBuffer())
      return { res, bytes }
    } catch (err) {
      if (call.signal?.aborted) throw new UntraceAbortError()
      if (timedOut) throw new UntraceTimeoutError(`untrace: no answer from ${hostOf(url)} within ${timeoutMs} ms`)
      throw new UntraceUnavailableError({
        status: 0,
        code: "network",
        message: `untrace: network error reaching ${hostOf(url)}: ${redactSecrets(String((err as Error)?.message ?? err))}`,
      })
    } finally {
      clearTimeout(timer)
      call.signal?.removeEventListener("abort", onAbort)
    }
  }

  /** @internal An API call with auth, retries (503, 429, network) and one token refresh on `token_expired`. */
  async request(method: string, path: string, opts: RequestOptions = {}): Promise<Answer> {
    if (opts.signal?.aborted) throw new UntraceAbortError()
    const idempotent = opts.idempotent ?? method !== "POST"
    let refreshed = false
    for (let attempt = 0; ; attempt++) {
      try {
        return await this.requestOnce(method, path, opts)
      } catch (err) {
        if (err instanceof ExpiredToken) {
          if (refreshed) throw err.original
          refreshed = true
          this.invalidate(err.accessToken)
          attempt--
          continue
        }
        const transport = err instanceof UntraceUnavailableError && err.status === 0
        if (attempt >= this.maxRetries || !isRetryable(err) || (transport && !idempotent)) throw err
        await sleep(backoffDelay(attempt, this.retryBaseMs, err), opts.signal)
      }
    }
  }

  private async requestOnce(method: string, path: string, opts: RequestOptions): Promise<Answer> {
    let url = this.baseUrl + path
    if (opts.query) {
      const q = new URLSearchParams()
      for (const [k, v] of Object.entries(opts.query)) if (v != null && v !== "") q.set(k, String(v))
      const s = q.toString()
      if (s) url += `?${s}`
    }
    const headers: Record<string, string> = { accept: "application/json", ...opts.headers }
    let body: BodyInit | undefined
    if (opts.json !== undefined) {
      headers["content-type"] = "application/json"
      body = JSON.stringify(opts.json)
    } else if (opts.body) {
      body = opts.body as BodyInit
    }
    let accessToken = ""
    if (opts.auth ?? true) {
      accessToken = (await this.getToken(false, opts)).accessToken
      headers.authorization = `Bearer ${accessToken}`
    }
    const answer = await this.send(url, { method, headers, body }, opts)
    const { res, bytes } = answer
    if (res.ok) return answer
    const parsed = parseJson(bytes)
    const obj = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {}
    if (res.status === 404 && opts.operationId && (OPERATIONS[opts.operationId].status as string) === "planned") {
      throw new UntracePlannedError(opts.operationId)
    }
    const err = errorFromResponse(res.status, obj, res.headers.get("retry-after"))
    if (accessToken && err instanceof UntraceAuthError && err.code === "token_expired") throw new ExpiredToken(accessToken, err)
    throw err
  }

  /**
   * Call any operation of the contract by its operationId, with JSON in and
   * JSON out. Path parameters are filled from `params`. A `planned` operation
   * that this Drive does not serve yet throws UntracePlannedError.
   */
  async call<T = unknown>(
    operationId: OperationId,
    input: { params?: Record<string, string>; query?: Record<string, string | number | null | undefined>; body?: unknown } & CallOptions = {}
  ): Promise<T> {
    const op = OPERATIONS[operationId]
    if (!op) throw invalid(`untrace: unknown operation ${String(operationId)}`)
    if (operationId === "createToken" || operationId === "uploadFile" || operationId === "downloadFile") {
      throw invalid(`untrace: use the dedicated method for ${operationId}`)
    }
    const path = op.path.replace(/\{(\w+)\}/g, (_m, name: string) => {
      const v = input.params?.[name]
      if (typeof v !== "string" || !v) throw invalid(`untrace: missing path parameter ${name}`)
      return encodeURIComponent(v)
    })
    const { bytes } = await this.request(op.method, path, {
      operationId,
      query: input.query,
      json: input.body,
      signal: input.signal,
      timeoutMs: input.timeoutMs,
    })
    return parseJson(bytes) as T
  }

  /** The owner's sharing key, with its signature checked. Cached for the life of the client. */
  async ownerShareKey(call: CallOptions = {}): Promise<Uint8Array> {
    if (!this.#shareKey) {
      this.#shareKey = (async () => {
        const rec = await this.call<OwnerShareKey>("getOwnerShareKey", call)
        if (!rec || typeof rec.publicKey !== "string" || !verifyShareKey(rec)) {
          throw new UntraceIntegrityError("untrace: the owner's sharing key signature does not verify; nothing was uploaded")
        }
        const pk = fromBase64(rec.publicKey)
        if (pk.length !== 32) throw new UntraceIntegrityError("untrace: the owner's sharing key is not 32 bytes")
        return pk
      })()
      this.#shareKey.catch(() => {
        this.#shareKey = null
      })
    }
    return this.#shareKey
  }

  /** @internal Seal a file key to this client and to the owner. */
  async sealFileKey(fileKey: Uint8Array, call: CallOptions): Promise<{ self: string; owner: string }> {
    const [keys, owner] = await Promise.all([this.clientKeys(), this.ownerShareKey(call)])
    return { self: sealToPublicKey(fileKey, keys.boxPublicKey), owner: sealToPublicKey(fileKey, owner) }
  }

  /** @internal Open a file key sealed to this client. */
  async openFileKey(sealed: string | null | undefined): Promise<Uint8Array> {
    if (!sealed) throw new UntraceIntegrityError("untrace: this file has no key sealed to this client")
    const keys = await this.clientKeys()
    try {
      return openSealed(sealed, keys.boxSecretKey)
    } catch {
      throw new UntraceIntegrityError("untrace: this client key cannot open the file key sealed to it")
    }
  }

  /**
   * @internal Open the key of a folder or file from what Drive returned: the
   * key where this client's entry sits (`sealed`) and the `keyPath` below it.
   */
  async openResourceKey(sealed: string | null | undefined, keyPath: readonly string[] | null | undefined): Promise<Uint8Array> {
    const start = await this.openFileKey(sealed)
    try {
      return await openKeyPath(start, keyPath ?? [])
    } catch {
      throw new UntraceIntegrityError("untrace: the key path to this folder or file does not open with this client key")
    } finally {
      start.fill(0)
    }
  }

  /** @internal The key of a folder or file this client reaches, opened here. */
  async resourceKey(r: ResourceRef, call: CallOptions = {}): Promise<Uint8Array> {
    if (r.type === "file") {
      const f = await this.files.get(r.id, call)
      return this.openResourceKey(f.wrappedKey, f.keyPath)
    }
    const f = await this.folders.get(r.id, call)
    return this.openResourceKey(f.sealedKey, f.keyPath)
  }

  /**
   * @internal A folder's public key, checked: this client opens the folder key
   * itself and derives the public key from it. A public key that does not
   * match is refused, so nothing is ever sealed to a key the server picked.
   */
  async folderBoxKey(folderId: string, call: CallOptions = {}): Promise<Uint8Array> {
    const hit = this.#folderBox.get(folderId)
    if (hit) return hit
    const f = await this.folders.get(folderId, call)
    const key = await this.openResourceKey(f.sealedKey, f.keyPath)
    try {
      const { publicKey, secretKey } = await deriveFolderBoxKeys(key)
      secretKey.fill(0)
      let claimed: Uint8Array | null
      try {
        claimed = fromBase64(f.boxPublicKey)
      } catch {
        claimed = null
      }
      if (!claimed || !sameBytes(claimed, publicKey)) {
        throw new UntraceIntegrityError("untrace: the folder's public key does not match its folder key; nothing was sealed to it")
      }
      if (this.#folderBox.size >= 256) this.#folderBox.clear()
      this.#folderBox.set(folderId, publicKey)
      return publicKey
    } finally {
      key.fill(0)
    }
  }

  /** A user's published sharing key, looked up by username, with its signature checked. */
  async userShareKey(username: string, call: CallOptions = {}): Promise<UserShareKey> {
    if (typeof username !== "string" || !USERNAME_RE.test(username)) throw invalid("untrace: username must be 6 to 32 characters of a-z, 0-9 and -")
    const rec = await this.call<OwnerShareKey>("getUserShareKey", { params: { username }, ...call })
    if (!rec || typeof rec.publicKey !== "string" || !verifyShareKey(rec)) {
      throw new UntraceIntegrityError(`untrace: the sharing key published for ${username} does not verify`)
    }
    const pk = fromBase64(rec.publicKey)
    if (pk.length !== 32) throw new UntraceIntegrityError(`untrace: the sharing key published for ${username} is not 32 bytes`)
    return { username, wallet: rec.wallet, publicKey: pk }
  }
}

export interface UserShareKey {
  username: string
  /** The account address that signed the key. */
  wallet: string
  /** X25519 public key, 32 bytes. */
  publicKey: Uint8Array
}

function parseJson(bytes: Uint8Array): unknown {
  const text = new TextDecoder().decode(bytes)
  if (!text) return null
  try {
    return JSON.parse(text)
  } catch {
    return { message: text.slice(0, 200) }
  }
}

function decodeHeaderName(v: string | null): string {
  if (!v) return "download"
  try {
    return decodeURIComponent(v)
  } catch {
    return v
  }
}

export class FilesApi {
  constructor(private readonly c: UntraceClient) {}

  /**
   * Files your key can reach, oldest first, paged by cursor (limit 1 to 200).
   * With `folderId`: only the files directly in that folder.
   */
  async list(opts: ListOptions & { folderId?: string | null } = {}): Promise<FileList> {
    assertListOptions(opts)
    if (opts.folderId != null) assertUuid(opts.folderId, "folderId")
    const r = await this.c.call<{ files?: FileSummary[]; nextCursor?: string | null }>("listFiles", {
      query: { cursor: opts.cursor ?? undefined, limit: opts.limit, folderId: opts.folderId ?? undefined },
      signal: opts.signal,
      timeoutMs: opts.timeoutMs,
    })
    return { files: r?.files ?? [], nextCursor: r?.nextCursor ?? null }
  }

  /** Every file, page by page. */
  async *listAll(opts: Omit<ListOptions, "cursor"> & { folderId?: string | null } = {}): AsyncGenerator<FileSummary> {
    let cursor: string | null = null
    do {
      const page: FileList = await this.list({ ...opts, cursor })
      yield* page.files
      cursor = page.nextCursor
    } while (cursor)
  }

  /** Metadata and the file key sealed to your key. */
  async get(fileId: string, call: CallOptions = {}): Promise<FileWithKey> {
    assertFileId(fileId)
    return this.c.call<FileWithKey>("getFile", { params: { fileId }, ...call })
  }

  async rename(fileId: string, name: string, call: CallOptions = {}): Promise<{ fileId: string; name: string }> {
    assertFileId(fileId)
    return this.c.call("updateFile", { params: { fileId }, body: { name: assertFileName(name) }, ...call })
  }

  /**
   * Move a file into another folder (role admin on the file and on the
   * target). The file key is opened here and sealed to the target folder's
   * checked public key. `null` moves it to the top level (the owner's keys only).
   */
  async move(fileId: string, folderId: string | null, call: CallOptions = {}): Promise<{ fileId: string; name: string; folderId: string | null }> {
    assertFileId(fileId)
    if (folderId === null) return this.c.call("updateFile", { params: { fileId }, body: { folderId: null }, ...call })
    assertUuid(folderId, "folderId")
    const box = await this.c.folderBoxKey(folderId, call)
    const fileKey = await this.c.resourceKey({ type: "file", id: fileId }, call)
    try {
      const folderSealedKey = sealToPublicKey(fileKey, box)
      return await this.c.call("updateFile", { params: { fileId }, body: { folderId, folderSealedKey }, ...call })
    } finally {
      fileKey.fill(0)
    }
  }

  /** Moves the file to the trash (scope `delete`, role admin). */
  async delete(fileId: string, call: CallOptions = {}): Promise<{ fileId: string; trashed: boolean }> {
    assertFileId(fileId)
    return this.c.call("deleteFile", { params: { fileId }, ...call })
  }

  /**
   * Encrypt on this machine (UTE1, AES-256-GCM, a fresh file key), seal the
   * file key to this client and to the owner, then upload the ciphertext.
   * Drive never receives the plaintext or the file key.
   */
  async upload(input: UploadInput, call: CallOptions = {}): Promise<UploadResult> {
    const name = assertFileName(input?.name)
    if (input.folderId == null || input.folderId === "") {
      throw invalid("untrace: folderId is required: a key uploads only into a folder it has been added to (create one with client.folders.create)")
    }
    assertUuid(input.folderId, "folderId")
    const folderId = input.folderId
    const mime = (input.mime ?? "application/octet-stream").trim() || "application/octet-stream"
    // eslint-disable-next-line no-control-regex
    if (!/^[\x21-\x7e]{1,128}$/.test(mime)) throw invalid("untrace: mime must be a printable media type of at most 128 characters")
    const plain = await toBytes(input.data)
    const chunkBytes = input.chunkBytes ?? UTE1_DEFAULT_CHUNK_BYTES
    if (ute1SealedLength(plain.length, chunkBytes) > MAX_UPLOAD_BODY_BYTES) {
      throw new UntraceTooLargeError({ status: 413, code: "payload_too_large", message: `untrace: the encrypted file is over ${MAX_UPLOAD_BODY_BYTES} bytes` })
    }
    const fileKey = newFileKey()
    try {
      const sealed = await this.c.sealFileKey(fileKey, call)
      const folderSealed = sealToPublicKey(fileKey, await this.c.folderBoxKey(folderId, call))
      const body = await encryptUte1(plain, fileKey, chunkBytes)
      // A POST is only retried on 503/429, which Drive sends before it stores anything.
      const { res, bytes } = await this.c.request("POST", OPERATIONS.uploadFile.path, {
        headers: {
          "content-type": "application/octet-stream",
          "x-untrace-file-name": encodeURIComponent(name),
          "x-untrace-file-type": mime,
          "x-untrace-sealed-key": sealed.self,
          "x-untrace-owner-sealed-key": sealed.owner,
          "x-untrace-folder-id": folderId,
          "x-untrace-folder-sealed-key": folderSealed,
        },
        body,
        signal: call.signal,
        timeoutMs: call.timeoutMs,
      })
      return { file: parseJson(bytes) as FileSummary, metering: parseMetering(res.headers) }
    } finally {
      fileKey.fill(0)
    }
  }

  /** Download the ciphertext, open your sealed file key and decrypt here. */
  async download(fileId: string, call: CallOptions = {}): Promise<DownloadResult> {
    assertFileId(fileId)
    const { res, bytes } = await this.c.request("GET", OPERATIONS.downloadFile.path.replace("{fileId}", fileId), {
      headers: { accept: "application/octet-stream" },
      signal: call.signal,
      timeoutMs: call.timeoutMs,
    })
    let fileKey = await this.c.openFileKey(res.headers.get("x-untrace-sealed-key"))
    try {
      let plain = await decryptUte1(bytes, fileKey).catch(() => null)
      if (!plain) {
        // The header carries the key where this client's entry sits. When that
        // entry is on a folder above the file, it is a folder key: walk the
        // file's keyPath (from its metadata) down to the file key and retry.
        const meta = await this.get(fileId, call)
        if (meta.keyPath?.length) {
          fileKey.fill(0)
          fileKey = await this.c.openResourceKey(meta.wrappedKey, meta.keyPath)
          plain = await decryptUte1(bytes, fileKey).catch(() => null)
        }
      }
      if (!plain) throw new UntraceIntegrityError("untrace: the downloaded file failed its integrity check")
      return {
        bytes: plain,
        name: decodeHeaderName(res.headers.get("x-untrace-file-name")),
        mime: res.headers.get("x-untrace-file-type") || "application/octet-stream",
      }
    } finally {
      fileKey.fill(0)
    }
  }
}

export interface CreateFolderInput {
  name: string
  /** Create inside this folder (role editor or above with `upload`). Omit for the top level of your key's Drive. */
  parentId?: string | null
}

export class FoldersApi {
  constructor(private readonly c: UntraceClient) {}

  /** Subfolders of `parentId`, or the top-level folders your key can reach when it is omitted. */
  async list(opts: ListOptions & { parentId?: string | null } = {}): Promise<FolderList> {
    assertListOptions(opts)
    if (opts.parentId != null) assertUuid(opts.parentId, "parentId")
    const r = await this.c.call<{ folders?: Folder[]; nextCursor?: string | null }>("listFolders", {
      query: { parentId: opts.parentId ?? undefined, cursor: opts.cursor ?? undefined, limit: opts.limit },
      signal: opts.signal,
      timeoutMs: opts.timeoutMs,
    })
    return { folders: r?.folders ?? [], nextCursor: r?.nextCursor ?? null }
  }

  /** Every folder at one level, page by page. */
  async *listAll(opts: Omit<ListOptions, "cursor"> & { parentId?: string | null } = {}): AsyncGenerator<Folder> {
    let cursor: string | null = null
    do {
      const page: FolderList = await this.list({ ...opts, cursor })
      yield* page.folders
      cursor = page.nextCursor
    } while (cursor)
  }

  /** Metadata, this key's role, the folder's public key and the sealed key path to it. */
  async get(folderId: string, call: CallOptions = {}): Promise<Folder> {
    assertUuid(folderId, "folderId")
    return this.c.call<Folder>("getFolder", { params: { folderId }, ...call })
  }

  /**
   * Create a folder. A fresh random folder key is made here. Drive receives
   * only its public key, plus copies of the key sealed to this client and to
   * the owner (top level) or to the parent folder's checked public key.
   */
  async create(input: CreateFolderInput, call: CallOptions = {}): Promise<Folder> {
    const name = assertFileName(input?.name)
    const parentId = input.parentId ?? null
    if (parentId !== null) assertUuid(parentId, "parentId")
    const folderKey = randomBytes(32)
    try {
      const { publicKey, secretKey } = await deriveFolderBoxKeys(folderKey)
      secretKey.fill(0)
      const body: Record<string, unknown> = { name, parentId, boxPublicKey: toBase64(publicKey) }
      if (parentId === null) {
        const sealed = await this.c.sealFileKey(folderKey, call)
        body.sealedKey = sealed.self
        body.ownerSealedKey = sealed.owner
      } else {
        body.parentSealedKey = sealToPublicKey(folderKey, await this.c.folderBoxKey(parentId, call))
      }
      return await this.c.call<Folder>("createFolder", { body, ...call })
    } finally {
      folderKey.fill(0)
    }
  }

  async rename(folderId: string, name: string, call: CallOptions = {}): Promise<Folder> {
    assertUuid(folderId, "folderId")
    return this.c.call<Folder>("updateFolder", { params: { folderId }, body: { name: assertFileName(name) }, ...call })
  }

  /**
   * Move a folder under another one (admin on the folder, editor with
   * `upload` on the target). The folder key is opened here and sealed to the
   * target's checked public key. `null` moves it to the top level (the
   * owner's keys only). A move inside itself or a subfolder answers 409 `conflict`.
   */
  async move(folderId: string, parentId: string | null, call: CallOptions = {}): Promise<Folder> {
    assertUuid(folderId, "folderId")
    if (parentId !== null) assertUuid(parentId, "parentId")
    const target = parentId === null ? await this.c.ownerShareKey(call) : await this.c.folderBoxKey(parentId, call)
    const key = await this.c.resourceKey({ type: "folder", id: folderId }, call)
    try {
      const sealed = sealToPublicKey(key, target)
      const body: Record<string, unknown> = parentId === null ? { parentId, ownerSealedKey: sealed } : { parentId, parentSealedKey: sealed }
      return await this.c.call<Folder>("updateFolder", { params: { folderId }, body, ...call })
    } finally {
      key.fill(0)
    }
  }

  /** Move the folder, its subfolders and their files to the trash (role admin, scope `delete`). */
  async trash(folderId: string, call: CallOptions = {}): Promise<{ removed: true }> {
    assertUuid(folderId, "folderId")
    return this.c.call("deleteFolder", { params: { folderId }, ...call })
  }
}

const KEY_OPS = {
  folder: { list: "listFolderKeys", attach: "attachFolderKey", change: "changeFolderKey", remove: "removeFolderKey", param: "folderId" },
  file: { list: "listFileKeys", attach: "attachFileKey", change: "changeFileKey", remove: "removeFileKey", param: "fileId" },
} as const

export interface AttachKeyInput {
  /** `client` (a developer key, keyId `utc_...`) or `passkey` (an account address). */
  keyType: KeyType
  keyId: string
  role: EntryRole
  scopes?: Scope[]
  /**
   * The attached key's X25519 public key, standard base64 (for a client key,
   * its `boxPublicKey()`). The folder or file key is sealed to it here.
   * Not used for `none` (a block).
   */
  publicKey?: string
}

function assertScopes(scopes: readonly unknown[]): void {
  if (!Array.isArray(scopes) || !scopes.every((s) => SCOPES.includes(s as Scope))) {
    throw invalid("untrace: scopes are download, upload, manage-sharing and delete")
  }
}

/**
 * Key entries on a folder or a file. Each entry is a key a person holds
 * (passkey or client credential), a role and scopes. Access resolves from the
 * top folder down; the nearest entry wins, a block (`none`) included.
 * Needs role admin and the `manage-sharing` scope.
 */
export class KeysApi {
  constructor(private readonly c: UntraceClient) {}

  async list(resource: ResourceRef, call: CallOptions = {}): Promise<KeyEntry[]> {
    assertResource(resource)
    const op = KEY_OPS[resource.type]
    const r = await this.c.call<{ entries?: KeyEntry[] }>(op.list, { params: { [op.param]: resource.id }, ...call })
    return r?.entries ?? []
  }

  /** Attach a key your own account holds. To give another person access, use `shares.offer`. */
  async attach(resource: ResourceRef, input: AttachKeyInput, call: CallOptions = {}): Promise<KeyEntry> {
    assertResource(resource)
    if (!KEY_TYPES.includes(input?.keyType)) throw invalid("untrace: keyType must be passkey or client")
    if (typeof input.keyId !== "string" || !/^[A-Za-z0-9_-]{8,128}$/.test(input.keyId)) throw invalid("untrace: keyId is not a valid key id")
    if (input.keyType === "client" && !CLIENT_ID_RE.test(input.keyId)) throw invalid("untrace: a client keyId is utc_ followed by 22 base58 characters")
    if (!ENTRY_ROLES.includes(input.role)) throw invalid("untrace: role must be admin, editor, viewer or none")
    if (input.scopes !== undefined) assertScopes(input.scopes)
    const body: Record<string, unknown> = { keyType: input.keyType, keyId: input.keyId, role: input.role }
    if (input.scopes) body.scopes = [...input.scopes]
    if (input.role !== "none") {
      if (!input.publicKey) throw invalid("untrace: publicKey is required to grant access: the key is sealed to it")
      const pk = publicKeyBytes(input.publicKey, "publicKey")
      const key = await this.c.resourceKey(resource, call)
      try {
        body.sealedKey = sealToPublicKey(key, pk)
      } finally {
        key.fill(0)
      }
    }
    const op = KEY_OPS[resource.type]
    return this.c.call<KeyEntry>(op.attach, { params: { [op.param]: resource.id }, body, ...call })
  }

  /** Change an entry's role or scopes. The owner's keys can never be changed (409 `owner_immutable`). */
  async change(resource: ResourceRef, entryId: string, change: { role?: EntryRole; scopes?: Scope[] }, call: CallOptions = {}): Promise<KeyEntry> {
    assertResource(resource)
    assertUuid(entryId, "entryId")
    const body: Record<string, unknown> = {}
    if (change?.role !== undefined) {
      if (!ENTRY_ROLES.includes(change.role)) throw invalid("untrace: role must be admin, editor, viewer or none")
      body.role = change.role
    }
    if (change?.scopes !== undefined) {
      assertScopes(change.scopes)
      body.scopes = [...change.scopes]
    }
    if (!Object.keys(body).length) throw invalid("untrace: give a role, scopes or both")
    const op = KEY_OPS[resource.type]
    return this.c.call<KeyEntry>(op.change, { params: { [op.param]: resource.id, entryId }, body, ...call })
  }

  /** Remove an entry. The owner's keys can never be removed (409 `owner_immutable`). */
  async remove(resource: ResourceRef, entryId: string, call: CallOptions = {}): Promise<{ removed: true }> {
    assertResource(resource)
    assertUuid(entryId, "entryId")
    const op = KEY_OPS[resource.type]
    return this.c.call(op.remove, { params: { [op.param]: resource.id, entryId }, ...call })
  }
}

export interface OfferShareInput {
  resourceType: ResourceType
  resourceId: string
  /** The recipient's Untrace username. */
  username: string
  role: GrantRole
}

export interface AcceptShareInput {
  /**
   * How to open the offered key, which is sealed to YOUR account's sharing
   * key: `shareSecretKey` (that X25519 secret key, 32 bytes) or `resourceKey`
   * (the already opened 32-byte folder or file key). The account's sharing
   * key normally stays in Drive, so most people accept in Drive.
   */
  shareSecretKey?: Uint8Array
  resourceKey?: Uint8Array
}

/**
 * Sharing between users. An offer carries the folder or file key sealed to
 * the recipient's published sharing key. Nothing is attached until the
 * recipient accepts with their OWN key. Nobody can attach a key in someone
 * else's name.
 */
export class SharesApi {
  constructor(private readonly c: UntraceClient) {}

  /** A user's published sharing key by username, signature checked. */
  lookup(username: string, call: CallOptions = {}): Promise<UserShareKey> {
    return this.c.userShareKey(username, call)
  }

  /** Offer a folder or file to a user (role admin and the `manage-sharing` scope on it). */
  async offer(input: OfferShareInput, call: CallOptions = {}): Promise<Share> {
    const resource = { type: input?.resourceType, id: input?.resourceId } as ResourceRef
    assertResource(resource)
    if (!GRANT_ROLES.includes(input.role)) throw invalid("untrace: role must be admin, editor or viewer")
    const recipient = await this.c.userShareKey(input.username, call)
    const key = await this.c.resourceKey(resource, call)
    let sealedKey: string
    try {
      sealedKey = sealToPublicKey(key, recipient.publicKey)
    } finally {
      key.fill(0)
    }
    return this.c.call<Share>("createShare", {
      body: { resourceType: resource.type, resourceId: resource.id, username: input.username, role: input.role, sealedKey },
      ...call,
    })
  }

  /** Pending shares offered to the account that owns this key. */
  async incoming(call: CallOptions = {}): Promise<Share[]> {
    const r = await this.c.call<{ shares?: Share[] }>("listIncomingShares", call)
    return r?.shares ?? []
  }

  /** Accept a share by attaching THIS client key. The offered key is re-sealed to this client here. */
  async accept(share: Pick<Share, "shareId" | "sealedKey">, input: AcceptShareInput, call: CallOptions = {}): Promise<KeyEntry> {
    assertUuid(share?.shareId, "shareId")
    let key: Uint8Array
    if (input?.resourceKey) {
      if (input.resourceKey.length !== 32) throw invalid("untrace: resourceKey must be 32 bytes")
      key = input.resourceKey.slice()
    } else if (input?.shareSecretKey) {
      if (!share.sealedKey) throw invalid("untrace: this share carries no sealed key")
      try {
        key = openSealed(share.sealedKey, input.shareSecretKey)
      } catch {
        throw new UntraceIntegrityError("untrace: this sharing key cannot open the offered key")
      }
    } else {
      throw invalid("untrace: give shareSecretKey or resourceKey to open the offered key")
    }
    try {
      const sealedKey = sealToPublicKey(key, publicKeyBytes(await this.c.boxPublicKey(), "boxPublicKey"))
      return await this.c.call<KeyEntry>("acceptShare", { params: { shareId: share.shareId }, body: { sealedKey }, ...call })
    } finally {
      key.fill(0)
    }
  }
}
