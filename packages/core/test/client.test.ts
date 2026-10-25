import { describe, expect, it } from "vitest"

import {
  backoffDelay,
  isRetryable,
  OPERATIONS,
  CONTRACT_COMMIT,
  parseMetering,
  UntraceAbortError,
  UntraceAuthError,
  UntraceClient,
  UntraceConflictError,
  UntraceIntegrityError,
  UntraceNotFoundError,
  UntracePaymentRequiredError,
  UntracePlannedError,
  UntraceRateLimitError,
  UntraceScopeError,
  UntraceTimeoutError,
  UntraceTooLargeError,
  UntraceUnavailableError,
  deriveClientKeys,
  sealToPublicKey,
  encryptUte1,
  newFileKey,
  randomBytes,
} from "../src/index"
import { BASE, CLIENT_ID, FOLDER_ID, RAW_SECRET, SECRET, createMockDrive, type MockOptions } from "./mock-drive"
import source from "../../../contract/SOURCE.json"

function setup(mock: MockOptions = {}, extra: Partial<ConstructorParameters<typeof UntraceClient>[0]> = {}) {
  const drive = createMockDrive(mock)
  const client = new UntraceClient({ clientId: CLIENT_ID, clientSecret: SECRET, baseUrl: BASE, fetch: drive.handler, retryBaseMs: 1, ...extra })
  return { drive, client }
}

const text = (s: string) => new TextEncoder().encode(s)

describe("construction", () => {
  it("reads env, refuses bad ids, secrets and URLs", () => {
    process.env.UNTRACE_CLIENT_ID = CLIENT_ID
    process.env.UNTRACE_CLIENT_SECRET = SECRET
    process.env.UNTRACE_BASE_URL = BASE + "/"
    try {
      const c = new UntraceClient({ fetch: (() => {}) as unknown as typeof fetch })
      expect(c.clientId).toBe(CLIENT_ID)
      expect(c.baseUrl).toBe(BASE)
    } finally {
      delete process.env.UNTRACE_CLIENT_ID
      delete process.env.UNTRACE_CLIENT_SECRET
      delete process.env.UNTRACE_BASE_URL
    }
    expect(() => new UntraceClient({ clientId: "bad", clientSecret: SECRET })).toThrow(/clientId/)
    expect(() => new UntraceClient({ clientId: CLIENT_ID })).toThrow(/clientSecret/)
    expect(() => new UntraceClient({ clientId: CLIENT_ID, clientSecret: "untrace_sk_v1_xx" })).toThrow(/32 bytes/)
    expect(() => new UntraceClient({ clientId: CLIENT_ID, clientSecret: SECRET, baseUrl: "ftp://x" })).toThrow(/http/)
    expect(() => new UntraceClient({ clientId: CLIENT_ID, clientSecret: SECRET, baseUrl: "not a url" })).toThrow(/valid URL/)
    expect(() => new UntraceClient({ clientId: CLIENT_ID, clientSecret: SECRET, baseUrl: "https://u:p@x" })).toThrow(/credentials/)
  })

  it("refuses to run in a browser unless told to", () => {
    const g = globalThis as Record<string, unknown>
    g.window = {}
    g.document = {}
    try {
      expect(() => new UntraceClient({ clientId: CLIENT_ID, clientSecret: SECRET })).toThrow(/server/)
      expect(() => new UntraceClient({ clientId: CLIENT_ID, clientSecret: SECRET, dangerouslyAllowBrowser: true })).not.toThrow()
    } finally {
      delete g.window
      delete g.document
    }
  })

  it("never prints the secret", () => {
    const { client } = setup()
    const shown = JSON.stringify(client) + String(Object.keys(client)) + require("node:util").inspect(client, { depth: 5 })
    expect(shown).not.toContain(SECRET.slice(14))
    expect(JSON.parse(JSON.stringify(client))).toEqual({ clientId: CLIENT_ID, baseUrl: BASE })
  })
})

describe("OAuth client credentials", () => {
  it("sends the derived value, never the raw secret, as a form post", async () => {
    const { drive, client } = setup()
    const t = await client.getToken()
    expect(t.accessToken).toMatch(/^tok_/)
    expect(t.scopes).toEqual(["download", "upload", "delete"])
    const req = drive.requests[0]!
    expect(req.method).toBe("POST")
    expect(req.url).toBe(`${BASE}/api/v1/oauth/token`)
    expect(req.headers["content-type"]).toBe("application/x-www-form-urlencoded")
    const form = new URLSearchParams(new TextDecoder().decode(req.body))
    expect(form.get("grant_type")).toBe("client_credentials")
    expect(form.get("client_id")).toBe(CLIENT_ID)
    expect(form.get("client_secret")).toBe((await deriveClientKeys(RAW_SECRET)).oauthSecret)
    // The raw secret never appears in any request, in any encoding.
    const raw = SECRET.slice("untrace_sk_v1_".length)
    for (const r of drive.requests) {
      const all = r.url + JSON.stringify(r.headers) + new TextDecoder().decode(r.body)
      expect(all).not.toContain(raw)
      expect(all).not.toContain("untrace_sk_v1_")
    }
  })

  it("caches the token and shares one in-flight request", async () => {
    const { drive, client } = setup()
    await Promise.all([client.getToken(), client.getToken(), client.files.list(), client.files.list()])
    expect(drive.tokenCount()).toBe(1)
    await client.getToken(true)
    expect(drive.tokenCount()).toBe(2)
  })

  it("refreshes a token close to expiry", async () => {
    const { drive, client } = setup({ expiresIn: 10 })
    await client.files.list()
    await client.files.list()
    expect(drive.tokenCount()).toBe(2)
  })

  it("passes a narrowed scope", async () => {
    const { drive, client } = setup({}, { scope: ["download"] })
    expect((await client.getToken()).scopes).toEqual(["download"])
    expect(new URLSearchParams(new TextDecoder().decode(drive.requests[0]!.body)).get("scope")).toBe("download")
    const s2 = setup({}, { scope: "download upload" })
    expect((await s2.client.getToken()).scopes).toEqual(["download", "upload"])
  })

  it("maps token errors", async () => {
    const wrong = new UntraceClient({ clientId: "utc_2222222222222222222222", clientSecret: SECRET, baseUrl: BASE, fetch: createMockDrive().handler })
    await expect(wrong.getToken()).rejects.toBeInstanceOf(UntraceAuthError)
    await expect(setup({}, { scope: "manage-sharing" }).client.getToken()).rejects.toBeInstanceOf(UntraceScopeError)
    await expect(setup({ noPlan: true }).client.getToken()).rejects.toBeInstanceOf(UntracePaymentRequiredError)
  })

  it("refuses a malformed token response", async () => {
    const f = (async () => new Response(JSON.stringify({ access_token: "", token_type: "Bearer" }), { status: 200 })) as unknown as typeof fetch
    const c = new UntraceClient({ clientId: CLIENT_ID, clientSecret: SECRET, baseUrl: BASE, fetch: f })
    await expect(c.getToken()).rejects.toThrow(/malformed token/)
    const g = (async () => new Response(JSON.stringify({ access_token: "x", token_type: "mac" }), { status: 200 })) as unknown as typeof fetch
    await expect(new UntraceClient({ clientId: CLIENT_ID, clientSecret: SECRET, baseUrl: BASE, fetch: g }).getToken()).rejects.toThrow(/malformed/)
  })

  it("gets a new token once on token_expired, then retries the call", async () => {
    const { drive, client } = setup({ expireTokens: true })
    const r = await client.files.list()
    expect(r.files).toEqual([])
    expect(drive.tokenCount()).toBe(2)
  })

  it("does not loop when the fresh token is also expired", async () => {
    const calls: string[] = []
    const f = (async (u: string) => {
      calls.push(u)
      if (u.endsWith("/oauth/token")) return new Response(JSON.stringify({ access_token: "t", token_type: "Bearer", expires_in: 900, scope: "" }))
      return new Response(JSON.stringify({ error: "token_expired", message: "expired" }), { status: 401 })
    }) as unknown as typeof fetch
    const c = new UntraceClient({ clientId: CLIENT_ID, clientSecret: SECRET, baseUrl: BASE, fetch: f })
    await expect(c.files.list()).rejects.toMatchObject({ code: "token_expired" })
    expect(calls.filter((u) => u.endsWith("/files")).length).toBe(2)
  })
})

describe("upload and download (UTE1, option B)", () => {
  it("encrypts locally, seals to self and owner, and round-trips", async () => {
    const { drive, client } = setup()
    const plain = text("hello untrace ".repeat(100))
    const up = await client.files.upload({ folderId: FOLDER_ID, data: plain, name: "notes/é.txt", mime: "text/plain", chunkBytes: 256 })
    expect(up.file).toMatchObject({ name: "notes/é.txt", mime: "text/plain", role: "editor" })
    expect(up.metering).toEqual({ billedTo: "owner", meteredBytes: up.file.size, usageBytes: up.file.size + 1000, quotaBytes: -1 })

    const req = drive.requests.find((r) => r.url.endsWith("/files/upload"))!
    expect(req.headers["content-type"]).toBe("application/octet-stream")
    expect(req.headers["x-untrace-file-name"]).toBe(encodeURIComponent("notes/é.txt"))
    expect(Buffer.from(req.body).includes(Buffer.from("hello untrace"))).toBe(false)
    expect(new TextDecoder().decode(req.body.subarray(0, 4))).toBe("UTE1")

    // The owner can open its copy of the file key.
    const stored = drive.files.get(up.file.fileId)!
    expect(drive.openOwnerKey(stored)).toHaveLength(32)

    const down = await client.files.download(up.file.fileId)
    expect(down.bytes).toEqual(plain)
    expect(down.name).toBe("notes/é.txt")
    expect(down.mime).toBe("text/plain")
  })

  it.each([
    ["Uint8Array", (b: Uint8Array) => b],
    ["ArrayBuffer", (b: Uint8Array) => b.slice().buffer],
    ["Blob", (b: Uint8Array) => new Blob([b as BlobPart])],
  ])("accepts a %s", async (_n, wrap) => {
    const { client } = setup()
    const plain = randomBytes(3000)
    const up = await client.files.upload({ folderId: FOLDER_ID, data: wrap(plain) as Uint8Array, name: "x.bin" })
    expect((await client.files.download(up.file.fileId)).bytes).toEqual(plain)
  })

  it("defaults the media type and refuses a bad one", async () => {
    const { drive, client } = setup()
    await client.files.upload({ folderId: FOLDER_ID, data: text("x"), name: "a" })
    expect(drive.requests.at(-1)!.headers["x-untrace-file-type"]).toBe("application/octet-stream")
    await expect(client.files.upload({ folderId: FOLDER_ID, data: text("x"), name: "a", mime: "text/plain; x=é" })).rejects.toThrow(/mime/)
  })

  it.each([
    ["empty", ""],
    ["spaces", "   "],
    ["too long", "x".repeat(257)],
    ["control", "a\nb"],
  ])("refuses a %s file name before any request", async (_n, name) => {
    const { drive, client } = setup()
    await expect(client.files.upload({ folderId: FOLDER_ID, data: text("x"), name })).rejects.toThrow(/name/)
    expect(drive.requests).toHaveLength(0)
  })

  it("refuses bad data", async () => {
    const { client } = setup()
    await expect(client.files.upload({ folderId: FOLDER_ID, data: "plain string" as unknown as Uint8Array, name: "a" })).rejects.toThrow(/Uint8Array/)
  })

  it("refuses a file over 16 MiB of ciphertext before uploading", async () => {
    const { drive, client } = setup()
    await expect(client.files.upload({ folderId: FOLDER_ID, data: new Uint8Array(16 * 1024 * 1024), name: "big" })).rejects.toBeInstanceOf(UntraceTooLargeError)
    expect(drive.requests).toHaveLength(0)
  })

  it("refuses to upload when the owner's sharing key signature is wrong", async () => {
    const { drive, client } = setup({ badShareKeySignature: true })
    await expect(client.files.upload({ folderId: FOLDER_ID, data: text("x"), name: "a" })).rejects.toBeInstanceOf(UntraceIntegrityError)
    expect(drive.requests.some((r) => r.url.endsWith("/files/upload"))).toBe(false)
  })

  it("caches the owner key, and retries after a failure", async () => {
    const { drive, client } = setup({ failures: [{ match: "/api/v1/owner/share-key", status: 404, body: { error: "not_found", message: "x" }, times: 1 }] })
    await expect(client.files.upload({ folderId: FOLDER_ID, data: text("x"), name: "a" })).rejects.toBeInstanceOf(UntraceNotFoundError)
    await client.files.upload({ folderId: FOLDER_ID, data: text("x"), name: "a" })
    await client.files.upload({ folderId: FOLDER_ID, data: text("y"), name: "b" })
    expect(drive.requests.filter((r) => r.url.endsWith("/owner/share-key"))).toHaveLength(2)
  })

  it("maps upload refusals", async () => {
    await expect(setup({ scopes: ["download"] }).client.files.upload({ folderId: FOLDER_ID, data: text("x"), name: "a" })).rejects.toBeInstanceOf(UntraceScopeError)
    await expect(setup({ noShareKey: true }).client.files.upload({ folderId: FOLDER_ID, data: text("x"), name: "a" })).rejects.toBeInstanceOf(UntraceNotFoundError)
    const pay = setup({ failures: [{ match: "/api/v1/files/upload", status: 402, body: { error: "payment_required", message: "full", code: "quota_exceeded" }, times: 1 }] })
    await expect(pay.client.files.upload({ folderId: FOLDER_ID, data: text("x"), name: "a" })).rejects.toMatchObject({ planCode: "quota_exceeded" })
  })

  it("refuses a download it cannot open, or whose body was tampered with", async () => {
    const { drive, client } = setup()
    const other = await deriveClientKeys(randomBytes(32))
    const key = newFileKey()
    const fileId = "11111111-1111-4111-8111-111111111111"
    drive.addFile({ fileId, name: "x", mime: "x/y", body: await encryptUte1(text("x"), key), selfKey: sealToPublicKey(key, other.boxPublicKey), ownerKey: "" })
    await expect(client.files.download(fileId)).rejects.toBeInstanceOf(UntraceIntegrityError)

    const mine = await deriveClientKeys(RAW_SECRET)
    const body = await encryptUte1(text("hello"), key)
    body[body.length - 1] ^= 1
    const id2 = "22222222-2222-4222-8222-222222222222"
    drive.addFile({ fileId: id2, name: "x", mime: "x/y", body, selfKey: sealToPublicKey(key, mine.boxPublicKey), ownerKey: "" })
    await expect(client.files.download(id2)).rejects.toThrow(/integrity/)
  })

  it("refuses a download with no sealed key header", async () => {
    const f = (async (u: string) =>
      u.endsWith("/oauth/token")
        ? new Response(JSON.stringify({ access_token: "t", token_type: "Bearer", expires_in: 900, scope: "" }))
        : new Response(new Uint8Array(17), { status: 200 })) as unknown as typeof fetch
    const c = new UntraceClient({ clientId: CLIENT_ID, clientSecret: SECRET, baseUrl: BASE, fetch: f })
    await expect(c.files.download("11111111-1111-4111-8111-111111111111")).rejects.toThrow(/no key sealed/)
  })

  it("maps a Drive-app file to unsupported_format", async () => {
    const { client } = setup({ failures: [{ match: "/api/v1/files/", status: 409, body: { error: "unsupported_format", message: "open it in Drive" }, times: 1 }] })
    await expect(client.files.download("11111111-1111-4111-8111-111111111111")).rejects.toBeInstanceOf(UntraceConflictError)
  })

  it("exposes this key's box public key", async () => {
    const { client } = setup()
    expect(await client.boxPublicKey()).toMatch(/^[A-Za-z0-9+/]{43}=$/)
  })
})

describe("files metadata", () => {
  it("lists with cursor paging and listAll walks every page", async () => {
    const { client } = setup()
    for (let i = 0; i < 5; i++) await client.files.upload({ folderId: FOLDER_ID, data: text(`f${i}`), name: `f${i}` })
    const p1 = await client.files.list({ limit: 2 })
    expect(p1.files).toHaveLength(2)
    expect(p1.nextCursor).toBe(p1.files[1]!.fileId)
    const p2 = await client.files.list({ limit: 2, cursor: p1.nextCursor })
    expect(p2.files[0]!.fileId > p1.files[1]!.fileId).toBe(true)
    const all: string[] = []
    for await (const f of client.files.listAll({ limit: 2 })) all.push(f.name)
    expect(all.sort()).toEqual(["f0", "f1", "f2", "f3", "f4"])
  })

  it.each([0, 201, 1.5])("refuses limit %s", async (limit) => {
    await expect(setup().client.files.list({ limit })).rejects.toThrow(/limit/)
  })

  it("refuses a cursor that is not a UUID", async () => {
    await expect(setup().client.files.list({ cursor: "../x" })).rejects.toThrow(/cursor/)
  })

  it("gets, renames and deletes", async () => {
    const { client } = setup()
    const { file } = await client.files.upload({ folderId: FOLDER_ID, data: text("x"), name: "a.txt" })
    const got = await client.files.get(file.fileId)
    expect(got.wrappedKey).toMatch(/^[A-Za-z0-9+/]+=*$/)
    expect(await client.files.rename(file.fileId, " b.txt ")).toEqual({ fileId: file.fileId, name: "b.txt" })
    expect(await client.files.delete(file.fileId)).toEqual({ fileId: file.fileId, trashed: true })
    await expect(client.files.get(file.fileId)).rejects.toBeInstanceOf(UntraceNotFoundError)
  })

  it.each(["get", "rename", "delete", "download"] as const)("%s refuses a fileId that is not a UUID", async (m) => {
    const { drive, client } = setup()
    const call = m === "rename" ? client.files.rename("../etc", "x") : client.files[m]("../etc")
    await expect(call).rejects.toThrow(/UUID/)
    expect(drive.requests).toHaveLength(0)
  })
})

describe("generic call() and planned operations", () => {
  it("fills path params and returns JSON", async () => {
    const { client } = setup()
    const { file } = await client.files.upload({ folderId: FOLDER_ID, data: text("x"), name: "a" })
    const got = await client.call<{ name: string }>("getFile", { params: { fileId: file.fileId } })
    expect(got.name).toBe("a")
  })

  it("every operation of this contract is live, so a 404 stays a plain not_found", async () => {
    const { client } = setup()
    for (const o of Object.values(OPERATIONS)) expect(o.status).toBe("live")
    await expect(client.call("getFolder", { params: { folderId: "11111111-1111-4111-8111-111111111111" } })).rejects.toBeInstanceOf(UntraceNotFoundError)
    expect(new UntracePlannedError("listFolders")).toMatchObject({ code: "planned", operationId: "listFolders" })
  })

  it("refuses unknown operations, missing params and the dedicated ones", async () => {
    const { client } = setup()
    await expect(client.call("nope" as never)).rejects.toThrow(/unknown operation/)
    await expect(client.call("getFile")).rejects.toThrow(/fileId/)
    for (const op of ["createToken", "uploadFile", "downloadFile"] as const) await expect(client.call(op)).rejects.toThrow(/dedicated/)
  })

  it("is generated from the recorded contract commit", () => {
    expect(CONTRACT_COMMIT).toBe(source.commit)
    const live = Object.values(OPERATIONS).filter((o) => o.status === "live").length
    expect(live).toBe(25)
    for (const o of Object.values(OPERATIONS)) expect(o.path.startsWith("/api/v1/")).toBe(true)
  })
})

describe("retries, timeouts and aborts", () => {
  it("retries 503 and 429 (Retry-After) on GET, then succeeds", async () => {
    const { drive, client } = setup({
      failures: [
        { match: "/api/v1/files", status: 503, times: 1 },
        { match: "/api/v1/files", status: 429, body: { error: "rate_limited", message: "slow" }, headers: { "retry-after": "0" }, times: 1 },
      ],
    })
    expect((await client.files.list()).files).toEqual([])
    expect(drive.requests.filter((r) => r.url.includes("/api/v1/files")).length).toBe(3)
  })

  it("gives up after maxRetries", async () => {
    const { client } = setup({ failures: [{ match: "/api/v1/files", status: 503, times: 10 }] }, { maxRetries: 1 })
    await expect(client.files.list()).rejects.toBeInstanceOf(UntraceUnavailableError)
  })

  it("never retries another 4xx", async () => {
    const { drive, client } = setup({ failures: [{ match: "/api/v1/files", status: 400, body: { error: "invalid_request", message: "x" }, times: 5 }] })
    await expect(client.files.list()).rejects.toMatchObject({ code: "invalid_request" })
    expect(drive.requests.filter((r) => r.url.includes("/api/v1/files")).length).toBe(1)
  })

  it("does not retry a network failure on upload (POST), but does on GET", async () => {
    let n = 0
    const drive = createMockDrive()
    const flaky = (async (u: string, init?: RequestInit) => {
      if (u.includes("/files") && n++ === 0) throw new TypeError("socket hang up")
      return drive.handler(u, init)
    }) as unknown as typeof fetch
    const c = new UntraceClient({ clientId: CLIENT_ID, clientSecret: SECRET, baseUrl: BASE, fetch: flaky, retryBaseMs: 1 })
    expect((await c.files.list()).files).toEqual([])
    n = 0
    await expect(c.files.upload({ folderId: FOLDER_ID, data: text("x"), name: "a" })).rejects.toMatchObject({ code: "network" })
  })

  it("times out", async () => {
    const hang = ((_u: string, init?: RequestInit) =>
      new Promise((_r, rej) => init?.signal?.addEventListener("abort", () => rej(new Error("aborted"))))) as unknown as typeof fetch
    const c = new UntraceClient({ clientId: CLIENT_ID, clientSecret: SECRET, baseUrl: BASE, fetch: hang, timeoutMs: 20, maxRetries: 0 })
    await expect(c.getToken()).rejects.toBeInstanceOf(UntraceTimeoutError)
  })

  it("honours an AbortSignal and never retries it", async () => {
    const { client } = setup()
    const ctl = new AbortController()
    ctl.abort()
    await expect(client.files.list({ signal: ctl.signal })).rejects.toBeInstanceOf(UntraceAbortError)
    const hang = ((_u: string, init?: RequestInit) =>
      new Promise((_r, rej) => init?.signal?.addEventListener("abort", () => rej(new Error("aborted"))))) as unknown as typeof fetch
    const c = new UntraceClient({ clientId: CLIENT_ID, clientSecret: SECRET, baseUrl: BASE, fetch: hang })
    const ctl2 = new AbortController()
    const p = c.getToken(false, { signal: ctl2.signal })
    ctl2.abort()
    await expect(p).rejects.toBeInstanceOf(UntraceAbortError)
  })

  it("redacts secrets in network error messages", async () => {
    const f = (async () => {
      throw new Error(`boom ${SECRET}`)
    }) as unknown as typeof fetch
    const c = new UntraceClient({ clientId: CLIENT_ID, clientSecret: SECRET, baseUrl: BASE, fetch: f, maxRetries: 0 })
    const e = await c.getToken().catch((x) => x)
    expect(e.message).not.toContain(SECRET.slice(14))
  })

  it("isRetryable and backoffDelay", () => {
    expect(isRetryable(new UntraceRateLimitError({ status: 429, code: "rate_limited", message: "" }))).toBe(true)
    expect(isRetryable(new UntraceAbortError())).toBe(false)
    expect(isRetryable(new Error("x"))).toBe(false)
    expect(backoffDelay(0, 100, new UntraceRateLimitError({ status: 429, code: "rate_limited", message: "", retryAfterSeconds: 2 }))).toBe(2000)
    expect(backoffDelay(0, 100, new UntraceRateLimitError({ status: 429, code: "rate_limited", message: "", retryAfterSeconds: 999 }))).toBe(30_000)
    const d = backoffDelay(3, 100)
    expect(d).toBeGreaterThanOrEqual(400)
    expect(d).toBeLessThanOrEqual(800)
    expect(backoffDelay(30, 100)).toBeLessThanOrEqual(10_000)
  })

  it("parseMetering reads billing headers", () => {
    expect(parseMetering(new Headers())).toEqual({ billedTo: null, meteredBytes: null, usageBytes: null, quotaBytes: null })
    expect(parseMetering(new Headers({ "x-untrace-metered-bytes": "abc" })).meteredBytes).toBeNull()
  })
})
