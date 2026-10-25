/**
 * A mock of the Drive API v1 as a `fetch` function, for tests only. It follows
 * contract/openapi.yaml (drive main, see contract/SOURCE.json): OAuth client
 * credentials (checks the derived value, stores only its SHA-256), the owner's
 * signed sharing key, folders with their own public keys, key entries on
 * folders and files resolved from the top folder down (the nearest entry wins,
 * a block included), key paths, UTE1 upload into a folder (required) and
 * download, file move, share offers by username, and accept.
 * Every request is recorded so tests can check what left the client.
 */
import { ed25519, x25519 } from "@noble/curves/ed25519"

import { deriveClientKeys, deriveFolderBoxKeys, exportClientSecret, openSealed, randomBytes, sealToPublicKey, SHARE_KEY_SIGN_PREFIX } from "../src/crypto"
import { fromBase64, toBase58, toBase64, toHex, utf8 } from "../src/encoding"
import { parseUte1Header } from "../src/ute1"

export const BASE = "https://drive.test"
export const CLIENT_ID = "utc_1111111111111111111111"
export const RAW_SECRET = new Uint8Array(32).map((_, i) => i + 1)
export const SECRET = exportClientSecret(RAW_SECRET)
/** A top-level folder the test key is admin of, made by the mock on first use. */
export const FOLDER_ID = "f0f0f0f0-0000-4000-8000-000000000001"

const SEALED_RE = /^[A-Za-z0-9+/]{120,400}={0,2}$/
const BOX_RE = /^[A-Za-z0-9+/]{43}=$/
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

export interface Recorded {
  method: string
  url: string
  headers: Record<string, string>
  body: Uint8Array
}

type GrantRole = "admin" | "editor" | "viewer"
type Role = "owner" | GrantRole

export interface Entry {
  entryId: string
  keyType: "passkey" | "client"
  keyId: string
  role: Role | "none"
  scopes: string[]
  sealedKey: string | null
  createdAt: string
}

export interface StoredFolder {
  folderId: string
  name: string
  parentId: string | null
  boxPublicKey: string
  ownerSealedKey: string | null
  /** The folder key sealed to the parent's public key (null at the top). */
  parentSealedKey: string | null
  entries: Entry[]
  trashed: boolean
  createdAt: string
}

export interface StoredFile {
  fileId: string
  name: string
  mime: string
  body: Uint8Array
  /** The file key sealed to this test key (its file-level entry), or "" for none. */
  selfKey: string
  ownerKey: string
  role: Role
  createdAt: string
  trashed: boolean
  folderId?: string | null
  /** The file key sealed to its folder's public key. */
  folderSealedKey?: string | null
  entries?: Entry[]
}

interface Share {
  shareId: string
  resourceType: "folder" | "file"
  resourceId: string
  username: string
  role: GrantRole
  sealedKey: string
  from: string
  createdAt: string
  status: "pending" | "accepted"
}

/** Drive stores hex SHA-256 of the 32 decoded bytes of the OAuth value, never the value. */
async function oauthHashOf(oauth: string): Promise<string> {
  let bytes: Uint8Array
  try {
    bytes = fromBase64(oauth)
  } catch {
    return ""
  }
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource)))
}

export interface MockOptions {
  scopes?: string[]
  /** Answer the next N calls to this path (exact or prefix match) with this status. */
  failures?: { match: string; status: number; body?: Record<string, unknown>; headers?: Record<string, string>; times: number }[]
  /** No sharing key published (409 on upload, 404 on share-key). */
  noShareKey?: boolean
  /** Sign the sharing key with the wrong wallet. */
  badShareKeySignature?: boolean
  /** Token lifetime in seconds. */
  expiresIn?: number
  /** The first token answers 401 token_expired on its first use. */
  expireTokens?: boolean
  /** No active plan. */
  noPlan?: boolean
  /** Do not create FOLDER_ID. */
  noFolder?: boolean
  /** Serve this boxPublicKey for every folder instead of the real one (a lying server). */
  fakeFolderBox?: string
}

function account(badSig = false) {
  const sign = ed25519.utils.randomPrivateKey()
  const wallet = toBase58(ed25519.getPublicKey(sign))
  const boxSecret = x25519.utils.randomPrivateKey()
  const publicKey = toBase64(x25519.getPublicKey(boxSecret))
  const signer = badSig ? ed25519.utils.randomPrivateKey() : sign
  const keySignature = toBase58(ed25519.sign(utf8(SHARE_KEY_SIGN_PREFIX + publicKey), signer))
  return { wallet, boxSecret, publicKey, keySignature }
}

export function createMockDrive(opts: MockOptions = {}) {
  const requests: Recorded[] = []
  const files = new Map<string, StoredFile>()
  const folders = new Map<string, StoredFolder>()
  const shares = new Map<string, Share>()
  const tokens = new Set<string>()
  const expiredOnce = new Set<string>()
  let tokenCount = 0
  let oauthHash: string | null = null
  const scopes = opts.scopes ?? ["download", "upload", "delete"]

  const owner = account(opts.badShareKeySignature)
  /** Published sharing keys by username. "me-the-owner" is the account that owns the test key. */
  const users = new Map<string, ReturnType<typeof account>>([
    ["bob-user", account()],
    ["mallory-user", account(true)],
    ["me-the-owner", owner],
  ])
  const failures = (opts.failures ?? []).map((f) => ({ ...f }))
  const now = () => new Date().toISOString()

  let seeded: Promise<void> | null = null
  /** Folder keys the mock made (tests compare them with what the client opened). */
  const folderKeys = new Map<string, Uint8Array>()

  async function makeFolder(f: { folderId?: string; name: string; parentId: string | null; mine: boolean; role?: Role | "none" }): Promise<StoredFolder> {
    const folderKey = randomBytes(32)
    const { publicKey } = await deriveFolderBoxKeys(folderKey)
    const me = await deriveClientKeys(RAW_SECRET)
    const parent = f.parentId ? folders.get(f.parentId)! : null
    const role = f.role ?? "admin"
    const folder: StoredFolder = {
      folderId: f.folderId ?? crypto.randomUUID(),
      name: f.name,
      parentId: f.parentId,
      boxPublicKey: toBase64(publicKey),
      ownerSealedKey: parent ? null : sealToPublicKey(folderKey, fromBase64(owner.publicKey)),
      parentSealedKey: parent ? sealToPublicKey(folderKey, fromBase64(parent.boxPublicKey)) : null,
      entries: f.mine
        ? [{ entryId: crypto.randomUUID(), keyType: "client", keyId: CLIENT_ID, role, scopes: [...scopes], sealedKey: role === "none" ? null : sealToPublicKey(folderKey, me.boxPublicKey), createdAt: now() }]
        : [],
      trashed: false,
      createdAt: now(),
    }
    folders.set(folder.folderId, folder)
    folderKeys.set(folder.folderId, folderKey)
    return folder
  }

  const seed = () => (seeded ??= opts.noFolder ? Promise.resolve() : makeFolder({ folderId: FOLDER_ID, name: "Inbox", parentId: null, mine: true }).then(() => undefined))

  const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } })
  const err = (status: number, error: string, message = error, extra: Record<string, unknown> = {}) => json({ error, message, ...extra }, status)
  const notFound = () => err(404, "not_found", "not found")
  const needScope = (s: string) => (scopes.includes(s) ? null : err(403, "insufficient_scope", "insufficient scope", { required: s }))

  // -- resolution: top folder down, then the file; the nearest entry for this key wins ----------
  type Granted = { ok: true; role: Role; sealedKey: string; keyPath: string[] }
  type Grant = Granted | { ok: false }

  function chainOf(folderId: string | null): StoredFolder[] | null {
    const chain: StoredFolder[] = []
    let id = folderId
    while (id) {
      const f = folders.get(id)
      if (!f || f.trashed) return null
      chain.unshift(f)
      id = f.parentId
    }
    return chain
  }

  function step(g: Grant, entries: Entry[], sealedToParent: string | null): Grant {
    const mine = entries.find((e) => e.keyType === "client" && e.keyId === CLIENT_ID)
    if (mine) return mine.role === "none" || !mine.sealedKey ? { ok: false } : { ok: true, role: mine.role, sealedKey: mine.sealedKey, keyPath: [] }
    if (!g.ok || !sealedToParent) return { ok: false }
    return { ...g, keyPath: [...g.keyPath, sealedToParent] }
  }

  function resolveFolder(folderId: string): Grant {
    const chain = chainOf(folderId)
    if (!chain || !chain.length) return { ok: false }
    let g: Grant = { ok: false }
    for (const f of chain) g = step(g, f.entries, f.parentSealedKey)
    return g
  }

  function resolveFile(f: StoredFile): Grant {
    let g: Grant = { ok: false }
    if (f.folderId) {
      const chain = chainOf(f.folderId)
      if (!chain) return { ok: false }
      for (const c of chain) g = step(g, c.entries, c.parentSealedKey)
    }
    const own: Entry[] = [...(f.entries ?? [])]
    if (f.selfKey) own.push({ entryId: `member:${CLIENT_ID}`, keyType: "client", keyId: CLIENT_ID, role: f.role, scopes, sealedKey: f.selfKey, createdAt: f.createdAt })
    return step(g, own, f.folderSealedKey ?? null)
  }

  const isAdmin = (g: Grant) => g.ok && (g.role === "owner" || g.role === "admin")
  const canCreateIn = (g: Grant) => g.ok && g.role !== "viewer"

  const describeFolder = (f: StoredFolder, g: Granted) => ({
    folderId: f.folderId,
    name: f.name,
    parentId: f.parentId,
    role: g.role,
    boxPublicKey: opts.fakeFolderBox ?? f.boxPublicKey,
    sealedKey: g.sealedKey,
    keyPath: g.keyPath,
    createdAt: f.createdAt,
  })
  const summary = (f: StoredFile, role: Role = f.role) => ({ fileId: f.fileId, name: f.name, size: f.body.length, mime: f.mime, role, createdAt: f.createdAt, folderId: f.folderId ?? null })

  function readBody(b: Uint8Array): Record<string, unknown> | null {
    try {
      const v = JSON.parse(new TextDecoder().decode(b)) as unknown
      return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null
    } catch {
      return null
    }
  }

  function keyRoute(entries: Entry[], g: Grant, entryId: string | null, method: string, body: Uint8Array): Response {
    const s = needScope("manage-sharing")
    if (s) return s
    if (!isAdmin(g)) return notFound()
    const pub = ({ sealedKey: _s, ...e }: Entry) => e
    if (!entryId && method === "GET") return json({ entries: entries.map(pub) })
    if (!entryId && method === "POST") {
      const b = readBody(body)
      if (!b) return err(400, "invalid_request", "invalid json")
      if (b.keyType !== "passkey" && b.keyType !== "client") return err(400, "invalid_request", "invalid keyType")
      if (!["admin", "editor", "viewer", "none"].includes(String(b.role))) return err(400, "invalid_request", "invalid role")
      if (b.role !== "none" && (typeof b.sealedKey !== "string" || !SEALED_RE.test(b.sealedKey))) return err(400, "invalid_request", "invalid sealedKey")
      const e: Entry = {
        entryId: crypto.randomUUID(),
        keyType: b.keyType,
        keyId: String(b.keyId),
        role: b.role as Entry["role"],
        scopes: Array.isArray(b.scopes) ? (b.scopes as string[]) : [],
        sealedKey: b.role === "none" ? null : (b.sealedKey as string),
        createdAt: now(),
      }
      entries.push(e)
      return json(pub(e), 201)
    }
    const e = entries.find((x) => x.entryId === entryId)
    if (!e) return notFound()
    if (e.role === "owner") return err(409, "owner_immutable", "the owner entry can never be changed")
    if (method === "PATCH") {
      const b = readBody(body) ?? {}
      if (b.role !== undefined) e.role = b.role as Entry["role"]
      if (Array.isArray(b.scopes)) e.scopes = b.scopes as string[]
      return json(pub(e))
    }
    if (method === "DELETE") {
      entries.splice(entries.indexOf(e), 1)
      return json({ removed: true })
    }
    return notFound()
  }

  async function handler(input: string | URL | Request, init: RequestInit = {}): Promise<Response> {
    await seed()
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url)
    const method = (init.method ?? "GET").toUpperCase()
    const headers = Object.fromEntries(new Headers(init.headers).entries())
    let body: Uint8Array = new Uint8Array(0)
    if (init.body instanceof Uint8Array) body = init.body as Uint8Array
    else if (typeof init.body === "string") body = utf8(init.body)
    else if (init.body) body = new Uint8Array(await new Response(init.body as BodyInit).arrayBuffer())
    requests.push({ method, url: url.href, headers, body })
    if (url.origin !== BASE) return notFound()
    const path = url.pathname

    for (const f of failures) {
      if (f.times > 0 && (path === f.match || path.startsWith(f.match))) {
        f.times--
        return json(f.body ?? { error: "unavailable", message: "try later" }, f.status, f.headers)
      }
    }

    if (path === "/api/v1/oauth/token" && method === "POST") {
      const form = new URLSearchParams(new TextDecoder().decode(body))
      if (form.get("grant_type") !== "client_credentials") return json({ error: "unsupported_grant_type" }, 400)
      oauthHash ??= await oauthHashOf((await deriveClientKeys(RAW_SECRET)).oauthSecret)
      const secret = form.get("client_secret") ?? ""
      if (form.get("client_id") !== CLIENT_ID || (await oauthHashOf(secret)) !== oauthHash) {
        return json({ error: "invalid_client", error_description: "invalid client" }, 401)
      }
      if (opts.noPlan) return err(402, "payment_required", "no active plan", { code: "no_subscription" })
      const asked = form.get("scope")?.split(" ").filter(Boolean)
      if (asked?.some((s) => !scopes.includes(s))) return json({ error: "invalid_scope" }, 400)
      const access = `tok_${++tokenCount}_${Math.random().toString(36).slice(2)}`
      tokens.add(access)
      return json({ access_token: access, token_type: "Bearer", expires_in: opts.expiresIn ?? 900, scope: (asked ?? scopes).join(" ") }, 200, { "cache-control": "no-store" })
    }

    const auth = headers.authorization ?? ""
    const tok = auth.startsWith("Bearer ") ? auth.slice(7) : ""
    if (!tokens.has(tok)) return err(401, "invalid_client", "missing or bad token")
    if (opts.expireTokens && expiredOnce.size === 0) {
      expiredOnce.add(tok)
      tokens.delete(tok)
      return err(401, "token_expired")
    }

    if (path === "/api/v1/owner/share-key" && method === "GET") {
      if (opts.noShareKey) return notFound()
      return json({ wallet: owner.wallet, publicKey: owner.publicKey, keySignature: owner.keySignature, signedMessagePrefix: SHARE_KEY_SIGN_PREFIX })
    }

    // -- users --------------------------------------------------------------------------------
    const um = /^\/api\/v1\/users\/([^/]+)\/share-key$/.exec(path)
    if (um && method === "GET") {
      const u = users.get(decodeURIComponent(um[1]!))
      if (!u) return notFound()
      return json({ wallet: u.wallet, publicKey: u.publicKey, keySignature: u.keySignature, signedMessagePrefix: SHARE_KEY_SIGN_PREFIX })
    }

    // -- folders ------------------------------------------------------------------------------
    if (path === "/api/v1/folders" && method === "GET") {
      const parentId = url.searchParams.get("parentId")
      const limit = Number(url.searchParams.get("limit") ?? 100)
      const cursor = url.searchParams.get("cursor")
      let list: { f: StoredFolder; g: Granted }[] = []
      if (parentId && !resolveFolder(parentId).ok) return notFound()
      for (const f of folders.values()) {
        if (f.trashed) continue
        if (parentId ? f.parentId !== parentId : !f.entries.some((e) => e.keyId === CLIENT_ID && e.role !== "none")) continue
        const g = resolveFolder(f.folderId)
        if (g.ok) list.push({ f, g })
      }
      list = list.sort((a, b) => (a.f.folderId < b.f.folderId ? -1 : 1)).filter((x) => !cursor || x.f.folderId > cursor)
      const page = list.slice(0, limit)
      return json({ folders: page.map((x) => describeFolder(x.f, x.g)), nextCursor: list.length > limit ? page[page.length - 1]!.f.folderId : null })
    }

    if (path === "/api/v1/folders" && method === "POST") {
      const b = readBody(body)
      if (!b || typeof b.name !== "string" || !b.name) return err(400, "invalid_request", "invalid name")
      if (typeof b.boxPublicKey !== "string" || !BOX_RE.test(b.boxPublicKey)) return err(400, "invalid_request", "invalid boxPublicKey")
      const parentId = (b.parentId as string | null | undefined) ?? null
      const folderId = crypto.randomUUID()
      let f: StoredFolder
      if (parentId === null) {
        const s = needScope("upload")
        if (s) return s
        if (typeof b.sealedKey !== "string" || !SEALED_RE.test(b.sealedKey)) return err(400, "invalid_request", "invalid sealedKey")
        if (typeof b.ownerSealedKey !== "string" || !SEALED_RE.test(b.ownerSealedKey)) return err(400, "invalid_request", "invalid ownerSealedKey")
        f = {
          folderId,
          name: b.name,
          parentId: null,
          boxPublicKey: b.boxPublicKey,
          ownerSealedKey: b.ownerSealedKey,
          parentSealedKey: null,
          entries: [{ entryId: crypto.randomUUID(), keyType: "client", keyId: CLIENT_ID, role: "admin", scopes: [...scopes], sealedKey: b.sealedKey, createdAt: now() }],
          trashed: false,
          createdAt: now(),
        }
      } else {
        if (!canCreateIn(resolveFolder(parentId))) return notFound()
        if (typeof b.parentSealedKey !== "string" || !SEALED_RE.test(b.parentSealedKey)) return err(400, "invalid_request", "invalid parentSealedKey")
        f = { folderId, name: b.name, parentId, boxPublicKey: b.boxPublicKey, ownerSealedKey: null, parentSealedKey: b.parentSealedKey, entries: [], trashed: false, createdAt: now() }
      }
      folders.set(folderId, f)
      return json(describeFolder(f, resolveFolder(folderId) as Granted), 201)
    }

    const fm = /^\/api\/v1\/folders\/([^/]+)(\/keys(?:\/([^/]+))?)?$/.exec(path)
    if (fm) {
      const folderId = decodeURIComponent(fm[1]!)
      const f = folders.get(folderId)
      const g: Grant = f && !f.trashed ? resolveFolder(folderId) : { ok: false }
      if (!f || !g.ok) return notFound()
      if (fm[2]) return keyRoute(f.entries, g, fm[3] ? decodeURIComponent(fm[3]) : null, method, body)
      if (method === "GET") return json(describeFolder(f, g))
      if (method === "PATCH") {
        const b = readBody(body)
        if (!b) return err(400, "invalid_request", "invalid json")
        if (b.parentId !== undefined) {
          if (!isAdmin(g)) return notFound()
          if (b.parentId === null) {
            if (typeof b.ownerSealedKey !== "string" || !SEALED_RE.test(b.ownerSealedKey)) return err(400, "invalid_request", "invalid ownerSealedKey")
            f.parentId = null
            f.parentSealedKey = null
            f.ownerSealedKey = b.ownerSealedKey
          } else {
            const target = String(b.parentId)
            if (chainOf(target)?.some((c) => c.folderId === folderId)) return err(409, "conflict", "a folder cannot move inside itself")
            if (!canCreateIn(resolveFolder(target))) return notFound()
            if (typeof b.parentSealedKey !== "string" || !SEALED_RE.test(b.parentSealedKey)) return err(400, "invalid_request", "invalid parentSealedKey")
            f.parentId = target
            f.parentSealedKey = b.parentSealedKey
          }
        }
        if (typeof b.name === "string") f.name = b.name
        return json(describeFolder(f, resolveFolder(folderId) as Granted))
      }
      if (method === "DELETE") {
        const s = needScope("delete")
        if (s) return s
        if (!isAdmin(g)) return notFound()
        f.trashed = true
        return json({ removed: true })
      }
    }

    // -- shares -------------------------------------------------------------------------------
    if (path === "/api/v1/shares" && method === "POST") {
      const s = needScope("manage-sharing")
      if (s) return s
      const b = readBody(body)
      if (!b) return err(400, "invalid_request", "invalid json")
      const { resourceType, resourceId, username, role, sealedKey } = b as Record<string, string>
      if (resourceType !== "folder" && resourceType !== "file") return err(400, "invalid_request", "invalid resourceType")
      if (!["admin", "editor", "viewer"].includes(role!)) return err(400, "invalid_request", "invalid role")
      if (!SEALED_RE.test(sealedKey ?? "")) return err(400, "invalid_request", "invalid sealedKey")
      const file = resourceType === "file" ? files.get(resourceId!) : undefined
      const g: Grant = resourceType === "folder" ? resolveFolder(resourceId!) : file && !file.trashed ? resolveFile(file) : { ok: false }
      if (!isAdmin(g)) return notFound()
      if (!users.has(username!)) return notFound()
      const share: Share = { shareId: crypto.randomUUID(), resourceType, resourceId: resourceId!, username: username!, role: role as GrantRole, sealedKey: sealedKey!, from: owner.wallet, createdAt: now(), status: "pending" }
      shares.set(share.shareId, share)
      const { sealedKey: _s, status: _st, username: _u, ...out } = share
      return json(out, 201)
    }
    if (path === "/api/v1/shares/incoming" && method === "GET") {
      const mine = [...shares.values()].filter((s) => s.username === "me-the-owner" && s.status === "pending")
      return json({ shares: mine.map(({ status: _s, username: _u, ...rest }) => rest) })
    }
    const sm = /^\/api\/v1\/shares\/([^/]+)\/accept$/.exec(path)
    if (sm && method === "POST") {
      const share = shares.get(decodeURIComponent(sm[1]!))
      if (!share || share.username !== "me-the-owner" || share.status !== "pending") return notFound()
      const b = readBody(body)
      if (!b || typeof b.sealedKey !== "string" || !SEALED_RE.test(b.sealedKey)) return err(400, "invalid_request", "invalid sealedKey")
      const entry: Entry = { entryId: crypto.randomUUID(), keyType: "client", keyId: CLIENT_ID, role: share.role, scopes: ["download", "upload", "manage-sharing", "delete"], sealedKey: b.sealedKey, createdAt: now() }
      if (share.resourceType === "folder") folders.get(share.resourceId)!.entries.push(entry)
      else (files.get(share.resourceId)!.entries ??= []).push(entry)
      share.status = "accepted"
      const { sealedKey: _s, ...out } = entry
      return json(out, 201)
    }

    // -- files --------------------------------------------------------------------------------
    if (path === "/api/v1/files" && method === "GET") {
      const limit = Number(url.searchParams.get("limit") ?? 100)
      const cursor = url.searchParams.get("cursor")
      const folderId = url.searchParams.get("folderId")
      if (folderId && !resolveFolder(folderId).ok) return notFound()
      const all = [...files.values()]
        .filter((f) => !f.trashed && (folderId ? f.folderId === folderId : true))
        .map((f) => ({ f, g: resolveFile(f) }))
        .filter((x): x is { f: StoredFile; g: Granted } => x.g.ok)
        .sort((a, b) => (a.f.fileId < b.f.fileId ? -1 : 1))
      const start = cursor ? all.findIndex((x) => x.f.fileId > cursor) : 0
      const page = start < 0 ? [] : all.slice(start, start + limit)
      const next = start >= 0 && start + limit < all.length ? page[page.length - 1]!.f.fileId : null
      return json({ files: page.map((x) => summary(x.f, x.g.role)), nextCursor: next })
    }

    if (path === "/api/v1/files/upload" && method === "POST") {
      const s = needScope("upload")
      if (s) return s
      const self = headers["x-untrace-sealed-key"] ?? ""
      const ownerKey = headers["x-untrace-owner-sealed-key"] ?? ""
      if (!SEALED_RE.test(self) || !SEALED_RE.test(ownerKey)) return err(400, "invalid_request", "bad sealed key")
      const folderId = (headers["x-untrace-folder-id"] ?? "").trim()
      const denied = () => err(403, "folder_access_required", "a key can only create files in a folder it has been added to")
      if (!folderId) return denied()
      if (!UUID_RE.test(folderId)) return err(400, "invalid_request", "invalid X-Untrace-Folder-Id")
      if (!canCreateIn(resolveFolder(folderId))) return denied()
      const folderSealedKey = headers["x-untrace-folder-sealed-key"] ?? ""
      if (!SEALED_RE.test(folderSealedKey)) return err(400, "invalid_request", "invalid X-Untrace-Folder-Sealed-Key")
      if (opts.noShareKey) return err(409, "conflict", "no sharing key")
      let name: string
      try {
        name = decodeURIComponent(headers["x-untrace-file-name"] ?? "")
      } catch {
        return err(400, "invalid_request", "bad name")
      }
      if (!name) return err(400, "invalid_request", "bad name")
      const h = parseUte1Header(body)
      if (!h || h.sealedBytes !== body.length) return err(400, "invalid_request", "not UTE1")
      if (body.length > 16 * 1024 * 1024) return err(413, "payload_too_large")
      const fileId = crypto.randomUUID()
      const f: StoredFile = {
        fileId,
        name,
        mime: headers["x-untrace-file-type"] ?? "application/octet-stream",
        body,
        selfKey: self,
        ownerKey,
        role: "editor",
        createdAt: now(),
        trashed: false,
        folderId,
        folderSealedKey,
      }
      files.set(fileId, f)
      return json(summary(f), 201, {
        "x-untrace-billed-to": "owner",
        "x-untrace-metered-bytes": String(body.length),
        "x-untrace-usage-bytes": String(body.length + 1000),
        "x-untrace-quota-bytes": "-1",
      })
    }

    const m = /^\/api\/v1\/files\/([^/]+)(\/content|\/keys(?:\/([^/]+))?)?$/.exec(path)
    if (m) {
      const f = files.get(decodeURIComponent(m[1]!))
      const g: Grant = f && !f.trashed ? resolveFile(f) : { ok: false }
      if (!f || !g.ok) return notFound()
      if (m[2]?.startsWith("/keys")) return keyRoute((f.entries ??= []), g, m[3] ? decodeURIComponent(m[3]) : null, method, body)
      if (m[2] && method === "GET") {
        // Like Drive: the header carries the key where this key's winning entry sits.
        return new Response(f.body as BodyInit, {
          status: 200,
          headers: {
            "content-type": "application/octet-stream",
            "x-untrace-sealed-key": g.sealedKey,
            "x-untrace-file-name": encodeURIComponent(f.name),
            "x-untrace-file-type": f.mime,
          },
        })
      }
      if (!m[2] && method === "GET") return json({ ...summary(f, g.role), wrappedKey: g.sealedKey, keyPath: g.keyPath })
      if (!m[2] && method === "PATCH") {
        const b = readBody(body) ?? {}
        if (b.folderId !== undefined) {
          if (!isAdmin(g)) return notFound()
          if (b.folderId === null) {
            f.folderId = null
            f.folderSealedKey = null
          } else {
            if (!isAdmin(resolveFolder(String(b.folderId)))) return notFound()
            if (typeof b.folderSealedKey !== "string" || !SEALED_RE.test(b.folderSealedKey)) return err(400, "invalid_request", "invalid folderSealedKey")
            f.folderId = String(b.folderId)
            f.folderSealedKey = b.folderSealedKey
          }
          return json({ fileId: f.fileId, name: f.name, folderId: f.folderId })
        }
        if (typeof b.name !== "string" || !b.name) return err(400, "invalid_request")
        f.name = b.name
        return json({ fileId: f.fileId, name: f.name })
      }
      if (!m[2] && method === "DELETE") {
        const s = needScope("delete")
        if (s) return s
        f.trashed = true
        return json({ fileId: f.fileId, trashed: true })
      }
    }
    return notFound()
  }

  return {
    handler: handler as typeof fetch,
    requests,
    files,
    folders,
    shares,
    ownerWallet: owner.wallet,
    /** Open the owner's sealed copy, as the owner's Drive app would. */
    openOwnerKey: (f: StoredFile) => openSealed(f.ownerKey, owner.boxSecret),
    /** Open a top-level folder's owner copy. */
    openOwnerFolderKey: (f: StoredFolder) => openSealed(f.ownerSealedKey!, owner.boxSecret),
    /** The sharing secret key of the account that owns the test key ("me-the-owner"). */
    myShareSecret: owner.boxSecret,
    userShareSecret: (u: string) => users.get(u)!.boxSecret,
    folderKey: (id: string) => folderKeys.get(id),
    tokenCount: () => tokenCount,
    seed,
    /** Put a file that was uploaded by someone else, sealed to `boxPublicKey`. */
    addFile(f: Omit<StoredFile, "createdAt" | "trashed" | "role"> & { role?: StoredFile["role"] }) {
      files.set(f.fileId, { role: "viewer", createdAt: now(), trashed: false, ...f })
    },
    /** A folder made by the mock. `mine`: the test key gets an entry with `role` (default admin). */
    async addFolder(f: { name: string; parentId?: string | null; mine?: boolean; role?: Role | "none" }) {
      await seed()
      return makeFolder({ name: f.name, parentId: f.parentId ?? null, mine: f.mine ?? false, role: f.role })
    },
    /** Offer a resource to the account that owns the test key, as another user would. */
    offerToMe(resourceType: "folder" | "file", resourceId: string, key: Uint8Array, role: GrantRole = "editor") {
      const share: Share = {
        shareId: crypto.randomUUID(),
        resourceType,
        resourceId,
        username: "me-the-owner",
        role,
        sealedKey: sealToPublicKey(key, fromBase64(owner.publicKey)),
        from: "bob-user",
        createdAt: now(),
        status: "pending",
      }
      shares.set(share.shareId, share)
      return share
    },
    fromBase64,
  }
}
