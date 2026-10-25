/**
 * Framework-neutral backend handler: Web `Request` in, Web `Response` out.
 *
 * Mount it on YOUR server (a Next.js route, Hono, a Worker, or Express via
 * `toNodeHandler`). The browser talks to that route; the client secret, the
 * file keys and the decryption stay on the server. @untracenetwork/react and
 * @untracenetwork/vue speak this protocol.
 *
 * Protocol (one route). Answers never carry sealed keys or key paths.
 *   GET  ?action=list[&folderId=&cursor=&limit=]     -> { files, nextCursor }
 *   GET  ?action=get&fileId=                         -> file metadata
 *   GET  ?action=download&fileId=                    -> the decrypted bytes
 *   GET  ?action=folders[&parentId=&cursor=&limit=]  -> { folders, nextCursor }
 *   GET  ?action=folder&folderId=                    -> folder metadata
 *   POST ?action=upload&folderId=, multipart: file[, name]   -> { file }
 *   POST ?action=rename&fileId=, json { name }
 *   POST ?action=move&fileId=, json { folderId }     (folderId null = top level)
 *   POST ?action=delete&fileId=, json {}
 *   POST ?action=create-folder[&parentId=], json { name }    -> folder
 *   POST ?action=rename-folder&folderId=, json { name }
 *   POST ?action=move-folder&folderId=, json { parentId }
 *   POST ?action=trash-folder&folderId=, json {}
 *   POST ?action=share, json { resourceType, resourceId, username, role }
 *
 * `upload` needs `folderId`: a key uploads only into a folder it was added to.
 *
 * Every POST must carry `x-untrace-request: 1` and a content type of
 * `application/json` (`multipart/form-data` for upload). A cross-site HTML
 * form can set neither, and a cross-origin fetch that sets the header needs a
 * CORS preflight this handler never grants, so writes cannot be forged.
 *
 * The action, fileId, folderId and parentId come from the query string, so
 * `authorize` runs BEFORE the body is read and sees every id it acts on
 * (except `share` and the move targets, which are in the JSON body: check
 * them in `authorize` by reading `request.clone().json()` if you need to).
 */

import { MAX_UPLOAD_BODY_BYTES, UntraceClient, type Folder, type GrantRole, type ResourceType, type UntraceClientOptions } from "./client"
import { UntraceError } from "./errors"

export const HANDLER_ACTIONS = [
  "list",
  "get",
  "download",
  "folders",
  "folder",
  "upload",
  "rename",
  "move",
  "delete",
  "create-folder",
  "rename-folder",
  "move-folder",
  "trash-folder",
  "share",
] as const
export type HandlerAction = (typeof HANDLER_ACTIONS)[number]

/** Read-only by default. Writes must be opted in. */
export const DEFAULT_ALLOWED_ACTIONS: readonly HandlerAction[] = ["list", "get", "download", "folders", "folder"]

/** Header every state-changing (POST) request must carry. */
export const UNTRACE_REQUEST_HEADER = "x-untrace-request"

export const MAX_JSON_BODY_BYTES = 64 * 1024
export const MAX_MULTIPART_BODY_BYTES = MAX_UPLOAD_BODY_BYTES + 1024 * 1024

const WRITE_ACTIONS = new Set<HandlerAction>(["upload", "rename", "move", "delete", "create-folder", "rename-folder", "move-folder", "trash-folder", "share"])

/** What `authorize` gets besides the action: the ids from the query string. */
export interface HandlerTarget {
  fileId: string | null
  folderId: string | null
  parentId: string | null
}

/** Folder metadata for a browser: no sealed key, no key path. */
export function publicFolder(f: Folder): Omit<Folder, "sealedKey" | "keyPath"> {
  const { sealedKey: _s, keyPath: _k, ...rest } = f
  return rest
}

export interface UntraceHandlerOptions extends UntraceClientOptions {
  /** A ready client. If omitted one is built from the other options or env. */
  client?: UntraceClient
  /** REQUIRED. Return false to answer 403. Runs before any body is read. */
  authorize: (request: Request, action: HandlerAction, fileId: string | null, target: HandlerTarget) => boolean | Promise<boolean>
  /** Actions this route exposes. Default: list, get, download. */
  allow?: readonly HandlerAction[]
  /** Origins allowed to POST from another origin. Default: none. */
  allowedOrigins?: readonly string[]
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } })
}

export function errorResponse(err: unknown): Response {
  if (err instanceof UntraceError) {
    const status = err.status >= 400 && err.status < 600 ? err.status : err.retryable ? 503 : err.code === "invalid_request" ? 400 : 500
    return json({ error: err.code, message: err.message, retryable: err.retryable }, status)
  }
  return json({ error: "server_error", message: "untrace: unexpected error" }, 500)
}

function isAction(v: unknown): v is HandlerAction {
  return typeof v === "string" && (HANDLER_ACTIONS as readonly string[]).includes(v)
}

export function contentDisposition(name: string): string {
  const ascii = name.replace(/[^\x20-\x7e]/g, "_").replace(/["\\]/g, "_")
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(name)}`
}

function hostOf(origin: string): string | null {
  try {
    return new URL(origin).host.toLowerCase()
  } catch {
    return null
  }
}

function csrfCheck(request: Request, url: URL, allowedOrigins: readonly string[]): Response | null {
  const forbid = (message: string) => json({ error: "forbidden", message }, 403)
  if (request.headers.get(UNTRACE_REQUEST_HEADER) !== "1") return forbid(`missing ${UNTRACE_REQUEST_HEADER}: 1 header`)
  const origin = request.headers.get("origin")
  if (origin !== null && allowedOrigins.some((o) => o.replace(/\/+$/, "").toLowerCase() === origin.toLowerCase())) return null
  const site = request.headers.get("sec-fetch-site")
  if (site && site !== "same-origin" && site !== "none") return forbid("cross-site request refused")
  if (origin === "null") return forbid("opaque origin refused")
  if (origin && hostOf(origin) !== url.host.toLowerCase()) return forbid("cross-origin request refused")
  return null
}

async function readLimited(request: Request, limit: number): Promise<string | null> {
  if (!request.body) return ""
  const reader = request.body.getReader()
  const parts: Uint8Array[] = []
  let n = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    n += value.byteLength
    if (n > limit) {
      await reader.cancel().catch(() => undefined)
      return null
    }
    parts.push(value)
  }
  const out = new Uint8Array(n)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.byteLength
  }
  return new TextDecoder().decode(out)
}

export function createUntraceHandler(opts: UntraceHandlerOptions): (request: Request) => Promise<Response> {
  if (typeof opts?.authorize !== "function") {
    throw new Error("untrace: createUntraceHandler needs an `authorize(request, action, fileId)` function")
  }
  const allow = new Set<HandlerAction>(opts.allow ?? DEFAULT_ALLOWED_ACTIONS)
  let client = opts.client ?? null
  const getClient = () => (client ??= new UntraceClient(opts))

  return async function handle(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url)
      const action: unknown = url.searchParams.get("action")
      let params: Record<string, unknown> = Object.fromEntries(url.searchParams.entries())
      let multipart = false
      if (request.method === "POST") {
        const refused = csrfCheck(request, url, opts.allowedOrigins ?? [])
        if (refused) return refused
        const type = (request.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase()
        multipart = type === "multipart/form-data"
        if (type !== "application/json" && !multipart) {
          return json({ error: "unsupported_media_type", message: "POST needs content-type application/json (multipart/form-data for upload)" }, 415)
        }
        if (multipart !== (action === "upload")) {
          return json({ error: "unsupported_media_type", message: multipart ? "only upload is multipart" : "upload must be multipart/form-data" }, 415)
        }
      } else if (request.method !== "GET") {
        return json({ error: "invalid_request", message: "method not allowed" }, 405)
      }
      if (!isAction(action)) return json({ error: "invalid_request", message: "unknown action" }, 400)
      if (WRITE_ACTIONS.has(action) !== (request.method === "POST")) {
        return json({ error: "invalid_request", message: `${action} needs ${WRITE_ACTIONS.has(action) ? "POST" : "GET"}` }, 405)
      }
      if (!allow.has(action)) return json({ error: "unsupported", message: `action ${action} is not enabled on this route` }, 403)
      const idOf = (k: string) => (typeof params[k] === "string" && params[k] ? (params[k] as string) : null)
      const fileId = idOf("fileId")
      const folderId = idOf("folderId")
      const parentId = idOf("parentId")
      if (!(await opts.authorize(request, action, fileId, { fileId, folderId, parentId }))) return json({ error: "forbidden", message: "not allowed" }, 403)

      let file: Blob | null = null
      if (request.method === "POST") {
        const limit = multipart ? MAX_MULTIPART_BODY_BYTES : MAX_JSON_BODY_BYTES
        const declared = Number(request.headers.get("content-length") ?? NaN)
        if (Number.isFinite(declared) && declared > limit) return json({ error: "payload_too_large", message: "request body too large" }, 413)
        if (multipart) {
          const form = await request.formData()
          const f = form.get("file")
          if (f && typeof f !== "string") file = f
          const name = form.get("name")
          if (typeof name === "string") params.name = name
        } else {
          const raw = await readLimited(request, limit)
          if (raw === null) return json({ error: "payload_too_large", message: "request body too large" }, 413)
          let body: unknown = {}
          if (raw.trim()) {
            try {
              body = JSON.parse(raw)
            } catch {
              return json({ error: "invalid_request", message: "invalid json" }, 400)
            }
          }
          if (!body || typeof body !== "object" || Array.isArray(body)) return json({ error: "invalid_request", message: "json body must be an object" }, 400)
          const b = body as Record<string, unknown>
          if (b.action !== undefined && b.action !== action) return json({ error: "invalid_request", message: "body action does not match the query" }, 400)
          if (b.fileId !== undefined && b.fileId !== fileId) return json({ error: "invalid_request", message: "body fileId does not match the query" }, 400)
          // The ids authorize saw are the ones acted on: the body may not override them.
          for (const k of ["folderId", "parentId"] as const) {
            if (b[k] !== undefined && params[k] !== undefined && b[k] !== params[k]) {
              return json({ error: "invalid_request", message: `body ${k} does not match the query` }, 400)
            }
          }
          params = { ...b, ...params }
        }
      }
      const need = (v: unknown, name: string): string => {
        if (typeof v !== "string" || !v) throw new UntraceError({ status: 400, code: "invalid_request", message: `missing ${name}` })
        return v
      }
      const target = (v: unknown, name: string): string | null => {
        if (v === null) return null
        return need(v, name)
      }
      const c = getClient()

      switch (action) {
        case "list": {
          const limit = params.limit == null ? undefined : Number(params.limit)
          return json(await c.files.list({ cursor: (params.cursor as string) || null, limit, folderId }))
        }
        case "folders": {
          const limit = params.limit == null ? undefined : Number(params.limit)
          const r = await c.folders.list({ cursor: (params.cursor as string) || null, limit, parentId })
          return json({ folders: r.folders.map(publicFolder), nextCursor: r.nextCursor })
        }
        case "folder":
          return json(publicFolder(await c.folders.get(need(folderId, "folderId"))))
        case "get": {
          const { wrappedKey: _drop, ...rest } = await c.files.get(need(fileId, "fileId"))
          return json(rest)
        }
        case "download": {
          const r = await c.files.download(need(fileId, "fileId"))
          return new Response(r.bytes as BodyInit, {
            headers: {
              "content-type": r.mime || "application/octet-stream",
              "content-length": String(r.bytes.length),
              "content-disposition": contentDisposition(r.name),
              "cache-control": "no-store",
            },
          })
        }
        case "upload": {
          if (!file) throw new UntraceError({ status: 400, code: "invalid_request", message: "missing file" })
          const name = typeof params.name === "string" && params.name ? params.name : ((file as { name?: string }).name || "upload")
          const r = await c.files.upload({ data: file, name, mime: file.type || undefined, folderId: need(folderId, "folderId") })
          return json({ file: r.file }, 201)
        }
        case "rename":
          return json(await c.files.rename(need(fileId, "fileId"), need(params.name, "name")))
        case "move":
          return json(await c.files.move(need(fileId, "fileId"), target(params.folderId, "folderId")))
        case "delete":
          return json(await c.files.delete(need(fileId, "fileId")))
        case "create-folder":
          return json(publicFolder(await c.folders.create({ name: need(params.name, "name"), parentId })), 201)
        case "rename-folder":
          return json(publicFolder(await c.folders.rename(need(folderId, "folderId"), need(params.name, "name"))))
        case "move-folder":
          return json(publicFolder(await c.folders.move(need(folderId, "folderId"), target(params.parentId, "parentId"))))
        case "trash-folder":
          return json(await c.folders.trash(need(folderId, "folderId")))
        case "share": {
          const { sealedKey: _s, ...share } = await c.shares.offer({
            resourceType: need(params.resourceType, "resourceType") as ResourceType,
            resourceId: need(params.resourceId, "resourceId"),
            username: need(params.username, "username"),
            role: need(params.role, "role") as GrantRole,
          })
          return json(share, 201)
        }
      }
    } catch (err) {
      return errorResponse(err)
    }
  }
}
