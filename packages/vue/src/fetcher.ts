/**
 * Browser-side fetcher for the Untrace backend route protocol. It
 * talks only to your own route and never imports the SDK core, so no secret
 * and no key material ship to the browser.
 */

export type Role = "owner" | "admin" | "editor" | "viewer"

export interface FileSummary {
  fileId: string
  name: string
  size: number
  mime: string
  role: Role
  createdAt: string
  folderId?: string | null
}

/** Folder metadata as the route answers it: no sealed key, no key path. */
export interface FolderSummary {
  folderId: string
  name: string
  parentId: string | null
  role: Role
  boxPublicKey: string
  createdAt: string
}

export interface ShareOffer {
  shareId: string
  resourceType: "folder" | "file"
  resourceId: string
  role: "admin" | "editor" | "viewer"
  from: string
  createdAt: string
}

export class UntraceRouteError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly retryable: boolean
  ) {
    super(message)
    this.name = "UntraceRouteError"
  }
}

export interface UntraceFetcher {
  /** Files you can see; pass `folderId` to list one folder. */
  list(cursor?: string | null, folderId?: string | null): Promise<{ files: FileSummary[]; nextCursor: string | null }>
  get(fileId: string): Promise<FileSummary>
  /** The decrypted file as a Blob (your server decrypts it). */
  download(fileId: string): Promise<Blob>
  /** A URL for an <a href download> link. Your route decides who may use it. */
  downloadUrl(fileId: string): string
  /** Upload into a folder. A key only uploads into a folder it was added to. */
  upload(file: Blob, folderId: string, name?: string): Promise<{ file: FileSummary }>
  rename(fileId: string, name: string): Promise<{ fileId: string; name: string }>
  /** Move a file into another folder (`null`: top level). */
  move(fileId: string, folderId: string | null): Promise<{ fileId: string; name: string; folderId?: string | null }>
  remove(fileId: string): Promise<{ fileId: string; trashed: boolean }>
  /** Top-level folders you were added to, or the subfolders of `parentId`. */
  folders(parentId?: string | null, cursor?: string | null): Promise<{ folders: FolderSummary[]; nextCursor: string | null }>
  folder(folderId: string): Promise<FolderSummary>
  createFolder(name: string, parentId?: string | null): Promise<FolderSummary>
  renameFolder(folderId: string, name: string): Promise<FolderSummary>
  moveFolder(folderId: string, parentId: string | null): Promise<FolderSummary>
  trashFolder(folderId: string): Promise<{ removed: true }>
  /** Offer a folder or file to a Drive username. Your server seals the key to their published sharing key. */
  share(input: { resourceType: "folder" | "file"; resourceId: string; username: string; role: "admin" | "editor" | "viewer" }): Promise<ShareOffer>
}

export function createUntraceFetcher(opts: { endpoint?: string; fetch?: typeof fetch } = {}): UntraceFetcher {
  const endpoint = opts.endpoint ?? "/api/untrace"
  const f = (input: string, init?: RequestInit) => (opts.fetch ?? globalThis.fetch)(input, init)
  const q = (params: Record<string, string | null | undefined>) => {
    const s = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) if (v) s.set(k, v)
    return `${endpoint}${endpoint.includes("?") ? "&" : "?"}${s.toString()}`
  }
  async function check(res: Response): Promise<Response> {
    if (res.ok) return res
    const body = (await res.json().catch(() => ({}))) as { error?: string; message?: string; retryable?: boolean }
    throw new UntraceRouteError(res.status, body.error ?? "error", body.message ?? `HTTP ${res.status}`, Boolean(body.retryable))
  }
  const getJson = async <T>(params: Record<string, string | null | undefined>) =>
    (await check(await f(q(params), { credentials: "same-origin" }))).json() as Promise<T>
  // Writes: the anti-CSRF header and a JSON content type a cross-site HTML form cannot send.
  // Ids go in the query string, so the route's authorize() sees them before the body.
  const postJson = async <T>(params: Record<string, string | null | undefined>, body: Record<string, unknown> = {}) =>
    (
      await check(
        await f(q(params), {
          method: "POST",
          credentials: "same-origin",
          headers: { "content-type": "application/json", "x-untrace-request": "1" },
          body: JSON.stringify(body),
        })
      )
    ).json() as Promise<T>

  return {
    list: (cursor, folderId) => getJson({ action: "list", cursor, folderId }),
    get: (fileId) => getJson({ action: "get", fileId }),
    download: async (fileId) => (await check(await f(q({ action: "download", fileId }), { credentials: "same-origin" }))).blob(),
    downloadUrl: (fileId) => q({ action: "download", fileId }),
    upload: async (file, folderId, name) => {
      if (!folderId) throw new UntraceRouteError(400, "invalid_request", "upload needs a folderId", false)
      const form = new FormData()
      form.set("file", file)
      if (name) form.set("name", name)
      const res = await f(q({ action: "upload", folderId }), { method: "POST", credentials: "same-origin", headers: { "x-untrace-request": "1" }, body: form })
      return (await check(res)).json()
    },
    rename: (fileId, name) => postJson({ action: "rename", fileId }, { name }),
    move: (fileId, folderId) => postJson({ action: "move", fileId }, { folderId }),
    remove: (fileId) => postJson({ action: "delete", fileId }),
    folders: (parentId, cursor) => getJson({ action: "folders", parentId, cursor }),
    folder: (folderId) => getJson({ action: "folder", folderId }),
    createFolder: (name, parentId) => postJson({ action: "create-folder", parentId }, { name }),
    renameFolder: (folderId, name) => postJson({ action: "rename-folder", folderId }, { name }),
    moveFolder: (folderId, parentId) => postJson({ action: "move-folder", folderId }, { parentId }),
    trashFolder: (folderId) => postJson({ action: "trash-folder", folderId }),
    share: (input) => postJson({ action: "share" }, { ...input }),
  }
}
