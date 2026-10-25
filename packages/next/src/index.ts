/**
 * @untracenetwork/next: server-only helpers for Next.js (App Router).
 *
 * The client secret is read on the server (UNTRACE_CLIENT_ID /
 * UNTRACE_CLIENT_SECRET) and never reaches the browser. Importing this module
 * from a client component throws at load time.
 */
import { UntraceClient, type UntraceClientOptions } from "@untracenetwork/sdk"
import { createUntraceHandler, publicFolder, type UntraceHandlerOptions } from "@untracenetwork/sdk/backend"

if (typeof window !== "undefined") {
  throw new Error("@untracenetwork/next is server-only. Use @untracenetwork/react in client components.")
}

export { UntraceClient }
export { DEFAULT_ALLOWED_ACTIONS, HANDLER_ACTIONS, type HandlerAction, type UntraceHandlerOptions } from "@untracenetwork/sdk/backend"

/**
 * Route handler factory for `app/api/untrace/route.ts`:
 *
 *   export const { GET, POST } = createUntraceRoute({ authorize: async () => !!(await auth()) })
 *   export const runtime = "nodejs"
 */
export function createUntraceRoute(opts: UntraceHandlerOptions): {
  GET: (request: Request) => Promise<Response>
  POST: (request: Request) => Promise<Response>
} {
  const handle = createUntraceHandler(opts)
  return { GET: handle, POST: handle }
}

let shared: UntraceClient | null = null

/** One UntraceClient per server process, built from env. Use in server actions and route handlers. */
export function getUntrace(opts?: UntraceClientOptions): UntraceClient {
  if (opts) return new UntraceClient(opts)
  return (shared ??= new UntraceClient())
}

/** @internal Tests only. */
export function resetUntrace(): void {
  shared = null
}

/**
 * Server action helpers. Wrap them in your own `"use server"` functions after
 * checking the session:
 *
 *   "use server"
 *   export async function listMyFiles() { await requireUser(); return untraceActions.listFiles() }
 *
 * Results are plain JSON with no key material.
 */
export const untraceActions = {
  async listFiles(cursor?: string | null, limit?: number, folderId?: string | null) {
    return getUntrace().files.list({ cursor, limit, folderId })
  },
  /** Top-level folders the key was added to, or the subfolders of `parentId`. No key material. */
  async listFolders(parentId?: string | null, cursor?: string | null) {
    const r = await getUntrace().folders.list({ parentId, cursor })
    return { folders: r.folders.map(publicFolder), nextCursor: r.nextCursor }
  },
  async createFolder(name: string, parentId?: string | null) {
    return publicFolder(await getUntrace().folders.create({ name, parentId }))
  },
  async getFile(fileId: string) {
    const { wrappedKey: _w, ...file } = await getUntrace().files.get(fileId)
    return file
  },
  /**
   * Upload from a form: `<form action={uploadAction}>` with an `<input type="file" name="file">`
   * and the target folder, either as `folderId` here or as a `folderId` form field.
   * A key only uploads into a folder it was added to.
   */
  async uploadFromForm(form: FormData, field = "file", folderId?: string) {
    const file = form.get(field)
    if (!file || typeof file === "string") throw new Error("untrace: no file in the form")
    const target = folderId ?? form.get("folderId")
    if (typeof target !== "string" || !target) throw new Error("untrace: no folderId for the upload")
    const r = await getUntrace().files.upload({ data: file, name: (file as File).name || "upload", mime: file.type || undefined, folderId: target })
    return r.file
  },
  async moveFile(fileId: string, folderId: string | null) {
    return getUntrace().files.move(fileId, folderId)
  },
  async renameFile(fileId: string, name: string) {
    return getUntrace().files.rename(fileId, name)
  },
  async deleteFile(fileId: string) {
    return getUntrace().files.delete(fileId)
  },
}
