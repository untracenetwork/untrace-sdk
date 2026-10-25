import { describe, expect, it } from "vitest"
import { createApp, ref } from "vue"

import { untracePlugin, useUntrace, useUntraceFiles, useUntraceFolders, useUntraceUpload, UNTRACE_KEY } from "../src/index"

const okFetch = (files: unknown[] = []) =>
  (async (_u: string, init?: RequestInit) =>
    init?.method === "POST"
      ? new Response(JSON.stringify({ file: { fileId: "f", name: "x" } }), { status: 201 })
      : new Response(JSON.stringify({ files, nextCursor: null }), { status: 200 })) as unknown as typeof fetch

/** Run a composable inside an app context (inject works), with no DOM. */
async function run<T>(setup: () => T, fetchImpl: typeof fetch): Promise<T> {
  const app = createApp({ render: () => null })
  app.use(untracePlugin, { endpoint: "/api/untrace", fetch: fetchImpl })
  return app.runWithContext(setup)
}

describe("@untracenetwork/vue", () => {
  it("the plugin provides a fetcher", () => {
    let provided: unknown
    const app = { provide: (k: unknown, v: unknown) => (provided = k === UNTRACE_KEY ? v : null) }
    untracePlugin.install(app as never, { endpoint: "/x" })
    expect((provided as { downloadUrl: (id: string) => string }).downloadUrl("a")).toBe("/x?action=download&fileId=a")
  })

  it("useUntrace falls back to the default route outside an app", () => {
    expect(useUntrace().downloadUrl("a")).toBe("/api/untrace?action=download&fileId=a")
  })

  it("useUntraceFiles refreshes and reports errors", async () => {
    const files = await run(() => useUntraceFiles({ immediate: false }), okFetch([{ fileId: "a" }]))
    await files.refresh()
    expect(files.files.value).toEqual([{ fileId: "a" }])
    expect(files.loading.value).toBe(false)
    const bad = await run(() => useUntraceFiles({ immediate: false }), (async () => new Response("{}", { status: 500 })) as unknown as typeof fetch)
    await bad.refresh()
    expect(bad.error.value).toBeTruthy()
  })

  it("useUntraceFiles and useUntraceFolders read a reactive folder id on each refresh", async () => {
    const urls: string[] = []
    const rec = (async (u: string) => {
      urls.push(u)
      return new Response(JSON.stringify(u.includes("action=folders") ? { folders: [{ folderId: "fo1" }], nextCursor: null } : { files: [], nextCursor: null }), { status: 200 })
    }) as unknown as typeof fetch
    const id = ref<string | null>(null)
    const files = await run(() => useUntraceFiles({ immediate: false, folderId: id }), rec)
    await files.refresh()
    id.value = "fo1"
    await files.refresh()
    const folders = await run(() => useUntraceFolders({ immediate: false, parentId: () => id.value }), rec)
    await folders.refresh()
    expect(folders.folders.value).toEqual([{ folderId: "fo1" }])
    expect(urls).toEqual(["/api/untrace?action=list", "/api/untrace?action=list&folderId=fo1", "/api/untrace?action=folders&parentId=fo1"])
    const bad = await run(() => useUntraceFolders({ immediate: false }), (async () => new Response("{}", { status: 500 })) as unknown as typeof fetch)
    await bad.refresh()
    expect(bad.error.value).toBeTruthy()
  })

  it("useUntraceUpload tracks state and rethrows", async () => {
    const up = await run(() => useUntraceUpload(), okFetch())
    expect(await up.upload(new Blob(["x"]), "fo1", "x")).toEqual({ file: { fileId: "f", name: "x" } })
    expect(up.uploading.value).toBe(false)
    const bad = await run(() => useUntraceUpload(), (async () => new Response("{}", { status: 403 })) as unknown as typeof fetch)
    await expect(bad.upload(new Blob(["x"]), "fo1")).rejects.toThrow()
    expect(bad.error.value).toBeTruthy()
  })
})
