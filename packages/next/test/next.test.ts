import { afterEach, describe, expect, it } from "vitest"

import { UntraceClient } from "@untracenetwork/sdk"
import { createUntraceRoute, getUntrace, resetUntrace, untraceActions } from "../src/index"
import { BASE, CLIENT_ID, FOLDER_ID, SECRET, createMockDrive } from "../../core/test/mock-drive"

function route(allow?: Parameters<typeof createUntraceRoute>[0]["allow"], authorize = () => true) {
  const drive = createMockDrive()
  const client = new UntraceClient({ clientId: CLIENT_ID, clientSecret: SECRET, baseUrl: BASE, fetch: drive.handler })
  return { drive, ...createUntraceRoute({ client, authorize, allow }) }
}

function useEnv(drive = createMockDrive()) {
  process.env.UNTRACE_CLIENT_ID = CLIENT_ID
  process.env.UNTRACE_CLIENT_SECRET = SECRET
  process.env.UNTRACE_BASE_URL = BASE
  const real = globalThis.fetch
  globalThis.fetch = drive.handler
  resetUntrace()
  return () => {
    globalThis.fetch = real
    delete process.env.UNTRACE_CLIENT_ID
    delete process.env.UNTRACE_CLIENT_SECRET
    delete process.env.UNTRACE_BASE_URL
    resetUntrace()
  }
}

describe("@untracenetwork/next createUntraceRoute", () => {
  it("requires an authorize function", () => {
    expect(() => createUntraceRoute({} as never)).toThrow(/authorize/)
  })

  it("uploads via multipart and downloads the decrypted bytes, with no key material in answers", async () => {
    const { GET, POST } = route(["list", "get", "download", "upload"])
    const form = new FormData()
    form.set("file", new Blob(["%PDF-1.7 hello"], { type: "application/pdf" }), "doc.pdf")
    const up = await POST(new Request(`http://app/api/untrace?action=upload&folderId=${FOLDER_ID}`, { method: "POST", body: form, headers: { "x-untrace-request": "1" } }))
    expect(up.status).toBe(201)
    const { file } = await up.json()
    const get = await (await GET(new Request(`http://app/api/untrace?action=get&fileId=${file.fileId}`))).text()
    expect(get).not.toContain("wrappedKey")
    expect(get).not.toContain(SECRET)
    const down = await GET(new Request(`http://app/api/untrace?action=download&fileId=${file.fileId}`))
    expect(down.headers.get("content-type")).toBe("application/pdf")
    expect(await down.text()).toBe("%PDF-1.7 hello")
  })

  it("answers 403 when authorize says no", async () => {
    const { GET } = route(undefined, () => false)
    expect((await GET(new Request("http://app/api/untrace?action=list"))).status).toBe(403)
  })
})

describe("@untracenetwork/next server helpers", () => {
  let restore: () => void = () => {}
  afterEach(() => restore())

  it("getUntrace builds one shared client from env, or a fresh one from options", () => {
    restore = useEnv()
    const a = getUntrace()
    expect(getUntrace()).toBe(a)
    const b = getUntrace({ clientId: CLIENT_ID, clientSecret: SECRET, baseUrl: BASE })
    expect(b).not.toBe(a)
  })

  it("untraceActions round-trip a form upload and strip the sealed key", async () => {
    const drive = createMockDrive()
    restore = useEnv(drive)
    const form = new FormData()
    form.set("file", new File(["hi"], "a.txt", { type: "text/plain" }))
    await expect(untraceActions.uploadFromForm(form)).rejects.toThrow(/folderId/)
    form.set("folderId", FOLDER_ID)
    const file = await untraceActions.uploadFromForm(form)
    expect(file.name).toBe("a.txt")
    expect(file.folderId).toBe(FOLDER_ID)
    const { folders } = await untraceActions.listFolders()
    expect(folders.map((f: { folderId: string }) => f.folderId)).toEqual([FOLDER_ID])
    expect(folders[0]).not.toHaveProperty("sealedKey")
    const sub = await untraceActions.createFolder("Sub", FOLDER_ID)
    expect(sub).toMatchObject({ name: "Sub", parentId: FOLDER_ID })
    expect(sub).not.toHaveProperty("keyPath")
    // Like Drive: the uploading key holds an editor entry on its own file, and moving needs admin.
    await expect(untraceActions.moveFile(file.fileId, sub.folderId)).rejects.toMatchObject({ status: 404 })
    expect((await untraceActions.listFiles(null, undefined, FOLDER_ID)).files).toHaveLength(1)
    expect((await untraceActions.listFiles(null, undefined, sub.folderId)).files).toHaveLength(0)
    expect((await untraceActions.listFiles()).files).toHaveLength(1)
    const got = await untraceActions.getFile(file.fileId)
    expect(got).not.toHaveProperty("wrappedKey")
    expect(await untraceActions.renameFile(file.fileId, "b.txt")).toEqual({ fileId: file.fileId, name: "b.txt" })
    expect(await untraceActions.deleteFile(file.fileId)).toEqual({ fileId: file.fileId, trashed: true })
    await expect(untraceActions.uploadFromForm(new FormData())).rejects.toThrow(/no file/)
  })
})
