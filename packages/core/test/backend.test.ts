import { describe, expect, it } from "vitest"

import { UntraceClient } from "../src/index"
import { createUntraceHandler, contentDisposition, HANDLER_ACTIONS, errorResponse, type HandlerAction } from "../src/backend"
import { UntraceError } from "../src/errors"
import { BASE, CLIENT_ID, FOLDER_ID, SECRET, createMockDrive } from "./mock-drive"

const ALL: HandlerAction[] = ["list", "get", "download", "upload", "rename", "delete"]

function handler(allow?: readonly HandlerAction[], authorize: (...a: unknown[]) => boolean = () => true, extra: { allowedOrigins?: string[] } = {}) {
  const drive = createMockDrive()
  const client = new UntraceClient({ clientId: CLIENT_ID, clientSecret: SECRET, baseUrl: BASE, fetch: drive.handler })
  return { drive, handle: createUntraceHandler({ client, authorize, allow, ...extra }) }
}

const post = (url: string, body: BodyInit, headers: Record<string, string> = {}) =>
  new Request(url, { method: "POST", body, headers: { "x-untrace-request": "1", ...headers } })
const jsonPost = (url: string, body: unknown, headers: Record<string, string> = {}) =>
  post(url, JSON.stringify(body), { "content-type": "application/json", ...headers })

async function uploadVia(handle: (r: Request) => Promise<Response>, data = "hello", name = "a.txt") {
  const form = new FormData()
  form.set("file", new Blob([data], { type: "text/plain" }), name)
  return handle(post(`http://app/api/untrace?action=upload&folderId=${FOLDER_ID}`, form))
}

describe("backend handler", () => {
  it("needs authorize", () => {
    expect(() => createUntraceHandler({} as never)).toThrow(/authorize/)
  })

  it("is read-only by default", async () => {
    const { handle } = handler()
    expect((await uploadVia(handle)).status).toBe(403)
    expect((await handle(new Request("http://app/api/untrace?action=list"))).status).toBe(200)
  })

  it("uploads, lists, gets (no sealed key), downloads, renames, deletes", async () => {
    const { handle } = handler(ALL)
    const up = await uploadVia(handle, "hello world", "é.txt")
    expect(up.status).toBe(201)
    const { file } = await up.json()
    const list = await (await handle(new Request("http://app/api/untrace?action=list&limit=10"))).json()
    expect(list.files).toHaveLength(1)
    const get = await handle(new Request(`http://app/api/untrace?action=get&fileId=${file.fileId}`))
    const getText = await get.text()
    expect(getText).not.toContain("wrappedKey")
    const down = await handle(new Request(`http://app/api/untrace?action=download&fileId=${file.fileId}`))
    expect(await down.text()).toBe("hello world")
    expect(down.headers.get("content-type")).toBe("text/plain")
    expect(down.headers.get("content-disposition")).toContain("filename*=UTF-8''%C3%A9.txt")
    expect(down.headers.get("cache-control")).toBe("no-store")
    const ren = await handle(jsonPost(`http://app/api/untrace?action=rename&fileId=${file.fileId}`, { name: "b.txt" }))
    expect(await ren.json()).toEqual({ fileId: file.fileId, name: "b.txt" })
    const del = await handle(jsonPost(`http://app/api/untrace?action=delete&fileId=${file.fileId}`, {}))
    expect(await del.json()).toEqual({ fileId: file.fileId, trashed: true })
  })

  it("serves folders, moves and shares with no key material, and passes every query id to authorize", async () => {
    const seen: unknown[] = []
    const drive = createMockDrive({ scopes: ["download", "upload", "delete", "manage-sharing"] })
    const client = new UntraceClient({ clientId: CLIENT_ID, clientSecret: SECRET, baseUrl: BASE, fetch: drive.handler })
    const handle = createUntraceHandler({
      client,
      allow: HANDLER_ACTIONS,
      authorize: (_r, action, _f, target) => {
        seen.push([action, target])
        return true
      },
    })
    const noKeys = (t: string) => {
      expect(t).not.toMatch(/sealedKey|keyPath|wrappedKey/)
      return JSON.parse(t)
    }
    const { folders } = noKeys(await (await handle(new Request("http://app/api/untrace?action=folders"))).text())
    expect(folders.map((f: { folderId: string }) => f.folderId)).toEqual([FOLDER_ID])
    noKeys(await (await handle(new Request(`http://app/api/untrace?action=folder&folderId=${FOLDER_ID}`))).text())
    const made = await handle(jsonPost(`http://app/api/untrace?action=create-folder&parentId=${FOLDER_ID}`, { name: "Sub" }))
    expect(made.status).toBe(201)
    const sub = noKeys(await made.text())
    expect(sub).toMatchObject({ name: "Sub", parentId: FOLDER_ID })
    const top = noKeys(await (await handle(jsonPost("http://app/api/untrace?action=create-folder", { name: "Top" }))).text())
    expect(noKeys(await (await handle(jsonPost(`http://app/api/untrace?action=rename-folder&folderId=${sub.folderId}`, { name: "Sub2" }))).text()).name).toBe("Sub2")
    const moved = noKeys(await (await handle(jsonPost(`http://app/api/untrace?action=move-folder&folderId=${sub.folderId}`, { parentId: top.folderId }))).text())
    expect(moved.parentId).toBe(top.folderId)
    // A body may not override the id authorize saw.
    expect((await handle(jsonPost(`http://app/api/untrace?action=move-folder&folderId=${sub.folderId}&parentId=${FOLDER_ID}`, { parentId: top.folderId }))).status).toBe(400)
    const share = await handle(jsonPost("http://app/api/untrace?action=share", { resourceType: "folder", resourceId: top.folderId, username: "bob-user", role: "viewer" }))
    expect(share.status).toBe(201)
    expect(noKeys(await share.text())).toMatchObject({ resourceType: "folder", resourceId: top.folderId, role: "viewer" })
    expect((await uploadVia(handle)).status).toBe(201)
    const noFolder = new FormData()
    noFolder.set("file", new Blob(["x"]), "x")
    expect(await (await handle(post("http://app/api/untrace?action=upload", noFolder))).json()).toMatchObject({ error: "invalid_request", message: "missing folderId" })
    expect((await handle(jsonPost(`http://app/api/untrace?action=trash-folder&folderId=${top.folderId}`, {}))).status).toBe(200)
    expect(seen).toContainEqual(["create-folder", { fileId: null, folderId: null, parentId: FOLDER_ID }])
    expect(seen).toContainEqual(["rename-folder", { fileId: null, folderId: sub.folderId, parentId: null }])
  })

  it("maps folder_access_required to 403 for the browser", async () => {
    const { drive, handle } = handler(ALL)
    const ro = await drive.addFolder({ name: "ro", mine: true, role: "viewer" })
    const form = new FormData()
    form.set("file", new Blob(["x"]), "x")
    const r = await handle(post(`http://app/api/untrace?action=upload&folderId=${ro.folderId}`, form))
    expect(r.status).toBe(403)
    expect(await r.json()).toMatchObject({ error: "folder_access_required", retryable: false })
  })

  it("uses the form name over the file name", async () => {
    const { drive, handle } = handler(ALL)
    const form = new FormData()
    form.set("file", new Blob(["x"]), "orig.txt")
    form.set("name", "chosen.txt")
    const r = await handle(post(`http://app/api/untrace?action=upload&folderId=${FOLDER_ID}`, form))
    expect((await r.json()).file.name).toBe("chosen.txt")
    expect([...drive.files.values()][0]!.name).toBe("chosen.txt")
  })

  it("never sends plaintext or secrets to Drive through the route", async () => {
    const { drive, handle } = handler(ALL)
    await uploadVia(handle, "top secret payload")
    for (const r of drive.requests) {
      expect(Buffer.from(r.body).includes(Buffer.from("top secret payload"))).toBe(false)
      expect(JSON.stringify(r.headers)).not.toContain("untrace_sk_v1_")
    }
  })

  it("runs authorize before the body and passes action + fileId", async () => {
    const seen: unknown[] = []
    const { handle } = handler(ALL, (_req, action, fileId) => {
      seen.push([action, fileId])
      return false
    })
    const r = await handle(jsonPost("http://app/api/untrace?action=delete&fileId=abc", {}))
    expect(r.status).toBe(403)
    expect(seen).toEqual([["delete", "abc"]])
  })

  it.each([
    ["missing anti-CSRF header", new Request("http://app/api/untrace?action=delete&fileId=x", { method: "POST", body: "{}", headers: { "content-type": "application/json" } }), 403],
    ["cross-site fetch", jsonPost("http://app/api/untrace?action=delete&fileId=x", {}, { "sec-fetch-site": "cross-site" }), 403],
    ["foreign origin", jsonPost("http://app/api/untrace?action=delete&fileId=x", {}, { origin: "https://evil.example" }), 403],
    ["opaque origin", jsonPost("http://app/api/untrace?action=delete&fileId=x", {}, { origin: "null" }), 403],
    ["form content type", post("http://app/api/untrace?action=delete&fileId=x", "a=b", { "content-type": "application/x-www-form-urlencoded" }), 415],
    ["json upload", jsonPost("http://app/api/untrace?action=upload", {}), 415],
    ["multipart delete", post("http://app/api/untrace?action=delete&fileId=x", new FormData()), 415],
    ["unknown action", new Request("http://app/api/untrace?action=nope"), 400],
    ["PUT", new Request("http://app/api/untrace?action=list", { method: "PUT" }), 405],
    ["delete via GET", new Request("http://app/api/untrace?action=delete&fileId=x"), 405],
    ["list via POST", jsonPost("http://app/api/untrace?action=list", {}), 405],
    ["bad json", post("http://app/api/untrace?action=delete&fileId=x", "{", { "content-type": "application/json" }), 400],
    ["array json", jsonPost("http://app/api/untrace?action=delete&fileId=x", []), 400],
    ["body action mismatch", jsonPost("http://app/api/untrace?action=delete&fileId=x", { action: "rename" }), 400],
    ["body fileId mismatch", jsonPost("http://app/api/untrace?action=delete&fileId=x", { fileId: "y" }), 400],
    ["declared too large", jsonPost("http://app/api/untrace?action=delete&fileId=x", {}, { "content-length": String(10 * 1024 * 1024) }), 413],
    ["actual too large", jsonPost("http://app/api/untrace?action=rename&fileId=x", { name: "x".repeat(70 * 1024) }), 413],
    ["upload without file", post("http://app/api/untrace?action=upload", new FormData()), 400],
    ["rename without name", jsonPost("http://app/api/untrace?action=rename&fileId=11111111-1111-4111-8111-111111111111", {}), 400],
    ["get without fileId", new Request("http://app/api/untrace?action=get"), 400],
  ])("refuses %s", async (_n, req, status) => {
    const { handle } = handler(ALL)
    expect((await handle(req as Request)).status).toBe(status)
  })

  it("accepts an allowed foreign origin and same-origin requests", async () => {
    const { handle } = handler(ALL, () => true, { allowedOrigins: ["https://app.example/"] })
    const ok = await handle(jsonPost("http://app/api/untrace?action=delete&fileId=11111111-1111-4111-8111-111111111111", {}, { origin: "https://app.example" }))
    expect(ok.status).toBe(404) // reached Drive: the file does not exist
    const same = await handle(jsonPost("http://app/api/untrace?action=delete&fileId=11111111-1111-4111-8111-111111111111", {}, { origin: "http://app", "sec-fetch-site": "same-origin" }))
    expect(same.status).toBe(404)
  })

  it("maps SDK errors to JSON with status", async () => {
    const { handle } = handler()
    const r = await handle(new Request("http://app/api/untrace?action=get&fileId=11111111-1111-4111-8111-111111111111"))
    expect(r.status).toBe(404)
    expect(await r.json()).toMatchObject({ error: "not_found", retryable: false })
    const bad = await handle(new Request("http://app/api/untrace?action=get&fileId=nope"))
    expect(bad.status).toBe(400)
  })

  it("builds the client from options when none is given", async () => {
    const drive = createMockDrive()
    const handle = createUntraceHandler({ clientId: CLIENT_ID, clientSecret: SECRET, baseUrl: BASE, fetch: drive.handler, authorize: () => true })
    expect((await handle(new Request("http://app/api/untrace?action=list"))).status).toBe(200)
  })

  it("errorResponse and contentDisposition", async () => {
    expect((await errorResponse(new Error("x")).json()).error).toBe("server_error")
    expect(errorResponse(new UntraceError({ status: 0, code: "network", message: "" }, true)).status).toBe(503)
    expect(errorResponse(new UntraceError({ status: 0, code: "integrity", message: "" })).status).toBe(500)
    expect(contentDisposition('a"b\\c.txt')).toContain('filename="a_b_c.txt"')
  })
})
