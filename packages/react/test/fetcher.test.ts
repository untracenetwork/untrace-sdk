import { describe, expect, it } from "vitest"

import { createUntraceFetcher, UntraceRouteError } from "../src/fetcher"
import * as react from "../src/index"
import * as vue from "../../vue/src/index"
import * as vueFetcher from "../../vue/src/fetcher"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

describe("browser fetcher (react + vue)", () => {
  it("calls only the developer's route, never Drive, with the anti-CSRF header on writes", async () => {
    const calls: string[] = []
    const posts: Headers[] = []
    const f = createUntraceFetcher({
      endpoint: "/api/untrace",
      fetch: (async (u: string, init?: RequestInit) => {
        calls.push(`${init?.method ?? "GET"} ${u}`)
        if (init?.method === "POST") posts.push(new Headers(init.headers))
        return new Response(JSON.stringify({ files: [], nextCursor: null }), { status: 200 })
      }) as typeof fetch,
    })
    await f.list()
    await f.list("c1")
    await f.get("id")
    await f.download("id")
    await f.rename("id", "n")
    await f.remove("id")
    await f.upload(new Blob(["x"]), "fo1", "x.txt")
    await f.upload(new Blob(["x"]), "fo1")
    await expect(f.upload(new Blob(["x"]), "")).rejects.toMatchObject({ status: 400, code: "invalid_request" })
    await f.list(null, "fo1")
    await f.move("id", "fo2")
    await f.move("id", null)
    await f.folders()
    await f.folders("fo1", "c2")
    await f.folder("fo1")
    await f.createFolder("A")
    await f.createFolder("B", "fo1")
    await f.renameFolder("fo1", "C")
    await f.moveFolder("fo1", null)
    await f.trashFolder("fo1")
    await f.share({ resourceType: "folder", resourceId: "fo1", username: "bob-user", role: "viewer" })
    expect(calls).toEqual([
      "GET /api/untrace?action=list",
      "GET /api/untrace?action=list&cursor=c1",
      "GET /api/untrace?action=get&fileId=id",
      "GET /api/untrace?action=download&fileId=id",
      "POST /api/untrace?action=rename&fileId=id",
      "POST /api/untrace?action=delete&fileId=id",
      "POST /api/untrace?action=upload&folderId=fo1",
      "POST /api/untrace?action=upload&folderId=fo1",
      "GET /api/untrace?action=list&folderId=fo1",
      "POST /api/untrace?action=move&fileId=id",
      "POST /api/untrace?action=move&fileId=id",
      "GET /api/untrace?action=folders",
      "GET /api/untrace?action=folders&parentId=fo1&cursor=c2",
      "GET /api/untrace?action=folder&folderId=fo1",
      "POST /api/untrace?action=create-folder",
      "POST /api/untrace?action=create-folder&parentId=fo1",
      "POST /api/untrace?action=rename-folder&folderId=fo1",
      "POST /api/untrace?action=move-folder&folderId=fo1",
      "POST /api/untrace?action=trash-folder&folderId=fo1",
      "POST /api/untrace?action=share",
    ])
    expect(posts).toHaveLength(12)
    expect(posts.every((h) => h.get("x-untrace-request") === "1")).toBe(true)
    expect(posts.slice(0, 2).map((h) => h.get("content-type"))).toEqual(["application/json", "application/json"])
    expect(f.downloadUrl("id")).toBe("/api/untrace?action=download&fileId=id")
    expect(createUntraceFetcher({ endpoint: "/r?x=1" }).downloadUrl("id")).toBe("/r?x=1&action=download&fileId=id")
  })

  it("throws UntraceRouteError with the route's code", async () => {
    const f = createUntraceFetcher({
      fetch: (async () => new Response(JSON.stringify({ error: "forbidden", message: "no", retryable: false }), { status: 403 })) as unknown as typeof fetch,
    })
    const e = await f.list().catch((x) => x)
    expect(e).toBeInstanceOf(UntraceRouteError)
    expect(e).toMatchObject({ status: 403, code: "forbidden", message: "no", retryable: false })
    const g = createUntraceFetcher({ fetch: (async () => new Response("oops", { status: 502 })) as unknown as typeof fetch })
    expect(await g.list().catch((x) => x)).toMatchObject({ status: 502, code: "error", message: "HTTP 502" })
  })

  it("react and vue ship the same fetcher, and import nothing from the core", () => {
    const here = (p: string) => readFileSync(fileURLToPath(new URL(p, import.meta.url)), "utf8")
    expect(here("../src/fetcher.ts")).toBe(here("../../vue/src/fetcher.ts"))
    for (const p of ["../src/index.ts", "../src/fetcher.ts", "../../vue/src/index.ts"]) {
      expect(here(p)).not.toMatch(/@untracenetwork\/sdk|@noble|subtle|untrace_sk_v1_/)
    }
    expect(typeof vueFetcher.createUntraceFetcher).toBe("function")
  })

  it("exports the hooks and composables", () => {
    expect(Object.keys(react).sort()).toEqual(["UntraceProvider", "UntraceRouteError", "createUntraceFetcher", "useUntrace", "useUntraceFiles", "useUntraceFolders", "useUntraceUpload"])
    expect(Object.keys(vue).sort()).toEqual(["UNTRACE_KEY", "UntraceRouteError", "createUntraceFetcher", "untracePlugin", "useUntrace", "useUntraceFiles", "useUntraceFolders", "useUntraceUpload"])
  })
})
