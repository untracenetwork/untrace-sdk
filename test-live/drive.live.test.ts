/**
 * Live test against a real Drive. Skipped unless UNTRACE_CLIENT_ID,
 * UNTRACE_CLIENT_SECRET and UNTRACE_BASE_URL are set. Run with `npm run test:live`
 * (or the manual "Live integration" workflow). Never part of per-push CI.
 *
 * Needs a key with the `upload`, `download` and `delete` scopes on an account
 * with an active plan. It creates one top-level folder, uploads one small file
 * into it, reads it back and trashes both.
 */
import { describe, expect, it } from "vitest"

import { UntraceAuthError, UntraceClient } from "@untracenetwork/sdk"

const enabled = Boolean(process.env.UNTRACE_CLIENT_ID && process.env.UNTRACE_CLIENT_SECRET && process.env.UNTRACE_BASE_URL)
if (!enabled) console.info("[untrace live] skipped: set UNTRACE_CLIENT_ID, UNTRACE_CLIENT_SECRET and UNTRACE_BASE_URL")

describe.skipIf(!enabled)("live Drive API v1", () => {
  it("gets a Bearer token with client credentials", async () => {
    const c = new UntraceClient()
    const t = await c.getToken()
    expect(t.accessToken.length).toBeGreaterThan(10)
    expect(t.expiresAt).toBeGreaterThan(Date.now())
  })

  it("refuses a wrong secret with invalid_client", async () => {
    const wrong = "untrace_sk_v1_" + Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url")
    const c = new UntraceClient({ clientSecret: wrong })
    await expect(c.getToken()).rejects.toBeInstanceOf(UntraceAuthError)
  })

  it("creates a folder, uploads into it, lists, downloads and trashes", async () => {
    const c = new UntraceClient()
    const folder = await c.folders.create({ name: `sdk-live ${new Date().toISOString()}` })
    try {
      expect(folder.role).toBe("admin")
      const plain = new TextEncoder().encode(`untrace sdk live ${new Date().toISOString()}`)
      const { file } = await c.files.upload({ folderId: folder.folderId, data: plain, name: "sdk-live.txt", mime: "text/plain" })
      try {
        expect(file.folderId).toBe(folder.folderId)
        const page = await c.files.list({ folderId: folder.folderId, limit: 200 })
        expect(page.files.map((f) => f.fileId)).toContain(file.fileId)
        const back = await c.files.download(file.fileId)
        expect(back.bytes).toEqual(plain)
        expect(back.name).toBe("sdk-live.txt")
      } finally {
        await c.files.delete(file.fileId)
      }
    } finally {
      await c.folders.trash(folder.folderId)
    }
  })
})
