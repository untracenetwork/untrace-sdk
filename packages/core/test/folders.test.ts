import { describe, expect, it } from "vitest"

import {
  deriveFolderBoxKeys,
  FOLDER_BOX_INFO,
  openKeyPath,
  openSealed,
  randomBytes,
  sealToPublicKey,
  UntraceClient,
  UntraceConflictError,
  UntraceFolderAccessError,
  UntraceIntegrityError,
  UntraceNotFoundError,
  UntraceScopeError,
  deriveClientKeys,
  encryptUte1,
  newFileKey,
} from "../src/index"
import { toBase64 } from "../src/encoding"
import { BASE, CLIENT_ID, FOLDER_ID, RAW_SECRET, SECRET, createMockDrive, type MockOptions } from "./mock-drive"

const ALL = ["download", "upload", "manage-sharing", "delete"]

function setup(mock: MockOptions = {}) {
  const drive = createMockDrive({ scopes: ALL, ...mock })
  const client = new UntraceClient({ clientId: CLIENT_ID, clientSecret: SECRET, baseUrl: BASE, fetch: drive.handler, retryBaseMs: 1 })
  return { drive, client }
}

const text = (s: string) => new TextEncoder().encode(s)
const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i])

describe("folder box keys", () => {
  it("derives a stable X25519 pair from the folder key under the public label", async () => {
    expect(FOLDER_BOX_INFO).toBe("untrace:folder-key:box:v1")
    const k = randomBytes(32)
    const a = await deriveFolderBoxKeys(k)
    const b = await deriveFolderBoxKeys(k)
    expect(sameBytes(a.publicKey, b.publicKey)).toBe(true)
    expect(a.publicKey).toHaveLength(32)
    expect(sameBytes(a.publicKey, (await deriveFolderBoxKeys(randomBytes(32))).publicKey)).toBe(false)
    // A key sealed to the folder's public key opens with the folder's secret key.
    const child = randomBytes(32)
    expect(sameBytes(openSealed(sealToPublicKey(child, a.publicKey), a.secretKey), child)).toBe(true)
    await expect(deriveFolderBoxKeys(new Uint8Array(31))).rejects.toThrow()
  })

  it("openKeyPath walks folder keys down a path", async () => {
    const top = randomBytes(32)
    const mid = randomBytes(32)
    const leaf = randomBytes(32)
    const path = [sealToPublicKey(mid, (await deriveFolderBoxKeys(top)).publicKey), sealToPublicKey(leaf, (await deriveFolderBoxKeys(mid)).publicKey)]
    expect(sameBytes(await openKeyPath(top, path), leaf)).toBe(true)
    expect(sameBytes(await openKeyPath(top, []), top)).toBe(true)
    await expect(openKeyPath(randomBytes(32), path)).rejects.toThrow()
  })
})

describe("folders", () => {
  it("lists the folders the key was added to and opens their keys", async () => {
    const { drive, client } = setup()
    const { folders, nextCursor } = await client.folders.list()
    expect(folders.map((f) => f.folderId)).toEqual([FOLDER_ID])
    expect(nextCursor).toBeNull()
    expect(folders[0]).toMatchObject({ role: "admin", keyPath: [], parentId: null })
    const key = await client.resourceKey({ type: "folder", id: FOLDER_ID })
    expect(sameBytes(key, drive.folderKey(FOLDER_ID)!)).toBe(true)
  })

  it("creates a top-level folder: only its public key and sealed copies leave the client", async () => {
    const { drive, client } = setup()
    const f = await client.folders.create({ name: "Reports" })
    expect(f).toMatchObject({ name: "Reports", parentId: null, role: "admin" })
    const req = drive.requests.find((r) => r.method === "POST" && r.url.endsWith("/api/v1/folders"))!
    const body = JSON.parse(new TextDecoder().decode(req.body))
    expect(Object.keys(body).sort()).toEqual(["boxPublicKey", "name", "ownerSealedKey", "parentId", "sealedKey"])
    // The owner opens the same folder key, and its public key matches.
    const stored = drive.folders.get(f.folderId)!
    const ownerKey = drive.openOwnerFolderKey(stored)
    expect(toBase64((await deriveFolderBoxKeys(ownerKey)).publicKey)).toBe(stored.boxPublicKey)
    expect(sameBytes(await client.resourceKey({ type: "folder", id: f.folderId }), ownerKey)).toBe(true)
  })

  it("creates a subfolder sealed to the parent's checked public key and reaches it by key path", async () => {
    const { drive, client } = setup()
    const sub = await client.folders.create({ name: "Q3", parentId: FOLDER_ID })
    expect(sub).toMatchObject({ parentId: FOLDER_ID, role: "admin" })
    expect(sub.keyPath).toHaveLength(1)
    const body = JSON.parse(new TextDecoder().decode(drive.requests.filter((r) => r.method === "POST" && r.url.endsWith("/api/v1/folders")).at(-1)!.body))
    expect(Object.keys(body).sort()).toEqual(["boxPublicKey", "name", "parentId", "parentSealedKey"])
    const deep = await client.folders.create({ name: "Week 1", parentId: sub.folderId })
    expect(deep.keyPath).toHaveLength(2)
    const key = await client.resourceKey({ type: "folder", id: deep.folderId })
    expect(toBase64((await deriveFolderBoxKeys(key)).publicKey)).toBe(deep.boxPublicKey)
    expect((await client.folders.list({ parentId: FOLDER_ID })).folders.map((f) => f.name)).toEqual(["Q3"])
  })

  it("refuses to seal to a folder public key that does not match the folder key", async () => {
    const fake = toBase64((await deriveFolderBoxKeys(randomBytes(32))).publicKey)
    const { drive, client } = setup({ fakeFolderBox: fake })
    await expect(client.folders.create({ name: "x", parentId: FOLDER_ID })).rejects.toBeInstanceOf(UntraceIntegrityError)
    await expect(client.files.upload({ folderId: FOLDER_ID, data: text("x"), name: "a" })).rejects.toBeInstanceOf(UntraceIntegrityError)
    expect(drive.requests.some((r) => r.method === "POST" && /\/folders$|\/files\/upload$/.test(r.url))).toBe(false)
  })

  it("renames, moves (sealing to the new parent or the owner) and trashes", async () => {
    const { drive, client } = setup()
    const a = await client.folders.create({ name: "A", parentId: FOLDER_ID })
    const b = await client.folders.create({ name: "B" })
    expect((await client.folders.rename(a.folderId, "A2")).name).toBe("A2")
    const moved = await client.folders.move(a.folderId, b.folderId)
    expect(moved.parentId).toBe(b.folderId)
    expect(sameBytes(await client.resourceKey({ type: "folder", id: a.folderId }), drive.folderKey(a.folderId) ?? (await client.resourceKey({ type: "folder", id: a.folderId })))).toBe(true)
    const top = await client.folders.move(a.folderId, null)
    expect(top.parentId).toBeNull()
    // The owner opens the copy sealed to the owner's sharing key.
    const ownerKey = drive.openOwnerFolderKey(drive.folders.get(a.folderId)!)
    expect(toBase64((await deriveFolderBoxKeys(ownerKey)).publicKey)).toBe(drive.folders.get(a.folderId)!.boxPublicKey)
    await expect(client.folders.move(b.folderId, b.folderId)).rejects.toBeInstanceOf(UntraceConflictError)
    expect(await client.folders.trash(b.folderId)).toEqual({ removed: true })
    await expect(client.folders.get(b.folderId)).rejects.toBeInstanceOf(UntraceNotFoundError)
  })

  it("validates ids and names before any request", async () => {
    const { drive, client } = setup()
    await expect(client.folders.get("nope")).rejects.toThrow(/folderId/)
    await expect(client.folders.create({ name: "" })).rejects.toThrow(/name/)
    await expect(client.folders.create({ name: "x", parentId: "bad" })).rejects.toThrow(/parentId/)
    await expect(client.folders.move(FOLDER_ID, "bad")).rejects.toThrow(/parentId/)
    await expect(client.folders.list({ limit: 0 })).rejects.toThrow()
    expect(drive.requests).toHaveLength(0)
  })
})

describe("files in folders", () => {
  it("upload requires a folderId and sends the folder-sealed copy", async () => {
    const { drive, client } = setup()
    await expect(client.files.upload({ data: text("x"), name: "a" } as never)).rejects.toThrow(/folderId is required/)
    await expect(client.files.upload({ folderId: "bad", data: text("x"), name: "a" })).rejects.toThrow(/folderId/)
    const { file } = await client.files.upload({ folderId: FOLDER_ID, data: text("hello"), name: "a.txt" })
    expect(file.folderId).toBe(FOLDER_ID)
    const up = drive.requests.find((r) => r.url.endsWith("/files/upload"))!
    expect(up.headers["x-untrace-folder-id"]).toBe(FOLDER_ID)
    const stored = drive.files.get(file.fileId)!
    // The folder-sealed copy opens with the folder's secret key to the same file key the owner holds.
    const { secretKey } = await deriveFolderBoxKeys(drive.folderKey(FOLDER_ID)!)
    expect(sameBytes(openSealed(stored.folderSealedKey!, secretKey), drive.openOwnerKey(stored))).toBe(true)
  })

  it("maps 403 folder_access_required to UntraceFolderAccessError", async () => {
    const { drive, client } = setup()
    const viewer = await drive.addFolder({ name: "ro", mine: true, role: "viewer" })
    const err = await client.files.upload({ folderId: viewer.folderId, data: text("x"), name: "a" }).catch((e) => e)
    expect(err).toBeInstanceOf(UntraceFolderAccessError)
    expect(err).toMatchObject({ status: 403, code: "folder_access_required", retryable: false })
    // A folder this key is not in at all: the folder lookup is a 404 before anything is sealed.
    const other = await drive.addFolder({ name: "theirs" })
    await expect(client.files.upload({ folderId: other.folderId, data: text("x"), name: "a" })).rejects.toBeInstanceOf(UntraceNotFoundError)
  })

  it("downloads a file reached through a folder entry by walking the key path", async () => {
    const { drive, client } = setup()
    const sub = await drive.addFolder({ name: "deep", parentId: FOLDER_ID })
    const fileKey = newFileKey()
    const plain = text("from a teammate")
    const { secretKey: _s, publicKey } = await deriveFolderBoxKeys(drive.folderKey(sub.folderId)!)
    drive.addFile({
      fileId: "22222222-2222-4222-8222-222222222222",
      name: "t.txt",
      mime: "text/plain",
      body: await encryptUte1(plain, fileKey),
      selfKey: "",
      ownerKey: "",
      folderId: sub.folderId,
      folderSealedKey: sealToPublicKey(fileKey, publicKey),
    })
    const meta = await client.files.get("22222222-2222-4222-8222-222222222222")
    expect(meta.keyPath).toHaveLength(2)
    expect(meta.role).toBe("admin")
    const r = await client.files.download("22222222-2222-4222-8222-222222222222")
    expect(new TextDecoder().decode(r.bytes)).toBe("from a teammate")
    expect((await client.files.list({ folderId: sub.folderId })).files).toHaveLength(1)
  })

  it("a block entry (none) on a subfolder hides what is below it", async () => {
    const { drive, client } = setup()
    const blocked = await drive.addFolder({ name: "hr", parentId: FOLDER_ID, mine: true, role: "none" })
    await expect(client.folders.get(blocked.folderId)).rejects.toBeInstanceOf(UntraceNotFoundError)
    expect((await client.folders.list({ parentId: FOLDER_ID })).folders).toHaveLength(0)
  })

  it("moves a file it administers into another folder, sealed to that folder", async () => {
    const { drive, client } = setup()
    const dest = await client.folders.create({ name: "Archive" })
    const fileKey = newFileKey()
    const me = await deriveClientKeys(RAW_SECRET)
    drive.addFile({
      fileId: "33333333-3333-4333-8333-333333333333",
      name: "m.txt",
      mime: "text/plain",
      body: await encryptUte1(text("move me"), fileKey),
      selfKey: sealToPublicKey(fileKey, me.boxPublicKey),
      ownerKey: "",
      role: "admin",
      folderId: FOLDER_ID,
      folderSealedKey: sealToPublicKey(fileKey, (await deriveFolderBoxKeys(drive.folderKey(FOLDER_ID)!)).publicKey),
    })
    const r = await client.files.move("33333333-3333-4333-8333-333333333333", dest.folderId)
    expect(r).toMatchObject({ folderId: dest.folderId })
    const stored = drive.files.get("33333333-3333-4333-8333-333333333333")!
    const destKey = await client.resourceKey({ type: "folder", id: dest.folderId })
    const { secretKey } = await deriveFolderBoxKeys(destKey)
    expect(sameBytes(openSealed(stored.folderSealedKey!, secretKey), fileKey)).toBe(true)
    expect(await client.files.move("33333333-3333-4333-8333-333333333333", null)).toMatchObject({ folderId: null })
    await expect(client.files.move("33333333-3333-4333-8333-333333333333", "bad")).rejects.toThrow(/folderId/)
  })
})

describe("keys", () => {
  it("lists, attaches (sealed to the given public key), changes and removes entries", async () => {
    const { drive, client } = setup()
    const ref = { type: "folder" as const, id: FOLDER_ID }
    expect((await client.keys.list(ref)).map((e) => e.keyId)).toEqual([CLIENT_ID])
    const other = await deriveClientKeys(randomBytes(32))
    const e = await client.keys.attach(ref, { keyType: "client", keyId: "utc_2222222222222222222222", role: "viewer", scopes: ["download"], publicKey: toBase64(other.boxPublicKey) })
    expect(e).toMatchObject({ role: "viewer", keyType: "client" })
    expect(e).not.toHaveProperty("sealedKey")
    const stored = drive.folders.get(FOLDER_ID)!.entries.find((x) => x.entryId === e.entryId)!
    expect(sameBytes(openSealed(stored.sealedKey!, other.boxSecretKey), drive.folderKey(FOLDER_ID)!)).toBe(true)
    expect(await client.keys.change(ref, e.entryId, { role: "editor" })).toMatchObject({ role: "editor" })
    const block = await client.keys.attach(ref, { keyType: "passkey", keyId: "WalletAddress111111111", role: "none" })
    expect(drive.folders.get(FOLDER_ID)!.entries.find((x) => x.entryId === block.entryId)!.sealedKey).toBeNull()
    expect(await client.keys.remove(ref, e.entryId)).toEqual({ removed: true })
    expect(await client.keys.list(ref)).toHaveLength(2)
  })

  it("validates input before any request", async () => {
    const { drive, client } = setup()
    const ref = { type: "folder" as const, id: FOLDER_ID }
    await expect(client.keys.attach(ref, { keyType: "client", keyId: "utc_not_base58_0OIl", role: "viewer", publicKey: "x" })).rejects.toThrow(/client keyId/)
    await expect(client.keys.attach(ref, { keyType: "client", keyId: "utc_2222222222222222222222", role: "viewer" })).rejects.toThrow(/publicKey is required/)
    await expect(client.keys.attach(ref, { keyType: "nope" as never, keyId: "x", role: "viewer" })).rejects.toThrow(/keyType/)
    await expect(client.keys.attach(ref, { keyType: "passkey", keyId: "WalletAddress111111111", role: "owner" as never })).rejects.toThrow(/role/)
    await expect(client.keys.change(ref, FOLDER_ID, {})).rejects.toThrow(/role, scopes/)
    await expect(client.keys.change(ref, FOLDER_ID, { scopes: ["root" as never] })).rejects.toThrow(/scopes/)
    await expect(client.keys.list({ type: "disk" as never, id: FOLDER_ID })).rejects.toThrow()
    expect(drive.requests).toHaveLength(0)
  })

  it("needs the manage-sharing scope", async () => {
    const { client } = setup({ scopes: ["download", "upload", "delete"] })
    await expect(client.keys.list({ type: "folder", id: FOLDER_ID })).rejects.toBeInstanceOf(UntraceScopeError)
  })
})

describe("shares", () => {
  it("looks up a username's signed sharing key and refuses a bad signature", async () => {
    const { client } = setup()
    const bob = await client.shares.lookup("bob-user")
    expect(bob.publicKey).toHaveLength(32)
    await expect(client.shares.lookup("mallory-user")).rejects.toBeInstanceOf(UntraceIntegrityError)
    await expect(client.shares.lookup("No Such")).rejects.toThrow(/username/)
    await expect(client.shares.lookup("nobody-here")).rejects.toBeInstanceOf(UntraceNotFoundError)
  })

  it("offers a folder sealed to the recipient's key, never to a key the server picked", async () => {
    const { drive, client } = setup()
    const s = await client.shares.offer({ resourceType: "folder", resourceId: FOLDER_ID, username: "bob-user", role: "viewer" })
    expect(s).toMatchObject({ resourceType: "folder", resourceId: FOLDER_ID, role: "viewer" })
    const stored = drive.shares.get(s.shareId)!
    expect(sameBytes(openSealed(stored.sealedKey, drive.userShareSecret("bob-user")), drive.folderKey(FOLDER_ID)!)).toBe(true)
    await expect(client.shares.offer({ resourceType: "folder", resourceId: FOLDER_ID, username: "mallory-user", role: "viewer" })).rejects.toBeInstanceOf(UntraceIntegrityError)
    await expect(client.shares.offer({ resourceType: "folder", resourceId: FOLDER_ID, username: "bob-user", role: "owner" as never })).rejects.toThrow(/role/)
  })

  it("accepts an incoming share by attaching this client key", async () => {
    const { drive, client } = setup()
    const theirs = await drive.addFolder({ name: "from bob" })
    await expect(client.folders.get(theirs.folderId)).rejects.toBeInstanceOf(UntraceNotFoundError)
    drive.offerToMe("folder", theirs.folderId, drive.folderKey(theirs.folderId)!)
    const [share] = await client.shares.incoming()
    expect(share).toMatchObject({ resourceType: "folder", resourceId: theirs.folderId })
    await expect(client.shares.accept(share!, { shareSecretKey: randomBytes(32) })).rejects.toBeInstanceOf(UntraceIntegrityError)
    await expect(client.shares.accept(share!, {})).rejects.toThrow(/shareSecretKey or resourceKey/)
    const entry = await client.shares.accept(share!, { shareSecretKey: drive.myShareSecret })
    expect(entry).toMatchObject({ keyType: "client", keyId: CLIENT_ID, role: "editor" })
    expect(sameBytes(await client.resourceKey({ type: "folder", id: theirs.folderId }), drive.folderKey(theirs.folderId)!)).toBe(true)
    expect(await client.shares.incoming()).toHaveLength(0)
  })

  it("accepts with an already opened resource key", async () => {
    const { drive, client } = setup()
    const theirs = await drive.addFolder({ name: "from bob" })
    const share = drive.offerToMe("folder", theirs.folderId, drive.folderKey(theirs.folderId)!, "viewer")
    await expect(client.shares.accept(share, { resourceKey: new Uint8Array(3) })).rejects.toThrow(/32 bytes/)
    expect(await client.shares.accept(share, { resourceKey: drive.folderKey(theirs.folderId)! })).toMatchObject({ role: "viewer" })
    expect((await client.folders.get(theirs.folderId)).role).toBe("viewer")
  })
})
