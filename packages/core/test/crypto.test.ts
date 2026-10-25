/**
 * Byte compatibility with Drive (untrace-drive 73bf7f2, branch feat/public-api-v1).
 * drive-vectors.json was produced once by running Drive's own reference code
 * (lib/cloud/crypto/client-key.ts, share-key.ts and public-api/ute1.ts); the SDK
 * must reproduce every value.
 */
import { describe, expect, it } from "vitest"

import {
  deriveClientKeys,
  deriveOAuthClientSecret,
  exportClientSecret,
  openSealed,
  parseClientSecret,
  sealToPublicKey,
  verifyShareKey,
  randomBytes,
  CLIENT_SECRET_PREFIX,
} from "../src/crypto"
import { fromBase64, fromBase58, toBase58, toBase64, toBase64Url, toHex, utf8 } from "../src/encoding"
import { decryptUte1, encryptUte1, parseUte1Header } from "../src/ute1"
import vectors from "./drive-vectors.json"

const fromHex = (h: string) => new Uint8Array(h.match(/../g)!.map((x) => parseInt(x, 16)))

/** Drive stores hex SHA-256 of the 32 decoded bytes of the OAuth value. */
async function oauthHash(oauth: string): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", fromBase64(oauth) as BufferSource)))
}

describe("client key derivation matches Drive", () => {
  it.each(vectors.keys)("secret $secretHex", async (v) => {
    const secret = fromHex(v.secretHex)
    const k = await deriveClientKeys(secret)
    expect(k.oauthSecret).toBe(v.oauthSecret)
    expect(toBase64(k.boxPublicKey)).toBe(v.boxPublicKey)
    expect(await deriveOAuthClientSecret(secret)).toBe(v.oauthSecret)
    // Drive stores SHA-256 of the OAuth value; the SDK's value hashes to the same.
    expect(await oauthHash(k.oauthSecret)).toBe(v.oauthHash)
    // The wire value is 43 base64url characters (contract pattern).
    expect(k.oauthSecret).toMatch(/^[A-Za-z0-9_-]{43}$/)
  })

  it("never derives the OAuth value equal to the box key or the raw secret", async () => {
    const secret = fromHex(vectors.keys[0]!.secretHex)
    const k = await deriveClientKeys(secret)
    expect(k.oauthSecret).not.toBe(toBase64Url(secret))
    expect(k.oauthSecret).not.toBe(toBase64Url(k.boxSecretKey))
  })
})

describe("UTE1 matches Drive", () => {
  const fileKey = fromHex(vectors.ute1.fileKey)

  it("decrypts Drive's sealed vector", async () => {
    const plain = await decryptUte1(fromHex(vectors.ute1.sealed), fileKey)
    expect(new TextDecoder().decode(plain)).toBe(vectors.ute1.plaintext)
  })

  it("decrypts Drive's empty-file vector", async () => {
    expect((await decryptUte1(fromHex(vectors.ute1.empty), fileKey)).length).toBe(0)
  })

  it("produces bodies with Drive's exact geometry", async () => {
    const sealed = await encryptUte1(utf8(vectors.ute1.plaintext), fileKey, vectors.ute1.chunkBytes)
    expect(sealed.length).toBe(fromHex(vectors.ute1.sealed).length)
    expect(toHex(sealed.subarray(0, 17))).toBe(vectors.ute1.sealed.slice(0, 34))
    expect(parseUte1Header(sealed)).toMatchObject({ chunkBytes: 7, totalBytes: vectors.ute1.plaintext.length })
  })

  it("opens a file key Drive's code sealed to client 0", async () => {
    const k = await deriveClientKeys(fromHex(vectors.keys[0]!.secretHex))
    expect(toHex(openSealed(vectors.ute1.sealedKeyToClient0, k.boxSecretKey))).toBe(vectors.ute1.fileKey)
  })
})

describe("client secret format", () => {
  it("round-trips untrace_sk_v1_", () => {
    const raw = randomBytes(32)
    const text = exportClientSecret(raw)
    expect(text.startsWith(CLIENT_SECRET_PREFIX)).toBe(true)
    expect(parseClientSecret(text)).toEqual(raw)
    expect(parseClientSecret(`  ${text}\n`)).toEqual(raw)
  })

  it.each([
    ["no prefix", "abc"],
    ["bad base64", `${CLIENT_SECRET_PREFIX}!!!!`],
    ["short", `${CLIENT_SECRET_PREFIX}${toBase64Url(new Uint8Array(16))}`],
    ["long", `${CLIENT_SECRET_PREFIX}${toBase64Url(new Uint8Array(33))}`],
  ])("refuses %s", (_n, text) => {
    expect(() => parseClientSecret(text)).toThrow(/untrace/)
  })

  it("refuses to export or derive from a key that is not 32 bytes", async () => {
    expect(() => exportClientSecret(new Uint8Array(31))).toThrow()
    await expect(deriveClientKeys(new Uint8Array(31))).rejects.toThrow()
  })
})

describe("sealed keys", () => {
  it("seal then open with the right key, fail with the wrong one", async () => {
    const a = await deriveClientKeys(randomBytes(32))
    const b = await deriveClientKeys(randomBytes(32))
    const key = randomBytes(32)
    const sealed = sealToPublicKey(key, a.boxPublicKey)
    expect(fromBase64(sealed).length).toBe(32 + 24 + 48)
    expect(sealed).toMatch(/^[A-Za-z0-9+/]{120,400}={0,2}$/)
    expect(openSealed(sealed, a.boxSecretKey)).toEqual(key)
    expect(() => openSealed(sealed, b.boxSecretKey)).toThrow(/cannot open/)
  })

  it("is randomized per seal", async () => {
    const a = await deriveClientKeys(randomBytes(32))
    const key = randomBytes(32)
    expect(sealToPublicKey(key, a.boxPublicKey)).not.toBe(sealToPublicKey(key, a.boxPublicKey))
  })

  it("refuses a tampered or short blob, and a bad recipient", async () => {
    const a = await deriveClientKeys(randomBytes(32))
    const bytes = fromBase64(sealToPublicKey(randomBytes(32), a.boxPublicKey))
    bytes[70] ^= 1
    expect(() => openSealed(toBase64(bytes), a.boxSecretKey)).toThrow()
    expect(() => openSealed(toBase64(new Uint8Array(60)), a.boxSecretKey)).toThrow(/too short/)
    expect(() => sealToPublicKey(randomBytes(32), new Uint8Array(31))).toThrow(/recipient/)
  })
})

describe("share key signature", () => {
  it("verifies a good record and refuses bad ones", async () => {
    const { ed25519 } = await import("@noble/curves/ed25519")
    const sk = ed25519.utils.randomPrivateKey()
    const wallet = toBase58(ed25519.getPublicKey(sk))
    const publicKey = toBase64(randomBytes(32))
    const keySignature = toBase58(ed25519.sign(utf8("untrace:share-key:v1:" + publicKey), sk))
    expect(verifyShareKey({ wallet, publicKey, keySignature })).toBe(true)
    expect(verifyShareKey({ wallet, publicKey: toBase64(randomBytes(32)), keySignature })).toBe(false)
    expect(verifyShareKey({ wallet: "0OIl", publicKey, keySignature })).toBe(false)
    expect(verifyShareKey({ wallet, publicKey, keySignature: toBase58(new Uint8Array(10)) })).toBe(false)
    expect(verifyShareKey({ wallet: toBase58(new Uint8Array(32)), publicKey, keySignature })).toBe(false)
  })
})

describe("encodings", () => {
  it("base64 and base64url round-trip at every padding length", () => {
    for (let n = 0; n < 8; n++) {
      const b = randomBytes(n)
      expect(fromBase64(toBase64(b))).toEqual(b)
      expect(fromBase64(toBase64Url(b))).toEqual(b)
    }
    expect(() => fromBase64("a")).toThrow()
    expect(() => fromBase64("ab$c")).toThrow()
  })

  it("base58 round-trips, keeps leading zeros, refuses bad characters", () => {
    const b = new Uint8Array([0, 0, 1, 2, 255])
    expect(fromBase58(toBase58(b))).toEqual(b)
    expect(toBase58(new Uint8Array(0))).toBe("")
    expect(() => fromBase58("0")).toThrow()
  })
})
