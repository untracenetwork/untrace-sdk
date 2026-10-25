import { describe, expect, it } from "vitest"

import {
  decryptUte1,
  encryptUte1,
  newFileKey,
  parseUte1Header,
  ute1SealedLength,
  UTE1_DEFAULT_CHUNK_BYTES,
  UTE1_HEADER_BYTES,
  UTE1_MAX_CHUNK_BYTES,
} from "../src/ute1"
import { randomBytes as rb } from "../src/crypto"

/** getRandomValues caps at 64 KiB per call. */
const randomBytes = (n: number) => {
  const out = new Uint8Array(n)
  for (let i = 0; i < n; i += 65536) out.set(rb(Math.min(65536, n - i)), i)
  return out
}

describe("UTE1 round trip", () => {
  it.each([
    [0, 7],
    [1, 7],
    [7, 7],
    [8, 7],
    [21, 7],
    [1000, 1],
    [5000, 4096],
    [70_000, UTE1_DEFAULT_CHUNK_BYTES],
  ])("%i bytes in chunks of %i", async (n, chunk) => {
    const key = newFileKey()
    const plain = randomBytes(n)
    const sealed = await encryptUte1(plain, key, chunk)
    expect(sealed.length).toBe(ute1SealedLength(n, chunk))
    expect(parseUte1Header(sealed)).toEqual({ chunkBytes: chunk, totalBytes: n, chunks: Math.ceil(n / chunk), sealedBytes: sealed.length })
    expect(await decryptUte1(sealed, key)).toEqual(plain)
  })

  it("uses a fresh IV per chunk and per call", async () => {
    const key = newFileKey()
    const plain = new Uint8Array(20)
    const a = await encryptUte1(plain, key, 10)
    const b = await encryptUte1(plain, key, 10)
    expect(a).not.toEqual(b)
    const iv0 = a.subarray(UTE1_HEADER_BYTES, UTE1_HEADER_BYTES + 12)
    const iv1 = a.subarray(UTE1_HEADER_BYTES + 38, UTE1_HEADER_BYTES + 50)
    expect(iv0).not.toEqual(iv1)
  })

  it("never contains the plaintext", async () => {
    const plain = new TextEncoder().encode("a very recognizable secret sentence ".repeat(10))
    const sealed = await encryptUte1(plain, newFileKey(), 64)
    expect(Buffer.from(sealed).includes(Buffer.from("recognizable"))).toBe(false)
  })
})

describe("UTE1 refuses bad input", () => {
  async function sample() {
    const key = newFileKey()
    const sealed = await encryptUte1(randomBytes(30), key, 10)
    return { key, sealed }
  }

  it("wrong key", async () => {
    const { sealed } = await sample()
    await expect(decryptUte1(sealed, newFileKey())).rejects.toThrow()
  })

  it("truncated body", async () => {
    const { key, sealed } = await sample()
    await expect(decryptUte1(sealed.subarray(0, sealed.length - 1), key)).rejects.toThrow(/well-formed/)
  })

  it("padded body", async () => {
    const { key, sealed } = await sample()
    const longer = new Uint8Array(sealed.length + 1)
    longer.set(sealed)
    await expect(decryptUte1(longer, key)).rejects.toThrow(/well-formed/)
  })

  it("a flipped ciphertext bit", async () => {
    const { key, sealed } = await sample()
    sealed[UTE1_HEADER_BYTES + 20] ^= 1
    await expect(decryptUte1(sealed, key)).rejects.toThrow()
  })

  it("swapped chunks (position is authenticated)", async () => {
    const { key, sealed } = await sample()
    const size = 38
    const a = sealed.slice(UTE1_HEADER_BYTES, UTE1_HEADER_BYTES + size)
    const b = sealed.slice(UTE1_HEADER_BYTES + size, UTE1_HEADER_BYTES + 2 * size)
    sealed.set(b, UTE1_HEADER_BYTES)
    sealed.set(a, UTE1_HEADER_BYTES + size)
    await expect(decryptUte1(sealed, key)).rejects.toThrow()
  })

  it("an edited header (header is authenticated)", async () => {
    const key = newFileKey()
    const sealed = await encryptUte1(randomBytes(20), key, 10)
    // Same geometry, different chunk size field would change length; flip version instead.
    const other = sealed.slice()
    other[4] = 2
    expect(parseUte1Header(other)).toBeNull()
    await expect(decryptUte1(other, key)).rejects.toThrow()
  })

  it.each([
    ["too short", new Uint8Array(5)],
    ["wrong magic", new Uint8Array([0x55, 0x54, 0x45, 0x32, 1, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0])],
    ["chunk size zero", new Uint8Array([0x55, 0x54, 0x45, 0x31, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])],
    ["chunk size over max", new Uint8Array([0x55, 0x54, 0x45, 0x31, 1, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0])],
    ["total over 2^53", new Uint8Array([0x55, 0x54, 0x45, 0x31, 1, 0, 0, 0, 7, 0, 0x20, 0, 0, 0, 0, 0, 0])],
  ])("header: %s", (_n, bytes) => {
    expect(parseUte1Header(bytes)).toBeNull()
  })

  it("refuses a bad chunk size or a bad key on encrypt", async () => {
    await expect(encryptUte1(new Uint8Array(1), newFileKey(), 0)).rejects.toThrow(/chunk/)
    await expect(encryptUte1(new Uint8Array(1), newFileKey(), UTE1_MAX_CHUNK_BYTES + 1)).rejects.toThrow(/chunk/)
    await expect(encryptUte1(new Uint8Array(1), newFileKey(), 1.5)).rejects.toThrow(/chunk/)
    await expect(encryptUte1(new Uint8Array(1), new Uint8Array(16))).rejects.toThrow(/32 bytes/)
  })
})
