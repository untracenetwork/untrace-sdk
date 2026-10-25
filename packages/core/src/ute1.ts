/**
 * UTE1: the one client-side encryption step of the Untrace Drive API v1.
 * Contract: contract/openapi.yaml, "Client-side encryption (UTE1)".
 *
 * Each file gets a fresh random 32-byte file key. The plaintext is sealed with
 * AES-256-GCM in chunks, on this machine, before anything is sent. Drive only
 * ever receives (and returns) these bytes.
 *
 *   header (17 bytes)
 *     [0..3]   "UTE1"
 *     [4]      version 0x01
 *     [5..8]   chunk size (plaintext bytes), uint32 BE, 1..16777216
 *     [9..16]  total plaintext length, uint64 BE
 *   chunk i (ceil(total / chunk) of them):
 *     12-byte random IV | AES-256-GCM ciphertext | 16-byte tag
 *     additional authenticated data = header || uint32 BE i
 *
 * The header fixes the exact body length, so a truncated or padded body is
 * refused, and the AAD binds every chunk to its position, so a swapped,
 * duplicated or moved chunk fails its tag. WebCrypto only, no extra packages.
 */

import { webCrypto } from "./crypto"

export const UTE1_HEADER_BYTES = 17
export const UTE1_IV_BYTES = 12
export const UTE1_TAG_BYTES = 16
export const UTE1_CHUNK_OVERHEAD = UTE1_IV_BYTES + UTE1_TAG_BYTES
export const UTE1_MAX_CHUNK_BYTES = 16 * 1024 * 1024
export const UTE1_DEFAULT_CHUNK_BYTES = 1024 * 1024
export const FILE_KEY_BYTES = 32

const MAGIC = [0x55, 0x54, 0x45, 0x31] // "UTE1"
const VERSION = 0x01
/** 2^53 / 2^32: the high word must keep the total a safe integer. */
const MAX_HIGH_WORD = 0x200000

export interface Ute1Header {
  chunkBytes: number
  totalBytes: number
  chunks: number
  /** The exact byte length of a well-formed UTE1 body with this header. */
  sealedBytes: number
}

const readU32 = (b: Uint8Array, at: number): number => b[at]! * 0x1000000 + ((b[at + 1]! << 16) | (b[at + 2]! << 8) | b[at + 3]!)

function writeU32(b: Uint8Array, at: number, v: number): void {
  b[at] = (v >>> 24) & 0xff
  b[at + 1] = (v >>> 16) & 0xff
  b[at + 2] = (v >>> 8) & 0xff
  b[at + 3] = v & 0xff
}

/** Size of the UTE1 body for a plaintext of `totalBytes`. */
export function ute1SealedLength(totalBytes: number, chunkBytes: number = UTE1_DEFAULT_CHUNK_BYTES): number {
  return UTE1_HEADER_BYTES + totalBytes + Math.ceil(totalBytes / chunkBytes) * UTE1_CHUNK_OVERHEAD
}

/** The header's geometry, or null when the bytes do not start with a UTE1 v1 header. */
export function parseUte1Header(bytes: Uint8Array): Ute1Header | null {
  if (bytes.length < UTE1_HEADER_BYTES) return null
  for (let i = 0; i < 4; i++) if (bytes[i] !== MAGIC[i]) return null
  if (bytes[4] !== VERSION) return null
  const chunkBytes = readU32(bytes, 5)
  if (chunkBytes < 1 || chunkBytes > UTE1_MAX_CHUNK_BYTES) return null
  const high = readU32(bytes, 9)
  if (high >= MAX_HIGH_WORD) return null
  const totalBytes = high * 0x100000000 + readU32(bytes, 13)
  const chunks = Math.ceil(totalBytes / chunkBytes)
  return { chunkBytes, totalBytes, chunks, sealedBytes: ute1SealedLength(totalBytes, chunkBytes) }
}

function header(totalBytes: number, chunkBytes: number): Uint8Array {
  const h = new Uint8Array(UTE1_HEADER_BYTES)
  h.set(MAGIC, 0)
  h[4] = VERSION
  writeU32(h, 5, chunkBytes)
  writeU32(h, 9, Math.floor(totalBytes / 0x100000000))
  writeU32(h, 13, totalBytes >>> 0)
  return h
}

function aad(h: Uint8Array, index: number): Uint8Array {
  const out = new Uint8Array(UTE1_HEADER_BYTES + 4)
  out.set(h, 0)
  writeU32(out, UTE1_HEADER_BYTES, index)
  return out
}

async function aesKey(fileKey: Uint8Array, usage: KeyUsage): Promise<CryptoKey> {
  if (fileKey.length !== FILE_KEY_BYTES) throw new Error("untrace: the file key must be 32 bytes")
  return webCrypto().subtle.importKey("raw", fileKey as BufferSource, { name: "AES-GCM" }, false, [usage])
}

/** A fresh random 32-byte file key. */
export function newFileKey(): Uint8Array {
  return webCrypto().getRandomValues(new Uint8Array(FILE_KEY_BYTES))
}

/** Encrypt `plaintext` under `fileKey` as a UTE1 body. */
export async function encryptUte1(plaintext: Uint8Array, fileKey: Uint8Array, chunkBytes: number = UTE1_DEFAULT_CHUNK_BYTES): Promise<Uint8Array> {
  if (!Number.isInteger(chunkBytes) || chunkBytes < 1 || chunkBytes > UTE1_MAX_CHUNK_BYTES) throw new Error("untrace: chunk size out of range")
  const c = webCrypto()
  const key = await aesKey(fileKey, "encrypt")
  const h = header(plaintext.length, chunkBytes)
  const out = new Uint8Array(ute1SealedLength(plaintext.length, chunkBytes))
  out.set(h, 0)
  let at = UTE1_HEADER_BYTES
  const chunks = Math.ceil(plaintext.length / chunkBytes)
  for (let i = 0; i < chunks; i++) {
    const iv = c.getRandomValues(new Uint8Array(UTE1_IV_BYTES))
    const part = plaintext.subarray(i * chunkBytes, Math.min((i + 1) * chunkBytes, plaintext.length))
    const body = new Uint8Array(
      await c.subtle.encrypt({ name: "AES-GCM", iv: iv as BufferSource, additionalData: aad(h, i) as BufferSource }, key, part as BufferSource)
    )
    out.set(iv, at)
    out.set(body, at + UTE1_IV_BYTES)
    at += UTE1_IV_BYTES + body.length
  }
  return out
}

/** Decrypt a UTE1 body. Throws on any malformed, truncated or tampered input. */
export async function decryptUte1(sealed: Uint8Array, fileKey: Uint8Array): Promise<Uint8Array> {
  const h = parseUte1Header(sealed)
  if (!h || h.sealedBytes !== sealed.length) throw new Error("untrace: not a well-formed UTE1 body")
  const c = webCrypto()
  const key = await aesKey(fileKey, "decrypt")
  const head = sealed.subarray(0, UTE1_HEADER_BYTES)
  const out = new Uint8Array(h.totalBytes)
  let at = UTE1_HEADER_BYTES
  for (let i = 0; i < h.chunks; i++) {
    const n = Math.min(h.chunkBytes, h.totalBytes - i * h.chunkBytes)
    const iv = sealed.subarray(at, at + UTE1_IV_BYTES)
    const body = sealed.subarray(at + UTE1_IV_BYTES, at + UTE1_CHUNK_OVERHEAD + n)
    const plain = await c.subtle.decrypt({ name: "AES-GCM", iv: iv as BufferSource, additionalData: aad(head, i) as BufferSource }, key, body as BufferSource)
    out.set(new Uint8Array(plain), i * h.chunkBytes)
    at += UTE1_CHUNK_OVERHEAD + n
  }
  return out
}
