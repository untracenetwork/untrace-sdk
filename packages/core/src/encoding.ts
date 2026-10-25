/** Byte and text encodings. No Buffer, so it runs in browsers, edge and Node. */

const enc = new TextEncoder()
const dec = new TextDecoder()

export const utf8 = (s: string): Uint8Array => enc.encode(s)
export const fromUtf8 = (b: Uint8Array): string => dec.decode(b)

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
const B64_LOOKUP = (() => {
  const t = new Int16Array(256).fill(-1)
  for (let i = 0; i < B64.length; i++) t[B64.charCodeAt(i)] = i
  t["-".charCodeAt(0)] = 62
  t["_".charCodeAt(0)] = 63
  return t
})()

/** Standard base64 with padding. */
export function toBase64(bytes: Uint8Array): string {
  let out = ""
  let i = 0
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!
    out += B64[(n >> 18) & 63]! + B64[(n >> 12) & 63]! + B64[(n >> 6) & 63]! + B64[n & 63]!
  }
  const rest = bytes.length - i
  if (rest === 1) {
    const n = bytes[i]! << 16
    out += B64[(n >> 18) & 63]! + B64[(n >> 12) & 63]! + "=="
  } else if (rest === 2) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8)
    out += B64[(n >> 18) & 63]! + B64[(n >> 12) & 63]! + B64[(n >> 6) & 63]! + "="
  }
  return out
}

/** Decodes standard base64 or base64url, padded or not. Throws on bad input. */
export function fromBase64(text: string): Uint8Array {
  const s = text.replace(/=+$/, "")
  if (s.length % 4 === 1) throw new Error("base64: bad length")
  const out = new Uint8Array(Math.floor((s.length * 3) / 4))
  let bits = 0
  let acc = 0
  let o = 0
  for (let i = 0; i < s.length; i++) {
    const v = B64_LOOKUP[s.charCodeAt(i)] ?? -1
    if (v < 0) throw new Error("base64: bad character")
    acc = (acc << 6) | v
    bits += 6
    if (bits >= 8) {
      bits -= 8
      out[o++] = (acc >> bits) & 0xff
    }
  }
  return out
}

export const toBase64Url = (bytes: Uint8Array): string =>
  toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")

export function toHex(bytes: Uint8Array): string {
  let s = ""
  for (const b of bytes) s += b.toString(16).padStart(2, "0")
  return s
}

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

/** Base58 (Bitcoin alphabet), used for Solana wallets and their signatures. */
export function fromBase58(text: string): Uint8Array {
  let zeros = 0
  while (zeros < text.length && text[zeros] === "1") zeros++
  const bytes: number[] = []
  for (let i = zeros; i < text.length; i++) {
    let carry = B58.indexOf(text[i]!)
    if (carry < 0) throw new Error("base58: bad character")
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j]! * 58
      bytes[j] = carry & 0xff
      carry >>= 8
    }
    while (carry > 0) {
      bytes.push(carry & 0xff)
      carry >>= 8
    }
  }
  const out = new Uint8Array(zeros + bytes.length)
  for (let i = 0; i < bytes.length; i++) out[zeros + i] = bytes[bytes.length - 1 - i]!
  return out
}

export function toBase58(bytes: Uint8Array): string {
  let zeros = 0
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++
  const digits: number[] = []
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i]!
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j]! << 8
      digits[j] = carry % 58
      carry = (carry / 58) | 0
    }
    while (carry > 0) {
      digits.push(carry % 58)
      carry = (carry / 58) | 0
    }
  }
  let out = "1".repeat(zeros)
  for (let i = digits.length - 1; i >= 0; i--) out += B58[digits[i]!]
  return out
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}
