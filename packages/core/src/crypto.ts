/**
 * Client key handling and the sealed-key format of the Untrace Drive API v1.
 * Contract: contract/openapi.yaml ("Client credentials", "Sealed keys").
 *
 * The client secret (`untrace_sk_v1_` + 32 bytes) never leaves this machine.
 * Two values are derived from it with HKDF-SHA256 (empty salt, 32 bytes):
 *
 *   info "untrace:client-key:oauth:v1" -> the OAuth `client_secret` sent to the token endpoint
 *   info "untrace:client-key:box:v1"   -> X25519 key pair; file keys are sealed to its public key
 *
 * Only the OAuth value travels, so Drive can never compute the box key and can
 * never open a file key sealed to this client.
 *
 * Sealed key: base64(ephemeral X25519 public key (32) || nonce (24) || XSalsa20-Poly1305 box),
 * the NaCl `box` construction with a fresh ephemeral key pair per seal.
 *
 * HKDF uses WebCrypto. X25519, Ed25519 (signature checks only) and
 * XSalsa20-Poly1305 use @noble, so the same code runs in Node 20+, Deno, Bun,
 * edge runtimes and browsers with no native modules.
 */

import { ed25519, x25519 } from "@noble/curves/ed25519"
import { hsalsa, xsalsa20poly1305 } from "@noble/ciphers/salsa"

import { concatBytes, fromBase58, fromBase64, toBase64, toBase64Url, utf8 } from "./encoding"

export const CLIENT_OAUTH_INFO = "untrace:client-key:oauth:v1"
export const CLIENT_BOX_INFO = "untrace:client-key:box:v1"
/** HKDF info for a folder's box key pair (contract: createFolder `boxPublicKey`). */
export const FOLDER_BOX_INFO = "untrace:folder-key:box:v1"
export const CLIENT_SECRET_PREFIX = "untrace_sk_v1_"
export const SHARE_KEY_SIGN_PREFIX = "untrace:share-key:v1:"

export interface ClientKeys {
  /** base64url (no padding) of HKDF(secret, CLIENT_OAUTH_INFO). The only value derived from the secret that is ever sent. */
  oauthSecret: string
  boxPublicKey: Uint8Array
  boxSecretKey: Uint8Array
}

/** @internal */
export function webCrypto(): Crypto {
  const c = (globalThis as { crypto?: Crypto }).crypto
  if (!c?.subtle || !c.getRandomValues) throw new Error("untrace: WebCrypto is not available (Node 20+ or a modern runtime is required)")
  return c
}

export function randomBytes(n: number): Uint8Array {
  const c = webCrypto()
  const out = new Uint8Array(n)
  // getRandomValues fills at most 65536 bytes per call.
  for (let i = 0; i < n; i += 65536) c.getRandomValues(out.subarray(i, Math.min(n, i + 65536)))
  return out
}

/** Parse `untrace_sk_v1_<base64url>` into the 32 raw secret bytes. */
export function parseClientSecret(text: string): Uint8Array {
  const t = text.trim()
  if (!t.startsWith(CLIENT_SECRET_PREFIX)) throw new Error("untrace: not an untrace_sk_v1_ client secret")
  let bytes: Uint8Array
  try {
    bytes = fromBase64(t.slice(CLIENT_SECRET_PREFIX.length))
  } catch {
    throw new Error("untrace: the client secret is not valid base64url")
  }
  if (bytes.length !== 32) throw new Error("untrace: the client secret must be 32 bytes")
  return bytes
}

export function exportClientSecret(secret: Uint8Array): string {
  if (secret.length !== 32) throw new Error("untrace: the client secret must be 32 bytes")
  return CLIENT_SECRET_PREFIX + toBase64Url(secret)
}

async function hkdf32(ikm: Uint8Array, info: string): Promise<Uint8Array> {
  const subtle = webCrypto().subtle
  const base = await subtle.importKey("raw", ikm as BufferSource, "HKDF", false, ["deriveBits"])
  const bits = await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: utf8(info) as BufferSource }, base, 256)
  return new Uint8Array(bits)
}

/** Deterministic: the same secret always gives the same OAuth value and box key pair. */
export async function deriveClientKeys(secret: Uint8Array): Promise<ClientKeys> {
  if (secret.length !== 32) throw new Error("untrace: the client secret must be 32 bytes")
  const oauth = await hkdf32(secret, CLIENT_OAUTH_INFO)
  const boxSecretKey = await hkdf32(secret, CLIENT_BOX_INFO)
  const oauthSecret = toBase64Url(oauth)
  oauth.fill(0)
  return { oauthSecret, boxSecretKey, boxPublicKey: x25519.getPublicKey(boxSecretKey) }
}

/**
 * A folder's X25519 key pair, from its random 32-byte folder key:
 * HKDF-SHA256(folder key, salt = empty, info = FOLDER_BOX_INFO, 32 bytes).
 * Subfolders and files in the folder carry their key sealed to the public key.
 */
export async function deriveFolderBoxKeys(folderKey: Uint8Array): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }> {
  if (folderKey.length !== 32) throw new Error("untrace: a folder key must be 32 bytes")
  const secretKey = await hkdf32(folderKey, FOLDER_BOX_INFO)
  return { secretKey, publicKey: x25519.getPublicKey(secretKey) }
}

/**
 * Walk a key path: `start` is the key where the caller's entry sits (already
 * opened). Each sealed key in `path` is sealed to the box key of the key
 * before it. Returns the last key (the target's own key). Intermediate keys
 * are wiped.
 */
export async function openKeyPath(start: Uint8Array, path: readonly string[]): Promise<Uint8Array> {
  let current: Uint8Array = start.slice()
  for (const sealed of path) {
    const { secretKey } = await deriveFolderBoxKeys(current)
    current.fill(0)
    try {
      current = openSealed(sealed, secretKey)
    } finally {
      secretKey.fill(0)
    }
  }
  return current
}

/** The OAuth `client_secret` for a raw client secret: base64url(HKDF(secret, CLIENT_OAUTH_INFO)). */
export async function deriveOAuthClientSecret(secret: Uint8Array): Promise<string> {
  const k = await deriveClientKeys(secret)
  k.boxSecretKey.fill(0)
  return k.oauthSecret
}

// -- sealed keys (NaCl box compatible) ----------------------------------------

const SIGMA = utf8("expand 32-byte k")

const u32 = (b: Uint8Array): Uint32Array => {
  const copy = b.slice()
  return new Uint32Array(copy.buffer, copy.byteOffset, copy.byteLength / 4)
}

/** crypto_box_beforenm: HSalsa20(X25519(sk, pk), 0^16). Same as nacl.box.before. */
function boxBefore(theirPublic: Uint8Array, mySecret: Uint8Array): Uint8Array {
  const shared = x25519.getSharedSecret(mySecret, theirPublic)
  const out = new Uint32Array(8)
  hsalsa(u32(SIGMA), u32(shared), new Uint32Array(4), out)
  shared.fill(0)
  return new Uint8Array(out.buffer.slice(0))
}

/** Seal a 32-byte key to an X25519 public key. Returns standard base64. */
export function sealToPublicKey(secret: Uint8Array, recipientPublicKey: Uint8Array): string {
  if (recipientPublicKey.length !== 32) throw new Error("untrace: bad recipient public key")
  const ephSecret = randomBytes(32)
  const ephPublic = x25519.getPublicKey(ephSecret)
  const nonce = randomBytes(24)
  const k = boxBefore(recipientPublicKey, ephSecret)
  const box = xsalsa20poly1305(k, nonce).encrypt(secret)
  ephSecret.fill(0)
  k.fill(0)
  return toBase64(concatBytes(ephPublic, nonce, box))
}

/** Open a sealed key. Throws on a wrong key or a tampered blob. */
export function openSealed(blob: string, mySecretKey: Uint8Array): Uint8Array {
  const bytes = fromBase64(blob)
  if (bytes.length <= 32 + 24 + 16) throw new Error("untrace: sealed key is too short")
  const k = boxBefore(bytes.subarray(0, 32), mySecretKey)
  try {
    return xsalsa20poly1305(k, bytes.subarray(32, 56)).decrypt(bytes.subarray(56))
  } catch {
    throw new Error("untrace: this key cannot open the sealed key")
  } finally {
    k.fill(0)
  }
}

/**
 * Verify a published sharing key (`GET /api/v1/owner/share-key`): a base58
 * Ed25519 signature by the account address (base58 public key) over
 * "untrace:share-key:v1:" + publicKey (the standard base64 string).
 */
export function verifyShareKey(rec: { wallet: string; publicKey: string; keySignature: string }): boolean {
  let pub: Uint8Array
  let sig: Uint8Array
  try {
    pub = fromBase58(rec.wallet)
    sig = fromBase58(rec.keySignature)
  } catch {
    return false
  }
  if (pub.length !== 32 || sig.length !== 64) return false
  try {
    return ed25519.verify(sig, utf8(SHARE_KEY_SIGN_PREFIX + rec.publicKey), pub)
  } catch {
    return false
  }
}
