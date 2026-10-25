#!/usr/bin/env node
// Public-surface gate for this repo (the leak gate in "SDK mode", Product/public-surface-staging.md).
//
//   node scripts/check-public.mjs
//
// Fails (exit 1) when a tracked file:
//   1. names core internals: split / erasure / Shamir / Reed-Solomon / GF(256) / Lagrange / node
//      topology / shard counts, or a core key-derivation label;
//   2. calls a crypto primitive outside the two files allowed to (option B: crypto.ts, ute1.ts),
//      or uses one that option B does not allow (pbkdf2, scrypt, createCipheriv);
//   3. derives anything with HKDF other than the client-key labels of the contract;
//   4. holds a secret, a private host or native / compiled code;
//   5. is a package without an Apache-2.0 LICENSE.
// The contract copy (contract/openapi.yaml) and this script are checked for secrets only.
import { execFileSync } from "node:child_process"
import { existsSync, readFileSync } from "node:fs"

const files = execFileSync("git", ["ls-files", "--cached", "--others", "--exclude-standard"], { encoding: "utf8" })
  .split("\n")
  .filter(Boolean)
  .filter((f) => existsSync(f))

const SELF = "scripts/check-public.mjs"
const CONTRACT = new Set(["contract/openapi.yaml", "contract/SOURCE.json"])
const CRYPTO_ALLOWED = new Set(["packages/core/src/crypto.ts", "packages/core/src/ute1.ts"])
const TEXT = /\.(m?[jt]sx?|c?js|json|ya?ml|md|txt|html|vue)$/

const BANNED_NAMES = [
  /shamir/i,
  /reed[-_ ]?solomon/i,
  /\berasure/i,
  /\bgf ?256\b|gf\(2\^8\)/i,
  /lagrange/i,
  /\bshards?\b/i,
  /split_secret|combine_secret|splitSecret|combineSecret/,
  /\bsss[_ ]?[kn]\b/i,
  /untrace:(file-(kek|dek)|wallet)/,
  /\/api\/nodes\b|nodeUrls?|UNTRACE_NODE_URLS/,
  /k[- ]of[- ]n/i,
]
const CRYPTO_CALL = /subtle\.(encrypt|decrypt|deriveKey|deriveBits|importKey|digest)|xsalsa20poly1305|getSharedSecret|\bhsalsa\b/
const FORBIDDEN_CRYPTO = /pbkdf2|scrypt\(|createCipheriv|createDecipheriv|tweetnacl|libsodium|shamir-secret-sharing/
const HKDF_LABEL = /"untrace:[a-z-]+:[a-z-]+:v\d"/g
const ALLOWED_LABELS = new Set([
  '"untrace:client-key:oauth:v1"',
  '"untrace:client-key:box:v1"',
  '"untrace:client-key:sign:v1"',
  '"untrace:share-key:v1:"',
  // Public in the Drive contract (createFolder boxPublicKey): a folder's box key pair.
  '"untrace:folder-key:box:v1"',
])
const SECRET = /BEGIN [A-Z ]*PRIVATE KEY|untrace_sk_v1_[A-Za-z0-9_-]{40,}|ghp_[A-Za-z0-9]{30,}|github_pat_|npm_[A-Za-z0-9]{30,}|sk_live_|AKIA[0-9A-Z]{16}/
const PRIVATE_INFRA = /core-pm|\.internal\b|neon\.tech|untrace-shards|aiteam|([0-9]{1,3}\.){3}[0-9]{1,3}:\d+/
const NATIVE = /\.(rs|c|cc|cpp|so|dylib|dll|a|wasm)$|(^|\/)Cargo\.(toml|lock)$/

const hits = []
const hit = (f, why) => hits.push(`${f}: ${why}`)

for (const f of files) {
  if (NATIVE.test(f)) hit(f, "native or compiled code")
  if (!TEXT.test(f) && !f.endsWith("LICENSE")) continue
  const text = readFileSync(f, "utf8")
  if (SECRET.test(text) && f !== SELF) hit(f, "secret pattern")
  if (f === SELF || CONTRACT.has(f)) continue
  if (PRIVATE_INFRA.test(text)) hit(f, `private infra reference (${text.match(PRIVATE_INFRA)[0]})`)
  for (const re of BANNED_NAMES) {
    const m = text.match(re)
    if (m) hit(f, `core internals name "${m[0]}"`)
  }
  if (FORBIDDEN_CRYPTO.test(text)) hit(f, `crypto outside option B (${text.match(FORBIDDEN_CRYPTO)[0]})`)
  const isTest = /(^|\/)test\//.test(f)
  if (!isTest && f.startsWith("packages/") && !CRYPTO_ALLOWED.has(f) && CRYPTO_CALL.test(text)) {
    hit(f, `crypto primitive call outside crypto.ts / ute1.ts (${text.match(CRYPTO_CALL)[0]})`)
  }
  for (const label of text.match(HKDF_LABEL) ?? []) if (!ALLOWED_LABELS.has(label)) hit(f, `key-derivation label ${label}`)
}

for (const p of ["", "packages/core/", "packages/next/", "packages/react/", "packages/vue/"]) {
  const lic = `${p}LICENSE`
  if (!existsSync(lic) || !/Apache License\s+Version 2\.0/.test(readFileSync(lic, "utf8"))) hit(lic, "not the Apache-2.0 licence")
  if (p) {
    const pkg = JSON.parse(readFileSync(`${p}package.json`, "utf8"))
    if (pkg.license !== "Apache-2.0") hit(`${p}package.json`, `license is ${pkg.license}`)
  }
}

if (hits.length) {
  console.error(hits.join("\n"))
  console.error(`public check: ${hits.length} problem(s)`)
  process.exit(1)
}
console.log(`public check: clean (${files.length} files)`)
