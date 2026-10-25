#!/usr/bin/env node
// Verify every package tarball ships only dist/, README.md, LICENSE and package.json,
// and that nothing looks like a secret or a test (js, d.ts and source maps, which embed
// sourcesContent). Run after `npm run build`.
import { execFileSync } from "node:child_process"
import { readFileSync } from "node:fs"

const PACKAGES = ["core", "next", "react", "vue"]
const ALLOWED = /^(package\.json|README\.md|LICENSE|dist\/.+)$/
const FORBIDDEN = [/\.env/, /\.test\./, /(^|\/)test\//, /fake-drive/, /\.tsbuildinfo$/, /(^|\/)src\//]
const SECRET_RE = /untrace_sk_v1_[A-Za-z0-9_-]{20,}/

let failed = false
const summary = []
for (const p of PACKAGES) {
  const dir = `packages/${p}`
  const out = execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], { cwd: dir, encoding: "utf8" })
  // npm <= 11 prints an array, npm 12 an object keyed by package name.
  const parsed = JSON.parse(out)
  const info = Array.isArray(parsed) ? parsed[0] : Object.values(parsed)[0]
  const files = info.files.map((f) => f.path)
  const bad = files.filter((f) => !ALLOWED.test(f) || FORBIDDEN.some((re) => re.test(f)))
  for (const f of files.filter((f) => f.startsWith("dist/") && /\.(c?js|d\.c?ts|map)$/.test(f))) {
    if (SECRET_RE.test(readFileSync(`${dir}/${f}`, "utf8"))) bad.push(`${f} (contains a client secret)`)
  }
  for (const must of ["package.json", "README.md", "LICENSE"]) if (!files.includes(must)) bad.push(`missing ${must}`)
  if (!files.some((f) => f.startsWith("dist/"))) bad.push("missing dist/ (run npm run build first)")
  if (bad.length) {
    failed = true
    console.error(`${info.name}@${info.version}: ${bad.join(", ")}`)
  }
  summary.push(`${info.name}@${info.version}: ${files.length} files, ${info.size} B packed (${files.filter((f) => !f.startsWith("dist/")).join(", ")} + ${files.filter((f) => f.startsWith("dist/")).length} dist)`)
}
console.log(summary.join("\n"))
if (failed) {
  console.error("pack check failed")
  process.exit(1)
}
