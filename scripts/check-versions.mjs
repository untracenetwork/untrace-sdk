#!/usr/bin/env node
// Usage: node scripts/check-versions.mjs <version>
// Fails unless the root and all 4 packages are at exactly <version>, and the
// inter-package dependency ranges accept it.
import { readFileSync } from "node:fs"

const want = process.argv[2]
if (!want || !/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(want)) {
  console.error(`::error::expected a semver version, got "${want ?? ""}"`)
  process.exit(1)
}
const read = (p) => JSON.parse(readFileSync(p, "utf8"))
let bad = 0
for (const p of [".", "packages/core", "packages/next", "packages/react", "packages/vue"]) {
  const v = read(`${p}/package.json`).version
  if (v !== want) {
    console.error(`::error::${p}/package.json is ${v}, expected ${want}`)
    bad++
  }
}
if (bad) process.exit(1)
console.log(`all packages at ${want}`)
