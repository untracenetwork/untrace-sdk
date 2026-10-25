/**
 * Release gating (audit H2, issue #5). A v* tag push must never publish:
 * only publish.yml publishes, it is manual, it needs a typed version, and its
 * publish job runs in the `npm-publish` environment (JC is the reviewer).
 */
import { execFileSync } from "node:child_process"
import { readdirSync, readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

import { describe, expect, it } from "vitest"

const root = fileURLToPath(new URL("../", import.meta.url))
const wf = (n: string) => readFileSync(`${root}.github/workflows/${n}`, "utf8")

/** Top-level `on:` block of a workflow (until the next top-level key). */
function onBlock(src: string): string {
  const m = /^on:\n([\s\S]*?)^(?=\S)/m.exec(src)
  return m ? m[1]! : ""
}

/** The jobs as { name: body } (2-space indented keys under `jobs:`). */
function jobs(src: string): Record<string, string> {
  const body = src.slice(src.search(/^jobs:\s*$/m))
  const out: Record<string, string> = {}
  const re = /^ {2}([A-Za-z0-9_-]+):\s*$/gm
  const hits = [...body.matchAll(re)]
  hits.forEach((h, i) => {
    out[h[1]!] = body.slice(h.index!, i + 1 < hits.length ? hits[i + 1]!.index : undefined)
  })
  return out
}

const publishes = (s: string) => /npm publish(?![^\n]*--dry-run)/.test(s)

describe("release workflows (audit H2 / #5)", () => {
  it("only publish.yml contains a real npm publish", () => {
    const files = readdirSync(`${root}.github/workflows`).filter((f) => /\.ya?ml$/.test(f))
    const real = files.filter((f) => publishes(wf(f)))
    expect(real).toEqual(["publish.yml"])
  })

  it("a v* tag push only verifies: dry-run, no token, no id-token", () => {
    const r = wf("release.yml")
    expect(onBlock(r)).toMatch(/push:\s*\n\s*tags: \["v\*"\]/)
    expect(r).toMatch(/npm publish[^\n]*--dry-run/)
    expect(publishes(r)).toBe(false)
    expect(r).not.toMatch(/NPM_TOKEN|NODE_AUTH_TOKEN|id-token|secrets\./)
    for (const step of ["npm run build", "npm run typecheck", "npm test", "npm run pack:check"]) expect(r).toContain(step)
  })

  it("publish.yml is workflow_dispatch only, with a required confirm input", () => {
    const p = wf("publish.yml")
    const on = onBlock(p)
    expect(on).toMatch(/^\s{2}workflow_dispatch:/m)
    expect(on).not.toMatch(/^\s{2}(push|pull_request|pull_request_target|release|schedule|workflow_run|workflow_call):/m)
    expect(on).toMatch(/confirm:\s*\n(\s+.*\n)*?\s+required: true/)
  })

  it("the confirm input must equal the tag, and is never interpolated into a shell", () => {
    const p = wf("publish.yml")
    expect(p).toContain('"v$CONFIRM" != "$GITHUB_REF_NAME"')
    expect(p).toContain('"$GITHUB_REF_TYPE" != "tag"')
    for (const line of p.split("\n").filter((l) => l.includes("${{ inputs."))) {
      expect(line).toMatch(/^\s+[A-Z_]+: \$\{\{ inputs\.confirm \}\}$/)
    }
  })

  it("only the publish job has id-token: write and secrets, in the npm-publish environment", () => {
    const p = wf("publish.yml")
    const top = p.slice(0, p.search(/^jobs:/m))
    expect(top).not.toMatch(/id-token/)
    const j = jobs(p)
    expect(Object.keys(j)).toEqual(["verify", "publish"])
    expect(j.publish).toMatch(/needs: verify/)
    expect(j.publish).toMatch(/environment: npm-publish/)
    expect(j.publish).toMatch(/id-token: write/)
    expect(j.publish).toMatch(/--provenance/)
    // npm rejects provenance from a private repo: fail early with a clear message
    expect(j.publish).toContain("github.event.repository.private")
    expect(j.verify).not.toMatch(/id-token|secrets\.|environment:/)
  })

  it("scripts/check-versions.mjs accepts the current version and rejects others", () => {
    const v = JSON.parse(readFileSync(`${root}package.json`, "utf8")).version as string
    const run = (arg: string) => {
      try {
        execFileSync(process.execPath, ["scripts/check-versions.mjs", arg], { cwd: root, stdio: "pipe" })
        return 0
      } catch (e) {
        return (e as { status: number }).status
      }
    }
    expect(run(v)).toBe(0)
    expect(run("9.9.9")).toBe(1)
    expect(run("1.0.0; rm -rf /")).toBe(1)
  })
})
