import { fileURLToPath } from "node:url"
import { defineConfig } from "vitest/config"

const src = (p: string) => fileURLToPath(new URL(`./packages/${p}`, import.meta.url))

// Live suite against a real Drive. Skipped unless the UNTRACE_* env vars are set.
// Run: npm run test:live (see test-live/README.md). Never part of per-push CI.
export default defineConfig({
  resolve: {
    alias: {
      "@untracenetwork/sdk/backend": src("core/src/backend.ts"),
      "@untracenetwork/sdk": src("core/src/index.ts"),
    },
  },
  test: {
    include: ["test-live/**/*.live.test.ts"],
    environment: "node",
    testTimeout: 120_000,
    hookTimeout: 120_000,
    fileParallelism: false,
    sequence: { concurrent: false },
  },
})
