import { fileURLToPath } from "node:url"
import { defineConfig } from "vitest/config"

const src = (p: string) => fileURLToPath(new URL(`./packages/${p}`, import.meta.url))

export default defineConfig({
  resolve: {
    alias: {
      "@untracenetwork/sdk/backend": src("core/src/backend.ts"),
      "@untracenetwork/sdk": src("core/src/index.ts"),
    },
  },
  test: { include: ["packages/*/test/**/*.test.ts", "test/**/*.test.ts"], environment: "node", testTimeout: 30_000 },
})
