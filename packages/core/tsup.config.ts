import { defineConfig } from "tsup"

export default defineConfig({
  entry: ["src/index.ts", "src/backend.ts"],
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  sourcemap: false,
  target: "es2022",
  external: [/^@untracenetwork\//, "react", "vue", "next"],
})
