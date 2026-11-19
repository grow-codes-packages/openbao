import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    "testing/index": "src/testing-entry.ts",
  },
  format: ["esm", "cjs"],
  outDir: "lib",
  target: "node22",
  platform: "node",
  dts: true,
  sourcemap: true,
  clean: true,
  // Shared chunks keep one copy of every class across "." and "./testing" (instanceof works).
  splitting: true,
  treeshake: true,
  shims: true,
});
