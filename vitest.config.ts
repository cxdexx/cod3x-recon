import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    testTimeout: 60000,
    globals: true,
    coverage: {
      provider: "v8",
      include: [
        "src/core/**/*.ts",
        "src/utils/**/*.ts",
        "src/engine/**/*.ts",
        "src/nuclei/**/*.ts",
        "src/plugins/**/*.ts"
      ]
    }
  }
});
