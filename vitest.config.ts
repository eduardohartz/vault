import { resolve } from "node:path"
import { defineConfig } from "vitest/config"

export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    // The P-521 arithmetic is a hand-rolled double-and-add over BigInt, so a
    // single scalar multiplication costs tens of milliseconds and the curve
    // tests do many. The 5s default flaked on a loaded machine; CI runners are
    // slower still, and a test that fails at random is a test people learn to
    // ignore.
    testTimeout: 30_000,
  },
  resolve: {
    alias: {
      "@": resolve(__dirname, "."),
    },
  },
})
