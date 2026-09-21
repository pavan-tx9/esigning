/// <reference types="vitest/config" />
import { fileURLToPath, URL } from "node:url";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  server: {
    // Not 5173: other projects on this machine sit there, and a signing UI that silently
    // attaches to the wrong dev server is worse than one that refuses to start.
    port: 5273,
    strictPort: true,
    proxy: {
      // The API is same-origin in production; in dev it lives on :8000.
      "/v1": {
        target: "http://localhost:8000",
        changeOrigin: false,
      },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    // Playwright specs are run by `bun run e2e`, not by vitest.
    exclude: ["e2e/**", "node_modules/**", "dist/**"],
    css: false,
  },
});
