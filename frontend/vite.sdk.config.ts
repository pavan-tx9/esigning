/// <reference types="vite/client" />
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
  define: {
    "process.env.NODE_ENV": '"production"',
  },
  build: {
    lib: {
      entry: fileURLToPath(new URL("./src/sdk/index.ts", import.meta.url)),
      name: "EsignSdk",
      formats: ["es"],
      fileName: () => "index.js",
    },
    outDir: "dist-sdk",
    emptyOutDir: true,
    sourcemap: true,
    rollupOptions: {
      external: ["react", "react-dom", "react/jsx-runtime", "@tanstack/react-query"],
    },
  },
});
