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
      entry: fileURLToPath(new URL("./src/sdk/mount.ts", import.meta.url)),
      name: "EsignSdk",
      formats: ["iife"],
      fileName: () => "esign-sdk.js",
    },
    outDir: "dist",
    emptyOutDir: false,
    cssCodeSplit: false,
    rollupOptions: {
      output: {
        assetFileNames: (asset) => {
          const names = "names" in asset && Array.isArray(asset.names) ? asset.names : [];
          const fallback = "name" in asset && typeof asset.name === "string" ? asset.name : "";
          const css =
            names.some((n) => typeof n === "string" && n.endsWith(".css")) ||
            fallback.endsWith(".css");
          return css ? "esign-sdk.css" : "assets/[name]-[hash][extname]";
        },
      },
    },
  },
});
